"""FWTrash v2.0 CLI - Modern command-line interface."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from fwtrash.core.blocking import BlockManager, BlockManagerConfig, IptablesBackend, NullBackend
from fwtrash.core.models import PipelineConfig, PipelineState
from fwtrash.engine.output import FileOutputHandler
from fwtrash.engine.pipeline import Pipeline
from fwtrash.parsers.base import LogParser
from fwtrash.rules.engine import RuleEngine

try:
    from fwtrash.api.server import create_app, set_pipeline_state
    from uvicorn import Config, Server
    HAS_DASHBOARD = True
except ImportError:
    HAS_DASHBOARD = False

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("fwtrash")

app = typer.Typer(
    name="fwtrash",
    help="FWTrash v2.0 - Modern security log analyzer",
    rich_markup_mode="rich",
)
console = Console()

_pipeline: Pipeline | None = None


def _signal_handler(sig: int, frame) -> None:
    global _pipeline
    if _pipeline:
        logger.info("Shutdown requested...")
        _pipeline.request_shutdown()


@app.callback()
def main(
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
) -> None:
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.WARNING)


@app.command()
def run(
    rules: Annotated[str, typer.Option("--rules", "-P")] = "",
    parser: Annotated[str, typer.Option("--parser", "-p")] = "auto",
    badips_file: Annotated[str, typer.Option("--badips", "-o")] = "",
    trash_file: Annotated[str, typer.Option("--trash", "-O")] = "",
    allowed_ips_file: Annotated[str, typer.Option("--allowed", "-a")] = "",
    command: Annotated[str, typer.Option("--command", "-c")] = "",
    dry_run: Annotated[bool, typer.Option("--dry-run", "-n")] = False,
    stat_keys: Annotated[str, typer.Option("--stat-keys", "-s")] = "",
    stat_template: Annotated[str, typer.Option("--stat-template", "-S")] = "",
    disable_stats: Annotated[bool, typer.Option("--disable-stats", "-d")] = False,
    stop_next_day: Annotated[bool, typer.Option("--stop-next-day", "-D")] = False,
    autosave: Annotated[int, typer.Option("--autosave")] = 10,
    dashboard: Annotated[bool, typer.Option("--dashboard")] = False,
    dashboard_port: Annotated[int, typer.Option("--dashboard-port")] = 8080,
    legacy_mode: Annotated[bool, typer.Option("--legacy-mode")] = False,
    version: Annotated[bool, typer.Option("--version", "-V")] = False,
) -> None:
    """Run FWTrash pipeline."""
    if version:
        console.print("FWTrash v2.0.0")
        raise typer.Exit()

    if not rules:
        logger.error("Rules file required (--rules/-P)")
        raise typer.Exit(1)

    if not Path(rules).exists():
        logger.error(f"Rules file not found: {rules}")
        raise typer.Exit(1)

    config = PipelineConfig(
        rules_file=rules,
        badips_file=badips_file or None,
        trash_file=trash_file or None,
        allowed_ips_file=allowed_ips_file or None,
        verbose=not disable_stats,
        disable_stats=disable_stats,
        stop_on_new_day=stop_next_day,
        autosave_interval=autosave,
        on_badip_command=command or None,
        stat_display_keys=stat_keys.split(",") if stat_keys else [],
        stat_display_template=stat_template,
    )

    allowed_ips = set()
    if allowed_ips_file and Path(allowed_ips_file).exists():
        with open(allowed_ips_file) as f:
            allowed_ips = {line.strip() for line in f if line.strip()}
        logger.info(f"Loaded {len(allowed_ips)} allowed IPs")

    asyncio.run(_async_run(config, parser, allowed_ips, dry_run, legacy_mode, dashboard, dashboard_port))


async def _async_run(
    config: PipelineConfig,
    parser_name: str,
    allowed_ips: set[str],
    dry_run: bool,
    legacy_mode: bool,
    dashboard: bool,
    dashboard_port: int,
) -> None:
    global _pipeline

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    parser = LogParser.get_parser(parser_name) if parser_name != "auto" else None

    rule_engine = RuleEngine()
    rule_engine.load_from_json(config.rules_file)
    logger.info(f"Loaded {len(rule_engine._rules)} rules")

    state = PipelineState(config=config)
    state.allowed_ips = allowed_ips

    output_handler = None
    if config.trash_file or config.badips_file:
        output_handler = FileOutputHandler(
            trash_file=config.trash_file,
            badips_file=config.badips_file,
            template=config.stat_display_template or "[--DATE] [--IP] => [--REQ]"
        )

    backend = NullBackend() if dry_run else IptablesBackend()
    logger.info("Dry-run mode" if dry_run else "Using iptables backend")

    block_manager = BlockManager(
        state=state,
        backend=backend,
        config=BlockManagerConfig(enable_auto_unblock=True)
    )

    _pipeline = Pipeline(
        config=config,
        parser=parser or LogParser.get_parser("http"),
        rule_engine=rule_engine,
        state=state,
        output_handler=output_handler,
        blocking_backend=backend
    )

    if not config.disable_stats:
        _pipeline.add_callback("trash", lambda e, r: logger.debug(f"Trash: {e.ip}"))
        _pipeline.add_callback("block", lambda d: logger.info(f"Blocked: {d.ip}"))

    # Start dashboard if requested
    dashboard_task = None
    if dashboard:
        if not HAS_DASHBOARD:
            logger.error("Dashboard not available. Install with: pip install fwtrash[dashboard]")
        else:
            set_pipeline_state(state)
            dashboard_task = asyncio.create_task(_start_dashboard(dashboard_port))

    await block_manager.start()

    try:
        logger.info("Starting pipeline... (Ctrl+C to stop)")
        if legacy_mode:
            logger.info("Legacy mode enabled")

        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        await _pipeline.run(reader)

    except KeyboardInterrupt:
        logger.info("Interrupted")
    finally:
        await block_manager.stop()
        if dashboard_task:
            dashboard_task.cancel()
            try:
                await dashboard_task
            except asyncio.CancelledError:
                pass

        if not config.disable_stats:
            _print_stats(state)


async def _start_dashboard(port: int) -> None:
    """Start dashboard server."""
    app = create_app()
    config = Config(app=app, host="0.0.0.0", port=port, log_level="warning")
    server = Server(config)
    logger.info(f"Dashboard started on http://0.0.0.0:{port}")
    await server.serve()


def _print_stats(state: PipelineState) -> None:
    table = Table(title="Pipeline Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    stats = state.stats
    table.add_row("Total Processed", str(stats.total_processed))
    table.add_row("Allowed", str(stats.total_allowed))
    table.add_row("Trash", str(stats.total_trash))
    table.add_row("Blocked", str(stats.total_blocked))
    table.add_row("Active Blocks", str(len(state.active_blocks)))
    table.add_row("Uptime (s)", f"{stats.uptime_seconds:.1f}")
    table.add_row("Rate (eps)", f"{stats.entries_per_second:.1f}")

    console.print()
    console.print(table)


@app.command()
def detect(lines: Annotated[int, typer.Option("--lines", "-n")] = 10) -> None:
    """Auto-detect log format."""
    console.print("[bold]Paste sample log lines (Ctrl+D when done):[/bold]")
    
    sample_lines = []
    try:
        while len(sample_lines) < lines:
            line = input()
            if line:
                sample_lines.append(line)
    except EOFError:
        pass

    results = []
    for name, pclass in LogParser._registry.items():
        parser = pclass()
        scores = [parser.can_parse(l) for l in sample_lines]
        avg = sum(scores) / len(scores) if scores else 0
        results.append((name, avg, pclass.description))

    results.sort(key=lambda x: x[1], reverse=True)

    table = Table(title="Detection Results")
    table.add_column("Parser", style="cyan")
    table.add_column("Confidence", style="magenta")
    table.add_column("Description", style="green")

    for name, score, desc in results:
        conf = "high" if score > 0.8 else "medium" if score > 0.5 else "low"
        table.add_row(name, f"{score:.1%} ({conf})", desc)

    console.print(table)
    if results and results[0][1] > 0.5:
        console.print(f"\n[green]Recommended: {results[0][0]}[/green]")


@app.command()
def list_parsers() -> None:
    """List available parsers."""
    table = Table(title="Available Parsers")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="green")

    for name, desc in sorted(LogParser.list_parsers().items()):
        table.add_row(name, desc)

    console.print(table)


@app.command()
def validate_rules(rules_file: Annotated[Path, typer.Argument()]) -> None:
    """Validate rules file."""
    if not rules_file.exists():
        console.print(f"[red]Not found: {rules_file}[/red]")
        raise typer.Exit(1)

    try:
        engine = RuleEngine()
        engine.load_from_json(str(rules_file))
        
        table = Table(title="Validation Results")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")
        
        stats = engine.get_stats()
        table.add_row("Rules Loaded", str(stats["rules_loaded"]))
        table.add_row("Conditions Cached", str(stats["conditions_cached"]))
        
        console.print(table)
        console.print("[green]Valid![/green]")
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
