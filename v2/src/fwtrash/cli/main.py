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
    help="FWTrash v2.0 - Modern security log analyzer. Use 'fwtrash run -h' for pipeline options, 'fwtrash --help' for all commands.",
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    add_completion=False,
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
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose (DEBUG) logging — alias for --debug full")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Quiet (WARNING only)")] = False,
    debug: Annotated[str, typer.Option("--debug", help="Debug: off | low (just Blocked + 10s stats changing) | half (add throttled TRASH samples) | full (per-condition). -v=full")] = "off",
) -> None:
    # Normalize --debug value (supports --debug low)
    dbg = (debug or "off").strip().lower()
    if dbg not in ("off", "low", "half", "half-all", "full"):
        if dbg in ("true", "1", "on", ""):
            dbg = "low"
    if verbose:
        dbg = "full"
    # Persist for run() to read via context
    import os
    os.environ["FWTRASH_DEBUG"] = dbg
    if dbg == "full" or verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif dbg == "half":
        logging.getLogger().setLevel(logging.INFO)


@app.command()
def run(
    rules: Annotated[str, typer.Option("--rules", "-P", help="Rules file (e.g. rules/http.rules)")] = "",
    input_file: Annotated[str, typer.Option("--input", "-i", help="Log file to read (e.g. /var/log/nginx/access.log). If omitted, reads from stdin — use: tail -F log | fwtrash run ...")] = "",
    follow: Annotated[bool, typer.Option("--follow", "-F", help="Follow file like tail -F (with rotation handling). Requires --input. Without it, file is read once and fwtrash exits.")] = False,
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
    debug: Annotated[str, typer.Option("--debug", help="Debug: off | low (just live stats + Blocked) | half (throttled trash) | half-all | full (per-condition). -v=>full")] = "off",
    block: Annotated[bool, typer.Option("--block", help="Treat every TRASH as DROP (force iptables block). Without it, generated rules are action=log (trash-only) so Blocked stays 0; batch `Blocked 0` is normal.")] = False,
    dashboard: Annotated[bool, typer.Option("--dashboard")] = False,
    dashboard_port: Annotated[int, typer.Option("--dashboard-port")] = 8080,
    legacy_mode: Annotated[bool, typer.Option("--legacy-mode")] = False,
    version: Annotated[bool, typer.Option("--version", "-V")] = False,
) -> None:
    """Run FWTrash pipeline.

    Input is either a file (--input) or stdin (pipe):

    \b
      # Live tailing (recommended for production):
      fwtrash run -P rules/http.rules --input /var/log/nginx/access.log --follow
      # or equivalently:
      tail -F /var/log/nginx/access.log | fwtrash run -P rules/http.rules

    \b
      # One-shot batch (process existing file and exit):
      fwtrash run -P rules/http.rules --input /var/log/nginx/access.log
      # or:
      cat /var/log/nginx/access.log | fwtrash run -P rules/http.rules
    """
    if version:
        console.print("FWTrash v2.0.0")
        raise typer.Exit()

    if not rules:
        logger.error("Rules file required (--rules/-P)")
        raise typer.Exit(1)

    if not Path(rules).exists():
        logger.error(f"Rules file not found: {rules}")
        raise typer.Exit(1)

    # --debug may arrive as bool True when passed as flag without value (typer)
    if isinstance(debug, bool):
        if debug:
            debug = "half"
        else:
            debug = "off"
    # Inherit global --debug/-v if run-level not set
    import os
    if debug == "off" and os.environ.get("FWTRASH_DEBUG", "off") != "off":
        debug = os.environ["FWTRASH_DEBUG"]
    debug = debug.strip().lower() if isinstance(debug, str) else "off"
    if debug in ("true", "1", "on", ""):
        debug = "low"
    if debug not in ("off", "low", "half", "half-all", "full"):
        logger.error("--debug must be off | low | half | half-all | full (got: %s)", debug)
        raise typer.Exit(1)
    # Ensure log level reflects run-local --debug too
    if debug == "full":
        logging.getLogger().setLevel(logging.DEBUG)
    elif debug in ("low", "half") and logging.getLogger().level > logging.INFO:
        logging.getLogger().setLevel(logging.INFO)

    if follow and not input_file:
        logger.error("--follow requires --input / -i")
        raise typer.Exit(1)
    if input_file and not Path(input_file).exists():
        logger.error(f"Input file not found: {input_file}")
        raise typer.Exit(1)

    config = PipelineConfig(
        rules_file=rules,
        input_file=input_file or None,
        follow=follow,
        badips_file=badips_file or None,
        trash_file=trash_file or None,
        allowed_ips_file=allowed_ips_file or None,
        verbose=not disable_stats,
        disable_stats=disable_stats,
        stop_on_new_day=stop_next_day,
        autosave_interval=autosave,
        debug_mode=debug,
        force_block=block,
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
            template=config.stat_display_template or "[--DATE] [--IP] => [--REQ]",
            debug=(config.debug_mode != "off"),
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
    # Callbacks: low/off = quiet (only live table + Blocked), half/full add trash stream
    if config.debug_mode in ("half", "half-all", "full"):
        _pipeline.add_callback("trash", lambda e, r: logger.info(f"[trash] {e.ip} -> {e.parsed_fields.get('req','')[:80]}"))
        _pipeline.add_callback("block", lambda d: logger.info(f"[block] {d.ip}"))
    elif dry_run:
        # dry-run without debug: still show what would block, but at debug level for trash
        _pipeline.add_callback("trash", lambda e, r: logger.debug(f"[dry-trash] {e.ip}"))
        _pipeline.add_callback("block", lambda d: logger.info(f"[dry-block] {d.ip}"))

    # Start dashboard if requested
    dashboard_task = None
    if dashboard:
        if not HAS_DASHBOARD:
            logger.error("Dashboard not available. Install with: pip install fwtrash[dashboard]")
        else:
            set_pipeline_state(state)
            dashboard_task = asyncio.create_task(_start_dashboard(dashboard_port))

    await block_manager.start()

    # Live stats: refresh the Pipeline Statistics table in place every 10s (no scrolling)
    # Disabled with -d/--disable-stats, and also off when --debug half/full is active (they have their own 10s summary)
    live_stats = None
    if not config.disable_stats and config.debug_mode in ("off", "low"):
        live_stats = asyncio.create_task(_live_stats_reporter(state))

    try:
        logger.info("Starting pipeline... (Ctrl+C to stop)")
        if legacy_mode:
            logger.info("Legacy mode enabled")

        if config.input_file:
            if config.follow:
                logger.info(f"Following {config.input_file} (tail -F mode)")
            else:
                logger.info(f"Reading {config.input_file} (batch mode, exits at EOF)")
            await _pipeline.run_file(config.input_file, follow=config.follow)
        else:
            # Stdin mode — warn if stdin is a tty (no pipe) so user sees why 0 lines processed
            if sys.stdin.isatty():
                logger.warning("No --input and no pipe detected (stdin is a TTY). Nothing to read.")
                logger.warning("Use one of:")
                logger.warning("  fwtrash run -P rules/http.rules --input /var/log/nginx/access.log --follow")
                logger.warning("  tail -F /var/log/nginx/access.log | fwtrash run -P rules/http.rules")
                logger.warning("Continuing to wait on stdin — press Ctrl+C to exit or pipe data in.")
            loop = asyncio.get_event_loop()
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)

            await _pipeline.run(reader)

    except KeyboardInterrupt:
        logger.info("Interrupted")
    finally:
        await block_manager.stop()
        if live_stats:
            live_stats.cancel()
            try:
                await live_stats
            except asyncio.CancelledError:
                pass
        if dashboard_task:
            dashboard_task.cancel()
            try:
                await dashboard_task
            except asyncio.CancelledError:
                pass

        if not config.disable_stats:
            _print_stats(state)


async def _live_stats_reporter(state: PipelineState, interval: float = 10.0) -> None:
    """Periodically re-render the Pipeline Statistics table in place (every 10s). Uses rich.live."""
    # Import lazily to avoid cycle if console not needed
    from rich.live import Live
    def _make_table() -> Table:
        t = Table(title=f"Pipeline Statistics (live, {interval:.0f}s)")
        t.add_column("Metric", style="cyan")
        t.add_column("Value", style="magenta")
        s = state.stats
        t.add_row("Total Processed", str(s.total_processed))
        t.add_row("Allowed", str(s.total_allowed))
        t.add_row("Trash", str(s.total_trash))
        t.add_row("Blocked", str(s.total_blocked))
        t.add_row("Active Blocks", str(len(state.active_blocks)))
        t.add_row("Uptime (s)", f"{s.uptime_seconds:.1f}")
        t.add_row("Rate (eps)", f"{s.entries_per_second:.1f}")
        return t
    try:
        with Live(_make_table(), console=console, refresh_per_second=1, transient=False) as live:
            while not state.shutdown_requested:
                await asyncio.sleep(interval)
                live.update(_make_table())
    except asyncio.CancelledError:
        raise
    except Exception:
        # Fallback: no live if terminal doesn't support it
        pass


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
def validate_rules(
    rules_file: Annotated[Path | None, typer.Argument(help="Rules file (e.g. rules/http.rules). If omitted, validates all *.rules found near the repo.")] = None,
) -> None:
    """Validate rules file(s).

    Examples:
      fwtrash validate-rules                    # discovers rules/*.rules
      fwtrash validate-rules rules/http.rules  # single file
      fwtrash validate-rules /var/log/nginx/access.log --help
    """
    candidates: list[Path] = []
    if rules_file is None:
        # Discover: prefer cwd/rules, then common fwtrash locations
        search_roots = [
            Path.cwd(),
            Path(__file__).resolve().parents[3],  # repo root ~/fwtrash
            Path.home() / "fwtrash",
        ]
        seen: set[Path] = set()
        for root in search_roots:
            if not root.is_dir():
                continue
            for pat in ("rules/*.rules", "rules/**/*.rules", "*.rules"):
                for p in root.glob(pat):
                    if p not in seen:
                        seen.add(p)
                        candidates.append(p)
        candidates = sorted(set(candidates))
        if not candidates:
            console.print("[yellow]No rules file given and none discovered.[/yellow]")
            console.print("Usage: [cyan]fwtrash validate-rules rules/http.rules[/cyan]")
            console.print("Hint: run from ~/fwtrash or pass full path, e.g.:")
            console.print("  [dim]fwtrash validate-rules ~/fwtrash/rules/http.rules[/dim]")
            raise typer.Exit(1)
    else:
        if not rules_file.exists():
            # Hint if user ran from ~ and did ls rules failed
            hint = ""
            alt = Path("/home/t3ch/fwtrash") / rules_file
            if alt.exists():
                hint = f" (hint: found at {alt} — try: fwtrash validate-rules {alt})"
            console.print(f"[red]Not found: {rules_file}[/red]{hint}")
            raise typer.Exit(1)
        candidates = [rules_file]

    # Validate each candidate
    rows: list[tuple[Path, dict]] = []
    had_error = False
    for pf in candidates:
        try:
            engine = RuleEngine()
            engine.load_from_json(str(pf))
            rows.append((pf, engine.get_stats()))
        except Exception as e:
            console.print(f"[red]Failed {pf}: {e}[/red]")
            had_error = True

    if not rows and had_error:
        raise typer.Exit(1)

    table = Table(title="Validation Results")
    table.add_column("File", style="cyan", overflow="fold")
    table.add_column("Rules", style="magenta", justify="right")
    table.add_column("Conditions", style="magenta", justify="right")
    table.add_column("Status", style="green")
    for pf, stats in rows:
        table.add_row(str(pf), str(stats["rules_loaded"]), str(stats["conditions_cached"]), "[green]Valid[/green]")
    console.print(table)
    if len(candidates) > 1:
        console.print(f"[dim]Validated {len(rows)}/{len(candidates)} file(s)[/dim]")
    if had_error:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
