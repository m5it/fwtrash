"""Pipeline engine for processing log streams.

Replaces v0.6's global state (Stats, g_badips, g_trash) with
dependency-injected PipelineState and async processing.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Coroutine, Protocol

from fwtrash.core.models import (
    BlockAction,
    BlockDecision,
    LogEntry,
    PipelineConfig,
    PipelineState,
    PipelineStats,
    Rule,
)
from fwtrash.parsers.base import LogParser, ParseError
from fwtrash.rules.engine import RuleEngine

logger = logging.getLogger("fwtrash.pipeline")


class OutputHandler(Protocol):
    """Protocol for output handlers (files, commands, etc.)."""
    
    async def write_trash(self, entry: LogEntry, rule: Rule | None = None) -> None:
        """Write trash entry to output."""
        ...
    
    async def write_block(self, decision: BlockDecision) -> None:
        """Write block decision to output."""
        ...
    
    async def close(self) -> None:
        """Clean up resources."""
        ...


class BlockingBackend(Protocol):
    """Protocol for IP blocking backends."""
    
    async def block(self, decision: BlockDecision) -> bool:
        """Execute block for the given decision."""
        ...
    
    async def unblock(self, ip: str) -> bool:
        """Remove block for IP."""
        ...
    
    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        ...


@dataclass
class RateLimiter:
    """Token bucket rate limiter for backpressure."""
    
    rate: float = 1000.0  # tokens per second
    burst: int = 100     # max tokens
    _tokens: float = field(default=0.0, init=False)
    _last_update: float = field(default_factory=time.time, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    
    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, waiting if necessary."""
        async with self._lock:
            now = time.time()
            elapsed = now - self._last_update
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last_update = now
            
            if self._tokens < tokens:
                wait_time = (tokens - self._tokens) / self.rate
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= tokens
    
    async def try_acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens without waiting."""
        async with self._lock:
            now = time.time()
            elapsed = now - self._last_update
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last_update = now
            
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


class Pipeline:
    """Main processing pipeline for log analysis.
    
    Replaces v0.6's global variables with dependency-injected state:
    - Stats -> PipelineState.stats
    - g_badips -> PipelineState.active_blocks
    - g_trash -> PipelineState.recent_trash
    - g_allowedips -> PipelineState.allowed_ips
    """
    
    def __init__(
        self,
        config: PipelineConfig,
        parser: LogParser,
        rule_engine: RuleEngine,
        state: PipelineState | None = None,
        output_handler: OutputHandler | None = None,
        blocking_backend: BlockingBackend | None = None,
    ) -> None:
        self.config = config
        self.parser = parser
        self.rule_engine = rule_engine
        self.state = state or PipelineState(config=config)
        self.output_handler = output_handler
        self.blocking_backend = blocking_backend
        
        # Async components
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=10000)
        self._rate_limiter = RateLimiter(rate=10000, burst=1000)
        self._shutdown_event = asyncio.Event()
        self._workers: list[asyncio.Task[Any]] = []
        self._num_workers = 4
        
        # Callbacks
        self._on_entry: list[Callable[[LogEntry], None]] = []
        self._on_trash: list[Callable[[LogEntry, Rule], None]] = []
        self._on_block: list[Callable[[BlockDecision], None]] = []
        
        # Debug throttling: buffer TRASH lines, flush every 10s to reduce movement
        self._debug_buf: list[str] = []
        self._debug_last_flush: float = 0.0
        self._debug_window_trash: int = 0
        self._debug_window_total: int = 0
        self._debug_window_start: float = time.time()
        self._debug_lock = asyncio.Lock() if False else None  # created lazily in async context

        # Bruteforce tracking: key -> ip -> deque[timestamps]
        from collections import defaultdict
        self._bruteforce_store: dict[int, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        # Serialize blocking per IP to avoid 4 concurrent workers adding same iptables rule
        self._block_lock = asyncio.Lock()

        # Setup signal handlers
        self._setup_signals()
    
    def _setup_signals(self) -> None:
        """Setup graceful shutdown on signals."""
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, self._signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
    
    def _signal_handler(self) -> None:
        """Handle shutdown signal."""
        logger.info("Shutdown signal received")
        self.request_shutdown()
    
    def request_shutdown(self) -> None:
        """Request graceful shutdown."""
        self.state.shutdown_requested = True
        self._shutdown_event.set()
    
    def add_callback(self, event: str, callback: Callable[..., None]) -> None:
        """Add event callback."""
        if event == "entry":
            self._on_entry.append(callback)
        elif event == "trash":
            self._on_trash.append(callback)
        elif event == "block":
            self._on_block.append(callback)
    
    async def process_line(self, line: str) -> LogEntry | None:
        """Process a single log line (non-blocking).
        
        Returns parsed entry or None if filtered/error.
        """
        # Rate limiting
        await self._rate_limiter.acquire()
        
        # Update stats
        self.state.stats.increment("processed")
        self.state.stats.last_entry_at = datetime.utcnow()
        
        # Parse
        try:
            entry = self.parser.parse(line)
        except ParseError as e:
            logger.debug(f"Parse error: {e}")
            self.state.stats.increment("errors")
            return None
        
        # Check allowlist
        if self.state.is_ip_allowed(entry.ip):
            self.state.stats.increment("allowed")
            return entry
        
        # Evaluate rules (with optional debug trace)
        # Evaluate (debug-aware to avoid double work)
        debug = getattr(self.config, "debug_mode", "off")
        matches: list = []
        if debug == "full":
            from fwtrash.rules.engine import Condition  # avoid cycle
            for rule in self.rule_engine._rules:
                if not rule.metadata.enabled:
                    continue
                conds = self.rule_engine._compiled_conditions.get(rule.rule_id, [])
                if not conds:
                    continue
                logger.debug(f"Rule {rule.rule_id[:8]} ({rule.metadata.name or 'unnamed'}, action={rule.action.value}): {len(conds)} cond(s)")
                rule_hit = True
                min_conf = 1.0
                for cond in conds:
                    res = cond.evaluate(entry)
                    val = cond._get_field_value(entry)
                    logger.debug(f"  cond field={cond.field!r} type={cond.condition_type.value} negate={cond.negate} val={str(val)[:120]!r} -> matched={res.matched} conf={res.confidence}")
                    if not res.matched:
                        rule_hit = False
                        break
                    min_conf = min(min_conf, res.confidence)
                if rule_hit and rule.matches_confidence(min_conf):
                    logger.debug(f"  => MATCH conf={min_conf}")
                    matches.append((rule, min_conf))
                else:
                    logger.debug(f"  => no match")
        else:
            matches = self.rule_engine.evaluate(entry)

        # Bruteforce: rules with bruteforce_count_key only become trash after threshold (repeat logic)
        # e.g. http.rules has [{"code":404,"bruteforce_count_key":1},{"ref":"\"-\"",...}] meaning 3x 404/- in 60s
        raw_is_trash = len(matches) > 0
        is_trash = raw_is_trash
        if raw_is_trash:
            # Check if all matched rules are bruteforce-gated
            non_bf_matches = []
            bf_matches = []
            for rule, conf in matches:
                if rule.is_brute_force_rule:
                    bf_matches.append((rule, conf))
                else:
                    non_bf_matches.append((rule, conf))
            if bf_matches and not non_bf_matches:
                # Only bruteforce rules matched — apply throttling
                triggered: list[tuple[Rule, float]] = []
                for rule, conf in bf_matches:
                    # Find the bruteforce key(s) used — take first (v0.6 uses same key across conditions)
                    bf_key = next((c.bruteforce_key for c in rule.conditions if c.bruteforce_key is not None), None)
                    if bf_key is None:
                        triggered.append((rule, conf))
                        continue
                    limits = self.config.bruteforce_limits.get(bf_key) if hasattr(self.config, "bruteforce_limits") else None
                    # Default like v0.6 example: key:1 -> 3/60, fallback 3/60
                    climit, tlimit = limits if limits else (3, 60)
                    dq = self._bruteforce_store[bf_key][entry.ip]
                    now_ts = time.time()
                    dq.append(now_ts)
                    # Evict outside window
                    while dq and dq[0] < now_ts - tlimit:
                        dq.popleft()
                    if len(dq) >= climit:
                        triggered.append((rule, conf))
                        # Keep window but don't reset immediately — v0.6 resets after trigger, we keep sliding
                        # Optional: clear after trigger to avoid spamming every line
                        # dq.clear()
                    else:
                        # Not yet threshold — treat as OK for now (but keep stats for debug)
                        logger.debug(f"Bruteforce key={bf_key} ip={entry.ip} {len(dq)}/{climit} in {tlimit}s — not yet trash")
                # Only keep those that passed threshold
                is_trash = len(triggered) > 0
                matches = triggered if is_trash else []
            # else: has at least one non-bf rule -> immediate trash

        # Debug output — throttled every 10s; low = quiet (live table only), half/full add samples
        if debug in ("half", "half-all", "full"):
            self._debug_window_total += 1
            if is_trash:
                self._debug_window_trash += 1
                if len(self._debug_buf) < 5:
                    self._debug_buf.append(f"TRASH {entry.ip} {entry.parsed_fields.get('code','-')} {entry.parsed_fields.get('req','-')[:100]!r} -> {len(matches)} rule(s)")
            now = time.time()
            # For is_trash we keep sample; for half-all we also want OK visibility via counts only
            is_flush = (now - self._debug_last_flush) >= 10.0
            must_flush = is_flush or (debug == "full" and len(self._debug_buf) >= 5)
            if must_flush and (self._debug_window_total > 0 or self._debug_buf):
                dt = now - self._debug_window_start
                eps = self._debug_window_total / dt if dt > 0 else 0
                trash_rate = (self._debug_window_trash / self._debug_window_total * 100) if self._debug_window_total else 0
                logger.info(f"[debug {debug}] {self._debug_window_trash}/{self._debug_window_total} trash ({trash_rate:.1f}%) {eps:.0f} eps | samples:")
                for line in self._debug_buf:
                    logger.info(f"  {line}")
                if debug == "half-all":
                    logger.info(f"  (half-all: {self._debug_window_total - self._debug_window_trash} OK suppressed in half, shown here)")
                self._debug_buf = []
                self._debug_window_trash = 0
                self._debug_window_total = 0
                self._debug_window_start = now
                self._debug_last_flush = now

        if is_trash:
            self.state.stats.increment("trash")
            self.state.stats.add_recent_trash(entry)
            
            for rule, confidence in matches:
                # Fire callbacks
                for cb in self._on_trash:
                    cb(entry, rule)
                
                # Output trash
                if self.output_handler:
                    await self.output_handler.write_trash(entry, rule)
                
                # Handle blocking (or forced via --block) — serialized per IP to dedup iptables
                force = getattr(self.config, "force_block", False)
                if (rule.action == BlockAction.DROP or force) and not self.state.is_ip_blocked(entry.ip):
                    async with self._block_lock:
                        if self.state.is_ip_blocked(entry.ip):
                            logger.debug(f"Skipping duplicate block for {entry.ip} (already in state)")
                        else:
                            decision = BlockDecision.from_rule(entry.ip, rule, entry, confidence)
                            await self._handle_block(decision)
                    # In --block mode, count as blocked immediately for stats parity
                    if force and rule.action != BlockAction.DROP:
                        logger.debug(f"--block forced DROP for {entry.ip} (rule log->drop)")
        else:
            self.state.stats.increment("allowed")
            self.state.stats.add_recent_pure(entry)
        
        # Fire entry callbacks
        for cb in self._on_entry:
            cb(entry)
        
        # Autosave state
        if self.state.stats.total_processed % self.config.autosave_interval == 0:
            self._autosave()
        
        return entry
    
    async def _handle_block(self, decision: BlockDecision) -> None:
        """Handle block decision."""
        # Add to state
        self.state.add_block(decision)
        
        # Execute block command
        if self.blocking_backend:
            success = await self.blocking_backend.block(decision)
            if success:
                decision.mark_executed()
        elif self.config.on_badip_command:
            # Legacy command execution
            await self._execute_command(decision)
        
        # Output
        if self.output_handler:
            await self.output_handler.write_block(decision)
        
        # Callbacks
        for cb in self._on_block:
            cb(decision)
    
    async def _execute_command(self, decision: BlockDecision) -> None:
        """Execute legacy command template."""
        if not self.config.on_badip_command:
            return
        
        cmd = self.config.on_badip_command.replace("[--IP]", decision.ip)
        cmd = cmd.replace("[--REASON]", decision.reason)
        
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
            if proc.returncode == 0:
                decision.mark_executed()
        except Exception as e:
            logger.error(f"Command failed: {e}")
    
    def _autosave(self) -> None:
        """Save checkpoint state."""
        self.state.checkpoint()
        # TODO: Persist to file
    
    async def _worker(self, worker_id: int) -> None:
        """Worker coroutine for parallel processing."""
        logger.debug(f"Worker {worker_id} started")
        
        while not self._shutdown_event.is_set():
            try:
                # Get line with timeout for periodic checks
                line = await asyncio.wait_for(
                    self._queue.get(),
                    timeout=0.1
                )
            except asyncio.TimeoutError:
                continue
            
            if line is None:  # Shutdown sentinel
                break
            
            try:
                await self.process_line(line)
            except Exception as e:
                logger.exception(f"Worker {worker_id} error: {e}")
            finally:
                self._queue.task_done()
        
        logger.debug(f"Worker {worker_id} stopped")
    
    async def feed(self, line: str) -> None:
        """Feed a line into the pipeline (async)."""
        await self._queue.put(line)
    
    async def feed_blocking(self, line: str, timeout: float | None = None) -> bool:
        """Feed with backpressure - waits if queue full."""
        try:
            await asyncio.wait_for(self._queue.put(line), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False
    
    async def run(self, input_stream: asyncio.StreamReader | None = None) -> None:
        """Run the pipeline."""
        self.state.is_running = True
        
        # Start workers
        self._workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self._num_workers)
        ]
        
        try:
            if input_stream:
                await self._read_stream(input_stream)
            else:
                # Wait for manual feed
                await self._shutdown_event.wait()
        finally:
            await self._shutdown()
    
    async def _read_stream(self, stream: asyncio.StreamReader) -> None:
        """Read from stream and feed pipeline."""
        while not self._shutdown_event.is_set():
            try:
                line = await stream.readline()
                if not line:
                    break  # EOF

                line_str = line.decode(self.parser.encoding).rstrip('\n')

                # Check for new day (v0.6 compatibility)
                if self.config.stop_on_new_day and self._is_new_day():
                    self.request_shutdown()
                    break

                await self.feed(line_str)
            except UnicodeDecodeError as e:
                logger.warning(f"Decode error: {e}")
                continue

    async def run_file(self, path: str, follow: bool = False) -> None:
        """Run pipeline reading from a file.

        Args:
            path: Log file path.
            follow: If True, keep tailing like ``tail -F`` (handles
                    rotation/truncation). If False, read once to EOF and exit.
        """
        self.state.is_running = True

        self._workers = [
            asyncio.create_task(self._worker(i)) for i in range(self._num_workers)
        ]

        try:
            if follow:
                await self._tail_file(path)
            else:
                await self._read_file(path)
            # When not following, wait for queue to drain via shutdown
            if not follow:
                await self._queue.join()
        finally:
            await self._shutdown()

    async def _read_file(self, path: str) -> None:
        """Read file once (batch mode) without following."""
        loop = asyncio.get_running_loop()
        # Use thread executor for blocking file I/O
        def _iter_lines():
            with open(path, "r", encoding=self.parser.encoding, errors="replace") as f:
                for line in f:
                    yield line.rstrip("\n")

        # We must not block the event loop on a 3 GB file — stream it line-by-line
        # via a thread so workers can process concurrently.
        import concurrent.futures
        # Simple synchronous generator wrapped in executor: read in thread, feed via queue
        def _produce():
            for line in _iter_lines():
                if self._shutdown_event.is_set():
                    break
                # feed is async — schedule via run_coroutine_threadsafe
                fut = asyncio.run_coroutine_threadsafe(self.feed(line), loop)
                try:
                    fut.result(timeout=5)
                except Exception:
                    pass
                if self.config.stop_on_new_day and self._is_new_day():
                    self.request_shutdown()
                    break

        await asyncio.to_thread(_produce)

    async def _tail_file(self, path: str) -> None:
        """Follow file like ``tail -F`` with rotation/truncation handling."""
        logger.info(f"Tailing {path} (follow mode, handles rotation)")
        # Start at end of file like tail -f (don't replay 15 M lines on restart)
        # Use --no-follow-start / reading from start if you need history.
        try:
            pos = Path(path).stat().st_size if Path(path).exists() else 0
        except OSError:
            pos = 0
        inode = None
        try:
            inode = Path(path).stat().st_ino
        except OSError:
            pass

        loop = asyncio.get_running_loop()

        while not self._shutdown_event.is_set():
            try:
                p = Path(path)
                if not p.exists():
                    await asyncio.sleep(0.5)
                    continue

                # Detect rotation: inode changed or file truncated
                try:
                    st = p.stat()
                    if inode is not None and st.st_ino != inode:
                        logger.info(f"Log rotated (inode {inode} -> {st.st_ino}), reopening")
                        inode = st.st_ino
                        pos = 0
                    elif st.st_size < pos:
                        logger.info("Log truncated, rewinding")
                        pos = 0
                    else:
                        inode = st.st_ino
                except OSError:
                    pass

                # Read new data
                def _read_chunk() -> list[str]:
                    nonlocal pos
                    lines: list[str] = []
                    try:
                        with open(path, "r", encoding=self.parser.encoding, errors="replace") as f:
                            f.seek(pos)
                            for line in f:
                                lines.append(line.rstrip("\n"))
                            pos = f.tell()
                    except OSError as e:
                        logger.warning(f"Read error: {e}")
                    return lines

                chunk = await asyncio.to_thread(_read_chunk)
                for line in chunk:
                    if not line:
                        continue
                    if self.config.stop_on_new_day and self._is_new_day():
                        self.request_shutdown()
                        return
                    await self.feed(line)

                await asyncio.sleep(0.2)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Tail error: {e}")
                await asyncio.sleep(1)
    
    def _is_new_day(self) -> bool:
        """Check if new day started."""
        current_day = datetime.utcnow().strftime('%d')
        return hasattr(self, '_last_day') and self._last_day != current_day
    
    def _flush_debug_window(self) -> None:
        """Emit any remaining debug samples on shutdown (so batch jobs aren't silent)."""
        debug = getattr(self.config, "debug_mode", "off")
        if debug in ("half", "half-all", "full") and (self._debug_window_total or self._debug_buf):
            now = time.time()
            dt = now - self._debug_window_start
            eps = self._debug_window_total / dt if dt > 0 else 0
            trash_rate = (self._debug_window_trash / self._debug_window_total * 100) if self._debug_window_total else 0
            logger.info(f"[debug {debug}] final {self._debug_window_trash}/{self._debug_window_total} trash ({trash_rate:.1f}%) {eps:.0f} p/s")
            for line in self._debug_buf:
                logger.info(f"  {line}")
            self._debug_buf = []
            self._debug_window_total = 0
            self._debug_window_trash = 0

    async def _shutdown(self) -> None:
        """Graceful shutdown."""
        self._flush_debug_window()
        logger.info("Shutting down pipeline...")
        self.state.is_running = False
        
        # Wait for queue to drain
        await self._queue.join()
        
        # Stop workers
        for _ in self._workers:
            await self._queue.put(None)  # Sentinel
        
        await asyncio.gather(*self._workers, return_exceptions=True)
        
        # Cleanup
        if self.output_handler:
            await self.output_handler.close()
        
        # Final checkpoint
        self._autosave()
        
        logger.info("Pipeline shutdown complete")
    
    def get_summary(self) -> dict[str, Any]:
        """Get current pipeline summary."""
        return self.state.summary
    
    def get_stats(self) -> PipelineStats:
        """Get current stats."""
        return self.state.stats
