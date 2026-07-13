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
        
        # Evaluate rules
        matches = self.rule_engine.evaluate(entry)
        
        is_trash = len(matches) > 0
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
                
                # Handle blocking
                if rule.action == BlockAction.DROP and not self.state.is_ip_blocked(entry.ip):
                    decision = BlockDecision.from_rule(entry.ip, rule, entry, confidence)
                    await self._handle_block(decision)
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
    
    def _is_new_day(self) -> bool:
        """Check if new day started."""
        current_day = datetime.utcnow().strftime('%d')
        return hasattr(self, '_last_day') and self._last_day != current_day
    
    async def _shutdown(self) -> None:
        """Graceful shutdown."""
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
