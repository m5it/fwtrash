"""BlockManager for IP blocking with pluggable backends.

Provides centralized block management with:
- Pluggable backends (iptables, null, file)
- Automatic block expiration
- Allowlist support
- Confidence scoring integration
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from fwtrash.core.models import BlockDecision, PipelineState

logger = logging.getLogger("fwtrash.blocking")


class BlockingBackend(Protocol):
    """Protocol for IP blocking implementations."""
    
    async def block(self, decision: BlockDecision) -> bool:
        """Execute block for the given decision."""
        ...
    
    async def unblock(self, ip: str) -> bool:
        """Remove block for IP."""
        ...
    
    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        ...


class NullBackend:
    """No-op backend for testing."""
    
    async def block(self, decision: BlockDecision) -> bool:
        logger.debug(f"[NULL] Would block {decision.ip}")
        return True
    
    async def unblock(self, ip: str) -> bool:
        logger.debug(f"[NULL] Would unblock {ip}")
        return True
    
    async def is_blocked(self, ip: str) -> bool:
        return False


class FileBackend:
    """Write blocks to file for audit/testing."""
    
    def __init__(self, block_file: str, unblock_file: str | None = None) -> None:
        from pathlib import Path
        self.block_file = Path(block_file)
        self.unblock_file = Path(unblock_file) if unblock_file else None
    
    async def block(self, decision: BlockDecision) -> bool:
        line = f"{decision.ip} # {decision.reason} at {decision.detected_at.isoformat()}\n"
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._append_file, self.block_file, line)
            return True
        except Exception as e:
            logger.error(f"Failed to write block: {e}")
            return False
    
    async def unblock(self, ip: str) -> bool:
        if not self.unblock_file:
            return True
        line = f"{ip} # unblocked\n"
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._append_file, self.unblock_file, line)
            return True
        except Exception as e:
            logger.error(f"Failed to write unblock: {e}")
            return False
    
    async def is_blocked(self, ip: str) -> bool:
        try:
            import aiofiles
            if not self.block_file.exists():
                return False
            async with aiofiles.open(self.block_file) as f:
                content = await f.read()
                return f"{ip} #" in content
        except Exception:
            return False
    
    def _append_file(self, path, line: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(line)


class IptablesBackend:
    """Linux iptables backend for production."""
    
    def __init__(
        self,
        chain: str = "INPUT",
        table: str = "filter",
        use_nftables: bool = False
    ) -> None:
        self.chain = chain
        self.table = table
        self.use_nftables = use_nftables
    
    async def block(self, decision: BlockDecision) -> bool:
        if self.use_nftables:
            cmd = f"nft add rule ip {self.table} {self.chain} ip saddr {decision.ip} drop"
        else:
            cmd = f"iptables -A {self.chain} -s {decision.ip}/32 -j DROP"
        
        return await self._run_command(cmd)
    
    async def unblock(self, ip: str) -> bool:
        if self.use_nftables:
            logger.warning("nftables unblock requires manual rule management")
            return False
        else:
            cmd = f"iptables -D {self.chain} -s {ip}/32 -j DROP"
        
        return await self._run_command(cmd)
    
    async def is_blocked(self, ip: str) -> bool:
        cmd = f"iptables -C {self.chain} -s {ip}/32 -j DROP 2>/dev/null && echo 'yes' || echo 'no'"
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await proc.communicate()
            return b"yes" in stdout
        except Exception:
            return False
    
    async def _run_command(self, cmd: str) -> bool:
        """Execute shell command."""
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                logger.error(f"Command failed: {cmd}")
                logger.error(f"stderr: {stderr.decode()}")
                return False
            
            return True
        except Exception as e:
            logger.exception(f"Failed to run command: {e}")
            return False


@dataclass
class BlockManagerConfig:
    """Configuration for BlockManager."""
    
    # Confidence thresholds
    min_confidence: float = 0.5
    high_confidence: float = 0.8
    
    # Block durations by confidence
    low_confidence_duration: int = 300      # 5 minutes
    medium_confidence_duration: int = 3600  # 1 hour
    high_confidence_duration: int = 86400   # 24 hours
    
    # Auto-unblock
    enable_auto_unblock: bool = True
    check_interval: int = 60  # seconds
    
    # Allowlist
    allow_private_ips: bool = True  # Don't block RFC1918


class BlockManager:
    """Centralized block management with expiration and confidence scoring."""
    
    def __init__(
        self,
        state: PipelineState,
        backend: BlockingBackend | None = None,
        config: BlockManagerConfig | None = None
    ) -> None:
        self.state = state
        self.backend = backend or NullBackend()
        self.config = config or BlockManagerConfig()
        
        self._cleanup_task: asyncio.Task | None = None
        self._running = False
    
    def _calculate_duration(self, confidence: float) -> int:
        """Calculate block duration based on confidence."""
        if confidence >= self.config.high_confidence:
            return self.config.high_confidence_duration
        elif confidence >= self.config.min_confidence:
            return self.config.medium_confidence_duration
        return self.config.low_confidence_duration
    
    def _is_allowed(self, ip: str) -> bool:
        """Check if IP is in allowlist."""
        # Check explicit allowlist
        if self.state.is_ip_allowed(ip):
            return True
        
        # Check private IPs
        if self.config.allow_private_ips:
            return self._is_private_ip(ip)
        
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is RFC1918 private."""
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False
    
    async def should_block(self, decision: BlockDecision) -> bool:
        """Determine if a block should be executed."""
        # Check confidence threshold
        if decision.confidence < self.config.min_confidence:
            logger.debug(f"Block rejected: confidence {decision.confidence} < {self.config.min_confidence}")
            return False
        
        # Check allowlist
        if self._is_allowed(decision.ip):
            logger.info(f"Block rejected: {decision.ip} is in allowlist")
            return False
        
        # Check if already blocked
        if await self.backend.is_blocked(decision.ip):
            logger.debug(f"Block rejected: {decision.ip} already blocked")
            return False
        
        return True
    
    async def execute_block(self, decision: BlockDecision) -> bool:
        """Execute a block decision."""
        # Calculate duration if not set
        if decision.expires_at is None:
            duration = self._calculate_duration(decision.confidence)
            decision.expires_at = datetime.utcnow() + timedelta(seconds=duration)
        
        # Execute backend block
        success = await self.backend.block(decision)
        
        if success:
            decision.mark_executed()
            self.state.add_block(decision)
            logger.info(f"Blocked {decision.ip} (confidence: {decision.confidence:.2f}, expires: {decision.expires_at})")
        else:
            logger.error(f"Failed to block {decision.ip}")
        
        return success
    
    async def unblock(self, ip: str) -> bool:
        """Remove a block."""
        # Remove from backend
        success = await self.backend.unblock(ip)
        
        # Remove from state
        decision = self.state.remove_block(ip)
        if decision:
            decision.mark_unblocked()
        
        if success:
            logger.info(f"Unblocked {ip}")
        
        return success
    
    async def process_decision(self, decision: BlockDecision) -> bool:
        """Process a block decision end-to-end."""
        if not await self.should_block(decision):
            return False
        
        return await self.execute_block(decision)
    
    async def cleanup_expired(self) -> int:
        """Remove expired blocks. Returns number unblocked."""
        expired = []
        now = datetime.utcnow()
        
        for ip, decision in list(self.state.active_blocks.items()):
            if decision.is_expired:
                expired.append(ip)
        
        for ip in expired:
            await self.unblock(ip)
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired blocks")
        
        return len(expired)
    
    async def start(self) -> None:
        """Start background cleanup task."""
        if self._running:
            return
        
        self._running = True
        
        if self.config.enable_auto_unblock:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("BlockManager cleanup started")
    
    async def stop(self) -> None:
        """Stop background cleanup."""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        
        logger.info("BlockManager stopped")
    
    async def _cleanup_loop(self) -> None:
        """Background loop for cleaning expired blocks."""
        while self._running:
            try:
                await self.cleanup_expired()
                await asyncio.sleep(self.config.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Cleanup error: {e}")
                await asyncio.sleep(self.config.check_interval)
    
    def get_stats(self) -> dict:
        """Get block statistics."""
        total = len(self.state.active_blocks)
        expired = sum(1 for d in self.state.active_blocks.values() if d.is_expired)
        
        return {
            "total_blocks": total,
            "active_blocks": total - expired,
            "expired_blocks": expired,
            "backend_type": self.backend.__class__.__name__
        }
