"""Blocking backends for different environments."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from pathlib import Path

from fwtrash.core.models import BlockDecision

logger = logging.getLogger("fwtrash.backends")


class BlockingBackend(ABC):
    """Abstract base for IP blocking implementations."""
    
    @abstractmethod
    async def block(self, decision: BlockDecision) -> bool:
        """Execute block for the given decision."""
        pass
    
    @abstractmethod
    async def unblock(self, ip: str) -> bool:
        """Remove block for IP."""
        pass
    
    @abstractmethod
    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        pass


class NullBackend(BlockingBackend):
    """No-op backend for testing."""
    
    async def block(self, decision: BlockDecision) -> bool:
        logger.debug(f"[NULL] Would block {decision.ip}")
        return True
    
    async def unblock(self, ip: str) -> bool:
        logger.debug(f"[NULL] Would unblock {ip}")
        return True
    
    async def is_blocked(self, ip: str) -> bool:
        return False


class FileBackend(BlockingBackend):
    """Write blocks to file for audit/testing."""
    
    def __init__(self, block_file: str, unblock_file: str | None = None) -> None:
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
            if not self.block_file.exists():
                return False
            content = self.block_file.read_text()
            return f"{ip} #" in content
        except Exception:
            return False
    
    def _append_file(self, path: Path, line: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(line)


class IptablesBackend(BlockingBackend):
    """Linux iptables/nftables backend for production."""
    
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


class DryRunBackend(IptablesBackend):
    """Iptables backend that only logs commands without executing."""
    
    async def block(self, decision: BlockDecision) -> bool:
        if self.use_nftables:
            cmd = f"nft add rule ip {self.table} {self.chain} ip saddr {decision.ip} drop"
        else:
            cmd = f"iptables -A {self.chain} -s {decision.ip}/32 -j DROP"
        
        logger.info(f"[DRY-RUN] Would execute: {cmd}")
        return True
    
    async def unblock(self, ip: str) -> bool:
        cmd = f"iptables -D {self.chain} -s {ip}/32 -j DROP"
        logger.info(f"[DRY-RUN] Would execute: {cmd}")
        return True
