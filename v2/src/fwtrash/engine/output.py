"""Output handlers for pipeline results."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import TextIO

from fwtrash.core.models import BlockDecision, LogEntry, Rule

logger = logging.getLogger("fwtrash.output")


class FileOutputHandler:
    """Write trash and blocks to files."""
    
    def __init__(
        self,
        trash_file: str | None = None,
        badips_file: str | None = None,
        template: str | None = None
    ) -> None:
        self.trash_file = Path(trash_file) if trash_file else None
        self.badips_file = Path(badips_file) if badips_file else None
        self.template = template or "[--DATE] [--IP] => [--REQ]"
        
        self._trash_fp: TextIO | None = None
        self._badips_fp: TextIO | None = None
        self._lock = asyncio.Lock()
    
    async def _get_trash_fp(self) -> TextIO:
        """Get or open trash file."""
        if self._trash_fp is None and self.trash_file:
            await asyncio.get_event_loop().run_in_executor(
                None, self._open_trash
            )
        return self._trash_fp
    
    def _open_trash(self) -> None:
        """Open trash file (sync)."""
        if self.trash_file:
            self.trash_file.parent.mkdir(parents=True, exist_ok=True)
            self._trash_fp = open(self.trash_file, "a")
    
    async def _get_badips_fp(self) -> TextIO | None:
        """Get or open badips file."""
        if self._badips_fp is None and self.badips_file:
            await asyncio.get_event_loop().run_in_executor(
                None, self._open_badips
            )
        return self._badips_fp
    
    def _open_badips(self) -> None:
        """Open badips file (sync)."""
        if self.badips_file:
            self.badips_file.parent.mkdir(parents=True, exist_ok=True)
            self._badips_fp = open(self.badips_file, "a")
    
    def _format_entry(self, entry: LogEntry, rule: Rule | None = None) -> str:
        """Format entry using template."""
        # Simple template replacement
        result = self.template
        result = result.replace("[--DATE]", entry.timestamp.isoformat())
        result = result.replace("[--IP]", entry.ip)
        result = result.replace("[--REQ]", entry.parsed_fields.get('req', '-'))
        result = result.replace("[--UA]", entry.parsed_fields.get('ua', '-'))
        result = result.replace("[--REF]", entry.parsed_fields.get('ref', '-'))
        result = result.replace("[--CODE]", str(entry.status_code or '-'))
        result = result.replace("[--LEN]", str(entry.response_size or '-'))
        
        if rule:
            result = result.replace("[--RULE]", rule.metadata.name)
        
        return result + "\n"
    
    async def write_trash(self, entry: LogEntry, rule: Rule | None = None) -> None:
        """Write trash entry."""
        fp = await self._get_trash_fp()
        if not fp:
            return
        
        line = self._format_entry(entry, rule)
        async with self._lock:
            await asyncio.get_event_loop().run_in_executor(
                None, fp.write, line
            )
    
    async def write_block(self, decision: BlockDecision) -> None:
        """Write block decision."""
        fp = await self._get_badips_fp()
        if not fp:
            return
        
        line = f"{decision.ip} # {decision.reason}\n"
        async with self._lock:
            await asyncio.get_event_loop().run_in_executor(
                None, fp.write, line
            )
    
    async def close(self) -> None:
        """Close files."""
        if self._trash_fp:
            await asyncio.get_event_loop().run_in_executor(
                None, self._trash_fp.close
            )
            self._trash_fp = None
        if self._badips_fp:
            await asyncio.get_event_loop().run_in_executor(
                None, self._badips_fp.close
            )
            self._badips_fp = None


class JSONOutputHandler:
    """Write structured JSON output."""
    
    def __init__(self, output_file: str) -> None:
        self.output_file = Path(output_file)
        self._fp: TextIO | None = None
        self._lock = asyncio.Lock()
    
    async def _get_fp(self) -> TextIO:
        if self._fp is None:
            await asyncio.get_event_loop().run_in_executor(None, self._open)
        return self._fp
    
    def _open(self) -> None:
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self._fp = open(self.output_file, "a")
    
    async def write_trash(self, entry: LogEntry, rule: Rule | None = None) -> None:
        fp = await self._get_fp()
        data = {
            "type": "trash",
            "timestamp": entry.timestamp.isoformat(),
            "ip": entry.ip,
            "request": entry.parsed_fields.get('req'),
            "user_agent": entry.user_agent,
            "rule": rule.metadata.name if rule else None
        }
        async with self._lock:
            await asyncio.get_event_loop().run_in_executor(
                None, self._fp.write, json.dumps(data) + "\n"
            )
    
    async def write_block(self, decision: BlockDecision) -> None:
        fp = await self._get_fp()
        data = {
            "type": "block",
            "ip": decision.ip,
            "reason": decision.reason,
            "confidence": decision.confidence,
            "detected_at": decision.detected_at.isoformat()
        }
        async with self._lock:
            await asyncio.get_event_loop().run_in_executor(
                None, self._fp.write, json.dumps(data) + "\n"
            )
    
    async def close(self) -> None:
        if self._fp:
            await asyncio.get_event_loop().run_in_executor(None, self._fp.close)
            self._fp = None
