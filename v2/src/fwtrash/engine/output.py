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
n        if self.trash_file:\n            self.trash_file.parent.mkdir(parents=True, exist_ok=True)\n            self._trash_fp = open(self.trash_file, "a")\n    \n    async def _get_badips_fp(self) -> TextIO | None:\n        \"\"\"Get or open badips file.\"\"\"\n        if self._badips_fp is None and self.badips_file:\n            await asyncio.get_event_loop().run_in_executor(\n                None, self._open_badips\n            )\n        return self._badips_fp\n    \n    def _open_badips(self) -> None:\n        \"\"\"Open badips file (sync).\"\"\"\n        if self.badips_file:\n            self.badips_file.parent.mkdir(parents=True, exist_ok=True)\n            self._badips_fp = open(self.badips_file, "a")\n    \n    def _format_entry(self, entry: LogEntry, rule: Rule | None = None) -> str:\n        \"\"\"Format entry using template.\"\"\"\n        # Simple template replacement\n        result = self.template\n        result = result.replace("[--DATE]", entry.timestamp.isoformat())\n        result = result.replace("[--IP]", entry.ip)\n        result = result.replace("[--REQ]", entry.parsed_fields.get('req', '-'))\n        result = result.replace("[--UA]", entry.parsed_fields.get('ua', '-'))\n        result = result.replace("[--REF]", entry.parsed_fields.get('ref', '-'))\n        result = result.replace("[--CODE]", str(entry.status_code or '-'))\n        result = result.replace("[--LEN]", str(entry.response_size or '-'))\n        \n        if rule:\n            result = result.replace("[--RULE]", rule.metadata.name)\n        \n        return result + "\n"
    
    async def write_trash(self, entry: LogEntry, rule: Rule | None = None) -> None:\n        \"\"\"Write trash entry.\"\"\"\n        fp = await self._get_trash_fp()\n        if not fp:\n            return\n        \n        line = self._format_entry(entry, rule)\n        async with self._lock:\n            await asyncio.get_event_loop().run_in_executor(\n                None, fp.write, line\n            )\n    \n    async def write_block(self, decision: BlockDecision) -> None:\n        \"\"\"Write block decision.\"\"\"\n        fp = await self._get_badips_fp()\n        if not fp:\n            return\n        \n        line = f"{decision.ip} # {decision.reason}\\n"\n        async with self._lock:\n            await asyncio.get_event_loop().run_in_executor(\n                None, fp.write, line\n            )\n    \n    async def close(self) -> None:\n        \"\"\"Close files.\"\"\"\n        if self._trash_fp:\n            await asyncio.get_event_loop().run_in_executor(\n                None, self._trash_fp.close\n            )\n            self._trash_fp = None\n        if self._badips_fp:\n            await asyncio.get_event_loop().run_in_executor(\n                None, self._badips_fp.close\n            )\n            self._badips_fp = None\n\n\nclass JSONOutputHandler:\n    \"\"\"Write structured JSON output.\"\"\"\n    \n    def __init__(self, output_file: str) -> None:\n        self.output_file = Path(output_file)\n        self._fp: TextIO | None = None\n        self._lock = asyncio.Lock()\n    \n    async def _get_fp(self) -> TextIO:\n        if self._fp is None:\n            await asyncio.get_event_loop().run_in_executor(None, self._open)\n        return self._fp\n    \n    def _open(self) -> None:\n        self.output_file.parent.mkdir(parents=True, exist_ok=True)\n        self._fp = open(self.output_file, "a")\n    \n    async def write_trash(self, entry: LogEntry, rule: Rule | None = None) -> None:\n        fp = await self._get_fp()\n        data = {\n            "type": "trash",\n            "timestamp": entry.timestamp.isoformat(),\n            "ip": entry.ip,\n            "request": entry.parsed_fields.get('req'),\n            "user_agent": entry.user_agent,\n            "rule": rule.metadata.name if rule else None\n        }\n        async with self._lock:\n            await asyncio.get_event_loop().run_in_executor(\n                None, self._fp.write, json.dumps(data) + "\\n"\n            )\n    \n    async def write_block(self, decision: BlockDecision) -> None:\n        fp = await self._get_fp()\n        data = {\n            "type": "block",\n            "ip": decision.ip,\n            "reason": decision.reason,\n            "confidence": decision.confidence,\n            "detected_at": decision.detected_at.isoformat()\n        }\n        async with self._lock:\n            await asyncio.get_event_loop().run_in_executor(\n                None, self._fp.write, json.dumps(data) + "\\n"\n            )\n    \n    async def close(self) -> None:\n        if self._fp:\n            await asyncio.get_event_loop().run_in_executor(None, self._fp.close)\n            self._fp = None
