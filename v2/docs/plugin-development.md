# Plugin Development Guide for FWTrash v2.0

## Creating a Custom Parser

### Basic Structure

```python
from __future__ import annotations

import re
from datetime import datetime, timezone

from fwtrash.core.models import LogEntry
from fwtrash.parsers.base import LogParser, ParseError, register_parser


@register_parser
class CustomLogParser(LogParser):
    """Custom log format parser."""
    
    # Required class attributes
    name = "custom"
    description = "My custom log format"
    supported_formats = ["custom"]
    
    def parse(self, line: str) -> LogEntry:
        """Parse a log line into LogEntry."""
        # Your parsing logic here
        return LogEntry(
            timestamp=datetime.now(timezone.utc),
            ip="192.168.1.1",
            raw_line=line,
            parsed_fields={}
        )
    
    def can_parse(self, line: str) -> float:
        """Return confidence score 0.0-1.0."""
        return 1.0 if line.startswith("CUSTOM") else 0.0
```

### Example: Syslog Parser

```python
import re
from datetime import datetime
from fwtrash.core.models import LogEntry
from fwtrash.parsers.base import LogParser, ParseError, register_parser

@register_parser
class SyslogParser(LogParser):
    name = "syslog"
    description = "RFC3164/RFC5424 syslog parser"
    supported_formats = ["syslog"]
    
    SYSLOG_PATTERN = re.compile(
        r'^(?P<priority><\d+>)?'
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<message>.*)$'
    )
    
    def parse(self, line: str) -> LogEntry:
        match = self.SYSLOG_PATTERN.match(line)
        if not match:
            raise ParseError(f"Invalid syslog: {line[:50]}")
        
        groups = match.groupdict()
        
        return LogEntry(
            timestamp=self._parse_timestamp(groups['timestamp']),
            ip=self._extract_ip(groups['message']),
            raw_line=line,
            parsed_fields={
                'host': groups['host'],
                'message': groups['message'],
                'priority': groups.get('priority', ''),
            }
        )
    
    def _parse_timestamp(self, ts: str) -> datetime:
        # Parse syslog timestamp
        return datetime.strptime(ts, "%b %d %H:%M:%S")
    
    def _extract_ip(self, message: str) -> str:
        # Try to find IP in message
        import re
        match = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', message)
        return match.group(0) if match else '0.0.0.0'
```

## Creating a Custom Backend

```python
from fwtrash.core.blocking import BlockingBackend
from fwtrash.core.models import BlockDecision

class WebhookBackend(BlockingBackend):
    """Send blocks to webhook."""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    async def block(self, decision: BlockDecision) -> bool:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.webhook_url,
                json={
                    'ip': decision.ip,
                    'reason': decision.reason,
                    'confidence': decision.confidence,
                }
            ) as resp:
                return resp.status == 200
    
    async def unblock(self, ip: str) -> bool:
        # Implement if webhook supports unblocking
        return True
    
    async def is_blocked(self, ip: str) -> bool:
        # Query webhook or maintain local cache
        return False
```

## Testing Your Plugin

```python
# test_my_parser.py
import pytest
from my_parser import CustomLogParser

def test_parse():
    parser = CustomLogParser()
    entry = parser.parse("CUSTOM 192.168.1.1 hello")
    assert entry.ip == "192.168.1.1"

def test_can_parse():
    parser = CustomLogParser()
    assert parser.can_parse("CUSTOM ...") == 1.0
    assert parser.can_parse("OTHER ...") == 0.0
```

## Packaging

Create a `setup.py` or `pyproject.toml`:

```toml
[project]
name = "fwtrash-myplugin"
version = "1.0.0"
dependencies = ["fwtrash>=2.0"]

[project.entry-points."fwtrash.parsers"]
myformat = "my_plugin:MyParser"
```

## Debugging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```
