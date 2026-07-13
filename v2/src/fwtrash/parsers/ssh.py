"""SSH auth log parser."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fwtrash.core.models import LogEntry
from fwtrash.parsers.base import LogParser, ParseError, register_parser


@register_parser
class SSHParser(LogParser):
    """Parser for SSH auth logs (/var/log/auth.log)."""
    
    name = "ssh"
    description = "SSH authentication log parser"
    supported_formats = ["auth", "secure"]
    
    # Standard auth log format
    AUTH_PATTERN = re.compile(
        r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+(?P<service>\S+):\s+'
        r'(?P<message>.*)$'
    )
    
    # Message patterns
    FAILED_PASSWORD = re.compile(
        r'Failed password for(?:\s+invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<ip>[\da-fA-F.:]+)\s+port\s+(?P<port>\d+)'
    )
    
    ACCEPTED_PASSWORD = re.compile(
        r'Accepted password for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\da-fA.F.:]+)\s+port\s+(?P<port>\d+)'
    )
    
    INVALID_USER = re.compile(
        r'Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>[\da-fA-F.:]+)\s+port\s+(?P<port>\d+)'
    )
    
    CONNECTION_CLOSED = re.compile(
        r'Connection closed by\s+(?P<ip>[\da-fA-F.:]+)\s+port\s+(?P<port>\d+)'
    )
    
    DISCONNECT = re.compile(
        r'Disconnected from\s+(?P<ip>[\da-fA-F.:]+)\s+port\s+(?P<port>\d+)'
    )
    
    MONTHS = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
        'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
        'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    def __init__(self, encoding: str = "utf-8", year: int | None = None) -> None:
        super().__init__(encoding)
        self.year = year or datetime.now().year
        self._month_cache: dict[tuple[str, int], datetime] = {}
    
    def parse(self, line: str) -> LogEntry:
        line = line.strip()
        if not line:
            raise ParseError("Empty line", line, self.name)
        
        match = self.AUTH_PATTERN.match(line)
        if not match:
            raise ParseError("Line does not match auth log format", line, self.name)
        
        return self._parse_auth(match, line)
    
    def _parse_auth(self, match: re.Match[str], raw_line: str) -> LogEntry:
        groups = match.groupdict()
        timestamp = self._parse_timestamp(
            groups['month'],
            groups['day'],
            groups['time']
        )
        
        message = groups['message']
        parsed = self._parse_message(message)
        
        parsed_fields = {
            'service': groups['service'],
            'host': groups['host'],
            'message': message,
            'event_type': parsed.get('event_type', 'unknown'),
            'user': parsed.get('user'),
            'port': parsed.get('port'),
        }
        
        return LogEntry(
            timestamp=timestamp,
            ip=parsed.get('ip', '0.0.0.0'),
            raw_line=raw_line,
            parsed_fields=parsed_fields
        )
    
    def _parse_timestamp(self, month_str: str, day_str: str, time_str: str) -> datetime:
        month = self.MONTHS.get(month_str, 1)
        day = int(day_str)
        hour, minute, second = map(int, time_str.split(':'))
        
        return datetime(
            self.year, month, day,
            hour, minute, second,
            tzinfo=timezone.utc
        )
    
    def _parse_message(self, message: str) -> dict[str, Any]:
        result: dict[str, Any] = {'event_type': 'unknown'}
        
        patterns = [
            ('failed_password', self.FAILED_PASSWORD),
            ('accepted_password', self.ACCEPTED_PASSWORD),
            ('invalid_user', self.INVALID_USER),
            ('connection_closed', self.CONNECTION_CLOSED),
            ('disconnect', self.DISCONNECT),
        ]
        
        for event_type, pattern in patterns:
            match = pattern.search(message)
            if match:
                result['event_type'] = event_type
                result.update(match.groupdict())
                break
        
        return result
    
    def can_parse(self, line: str) -> float:
        line = line.strip()
        if not line:
            return 0.0
        
        if self.AUTH_PATTERN.match(line):
            return 1.0
        
        if re.match(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line):
            return 0.5
        
        return 0.0
    
    def get_field(self, entry: LogEntry, field: str) -> Any:
        if hasattr(entry, field):
            return getattr(entry, field)
        return entry.parsed_fields.get(field)
