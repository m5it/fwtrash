"""HTTP access log parser for nginx/apache format.

Compatible with v0.6 http.rules fields:
- ip, date, req, code, len, ref, ua
- method, path (extracted from req)
- status_code (from code)
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fwtrash.core.models import LogEntry
from fwtrash.parsers.base import LogParser, ParseError, register_parser


@register_parser
class HTTPParser(LogParser):
    """Parser for nginx/apache combined log format."""
    
    name = "http"
    description = "HTTP access log parser (nginx/apache)"
    supported_formats = ["nginx", "apache", "combined"]
    
    COMBINED_PATTERN = re.compile(
        r'^(?P<ip>[\da-fA-F.:]+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<auth>\S+)\s+'
        r'\[(?P<date>[^\]]+)\]\s+'
        r'"(?P<req>[^"]*)"\s+'
        r'(?P<code>\d+)\s+'
        r'(?P<len>\S+)\s+'
        r'"(?P<ref>[^"]*)"\s+'
        r'"(?P<ua>[^"]*)"'
        r'(?:\s+"(?P<extra>[^"]*)")?'
    )
    
    ALT_PATTERN = re.compile(
        r'^(?P<ip>[\da-fA-F.:]+)\s+'
        r'\[(?P<date>[^\]]+)\]\s+'
        r'"(?P<req>[^"]*)"\s+'
        r'(?P<code>\d+)\s+'
        r'(?P<len>\S+)'
    )
    
    DATE_PATTERN = re.compile(
        r'^(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):'
        r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})'
        r'\s+(?P<tz_sign>[+-])(?P<tz_hour>\d{2})(?P<tz_min>\d{2})$'
    )
    
    REQUEST_PATTERN = re.compile(
        r'^(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<protocol>\S+))?$'
    )
    
    ERROR_PATTERN = re.compile(
        r'^(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})\s+'
        r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+'
        r'\[(?P<level>\w+)\]\s+'
        r'(?P<pid>\d+)#\d+:\s+\*(?P<tid>\d+)\s+'
        r'(?P<message>.+)'
    )
    
    MONTHS = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
        'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
        'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    def __init__(self, encoding: str = "utf-8") -> None:
        super().__init__(encoding)
        self._date_cache: dict[str, datetime] = {}
    
    def parse(self, line: str) -> LogEntry:
        line = line.strip()
        if not line:
            raise ParseError("Empty line", line, self.name)
        
        match = self.COMBINED_PATTERN.match(line)
        if not match:
            match = self.ALT_PATTERN.match(line)
        
        if match:
            return self._parse_combined(match, line)
        
        error_match = self.ERROR_PATTERN.match(line)
        if error_match:
            return self._parse_error(error_match, line)
        
        raise ParseError("Line does not match HTTP log format", line, self.name)
    
    def _parse_combined(self, match: re.Match[str], raw_line: str) -> LogEntry:
        groups = match.groupdict()
        timestamp = self._parse_date(groups['date'])
        req = groups.get('req', '')
        method, path, protocol = self._parse_request(req)
        
        parsed_fields = {
            'req': req,
            'code': groups.get('code', ''),
            'len': groups.get('len', '-'),
            'ref': groups.get('ref', '-'),
            'ua': groups.get('ua', ''),
            'ident': groups.get('ident', '-'),
            'auth': groups.get('auth', '-'),
        }
        
        if groups.get('extra'):
            parsed_fields['extra'] = groups['extra']
        
        return LogEntry(
            timestamp=timestamp,
            ip=groups['ip'],
            raw_line=raw_line,
            parsed_fields=parsed_fields,
            method=method,
            path=path,
            status_code=int(groups['code']) if groups.get('code') and groups['code'].isdigit() else None,
            user_agent=groups.get('ua') or None,
            referer=groups.get('ref') if groups.get('ref') != '-' else None,
            response_size=int(groups['len']) if groups.get('len') and groups['len'].isdigit() else None
        )
    
    def _parse_error(self, match: re.Match[str], raw_line: str) -> LogEntry:
        groups = match.groupdict()
        month_num = int(groups['month'])
        timestamp = datetime(
            int(groups['year']),
            month_num,
            int(groups['day']),
            int(groups['hour']),
            int(groups['minute']),
            int(groups['second']),
            tzinfo=timezone.utc
        )
        
        message = groups.get('message', '')
        ip = self._extract_ip_from_message(message)
        
        parsed_fields = {
            'level': groups.get('level', 'error'),
            'pid': groups.get('pid', ''),
            'tid': groups.get('tid', ''),
            'message': message,
            'type': 'error'
        }
        
        return LogEntry(
            timestamp=timestamp,
            ip=ip or '0.0.0.0',
            raw_line=raw_line,
            parsed_fields=parsed_fields
        )
    
    def _parse_date(self, date_str: str) -> datetime:
        if date_str in self._date_cache:
            return self._date_cache[date_str]
        
        match = self.DATE_PATTERN.match(date_str)
        if not match:
            return self._parse_date_alt(date_str)
        
        g = match.groupdict()
        month = self.MONTHS.get(g['month'], 1)
        
        tz_hours = int(g['tz_hour'])
        tz_mins = int(g['tz_min'])
        tz_offset = (tz_hours * 60 + tz_mins) * 60
        if g['tz_sign'] == '-':
            tz_offset = -tz_offset
        
        tz = timezone(timedelta(seconds=tz_offset))
        
        dt = datetime(
            int(g['year']),
            month,
            int(g['day']),
            int(g['hour']),
            int(g['minute']),
            int(g['second']),
            tzinfo=tz
        )
        
        self._date_cache[date_str] = dt
        return dt
    
    def _parse_date_alt(self, date_str: str) -> datetime:
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except ValueError:
            pass
        return datetime.now(timezone.utc)
    
    def _parse_request(self, req: str) -> tuple[str, str, str]:
        if not req:
            return ('', '', '')
        
        match = self.REQUEST_PATTERN.match(req)
        if match:
            return (
                match.group('method') or '',
                match.group('path') or '',
                match.group('protocol') or ''
            )
        return ('', req, '')
    
    def _extract_ip_from_message(self, message: str) -> str | None:
        match = re.search(r'client[:\s]+([\da-fA-F.:]+)', message)
        if match:
            return match.group(1)
        return None
    
    def can_parse(self, line: str) -> float:
        line = line.strip()
        if not line:
            return 0.0
        
        if self.COMBINED_PATTERN.match(line):
            return 1.0
        if self.ALT_PATTERN.match(line):
            return 0.9
        if self.ERROR_PATTERN.match(line):
            return 0.8
        if re.match(r'^[\da-fA-F.:]+\s', line):
            return 0.3
        return 0.0
    
    def get_field(self, entry: LogEntry, field: str) -> Any:
        if hasattr(entry, field):
            return getattr(entry, field)
        return entry.parsed_fields.get(field)
