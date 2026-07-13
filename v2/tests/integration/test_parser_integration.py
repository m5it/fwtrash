"""Integration tests with real log files."""

import gzip
import json
from pathlib import Path

import pytest

from fwtrash.parsers.http import HTTPParser
from fwtrash.parsers.base import LogParser


class TestHTTPParserWithRealLogs:
    """Test HTTP parser against real access logs."""
    
    @pytest.fixture
    def parser(self) -> HTTPParser:
        return HTTPParser()
    
    def test_parse_sample_log_lines(self, parser: HTTPParser) -> None:
        """Parse sample lines from testlogs/access.log."""
        # Sample lines extracted from actual log
        lines = [
            '17.246.23.226 [13/Jul/2026:00:48:09 +0100] "GET /src/multiline.js HTTP/1.0" 200 2375 "https://www.lokkal.com/1,mexico,san_miguel_de_allende/search/painting%20lessons" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15" "17.246.23.226"',
            '146.75.164.0 [13/Jul/2026:00:48:11 +0100] "GET /sma/999/ph/doyreds.jpg HTTP/1.0" 200 42546 "-" "Mozilla/5.0" "146.75.164.0"',
            '34.194.95.99 [13/Jul/2026:00:48:12 +0100] "GET /sma/magazine/2026/june/nonas.php HTTP/1.0" 200 220312 "-" "Mozilla/5.0 AppleWebKit/537.36" "34.194.95.99"',
        ]
        
        for line in lines:
            entry = parser.parse(line)
            
            assert entry.ip is not None and entry.ip != "0.0.0.0"
            assert entry.timestamp is not None
            assert entry.method in ["GET", "POST", "HEAD", "PUT", "DELETE"]
            assert entry.status_code is not None
            assert entry.status_code > 0
            
            # v0.6 compatibility fields
            assert 'code' in entry.parsed_fields
            assert 'ua' in entry.parsed_fields
            assert 'req' in entry.parsed_fields
    
    def test_parser_registration(self) -> None:
        """Verify parsers are registered."""
        parsers = LogParser.list_parsers()
        assert 'http' in parsers
        assert 'ssh' in parsers
        
        http = LogParser.get_parser('http')
        assert isinstance(http, HTTPParser)
    
    def test_auto_detect_http(self) -> None:
        """Auto-detect HTTP format from real logs."""
        line = '17.246.23.226 [13/Jul/2026:00:48:09 +0100] "GET /src/multiline.js HTTP/1.0" 200 2375 "-" "Mozilla/5.0"'
        
        detected = LogParser.auto_detect(line)
        assert detected is not None
        assert isinstance(detected, HTTPParser)
    
    def test_bulk_parse_performance(self, parser: HTTPParser) -> None:
        """Parse many lines efficiently."""
        lines = [
            f'192.168.1.{i} - - [10/Oct/2023:13:{i:02d}:36 -0400] "GET /page{i} HTTP/1.1" 200 {i*100} "-" "Mozilla/5.0"'
            for i in range(1000)
        ]
        
        entries = []
        for line in lines:
            entry = parser.parse(line)
            entries.append(entry)
        
        assert len(entries) == 1000
        assert all(e.ip.startswith("192.168.1.") for e in entries)
    
    def test_v06_field_compatibility(self, parser: HTTPParser) -> None:
        """Ensure v0.6 rule fields are available."""
        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] "GET /admin HTTP/1.1" 200 452 "https://example.com/" "Mozilla/5.0"'
        
        entry = parser.parse(line)
        
        # Fields used in http.rules
        v06_fields = ['ip', 'date', 'req', 'code', 'len', 'ref', 'ua', 'method', 'path']
        
        for field in v06_fields:
            value = parser.get_field(entry, field)
            assert value is not None, f"Field {field} should be available"
        
        # Specific assertions
        assert entry.parsed_fields['code'] == "200"
        assert entry.parsed_fields['req'] == "GET /admin HTTP/1.1"
        assert entry.parsed_fields['ua'] == "Mozilla/5.0"
        assert entry.parsed_fields['ref'] == "https://example.com/"
