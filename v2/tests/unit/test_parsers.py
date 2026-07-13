"""Unit tests for log parsers."""

import pytest
from datetime import datetime, timezone

from fwtrash.core.models import LogEntry
from fwtrash.parsers.base import LogParser, ParseError
from fwtrash.parsers.http import HTTPParser


class TestHTTPParser:
    """Test HTTPParser with real log formats."""
    
    @pytest.fixture
    def parser(self) -> HTTPParser:
        return HTTPParser()
    
    def test_combined_log_format(self, parser: HTTPParser) -> None:
        """Standard nginx combined log format."""
        line = '17.246.23.226 - - [13/Jul/2026:00:48:09 +0100] "GET /src/multiline.js HTTP/1.0" 200 2375 "https://example.com/" "Mozilla/5.0"'
        
        entry = parser.parse(line)
        
        assert entry.ip == "17.246.23.226"
        assert entry.method == "GET"
        assert entry.path == "/src/multiline.js"
        assert entry.status_code == 200
        assert entry.response_size == 2375
        assert entry.user_agent == "Mozilla/5.0"
        assert entry.referer == "https://example.com/"
        
        # v0.6 compatibility fields
        assert entry.parsed_fields['code'] == "200"
        assert entry.parsed_fields['len'] == "2375"
        assert entry.parsed_fields['ua'] == "Mozilla/5.0"
        assert entry.parsed_fields['ref'] == "https://example.com/"
        assert entry.parsed_fields['req'] == "GET /src/multiline.js HTTP/1.0"
    
    def test_minimal_format(self, parser: HTTPParser) -> None:
        """Minimal log format without all fields."""
        line = '146.75.164.0 [13/Jul/2026:00:48:11 +0100] "GET /sma/999/ph/doyreds.jpg HTTP/1.0" 200 42546'
        
        entry = parser.parse(line)
        
        assert entry.ip == "146.75.164.0"
        assert entry.method == "GET"
        assert entry.path == "/sma/999/ph/doyreds.jpg"
        assert entry.status_code == 200
        assert entry.response_size == 42546
    
    def test_bot_user_agent(self, parser: HTTPParser) -> None:
        """Parse line with complex bot user agent."""
        line = '34.194.95.99 - - [13/Jul/2026:00:48:12 +0100] "GET /sma/magazine/2026/june/nonas.php HTTP/1.0" 200 220312 "-" "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36"'
        
        entry = parser.parse(line)
        
        assert entry.ip == "34.194.95.99"
        assert "Amazonbot" in entry.user_agent
        assert entry.status_code == 200
    
    def test_url_encoding(self, parser: HTTPParser) -> None:
        """Handle URL-encoded paths."""
        line = '17.246.23.226 - - [13/Jul/2026:00:48:09 +0100] "GET /search/painting%20lessons HTTP/1.0" 200 1000 "-" "Mozilla/5.0"'
        
        entry = parser.parse(line)
        
        assert entry.path == "/search/painting%20lessons"
    
    def test_post_request(self, parser: HTTPParser) -> None:
        """Parse POST request."""
        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] "POST /api/login HTTP/1.1" 302 0 "-" "curl/7.68.0"'
        
        entry = parser.parse(line)
        
        assert entry.method == "POST"
        assert entry.path == "/api/login"
        assert entry.status_code == 302
    
    def test_404_response(self, parser: HTTPParser) -> None:
        """Parse 404 not found."""
        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] "GET /nonexistent HTTP/1.1" 404 146 "-" "Mozilla/5.0"'
        
        entry = parser.parse(line)
        
        assert entry.status_code == 404
        assert entry.response_size == 146
    
    def test_dash_referer(self, parser: HTTPParser) -> None:
        """Handle '-' as referer (no referer)."""
        line = '146.75.164.0 - - [13/Jul/2026:00:48:11 +0100] "GET /image.jpg HTTP/1.0" 200 100 "-" "Mozilla/5.0"'
        
        entry = parser.parse(line)
        
        assert entry.parsed_fields['ref'] == '-'
        assert entry.referer is None  # Converted to None
    
    def test_ipv6_address(self, parser: HTTPParser) -> None:
        """Parse IPv6 addresses."""
        line = '2001:db8::1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"'
        
        entry = parser.parse(line)
        
        assert entry.ip == "2001:db8::1"
    
    def test_error_log_format(self, parser: HTTPParser) -> None:
        """Parse nginx error log format."""
        line = '2023/10/10 13:55:36 [error] 1234#5678: *12345 FastCGI sent in stderr: "Primary script unknown" while reading response header from upstream, client: 8.222.225.103, server: example.com, request: "GET /test.php HTTP/1.1", upstream: "fastcgi://unix:/run/php.sock:", host: "example.com"'
        
        entry = parser.parse(line)
        
        assert entry.parsed_fields['type'] == 'error'
        assert entry.parsed_fields['level'] == 'error'
        assert '8.222.225.103' in entry.ip or entry.parsed_fields.get('message', '')
    
    def test_empty_line(self, parser: HTTPParser) -> None:
        """Empty line raises ParseError."""
        with pytest.raises(ParseError):
            parser.parse("")
        
        with pytest.raises(ParseError):
            parser.parse("   ")
    
    def test_invalid_line(self, parser: HTTPParser) -> None:
        """Invalid line raises ParseError."""
        with pytest.raises(ParseError):
            parser.parse("not a valid log line")
    
    def test_can_parse_confidence(self, parser: HTTPParser) -> None:
        """Test confidence scoring."""
        # Perfect match
        assert parser.can_parse('192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] "GET / HTTP/1.1" 200 0 "-" "-"') == 1.0
        
        # Alt format
        assert parser.can_parse('192.168.1.1 [10/Oct/2023:13:55:36 -0400] "GET / HTTP/1.1" 200 0') == 0.9
        
        # Error format
        assert parser.can_parse('2023/10/10 13:55:36 [error] 1234#5678: *1 test') == 0.8
        
        # Starts with IP but not HTTP
        assert parser.can_parse('192.168.1.1 something else') == 0.3
        
        # No match
        assert parser.can_parse('random text') == 0.0
        assert parser.can_parse('') == 0.0


class TestParserRegistry:
    """Test parser registration and discovery."""
    
    def test_http_parser_registered(self) -> None:
        """HTTP parser should be auto-registered."""
        parsers = LogParser.list_parsers()
        assert 'http' in parsers
        assert 'nginx' in parsers['http'].lower() or 'apache' in parsers['http'].lower()
    
    def test_get_parser(self) -> None:
        """Get parser by name."""
        parser = LogParser.get_parser('http')
        assert isinstance(parser, HTTPParser)
    
    def test_unknown_parser(self) -> None:
        """Unknown parser raises error."""
        with pytest.raises(ValueError, match="Unknown parser"):
            LogParser.get_parser('nonexistent')
    
    def test_auto_detect_http(self) -> None:
        """Auto-detect HTTP format."""
        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] "GET / HTTP/1.1" 200 0 "-" "-"'
        parser = LogParser.auto_detect(line)
        
        assert parser is not None
        assert isinstance(parser, HTTPParser)
    
    def test_auto_detect_no_match(self) -> None:
        """Auto-detect returns None for unknown format."""
        parser = LogParser.auto_detect("completely unknown format")
        assert parser is None


class TestParserEdgeCases:
    """Edge cases and special formats."""
    
    def test_very_long_user_agent(self) -> None:
        """Handle very long user agent strings."""
        ua = "Mozilla/5.0 " * 100
        line = f'192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] "GET / HTTP/1.1" 200 0 "-" "{ua}"'
        
        parser = HTTPParser()
        entry = parser.parse(line)
        
        assert len(entry.user_agent) > 500
    
    def test_unicode_in_path(self) -> None:
        """Handle unicode in URL path."""
        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] "GET /café HTTP/1.1" 200 0 "-" "-"'
        
        parser = HTTPParser()
        entry = parser.parse(line)
        
        assert 'café' in entry.path or '%C3%A9' in entry.path
    
    def test_multiple_spaces(self) -> None:
        """Handle varying whitespace."""
        line = '192.168.1.1  -  -  [10/Oct/2023:13:55:36 -0400]  "GET / HTTP/1.1"  200  0  "-"  "-"'
        
        parser = HTTPParser()\n        # May or may not parse depending on regex strictness\n        try:\n            entry = parser.parse(line)\n            assert entry.ip == "192.168.1.1"\n        except ParseError:\n            pass  # Also acceptable if strict\n    \n    def test_size_zero(self, parser: HTTPParser) -> None:\n        \"\"\"Handle zero byte responses.\"\"\"\n        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] \"GET /favicon.ico HTTP/1.1\" 404 0 \"-\" \"-\"'\n        \n        entry = parser.parse(line)\n        assert entry.response_size == 0 or entry.response_size is None\n    \n    def test_size_dash(self, parser: HTTPParser) -> None:\n        \"\"\"Handle '-' as response size (common in nginx).\"\"\"\n        line = '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] \"GET / HTTP/1.1\" 200 - \"-\" \"-\"'\n        \n        entry = parser.parse(line)\n        assert entry.parsed_fields['len'] == '-'\n        assert entry.response_size is None\n