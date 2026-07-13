"""Pytest configuration and shared fixtures."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fwtrash.core.blocking import BlockManager, BlockManagerConfig
from fwtrash.core.models import LogEntry, PipelineConfig, PipelineState, RuleCondition, ConditionType
from fwtrash.parsers.http import HTTPParser
from fwtrash.parsers.ssh import SSHParser
from fwtrash.rules.engine import RuleEngine


@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_http_log(fixtures_dir: Path) -> Path:
    """Return path to sample HTTP access log."""
    # Use actual testlogs from parent project
    project_root = Path(__file__).parent.parent.parent
    return project_root / "testlogs" / "access.log"


@pytest.fixture
def sample_http_lines() -> list[str]:
    """Sample HTTP log lines for testing."""
    return [
        '192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"',
        '192.168.1.1 - - [10/Oct/2023:13:55:37 -0400] "GET /admin HTTP/1.1" 200 452 "-" "Mozilla/5.0"',
        '192.168.1.1 - - [10/Oct/2023:13:55:38 -0400] "POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0"',
        '10.0.0.1 - - [10/Oct/2023:13:55:39 -0400] "GET /wp-admin HTTP/1.1" 404 146 "-" "BadBot/1.0"',
        '192.168.1.100 - - [10/Oct/2023:13:55:40 -0400] "GET /api/users HTTP/1.1" 200 1024 "-" "curl/7.68.0"',
    ]


@pytest.fixture
def sample_ssh_lines() -> list[str]:
    """Sample SSH log lines for testing."""
    return [
        'Oct 10 13:55:36 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 12345 ssh2',
        'Oct 10 13:55:37 server sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 12346 ssh2',
        'Oct 10 13:55:38 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 12347 ssh2',
        'Oct 10 13:55:39 server sshd[1234]: Accepted password for user from 192.168.1.50 port 12348 ssh2',
        'Oct 10 13:55:40 server sshd[1234]: Invalid user test from 192.168.1.200 port 12349',
    ]


@pytest.fixture
def http_parser() -> HTTPParser:
    """HTTP parser instance."""
    return HTTPParser()


@pytest.fixture
def ssh_parser() -> SSHParser:
    """SSH parser instance."""
    return SSHParser()


@pytest.fixture
def rule_engine() -> RuleEngine:
    """Rule engine with sample rules."""
    engine = RuleEngine()
    return engine


@pytest.fixture
def sample_rules() -> list[dict]:
    """Sample v0.6 format rules."""
    return [
        [
            {"key": "path", "type": 2, "data": r"/admin"},
            {"key": "method", "type": 2, "data": r"GET"}
        ],
        [
            {"key": "ua", "type": 2, "data": r"BadBot"}
        ],
    ]


@pytest.fixture
def pipeline_config() -> PipelineConfig:
    """Default pipeline configuration."""
    return PipelineConfig(
        rules_file="test.rules",
        badips_file="test_badips.txt",
        trash_file="test_trash.txt",
    )


@pytest.fixture
def pipeline_state(pipeline_config: PipelineConfig) -> PipelineState:
    """Pipeline state with sample data."""
    return PipelineState(config=pipeline_config)


@pytest.fixture
def block_manager(pipeline_state: PipelineState) -> BlockManager:
    """Block manager with null backend."""
    from fwtrash.core.blocking import NullBackend
    return BlockManager(
        state=pipeline_state,
        backend=NullBackend(),
        config=BlockManagerConfig(enable_auto_unblock=False)
    )


@pytest.fixture
def sample_log_entry() -> LogEntry:
    """Single sample log entry."""
    return LogEntry(
        timestamp=datetime(2023, 10, 10, 13, 55, 36, tzinfo=timezone.utc),
        ip="192.168.1.100",
        raw_line='192.168.1.100 - - [10/Oct/2023:13:55:36 -0400] "GET /admin HTTP/1.1" 200 452',
        parsed_fields={
            "method": "GET",
            "path": "/admin",
            "code": "200",
            "ua": "Mozilla/5.0",
        },
        method="GET",
        path="/admin",
        status_code=200,
    )


@pytest.fixture
def malicious_log_entry() -> LogEntry:
    """Sample malicious log entry."""
    return LogEntry(
        timestamp=datetime(2023, 10, 10, 13, 55, 36, tzinfo=timezone.utc),
        ip="10.0.0.1",
        raw_line='10.0.0.1 - - [10/Oct/2023:13:55:36 -0400] "GET /wp-admin HTTP/1.1" 404 146',
        parsed_fields={
            "method": "GET",
            "path": "/wp-admin",
            "code": "404",
            "ua": "BadBot/1.0",
        },
        method="GET",
        path="/wp-admin",
        status_code=404,
    )
