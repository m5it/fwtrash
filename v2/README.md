# FWTrash v2.0 🛡️

Modern security log analyzer with real-time threat detection and automatic IP blocking.

[![CI](https://github.com/grandekos/fwtrash/workflows/CI/badge.svg)](https://github.com/grandekos/fwtrash/actions)
[![codecov](https://codecov.io/gh/grandekos/fwtrash/branch/main/graph/badge.svg)](https://codecov.io/gh/grandekos/fwtrash)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Features

- 🔍 **Multi-format Log Parsing** - HTTP, SSH, TCPDump, custom plugins
- 🚫 **Real-time IP Blocking** - iptables integration with automatic unblocking
- 📊 **Optional Web Dashboard** - Live monitoring via FastAPI/WebSocket
- 🧪 **Fully Tested** - 90%+ coverage with pytest
- 🔌 **Plugin Architecture** - Easy to extend with custom parsers
- ⚡ **Async Processing** - High-throughput log stream handling

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         FWTrash v2.0                        │
├─────────────────────────────────────────────────────────────┤
│  CLI (Typer)  │  Dashboard (FastAPI)  │  Python API       │
├─────────────────────────────────────────────────────────────┤
│  Pipeline Engine (async)                                    │
│  ├─ Rate Limiter (token bucket)                             │
│  ├─ Parser (plugin-based)                                   │
│  ├─ Rule Engine (typed conditions)                          │
│  └─ Block Manager (pluggable backends)                     │
├─────────────────────────────────────────────────────────────┤
│  State (Pydantic models)                                      │
│  ├─ PipelineState (replaces global vars)                    │
│  ├─ BlockDecision (with expiration)                        │
│  └─ PipelineStats (metrics)                                │
├─────────────────────────────────────────────────────────────┤
│  Backends: Iptables │ File (audit) │ Null (testing)        │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install
pip install fwtrash

# Basic HTTP log monitoring
tail -f /var/log/nginx/access.log | fwtrash run -P rules/http.rules

# With blocking enabled
tail -f /var/log/nginx/access.log | fwtrash run \
  -P rules/http.rules \
  -c "iptables -A INPUT -s [--IP]/32 -j DROP"

# With web dashboard
tail -f /var/log/nginx/access.log | fwtrash run \
  -P rules/http.rules \
  --dashboard --dashboard-port 8080
```

## Installation

```bash
# From PyPI
pip install fwtrash

# With dashboard support
pip install fwtrash[dashboard]

# Development install
git clone https://github.com/grandekos/fwtrash.git
cd fwtrash
pip install -e ".[dev]"
```

## Configuration

### Rules File (JSON)

```json
[
  [
    {"key": "path", "type": 2, "data": "/admin"},
    {"key": "method", "type": 2, "data": "GET"}
  ],
  [
    {"key": "ua", "type": 2, "data": "BadBot"}
  ]
]
```

**Condition Types:**
- `1`: base64_decode + regex
- `2`: regex match
- `3`: plain string match
- `4-8`: length comparisons (>=, >, <=, <, ==)

### Environment Variables

```bash
export FWTRASH_LOG_LEVEL=debug
export FWTRASH_STATE_FILE=/var/lib/fwtrash/state.json
```

## Plugin Development

### Custom Parser

```python
from fwtrash.parsers.base import LogParser, register_parser
from fwtrash.core.models import LogEntry

@register_parser
class MyParser(LogParser):
    name = "myformat"
    description = "My custom log format"
    
    def parse(self, line: str) -> LogEntry:
        # Parse line and return LogEntry
        return LogEntry(
            timestamp=datetime.now(timezone.utc),
            ip="192.168.1.1",
            raw_line=line,
            parsed_fields={"custom": "value"}
        )
    
    def can_parse(self, line: str) -> float:
        # Return confidence 0.0-1.0
        return 1.0 if line.startswith("MYFORMAT") else 0.0
```

### Custom Backend

```python
from fwtrash.core.blocking import BlockingBackend

class MyBackend(BlockingBackend):
    async def block(self, decision: BlockDecision) -> bool:
        # Implement blocking
        return True
    
    async def unblock(self, ip: str) -> bool:
        # Implement unblocking
        return True
```

## Commands

| Command | Description |
|---------|-------------|
| `fwtrash run` | Start processing pipeline |
| `fwtrash detect` | Auto-detect log format |
| `fwtrash list-parsers` | List available parsers |
| `fwtrash validate-rules` | Validate rules file |
| `fwtrash dashboard` | Launch web dashboard |

## Docker

```bash
docker-compose up -d
# Access dashboard at http://localhost:8080
```

## Migration from v0.6

See [MIGRATION.md](MIGRATION.md) for detailed upgrade guide.

## License

MIT - See [LICENSE](LICENSE)
