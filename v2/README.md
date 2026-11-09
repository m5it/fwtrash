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
│  State (Pydantic models)                                    │
│  ├─ PipelineState (replaces global vars)                    │
│  ├─ BlockDecision (with expiration)                         │
│  └─ PipelineStats (metrics)                               │
├─────────────────────────────────────────────────────────────┤
│  Backends: Iptables │ File (audit) │ Null (testing)        │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Without pip install (run from source)

```bash
# From repo root — no pip install needed
pip install -r requirements.txt        # or: pip install -r v2/requirements.txt analogue
python main.py -h            # alias for --help
python main.py run -h        # pipeline options
python main.py run -P rules/http.rules -o badips.out

# New: read file directly (no pipe needed — handles 3GB+ logs streamed)
python main.py run -P rules/http.rules --input /var/log/nginx/access.log          # batch to EOF then exit
python main.py run -P rules/http.rules --input /var/log/nginx/access.log --follow  # live tail -F with rotation

# Piped logs (same as v0.6 style — still supported)
tail -F /var/log/nginx/access.log | python main.py run -P rules/http.rules
cat ../access.log | python main.py run -P rules/http.generated.rules --dry-run -d

# Alternative: editable install still works
cd v2
pip install -e ".[dev]"
fwtrash --help
fwtrash run -h

# Or run as module
python -m fwtrash.cli.main --help
```

### With pip install (when published)

```bash
pip install fwtrash[dashboard]

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

### From Source (Development)

```bash
git clone https://github.com/grandekos/fwtrash.git
cd fwtrash/v2
pip install -e ".[dev]"
```

### With Dashboard Support

```bash
pip install -e ".[dashboard]"
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

See [docs/plugin-development.md](docs/plugin-development.md) for full guide.

## CLI Help

Both `-h` and `--help` are accepted at every level (via `context_settings={"help_option_names": ["-h","--help"]}`):

```bash
python main.py -h          # top-level commands
python main.py --help       # same as -h
python main.py run -h      # pipeline options (flags below)
python main.py run --help  # same as -h
```

## Commands

| Command | Description |
|---------|-------------|
| `fwtrash run` | Start processing pipeline (`-P`, `-i/--input`, `-F/--follow`, `-p`, `-o/-O`, `-a`, `-c`, `-n`, `-d`, `-D`, `--dashboard`) |
| `fwtrash detect` | Auto-detect log format |
| `fwtrash list-parsers` | List available parsers |
| `fwtrash validate-rules` | Validate rules file |
| `fwtrash dashboard` | Launch web dashboard |

### `fwtrash run` — input modes

* `fwtrash run -P rules/http.rules --input /var/log/nginx/access.log --follow` — follow live log (recommended, like `tail -F`, handles rotation). Starts at EOF.
* `fwtrash run -P rules/http.rules --input /var/log/nginx/access.log` — batch: stream to EOF then exit (good for 3.4G replays; streams, doesn't load whole file).
* `tail -F … | fwtrash run -P rules/http.rules` / `cat file | fwtrash …` — stdin pipe mode (v0.6 compatible). With no `--input` and no pipe on a TTY, fwtrash warns and explains the two alternatives.

### `fwtrash run` — debugging bad traffic (nothing shows?)

Your `~/fwtrash` batch with `rules/http.generated.rules` did match: `Trash 24 910 / 672 429` (3.7%). `Blocked 0` is expected — generated rules default to `action=log` (trash-only) so they don't auto-block via `iptables`; add `action=drop` or rely on `-c` command (future).

To see per-line decisions:

```bash
# half — per-line summary (recommended for live attacks like your batch/v1 405 burst):
sudo fwtrash run -P rules/http.generated.rules --input /var/log/nginx/access.log --follow --debug half --dry-run -d
sudo fwtrash run -P rules/http.generated.rules --debug half --dry-run          # same, global flag
python main.py -v run -P rules/http.generated.rules --input /var/log/nginx/access.log --follow  # -v = --debug full alias

# full — per-rule, per-condition trace (verbose):
echo 'POST /batch/v1 ... 405' | python main.py run -P rules/http.generated.rules --debug full --dry-run -d
echo '...' | python main.py -v run -P rules/http.generated.rules --dry-run -d  # -v alias

# also: -h/--help at every level
python main.py -h; python main.py run -h; fwtrash validate-rules -h
```

## Docker

```bash
docker-compose up -d
# Access dashboard at http://localhost:8080
```

## Testing

```bash
cd v2
make test          # Run all tests
make lint          # Run linters
make build         # Build package
```

## Migration from v0.6

See [MIGRATION.md](MIGRATION.md) for detailed upgrade guide.

## License

Copyright 2026 Blaz Kos — Licensed under the **Modified Apache License, Version 2.0** with additional commercial terms. See [LICENSE](../LICENSE) (repo root) for full text.

Summary of additional terms:
- **Commercial use** requires written notification to w4d4f4k@gmail.com within 30 days (use case, users, deployment, contact).
- **Commercial use** requires payment of a license fee (invoiced by licensor).
- Licensor retains **audit rights** and **termination for non-compliance**.
- **Governing law:** Spain / Canary Islands (Las Palmas de Gran Canaria); Slovenian law may apply for Slovenian consumers where mandatory.

For licensing inquiries: w4d4f4k@gmail.com.

## Author

t3ch (w4d4f4k at gmail dot com) — [grandekos.com](https://grandekos.com)
