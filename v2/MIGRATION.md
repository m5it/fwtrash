# Migration Guide: FWTrash v0.6 → v2.0

This guide helps you migrate from FWTrash v0.6 to the new v2.0 architecture.

## Quick Start

```bash
# Old way (v0.6)
python fwtrash.py -P rules/http.rules -o badips.txt

# New way (v2.0)
fwtrash run -P rules/http.rules -o badips.txt

# Or with pip install
pip install fwtrash
fwtrash run -P rules/http.rules -o badips.txt
```

## Breaking Changes

| v0.6 | v2.0 | Notes |
|------|------|-------|
| `python fwtrash.py` | `fwtrash run` | Command structure changed |
| Global state files | `--state-file` | State persistence explicit |
| `modules/http.py` | Built-in parsers | Auto-detected, no `-p` needed |
| `crc32b` hashing | MD5 hashing | Different hash algorithm |

## Command Line Changes

### v0.6 Style
```bash
tail -f /var/log/nginx/access.log | \
  python fwtrash.py -P rules/http.rules \
  -o badips.out -O trash.out \
  -a allowedips.txt \
  -c "iptables -A INPUT -s [--IP]/32 -j DROP" \
  -s "date,ip,repeat,req" \
  -S "[--DATE] - [--IP] => [--REQ]" \
  -d \
  -D
```

### v2.0 Equivalent
```bash
tail -f /var/log/nginx/access.log | \
  fwtrash run -P rules/http.rules \
  -o badips.out -O trash.out \
  -a allowedips.txt \
  -c "iptables -A INPUT -s [--IP]/32 -j DROP" \
  -s "date,ip,repeat,req" \
  -S "[--DATE] - [--IP] => [--REQ]" \
  -d \
  -D
```

## Rules File Compatibility

Rules files are **fully compatible** between v0.6 and v2.0:

```json
[
  [
    {"key": "path", "type": 2, "data": "/admin"},
    {"key": "method", "type": 2, "data": "GET"}
  ]
]
```

## New Features in v2.0

### Web Dashboard
```bash
fwtrash run -P rules/http.rules --dashboard --dashboard-port 8080
# Open http://localhost:8080
```

### Structured Output
```bash
# JSON output
fwtrash run -P rules.json --output-format json

# Better stats with --verbose
fwtrash run -P rules.json -v
```

### Auto-Detection
```bash
# No need to specify parser
fwtrash run -P rules.json < access.log

# Or detect format
fwtrash detect < sample.log
```

## Python API Changes

### v0.6 Style
```python
from functions import crc32b
import modules.http as http

line = "192.168.1.1 - - [10/Oct/2023:13:55:36 -0400] ..."
xobj = http.XObj(line)
# xobj is a dict with ip, date, req, etc.
```

### v2.0 Style
```python
from fwtrash.parsers.http import HTTPParser
from fwtrash.core.models import LogEntry

parser = HTTPParser()
entry = parser.parse(line)
# entry is a typed LogEntry with fields
print(entry.ip, entry.method, entry.path)
```

## State Management

v2.0 uses proper state management:

```python
from fwtrash.core.models import PipelineState

state = PipelineState()
state.allowed_ips = {"192.168.1.1"}
state.add_block(decision)
```

## Migration Checklist

- [ ] Install v2.0: `pip install fwtrash`
- [ ] Update scripts to use `fwtrash` command
- [ ] Test with `--dry-run` first
- [ ] Verify rules still match
- [ ] Update any custom Python integrations
- [ ] Consider using new dashboard feature

## Rollback

If you need to rollback to v0.6:

```bash
pip uninstall fwtrash
# Use your original fwtrash.py
```

## Getting Help

- Documentation: https://fwtrash.readthedocs.io
- Issues: https://github.com/grandekos/fwtrash/issues
- Migration questions: Open an issue with `migration` label
