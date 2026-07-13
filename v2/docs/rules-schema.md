# FWTrash Rules JSON Schema

## Overview

Rules in FWTrash v2.0 use a JSON format compatible with v0.6, with extensions for typed conditions.

## Schema Definition

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "FWTrash Rules",
  "type": "array",
  "items": {
    "type": "array",
    "description": "A single rule with one or more conditions",
    "items": {
      "type": "object",
      "required": ["key", "type", "data"],
      "properties": {
        "key": {
          "type": "string",
          "description": "Field to match against (ip, path, ua, etc.)"
        },
        "type": {
          "type": "integer",
          "enum": [1, 2, 3, 4, 5, 6, 7, 8],
          "description": "Condition type (see below)"
        },
        "data": {
          "type": "string",
          "description": "Pattern or value to match"
        },
        "bruteforce_count_key": {
          "type": "integer",
          "minimum": 0,
          "maximum": 999,
          "description": "Optional brute force tracking key"
        },
        "name": {
          "type": "string",
          "description": "Human-readable rule name (v2.0+)"
        },
        "description": {
          "type": "string",
          "description": "Rule description (v2.0+)"
        }
      }
    }
  }
}
```

## Condition Types

| Type | Name | Description | Example |
|------|------|-------------|---------|
| 1 | `base64_regex` | Base64 decode, then regex | Encoded payloads |
| 2 | `regex` | Regular expression match | `/admin.*` |
| 3 | `plain` | Exact string match | `GET` |
| 4 | `length_gte` | Length >= value | `len >= 100` |
| 5 | `length_gt` | Length > value | `len > 100` |
| 6 | `length_lte` | Length <= value | `len <= 100` |
| 7 | `length_lt` | Length < value | `len < 100` |
| 8 | `length_eq` | Length == value | `len == 100` |

## Examples

### Basic Rule

```json
[
  [{"key": "path", "type": 2, "data": "/admin"}]
]
```

### Multiple Conditions (AND logic)

```json
[
  [
    {"key": "path", "type": 2, "data": "/admin"},
    {"key": "method", "type": 2, "data": "GET"}
  ]
]
```

### Brute Force Protection

```json
[
  [
    {"key": "path", "type": 2, "data": "/login", "bruteforce_count_key": 1}
  ]
]
```

Use with `-b "key:1,climit:5,tlimit:60"` to block after 5 attempts in 60 seconds.

### v2.0 Extended Format

```json
[
  [
    {
      "key": "ua",
      "type": 2,
      "data": "BadBot",
      "name": "Bot Detection",
      "description": "Detects known bad user agents"
    }
  ]
]
```

## Available Fields by Parser

### HTTP Parser
- `ip` - Source IP address
- `date` - Request timestamp
- `method` - HTTP method (GET, POST, etc.)
- `path` - Request path
- `req` - Full request line
- `code` - HTTP status code
- `len` - Response size
- `ref` - Referer header
- `ua` - User agent

### SSH Parser
- `ip` - Source IP
- `user` - Username attempted
- `event_type` - `failed_password`, `accepted_password`, `invalid_user`
- `port` - Source port

## Validation

Validate your rules:

```bash
fwtrash validate-rules rules.json
```
