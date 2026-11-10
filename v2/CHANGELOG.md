# Changelog — FWTrash v2

All notable changes to the v2 rewrite. For legacy v0.x history see root [README.md](../README.md#about-versions).

## [2.0.1] — 2026-11-10

### Added
- `main.py` launcher at repo root — run without `pip install` (`python main.py run -P rules/http.rules`). Fixes import shadowing by putting `v2/src` before repo root on `sys.path` (87f8e82 → 0299385).
- `requirements.txt` / `requirements-dev.txt` / `requirements-dashboard.txt` split from `pyproject.toml`.
- CLI: `--input/-i` + `--follow/-F` — direct file read and `tail -F` with rotation handling (streams 3GB+ without loading whole file). Stdin pipe still supported.
- CLI: `--debug off|low|half|half-all|full` (global and per-command), `-v` → `full`, `-h` alias at every level via `help_option_names`.
- CLI: `--block` — force every `TRASH` to `DROP`/iptables (by default generated rules are `action=log` only, so `Blocked 0` is normal).
- CLI: `validate-rules` now discovers `rules/*.rules` when no arg given; helpful hints for wrong cwd.
- Live 10s stats reporter (`_live_stats_reporter`) for `off`/`low` modes; `half`/`full` use throttled debug window.
- TTY warning when no `--input` and no pipe.

### Changed
- Updated `v2/README.md` Quick Start with `main.py`, `--input/--follow`, `--debug` examples and `fwtrash run` input-modes table.
- License clarified as **Modified Apache License 2.0** with additional commercial terms (notification/payment, audit, ES/SI governing law) — `LICENSE` copied to `v2/LICENSE`.
- `PipelineConfig`: new fields `input_file`, `follow`, `debug_mode`, `force_block`, `bruteforce_limits`.

### Fixed
- **Blocking idempotent**: `IptablesBackend.block()` now `is_blocked()` check — no duplicate iptables rules on restart/race.
- **Repeated IP blocking**: deduplicated display/stats for same IP (0299385).
- **Debug display**: throttled window, correct level routing (`low`→INFO, `full`→DEBUG).
- **Rules engine** (`v2/src/fwtrash/rules/engine.py`): handles v0.6 line-delimited `rules/*.rules` with `#` comments, string `type` `"1"`→`int` coercion, `length_value` extraction for types 4–8, better error with filename+line context.
- **Output**: `FileOutputHandler` flushes after each write; adds rule hint (`[--RULE]`/`[--RULE_ID]`) and `_block_debug_line` with timestamp/rule/reason/code/req/ua.

### Rules
- New `rules/http.generated.rules` (13 rules) and `rules/http.long_sql_traversal.rules` (7 rules).

### Docs / Assets
- Screenshot `pic/screenshot1.jpg` (1106×513) — embedded in root and `v2/README.md`.

## [2.0.0] — 2026-07-13

- Initial v2 rewrite: `src/fwtrash/{api,cli,core,engine,parsers,rules}` package, async pipeline, Pydantic models, plugin parsers, Typer CLI, Rich output, optional FastAPI dashboard, Docker + GH Actions. See [MIGRATION.md](MIGRATION.md) and git log (`c21ce55`→`0010005`) for full history.
