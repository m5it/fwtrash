#!/usr/bin/env python3
"""FWTrash launcher — run without pip install.

Usage:
    python main.py --help
    python main.py run -P rules/http.rules -o badips.out
    tail -f /var/log/nginx/access.log | python main.py run -P rules/http.rules

    # Legacy v0.6 (still supported):
    python main.py --legacy -P rules/http.rules -o badips.out
    tail -f /var/log/nginx/access.log | python fwtrash.py -P rules/http.rules

This script sets up sys.path so the v2 package in v2/src/ is importable
without `pip install`, then delegates to the Typer CLI.
"""

from __future__ import annotations

import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap: make v2/src importable without pip install
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
V2_SRC = ROOT / "v2" / "src"

if V2_SRC.exists():
    sys.path.insert(0, str(V2_SRC))

# Also ensure repo root is on path for `modules.*` / `functions` legacy imports,
# but it must come *after* V2_SRC so `fwtrash.py` does not shadow `v2/src/fwtrash/`
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))


def _check_dependencies() -> list[str]:
    """Return list of missing required packages, empty if all present."""
    missing: list[str] = []
    for pkg, import_name in [
        ("pydantic", "pydantic"),
        ("typer", "typer"),
        ("rich", "rich"),
        ("watchdog", "watchdog"),
        ("pyyaml", "yaml"),
    ]:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pkg)
    return missing


def main() -> None:
    # Allow explicit legacy mode: --legacy as first arg delegates to fwtrash.py
    if len(sys.argv) > 1 and sys.argv[1] == "--legacy":
        sys.argv.pop(1)
        # Re-exec via legacy script
        import runpy

        legacy = ROOT / "fwtrash.py"
        if not legacy.exists():
            print(f"Legacy script not found: {legacy}", file=sys.stderr)
            sys.exit(1)
        # runpy keeps sys.argv as remaining args
        runpy.run_path(str(legacy), run_name="__main__")
        return

    missing = _check_dependencies()
    if missing:
        print(f"Missing dependencies: {', '.join(missing)}", file=sys.stderr)
        print(f"Install them with:", file=sys.stderr)
        print(f"  pip install -r requirements.txt", file=sys.stderr)
        print(f"  # or", file=sys.stderr)
        print(f"  pip install {' '.join(missing)}", file=sys.stderr)
        print(f"  # or (inside v2/ with extras):", file=sys.stderr)
        print(f"  pip install -e \"v2[dev]\"  # from repo root", file=sys.stderr)
        sys.exit(1)

    # Import after path setup & dep check
    try:
        from fwtrash.cli.main import app
    except ImportError as exc:
        print(f"Failed to import FWTrash v2 package: {exc}", file=sys.stderr)
        print(f"  V2_SRC={V2_SRC} exists={V2_SRC.exists()}", file=sys.stderr)
        print(f"  sys.path[0:3]={sys.path[0:3]}", file=sys.stderr)
        print(f"  Hint: pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)

    # Delegate to Typer — it handles --help, --version, subcommands, etc.
    app()


if __name__ == "__main__":
    main()
