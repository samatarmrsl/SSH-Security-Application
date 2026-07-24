#!/usr/bin/env python3
"""Initialize SSH Brute Guard's SQLite schema."""

from __future__ import annotations

import argparse
from pathlib import Path

from ssh_guard.main import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parsed = parser.parse_args()
    arguments = ["init-db"]
    if parsed.config:
        arguments = ["--config", str(parsed.config), *arguments]
    raise SystemExit(main(arguments))
