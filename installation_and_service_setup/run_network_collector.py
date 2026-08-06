#!/usr/bin/env python3
"""Run the Stage 3 TCP/22 network metadata collector."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "application_source_code"))

from ssh_security_application.main import main  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--fixture", type=Path)
    modes.add_argument("--follow", action="store_true")
    parsed = parser.parse_args()

    arguments = ["collect-network"]
    if parsed.fixture:
        arguments.extend(["--fixture", str(parsed.fixture)])
    elif parsed.follow:
        arguments.append("--follow")
    if parsed.config:
        arguments = ["--config", str(parsed.config), *arguments]
    raise SystemExit(main(arguments))
