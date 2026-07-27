#!/usr/bin/env python3
"""Run Stage 4 correlation, scoring, classification, and decision logic."""

from __future__ import annotations

import argparse
from pathlib import Path

from ssh_security_app.main import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("--source-ip")
    targets.add_argument("--all", action="store_true")
    parser.add_argument("--window-end")
    parser.add_argument(
        "--apply-response",
        action="store_true",
        help="requires automatic_response mode and a prepared project chain",
    )
    parsed = parser.parse_args()

    arguments = ["detect"]
    if parsed.source_ip:
        arguments.extend(["--source-ip", parsed.source_ip])
    else:
        arguments.append("--all")
    if parsed.window_end:
        arguments.extend(["--window-end", parsed.window_end])
    if parsed.apply_response:
        arguments.append("--apply-response")
    if parsed.config:
        arguments = ["--config", str(parsed.config), *arguments]
    raise SystemExit(main(arguments))
