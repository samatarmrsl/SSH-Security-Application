#!/usr/bin/env python3
"""Remove only recognized SSH Security Application rules, exact jump, and project chain."""

from __future__ import annotations

import argparse
from pathlib import Path

from ssh_security_app.main import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument(
        "--confirm-firewall-changes",
        action="store_true",
        required=True,
        help="required acknowledgement for the scoped firewall cleanup",
    )
    parsed = parser.parse_args()
    arguments = ["firewall-cleanup", "--confirm-firewall-changes"]
    if parsed.config:
        arguments = ["--config", str(parsed.config), *arguments]
    raise SystemExit(main(arguments))
