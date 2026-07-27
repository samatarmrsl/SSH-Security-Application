#!/usr/bin/env python3
"""Launch the first-party dashboard as the current non-root user."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from ssh_security_app.ui.dashboard import main as dashboard_main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Refusing to run the dashboard as root.", file=sys.stderr)
        return 2
    dashboard_args = ["--config", str(args.config)] if args.config else []
    return dashboard_main(dashboard_args)


if __name__ == "__main__":
    raise SystemExit(main())
