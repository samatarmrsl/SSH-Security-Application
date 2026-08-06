#!/usr/bin/env python3
"""Automate the guarded Ubuntu prerequisites for SSH Security Application testing."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "application_source_code"))

from ssh_security_application.setup_environment import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(repository_root=REPOSITORY_ROOT))
