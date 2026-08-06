#!/usr/bin/env python3
"""Run the complete Ubuntu/Kali SSH Security Application lab with one command."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPOSITORY_ROOT / "application_source_code"))

from ssh_security_application.lab import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(repository_root=REPOSITORY_ROOT))
