#!/usr/bin/env python3
"""Install or verify the complete authorized live-lab infrastructure."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from ssh_security_app.live_lab_setup import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(repository_root=REPOSITORY_ROOT))
