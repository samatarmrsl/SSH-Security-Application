#!/usr/bin/env python3
"""Automate the guarded Ubuntu prerequisites for SSH Security Application testing."""

from __future__ import annotations

from pathlib import Path

from ssh_security_app.setup_environment import main

if __name__ == "__main__":
    raise SystemExit(main(repository_root=Path(__file__).resolve().parents[1]))
