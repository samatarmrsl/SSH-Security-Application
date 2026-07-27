# SSH Security Application Development Guide

## Scope and safety

- This project is for an authorized Ubuntu virtual lab.
- Simulation Mode is the default.
- Never run privileged commands, modify iptables, or change host services without explicit approval.
- Never flush iptables, change a default policy, or modify rules outside the project-owned chain.
- Never collect passwords or SSH payload contents.
- Validate IP addresses with Python's `ipaddress` module before making security decisions.
- Use subprocess argument lists with `shell=False`.
- Use parameterized SQLite statements.

## Development expectations

- Keep the Python package in `src/ssh_security_app`.
- Keep parsing functions pure and independently testable.
- Use UTC-aware datetimes, type hints, and dataclasses.
- Keep SQL in the database and repository layers.
- Add tests with every behavior change.
- Run `pytest`, Ruff, and `compileall` before considering work complete.
- Update the README whenever setup, configuration, or commands change.

## Current implementation boundary

Stages 1 through 8 are implemented. The package includes authentication and
network collection, correlation and scoring, guarded temporary blocking,
expiration, SQLite-backed manual unblocking, startup reconciliation, safe
cleanup, the final dashboard, a managed application controller, systemd units,
tests, and operational documentation. Live firewall validation must remain
limited to an authorized lab, a dedicated chain, validated disposable source
addresses, and explicit operator approval.
