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

- Keep the Python package in `application_source_code/ssh_security_application`.
- Keep parsing functions pure and independently testable.
- Use UTC-aware datetimes, type hints, and dataclasses.
- Keep SQL in the database and repository layers.
- Add tests with every behavior change.
- Run `pytest`, Ruff, and `compileall` before considering work complete.
- Update the README whenever setup, configuration, or commands change.

## Current implementation boundary

The terminal-first implementation includes authentication and network
collection, correlation and scoring, guarded temporary blocking, expiration,
direct CLI manual unblocking, startup reconciliation, safe cleanup, a managed
terminal monitor, systemd units, verification, and operational documentation.
Live firewall validation must remain limited to an authorized lab, a dedicated
chain, validated disposable source addresses, and explicit operator approval.
