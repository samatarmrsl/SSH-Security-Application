# SSH Brute Guard Development Guide

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

- Keep the Python package in `src/ssh_guard`.
- Keep parsing functions pure and independently testable.
- Use UTC-aware datetimes, type hints, and dataclasses.
- Keep SQL in the database and repository layers.
- Add tests with every behavior change.
- Run `pytest`, Ruff, and `compileall` before considering work complete.
- Update the README whenever setup, configuration, or commands change.

## Current implementation boundary

Stages 1 and 2 cover the project foundation and authentication evidence. Network
collection, detection, scoring, firewall enforcement, expiration, reconciliation,
and the Streamlit dashboard belong to later explicitly approved stages.
