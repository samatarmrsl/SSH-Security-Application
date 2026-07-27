# Testing

Automated tests use sanitized fixtures, temporary SQLite databases, and an
in-memory iptables runner. They do not alter the host firewall.

```bash
source .venv/bin/activate
python -m pytest --cov=ssh_security_app --cov-report=term-missing
ruff check .
ruff format --check .
python -m compileall -q src scripts
```

Coverage includes configuration, parsers, normalization, deduplication,
repositories, profiles, allowlisting, correlation, risk scoring, modes,
dashboard queries, exact firewall commands, block creation and rollback,
expiration retry, manual requests, reconciliation, cleanup, and controller
shutdown.

The July 2026 acceptance pass additionally verified a clean wheel installation,
packaged defaults and static assets, live Ubuntu journal/tcpdump collection,
dashboard persistence and graceful restart, and the real iptables binary in an
isolated user/network namespace. The namespace test created the dedicated
chain, inserted and confirmed a source rule, exercised automatic and manual
removal, and performed guarded cleanup without altering the host firewall.

For a live authorized-lab test:

1. Back up current iptables state.
2. Confirm the configured protected addresses include every server and
   management address.
3. Confirm the disposable client IP is not the current administrative client.
4. Initialize only the dedicated chain.
5. Start collectors before generating controlled failed SSH attempts.
6. Inspect evidence and run Automatic Response.
7. Confirm the exact rule exists only in `SSH_SECURITY_APP`.
8. Confirm the rule expires, or queue and process a manual removal.
9. Run reconciliation and inspect audit/health rows.
10. Run the cleanup helper and confirm the dedicated chain and jump are gone.

The full commands and expected results are in the README's live test section.
Never use a production host, public target, attempted real password, firewall
flush, or default-policy change.
