# Architecture

SSH Security Application separates unprivileged evidence collection and dashboard work
from the capability-bearing response path.

```text
journalctl -> auth parser -----\
                               > SQLite -> correlation -> risk decision
tcpdump -> network parser -----/                         |
                                                         v
                                      dedicated-chain block manager
                                                         |
                     dashboard -> SQLite action request  |
                                      |                  |
                                      v                  v
                              privileged response worker
                              expiration / manual removal
                              startup reconciliation
```

The authentication collector reads OpenSSH journal text. The network collector
captures only metadata for TCP connections whose destination is the configured
SSH port. Parsers normalize records and repositories store them in SQLite.
Correlation reads a five-minute source-IP window and creates an explainable
score, classification, and decision.

Simulation and Log Only modes do not call the firewall manager. Automatic
Response applies an exact IPv4 TCP/22 `DROP` rule only after the detection,
address, allowlist, protected-address, sensor-health, database-health, active
block, duplicate-rule, and corroborating-network checks pass.

`FirewallManager` owns all iptables command construction. It uses argument
arrays, an absolute executable, `shell=False`, and only
`SSH_SECURITY_APP`. It never flushes a chain or changes a default policy.

The first-party dashboard uses a Python standard-library HTTP server and
project-owned HTML, CSS, and JavaScript. It has no external dashboard runtime
and runs without firewall capabilities. A manual unblock writes a validated
`Pending` row to `action_requests`. `ActionRequestWorker` independently
validates the request and active block before deleting the exact rule.
`ExpirationWorker` removes expired exact rules. `FirewallReconciler` compares
active database state with the dedicated chain at worker startup and never
automatically deletes an unknown rule.

`ApplicationController` owns the long-running collector, detector, and response
threads, handles a shared stop event, stops collector subprocesses, and records
health and audit state. The dashboard remains a separate systemd service.
