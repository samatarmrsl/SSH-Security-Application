# System Architecture

The SSH Security Application is now terminal-first.

```text
OpenSSH journal collector       tcpdump TCP/22 collector
          |                              |
          v                              v
  event normalization and duplicate prevention
          |
          v
        SQLite
          |
          v
source-IP correlation -> explainable risk score -> response decision
          |
          v
terminal alert and audit log
          |
          v
temporary iptables block, expiration, manual unblock, reconciliation
```

There is no browser dashboard, HTTP API, CSRF layer, JavaScript, or
dashboard-generated action queue in the terminal-first design.

The only module allowed to construct or execute `iptables` commands is:

```text
application_source_code/ssh_security_application/iptables_firewall_response/firewall.py
```

The committed default mode is Simulation Mode.
