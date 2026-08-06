# Final Report Project Context

This file summarizes the current terminal-first SSH Security Application for a
final report or presentation.

## Project Purpose

The project is a defensive, host-based SSH brute-force detection and temporary
blocking application for an authorized Ubuntu/Kali lab.

It monitors an Ubuntu OpenSSH server, collects authentication failures and
TCP/22 network metadata, correlates activity by source IPv4 address, calculates
an explainable deterministic risk score, records results in SQLite, displays
alerts in the terminal, and temporarily blocks eligible high-risk sources with
the dedicated `SSH_SECURITY_APP` iptables chain.

## Reference Infrastructure

- Security VM: Ubuntu 20.04 LTS
- Security VM lab interface: `ens37`
- Security VM lab IP: `192.168.12.1`
- Attacker VM: Kali Linux
- Kali interface: `eth0`
- Kali IP: `192.168.12.3`
- Protected service: OpenSSH on TCP/22
- Firewall response: `iptables`
- Project chain: `SSH_SECURITY_APP`
- Demo block duration: 120 seconds

## Current Design

The current implementation is terminal-first. The previous browser dashboard,
HTTP routes, JavaScript assets, CSRF handling, dashboard systemd unit, and
dashboard action-request workflow were removed.

Main terminal commands:

```bash
ssh-security-app status
ssh-security-app detections --limit 20
ssh-security-app blocks --limit 20
sudo ssh-security-app rules
sudo ssh-security-app unblock 192.168.12.3
ssh-security-app allowlist add 192.168.12.2 --reason "Administrator workstation"
ssh-security-app allowlist list
sudo ssh-security-app monitor
```

## Evidence Sources

Authentication evidence comes from the systemd journal for OpenSSH.

Network evidence comes from filtered tcpdump metadata equivalent to:

```text
tcpdump -i ens37 -nn -l -tt -s 96 tcp dst port 22
```

The application does not collect passwords, SSH payloads, or decrypted SSH
content.

## Detection Logic

Evidence is normalized, deduplicated, stored in SQLite, and correlated by source
IPv4 address over a configurable time window.

The risk score uses:

- failed authentication volume;
- username diversity;
- TCP/22 corroboration;
- attempt rate;
- previous detection or block history;
- invalid-user evidence;
- recent successful-login context.

Risk classifications:

- Low Concern
- Unusual
- Suspicious
- High Risk

## Response Logic

Simulation Mode is the safe committed default. It stores detections and prints
`WOULD_BLOCK` without modifying the firewall.

Log Only Mode records detections but does not block.

Automatic Response Mode blocks only after safety checks pass. It inserts exact
source-specific TCP/22 DROP rules in `SSH_SECURITY_APP`, for example:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp --dport 22 -j DROP
```

The application never flushes iptables, never changes default policies, and
does not delete unknown rules automatically.

## Persistence

SQLite stores:

- authentication events;
- network events;
- IP profiles;
- detections;
- detection/evidence links;
- temporary blocks;
- allowlist entries;
- audit log;
- parser errors;
- component health;
- application state.

The dashboard-only `action_requests` table is no longer created for new
databases.

## Repository Organization

- `application_configuration/`: safe defaults and lab example config.
- `installation_and_service_setup/`: setup helpers and systemd units.
- `project_documentation/`: project overview, architecture, command reference,
  database notes, firewall safety rules, verification, and cleanup.
- `application_source_code/ssh_security_application/`: Python application.
- `verification_and_validation/`: automated tests and sample evidence.

## Verification Status

After the terminal-first refactor, the automated suite passes:

```text
161 passed
```

The remaining practical validation step is to rerun the live Ubuntu/Kali demo
using Kali-generated SSH brute-force attempts and confirm detection, blocking,
rule display, automatic expiration, and restored SSH connectivity.
