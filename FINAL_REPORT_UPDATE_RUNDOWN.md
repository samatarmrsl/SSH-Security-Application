# Final Report Update Rundown

Use this file to update the final report so it matches the current
implementation.

## Main Report Correction

The final implementation is a custom terminal-based Python application called
SSH Security Application. It is not `sshguard`, it does not use Streamlit, and
it does not use a browser dashboard.

The project runs on an Ubuntu 20.04 Security VM and detects SSH brute-force
activity from a Kali attacker VM. It collects OpenSSH authentication evidence,
captures SSH network metadata, stores evidence in SQLite, scores source IPs for
brute-force behavior, and temporarily blocks high-risk IPs with `iptables`.

## Current Lab Environment

| Machine | OS | Interface | IP address | Purpose |
|---|---|---|---|---|
| Security VM | Ubuntu 20.04 | `ens37` | `192.168.12.1` | Runs OpenSSH and this application |
| Attacker VM | Kali Linux | `eth0` | `192.168.12.3` | Generates authorized SSH brute-force traffic |

## Current Implementation Summary

The application uses two evidence sources:

1. OpenSSH authentication logs from `journalctl`.
2. TCP destination-port 22 metadata from `tcpdump`.

The application then:

1. Parses the evidence.
2. Validates IP addresses.
3. Normalizes timestamps and IP values.
4. Deduplicates repeated evidence.
5. Stores evidence in SQLite.
6. Correlates evidence by source IP.
7. Calculates an explainable risk score.
8. Classifies the source IP.
9. Decides whether to log, simulate a block, or block for real.
10. In Automatic Response Mode, creates a temporary `iptables` DROP rule.
11. Removes the block automatically after the configured timeout.

## Firewall Implementation

The project uses `iptables` for offender blocking.

It creates and manages a dedicated chain:

```text
SSH_SECURITY_APP
```

Expected block rule:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp --dport 22 -j DROP
```

The application only manages project-owned rules. It does not flush the whole
firewall or change default firewall policies.

## Operating Modes

| Mode | Meaning |
|---|---|
| `simulation` | Detects and explains attacks but does not change the firewall. |
| `log_only` | Logs detections without blocking. |
| `automatic_response` | Temporarily blocks high-risk IPs with iptables. |

The committed default is Simulation Mode. The live lab setup writes Automatic
Response Mode so the demonstration can show real blocking.

## One-Command Setup

The current setup command is:

```bash
python3 run_lab.py --apply --watch
```

This command:

- installs required packages if missing;
- enables OpenSSH;
- gives `tcpdump` capture capability;
- installs the app under `/opt/ssh-security-application`;
- writes `/etc/ssh-security-app/config.json`;
- initializes SQLite;
- installs systemd services;
- initializes the `SSH_SECURITY_APP` iptables chain;
- starts monitoring;
- follows live logs.

## Main Production Commands

Status:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json status
```

Show detections:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json detections
```

Show blocks:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json blocks
```

Show iptables rules:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json rules
```

Manual unblock:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json unblock 192.168.12.3
```

## Kali Demonstration

Hydra is used from Kali only in the authorized isolated lab.

Example:

```bash
timeout 90s hydra \
  -L usernames.txt \
  -P passwords.txt \
  -t 2 \
  -W 3 \
  -V \
  -I \
  -o hydra-results.txt \
  ssh://192.168.12.1
```

Expected demonstration result:

- the Ubuntu Security VM logs failed SSH logins;
- the application detects brute-force behavior from `192.168.12.3`;
- the application prints the risk score and decision;
- the application creates an iptables DROP rule;
- Kali SSH attempts time out while blocked;
- the block expires automatically after about 120 seconds.

## Current Repository Structure

```text
application_source_code/ssh_security_application/
├── main.py
├── lab.py
├── live_lab_setup.py
├── service.py
├── terminal.py
├── config.py
├── models.py
├── constants.py
├── audit.py
├── health.py
├── modes.py
├── ip_validation.py
├── evidence_collection/
│   ├── auth.py
│   └── network.py
├── ssh_brute_force_detection/
│   ├── detection.py
│   ├── normalization.py
│   └── deduplication.py
├── iptables_firewall_response/
│   └── firewall.py
└── sqlite_data_storage/
    ├── storage.py
    └── schema.sql
```

## File Purpose Summary

| File | Purpose |
|---|---|
| `run_lab.py` | One-command setup/start/watch script. |
| `main.py` | Defines the `ssh-security-app` terminal commands. |
| `lab.py` | Wraps the full live-lab setup with simple defaults. |
| `live_lab_setup.py` | Installs and verifies the production Ubuntu/Kali lab. |
| `service.py` | Runs the live monitoring loop. |
| `terminal.py` | Prints readable terminal output. |
| `config.py` | Loads and validates configuration. |
| `models.py` | Defines shared data records. |
| `auth.py` | Handles OpenSSH authentication evidence. |
| `network.py` | Handles tcpdump SSH network evidence. |
| `detection.py` | Handles correlation, scoring, classification, and allowlist behavior. |
| `firewall.py` | Handles iptables rules, blocking, expiration, and reconciliation. |
| `storage.py` | Handles SQLite database access and queries. |

## Testing and Validation

Current automated validation:

- 165 pytest tests passed.
- Ruff lint passed.
- Ruff format check passed.
- Python compile check passed.
- Production-style wheel install smoke test passed.

## Report Wording to Use

Use:

- “terminal-first implementation”
- “custom SSH Security Application”
- “dedicated iptables chain”
- “one-command Ubuntu/Kali lab setup”
- “temporary automatic blocking”
- “explainable risk scoring”

Avoid:

- “Streamlit dashboard”
- “web dashboard”
- “browser UI”
- “sshguard”
- “firewalld blocking”
- “manual staged prototype only”

## Suggested Final Implementation Paragraph

The final implementation is a simplified terminal-first Python application that
runs on an Ubuntu 20.04 Security VM. It monitors OpenSSH authentication logs and
tcpdump SSH network metadata, stores evidence in SQLite, correlates events by
source IP, calculates an explainable brute-force risk score, and temporarily
blocks high-risk IP addresses with a dedicated `iptables` chain. The project
includes a one-command Ubuntu/Kali lab setup, systemd services for continuous
monitoring, automatic block expiration, manual unblock capability, terminal
status commands, and automated validation tests.

## Suggested Conclusion Paragraph

The completed system demonstrates a working host-based SSH brute-force
detection and response pipeline in an isolated Ubuntu/Kali lab. The final design
prioritizes simplicity, explainability, and safe firewall handling. Instead of
using an external product or a web dashboard, the project implements the
detection and response workflow directly in Python and exposes results through
clear terminal commands.
