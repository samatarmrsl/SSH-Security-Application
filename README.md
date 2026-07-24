# SSH Brute Guard

SSH Brute Guard is a defensive Python application that collects OpenSSH
authentication records and TCP destination-port 22 metadata, correlates both
evidence sources by IP address and time, and creates a solution to prevent further attempts by blocking the IP.

## Current Progress 
Stages 1–4 are complete. The application can collect, normalize, deduplicate,
store, correlate, score, classify, and audit evidence. Simulation Mode is the
safe default: a high-risk result says `WOULD_BLOCK`, but no firewall command is
executed. The dashboard, firewall response, and block-removal will be completed next.

## Purpose and use cases

The project helps an admin:

- Collect successful and failed OpenSSH authentication events.
- Collect only metadata summaries for TCP connections to the configured SSH
  port; it does not inspect packet payloads.
- Quarantine unsupported, malformed, or invalid evidence instead of guessing.
- Normalize timestamps and IP addresses and reject duplicate records.
- Maintain a history profile for each observed source IP.
- Correlate authentication and network evidence in a five-minute window.
- Calculate an explainable risk score from 0 to 100.
- Classify activity as Low Concern, Unusual, Suspicious, or High Risk.
- Suppress unsafe responses for allowlisted, ineligible, already blocked, or
  insufficiently corroborated sources.
- Record evidence, detections, decisions, health, and audit history in SQLite.
- Reproduce the pipeline safely with sanitized fixture files.

The application does not collect attempted passwords, private keys, SSH payload
contents, or decrypted traffic.

The project is not intended to replace existing solutions, it is merely a tool that can be used on your environment for protection purposes similar to how an AV would function.

## Work completed so far

### Stage 1 — Foundation

- Python `src` package layout and `ssh-guard` command-line entry point.
- JSON defaults with an ignored local override file.
- Strict validation for operating modes, paths, thresholds, ports, interfaces,
  protected addresses, and numeric ranges.
- Simulation Mode as the default.
- Typed models for evidence, detections, decisions, blocks, health, and audit.
- SQLite connection management with foreign keys, WAL mode, busy timeout,
  short transactions, schema migration, and parameterized SQL.
- Tables and repository APIs for evidence, profiles, detections, allowlisting,
  blocks, action requests, parser errors, audit, and health.
- Structured JSON logging, component health, audit logging, database
  initialization, Ruff, pytest, and coverage reporting.

### Stage 2 — Authentication evidence

- Pure OpenSSH journal parser for failed passwords, invalid users, accepted
  passwords, accepted public keys, connection closure, unsupported records, and
  malformed records.
- UTC timestamp normalization and IPv4/IPv6 technical classification.
- Eligibility explanations for loopback, link-local, multicast, unspecified,
  special-purpose, IPv6, protected, and allowlisted addresses.
- Fixture, one-shot, and continuous `journalctl` collection.
- Safe subprocess argument lists with `shell=False`, error handling, health
  reporting, and clean termination.
- Authentication storage, parser-error quarantine, IP-profile updates, audit
  records, sanitized fixtures, and integration tests.

### Stage 3 — Network evidence

- Pure parser for the epoch-timestamped output emitted by the configured
  `tcpdump` command.
- IPv4 and IPv6 source/destination parsing, TCP port extraction, flag
  extraction, and destination-port filtering.
- A deliberately narrow live capture command:

  ```text
  /usr/bin/tcpdump -i INTERFACE -nn -l -tt -s 96 tcp dst port 22
  ```

- Metadata-only event storage. Packet bodies are neither parsed nor stored.
- Fixture mode for safe tests and continuous live mode with clean shutdown,
  stderr capture, bounded restart attempts, restart delay, and sensor health.
- Normalized network events, stable fingerprints, short-window in-memory
  deduplication, database uniqueness protection, parser-error quarantine,
  profile updates, and audit records.
- Normal, brute-force, and malformed sanitized network fixtures plus unit and
  end-to-end tests.

### Stage 4 — Correlation and detection

- Shared UTC/IP normalization and stable evidence fingerprints for both
  collectors.
- Five-minute correlation by normalized source IP across authentication and
  TCP/22 evidence.
- Counts for failed and successful authentication, invalid-user activity,
  unique usernames, network connections, attempt rate, recent success,
  previous detections, and previous blocks.
- Explainable 0–100 risk scoring with a stored point-by-point breakdown.
- Exact classifications:

  | Score | Classification |
  |---:|---|
  | 0–29 | Low Concern |
  | 30–49 | Unusual |
  | 50–69 | Suspicious |
  | 70–100 | High Risk |

- Decision logic for store, display, log, suppress, `WOULD_BLOCK`, and future
  `BLOCK` results.
- Safety gates for failure count, risk threshold, address eligibility,
  allowlisting, existing blocks, TCP/22 corroboration, database health, and both
  sensor health records.
- Validated IPv4 allowlist add/list/disable operations with optional expiration
  and an audit trail. Allowlisting suppresses response only; collection,
  correlation, scoring, and display remain intact.
- Evidence-to-detection links, duplicate-detection prevention, IP-profile
  detection counts, detection audits, CLI commands, and end-to-end tests.

## Work remaining

| Stage | Remaining work |
|---|---|
| 5 — Safe modes and initial dashboard | Complete the operational services for Simulation and Log Only modes and build the first read-only detection dashboard. |
| 6 — Firewall response | Build the dedicated-chain command layer, initialize and verify `SSH_BRUTE_GUARD`, manage rules, and guard Automatic Response Mode. |
| 7 — Block removal | Add expiration, manual-unblock requests, startup reconciliation, recovery, and cleanup workers. |
| 8 — Final dashboard and validation | Add block, allowlist, audit, and health pages; systemd units; live-lab validation; and final operational documentation. |

Stages 1–4 do not invoke `iptables`, add rules, or remove rules. Even if
`response.mode` is set to `automatic_response`, no current component executes a
firewall decision. That capability is intentionally deferred until Stages 6–7.

## Current data flow

```text
OpenSSH journal or auth fixture       tcpdump TCP/22 summaries or fixture
                 |                                      |
                 v                                      v
       authentication parser                   network parser
                 |                                      |
                 +---------------+----------------------+
                                 |
                                 v
                 validation + normalization + deduplication
                                 |
                  +--------------+--------------+
                  |                             |
                  v                             v
          auth_events/network_events       parser_errors
                  |                             |
                  +--------------+--------------+
                                 |
                                 v
                five-minute correlation by source IP
                                 |
                                 v
                 risk score + classification + decision
                                 |
                  +--------------+--------------+
                  |              |              |
                  v              v              v
             detections   detection_evidence  audit_log
                  |
                  v
             ip_profiles
```

## Repository layout

```text
SSH-Security-Application/
├── AGENTS.md
├── README.md
├── pyproject.toml
├── requirements.txt
├── config/
│   ├── default.json
│   └── local.example.json
├── data/
│   └── .gitkeep
├── logs/
│   └── .gitkeep
├── scripts/
│   ├── initialize_database.py
│   ├── run_auth_collector.py
│   ├── run_network_collector.py
│   └── run_detection.py
├── src/ssh_guard/
│   ├── collectors/
│   │   ├── auth_ingestor.py
│   │   ├── auth_journal.py
│   │   ├── auth_parser.py
│   │   ├── network_ingestor.py
│   │   ├── network_parser.py
│   │   └── network_tcpdump.py
│   ├── core/
│   │   ├── allowlist.py
│   │   ├── classification.py
│   │   ├── correlation.py
│   │   ├── deduplication.py
│   │   ├── ip_profiles.py
│   │   ├── ip_validation.py
│   │   ├── normalization.py
│   │   └── risk_score.py
│   └── db/
│       ├── database.py
│       ├── repositories.py
│       └── schema.sql
└── tests/
    ├── fixtures/
    ├── integration/
    └── unit/
```

## Complete Ubuntu setup

These steps assume Ubuntu 20.04 or newer and Python 3.8 or newer. Run each
command in order. Commands beginning with `sudo` change host configuration and
should be run manually only on the authorized lab VM.

### 1. Update package information

```bash
sudo apt update
```

### 2. Install operating-system prerequisites

```bash
sudo apt install -y git python3 python3-venv python3-pip openssh-server sqlite3 tcpdump libcap2-bin
```

### 3. Verify the installed tools

```bash
python3 --version
git --version
sqlite3 --version
tcpdump --version
systemctl --version
```

### 4. Enable and start OpenSSH

```bash
sudo systemctl enable --now ssh.service
```

```bash
systemctl status ssh.service --no-pager
```

```bash
ss -lnt
```

Look for a local listening address whose port is `:22`.

### 5. Clone the repository and select `Dev`

For a new clone:

```bash
cd "$HOME"
git clone https://github.com/samatarmrsl/SSH-Security-Application.git
cd SSH-Security-Application
git fetch origin
git switch Dev
git pull --ff-only origin Dev
```

For an existing clone:

```bash
cd "$HOME/SSH-Security-Application"
git status
git fetch origin
git switch Dev
git pull --ff-only origin Dev
```

Do not pull over uncommitted local changes. Commit, stash, or back them up first.

### 6. Create and activate the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

```bash
which python
python --version
```

The `which python` result should end in
`SSH-Security-Application/.venv/bin/python`.

### 7. Install the application and development tools

```bash
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

The optional packages reserved for later dashboard work can be installed with:

```bash
python -m pip install -e '.[dev,dashboard]'
```

### 8. Create and edit the local configuration

```bash
cp config/local.example.json config/local.json
```

```bash
ip -br address
```

```bash
nano config/local.json
```

Set:

- `network_sensor.interface` to the interface that sees the authorized client.
- `network_sensor.protected_ipv4_addresses` to the server VM's own IPv4
  address or addresses.
- `authentication_sensor.systemd_unit` to `sshd.service` only if that is the
  actual unit on the host.
- `network_sensor.tcpdump_path` if `command -v tcpdump` is not
  `/usr/bin/tcpdump`.
- `response.mode` to `simulation` for the safe demonstration.

Save with `Ctrl+O`, press `Enter`, and exit nano with `Ctrl+X`.

Check the JSON and application-level validation:

```bash
python -m json.tool config/local.json
ssh-guard --config config/local.json validate-config
```

Expected validation:

```text
Configuration is valid. Mode=simulation; environment=ubuntu-lab
```

### 9. Grant narrow non-root journal access

Try reading recent OpenSSH records:

```bash
journalctl -u ssh.service -n 10 -o short-iso --no-pager
```

If access is denied:

```bash
sudo usermod -aG systemd-journal "$USER"
newgrp systemd-journal
```

`newgrp` opens a new shell, so return to the repository and reactivate:

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
journalctl -u ssh.service -n 10 -o short-iso --no-pager
```

### 10. Grant narrow non-root packet-capture capability

Do not run the complete application as root. Resolve the configured `tcpdump`
binary, assign only packet-capture capabilities to that binary, and verify them:

```bash
command -v tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
getcap "$(command -v tcpdump)"
```

Expected `getcap` output includes:

```text
cap_net_admin,cap_net_raw=eip
```

Package upgrades can replace the binary and remove its capabilities. Recheck
`getcap` after upgrading `tcpdump`.

### 11. Initialize or migrate SQLite

```bash
ssh-guard --config config/local.json init-db
```

Equivalent script:

```bash
python scripts/initialize_database.py --config config/local.json
```

Expected output:

```text
Database initialized: data/ssh_guard.db
```

Verify the database:

```bash
ls -lh data/ssh_guard.db
sqlite3 data/ssh_guard.db ".tables"
sqlite3 data/ssh_guard.db "PRAGMA journal_mode;"
```

Initialization is idempotent and migrates a Stage 1–2 database without deleting
its evidence.

## Safe fixture demonstration

Fixture mode never invokes `journalctl` or `tcpdump` and never changes the
firewall. Start from the initialized database above.

### 1. Ingest ten sanitized failed authentications

```bash
ssh-guard --config config/local.json collect-auth --fixture tests/fixtures/auth_bruteforce.log
```

### 2. Ingest the matching sanitized TCP/22 records

```bash
ssh-guard --config config/local.json collect-network --fixture tests/fixtures/network_bruteforce.log
```

### 3. Run correlation at the fixture's fixed window end

```bash
ssh-guard --config config/local.json detect --source-ip 192.168.56.40 --window-end "2026-07-24T08:25:00+00:00"
```

The expected result includes:

```text
source=192.168.56.40, score=80, classification=High Risk, decision=WOULD_BLOCK
```

The breakdown is 40 points for ten failures, 15 for four usernames, 15 for ten
network connections, 10 for the attempt rate, and 0 from the other factors.
Simulation Mode confirms the response that would be selected while making no
firewall change.

Run all candidate sources in a window instead:

```bash
ssh-guard --config config/local.json detect --all --window-end "2026-07-24T08:25:00+00:00"
```

Replaying the same fixtures or detection window is safely ignored by the stable
evidence and detection fingerprints.

### Additional parser fixtures

```bash
ssh-guard --config config/local.json collect-auth --fixture tests/fixtures/auth_normal.log
ssh-guard --config config/local.json collect-auth --fixture tests/fixtures/auth_invalid_users.log
ssh-guard --config config/local.json collect-auth --fixture tests/fixtures/auth_malformed.log
ssh-guard --config config/local.json collect-network --fixture tests/fixtures/network_normal.log
ssh-guard --config config/local.json collect-network --fixture tests/fixtures/network_malformed.log
```

Equivalent helper scripts:

```bash
python scripts/run_auth_collector.py --config config/local.json --fixture tests/fixtures/auth_normal.log
python scripts/run_network_collector.py --config config/local.json --fixture tests/fixtures/network_normal.log
python scripts/run_detection.py --config config/local.json --source-ip 192.168.56.40 --window-end "2026-07-24T08:25:00+00:00"
```

## Live evidence collection

Use live commands only inside the authorized Ubuntu lab.

### Authentication: one-shot

```bash
ssh-guard --config config/local.json collect-auth --once
```

With a custom lookback:

```bash
ssh-guard --config config/local.json collect-auth --once --since "-15 minutes"
```

### Authentication: continuous

```bash
ssh-guard --config config/local.json collect-auth --follow
```

### TCP/22 metadata: continuous

```bash
ssh-guard --config config/local.json collect-network --follow
```

`collect-network` with no fixture also starts live continuous mode:

```bash
ssh-guard --config config/local.json collect-network
```

Stop either continuous collector cleanly with `Ctrl+C`.

In normal operation, run both collectors in separate terminals. In each
terminal:

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
```

Then run the authentication command in one and the network command in the
other. Stage 8 will add managed systemd services.

### Generate one controlled lab event

On a separate authorized lab client:

```bash
SSH_GUARD_SERVER_IP=192.168.56.10
ssh ssh_guard_test_user@"$SSH_GUARD_SERVER_IP"
```

Enter one deliberately incorrect test password, stop with `Ctrl+C`, and return
to the server. Do not test an account or host outside the authorized lab.

Run detection for current evidence:

```bash
ssh-guard --config config/local.json detect --all
```

The default suspicious threshold is five failures in five minutes, so one
controlled failure should be stored but should not create a detection.

## Allowlist operations

Add a permanent authorized lab address:

```bash
ssh-guard --config config/local.json allowlist-add 192.168.56.20 --description "Lab administrator workstation" --reason "Trusted management source" --created-by "$USER"
```

Add an entry that expires at a UTC-aware time:

```bash
ssh-guard --config config/local.json allowlist-add 192.168.56.21 --description "Temporary lab scanner" --reason "Authorized exercise" --created-by "$USER" --expires-at "2026-07-25T18:00:00+00:00" --notes "Remove after the exercise"
```

List active entries:

```bash
ssh-guard --config config/local.json allowlist-list
```

Copy the returned entry ID and disable it:

```bash
SSH_GUARD_ALLOWLIST_ID="paste-entry-id-here"
ssh-guard --config config/local.json allowlist-disable "$SSH_GUARD_ALLOWLIST_ID"
```

Only validated IPv4 addresses are accepted. An allowlisted source is still
collected and scored; its response decision becomes `SUPPRESS_ALLOWLIST`.

## Inspect SQLite evidence and decisions

Authentication events:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, source_ip, username, event_type, success FROM auth_events ORDER BY event_time DESC LIMIT 20;"
```

Network metadata:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, source_ip, destination_ip, destination_port, tcp_flags, interface_name FROM network_events ORDER BY event_time DESC LIMIT 20;"
```

Risk detections and decisions:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT window_end, source_ip, failed_count, network_connection_count, risk_score, classification, decision FROM detections ORDER BY created_at DESC LIMIT 20;"
```

Linked evidence counts:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT detection_id, evidence_type, COUNT(*) AS evidence_count FROM detection_evidence GROUP BY detection_id, evidence_type ORDER BY detection_id, evidence_type;"
```

IP profiles:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT source_ip, ip_category, failed_count_total, successful_count_total, detection_count, last_seen FROM ip_profiles ORDER BY last_seen DESC;"
```

Parser failures:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, sensor, error_message, raw_message FROM parser_errors ORDER BY event_time DESC LIMIT 20;"
```

Audit records:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, component, action, result, target FROM audit_log ORDER BY event_time DESC LIMIT 20;"
```

Component health:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT component, status, last_success, last_error, details FROM component_health ORDER BY component;"
```

Database health:

```bash
sqlite3 data/ssh_guard.db "PRAGMA quick_check;"
sqlite3 data/ssh_guard.db "PRAGMA journal_mode;"
```

## Configuration reference

`config/default.json` contains committed defaults. The ignored
`config/local.json` is recursively merged over them.

| Section | Important settings |
|---|---|
| `application` | Display name and environment |
| `detection` | Five-minute window, detection/blocking failure thresholds, high-risk score, and recent-success period |
| `response` | Safe mode, future block duration, expiration interval, backend, and dedicated chain |
| `authentication_sensor` | Enable flag, SSH unit, `journalctl` path, and lookback |
| `network_sensor` | Enable flag, interface, SSH port, `tcpdump` path, snapshot length, restart policy, and protected server IPv4 addresses |
| `database` | SQLite path, busy timeout, and WAL |
| `dashboard` | Reserved dashboard bind address and port |
| `logging` | Level, rotating JSON log path, size, and backups |

Valid response modes:

- `simulation`: creates and audits decisions such as `WOULD_BLOCK`; never
  changes the firewall.
- `log_only`: stores and logs detections; never changes the firewall.
- `automatic_response`: reserved for the guarded firewall manager in Stage 6.
  Current Stages 1–4 still do not execute firewall commands.

## Risk-score breakdown

The calculation is deterministic and clamped to 0–100:

| Factor | Points |
|---|---|
| Failed authentication volume | 3: 10; 5: 20; 8: 30; 10+: 40 |
| Unique usernames | 2: 5; 3: 10; 4–5: 15; 6+: 20 |
| Matching TCP/22 connections | 1–4: 5; 5–9: 10; 10+: 15 |
| Failed attempts per minute | 1–1.999: 5; 2+: 10 |
| Previous history | prior detection: 5; prior block: 10 |
| Invalid-user activity | 1–2: 2; 3+: 5 |
| Recent successful login | subtract 10 |

Each detection stores the complete breakdown so an operator can explain the
classification and decision later.

## Run the automated checks

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
```

```bash
python -m pytest --cov=ssh_guard --cov-report=term-missing
ruff check .
ruff format --check .
python -m compileall -q src scripts
```

At completion of Stages 1–4, the suite contains 108 passing unit and integration
tests and reports 79% overall statement/branch coverage on Python 3.8.

## Logging

The default rotating JSON log is `logs/ssh_guard.log`.

```bash
tail -f logs/ssh_guard.log
```

## Troubleshooting

### `python3 -m venv .venv` reports that `ensurepip` is unavailable

```bash
sudo apt update
sudo apt install -y python3-venv
mv .venv .venv.incomplete
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

The previous incomplete directory remains at `.venv.incomplete` until you
inspect and remove it.

### `ssh-guard: command not found`

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
python -m pip install -e '.[dev]'
which ssh-guard
```

Fallback invocation:

```bash
python -m ssh_guard.main validate-config
```

### Configuration error or invalid JSON

```bash
python -m json.tool config/local.json
diff -u config/local.example.json config/local.json
ssh-guard --config config/local.json validate-config
```

### `Unit ssh.service could not be found`

```bash
systemctl list-unit-files 'ssh*.service'
systemctl status sshd.service --no-pager
```

If `sshd.service` is the real unit:

```bash
nano config/local.json
```

Set `authentication_sensor.systemd_unit` to `sshd.service`, save, and validate
again.

### `journalctl` reports insufficient permissions

```bash
sudo usermod -aG systemd-journal "$USER"
newgrp systemd-journal
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
journalctl -u ssh.service -n 10 -o short-iso --no-pager
```

### No OpenSSH records are returned

```bash
systemctl is-active ssh.service
journalctl -u ssh.service -n 50 -o short-iso --no-pager
ss -lnt
ssh-guard --config config/local.json collect-auth --once --since "yesterday"
```

### `tcpdump` is missing

```bash
sudo apt update
sudo apt install -y tcpdump libcap2-bin
command -v tcpdump
```

Update `network_sensor.tcpdump_path` if the path differs from the configuration.

### `tcpdump` reports permission denied

```bash
command -v tcpdump
getcap "$(command -v tcpdump)"
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
getcap "$(command -v tcpdump)"
```

Do not solve this by running the whole application or a future dashboard as
root.

### `tcpdump` reports that the interface does not exist

```bash
ip -br link
ip -br address
```

Copy the correct interface name into `network_sensor.interface`, then:

```bash
ssh-guard --config config/local.json validate-config
ssh-guard --config config/local.json collect-network --follow
```

### The network collector repeatedly restarts

Inspect sensor health and the application log:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT component, status, last_error, details FROM component_health WHERE component = 'network_sensor';"
tail -n 100 logs/ssh_guard.log
```

Confirm the executable, capability, interface, and SSH port:

```bash
command -v tcpdump
getcap "$(command -v tcpdump)"
ip -br address
python -m json.tool config/local.json
```

### Evidence appears in `parser_errors`

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, sensor, error_message, raw_message FROM parser_errors ORDER BY event_time DESC LIMIT 20;"
```

Unsupported messages are deliberately quarantined. If a common format should be
supported, open an issue with a sanitized example. Never include passwords,
keys, or unauthorized public addresses.

### Detection says no new result was created

Check whether the threshold was met:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT source_ip, COUNT(*) AS failures FROM auth_events WHERE success = 0 GROUP BY source_ip;"
```

Check the evidence timestamps:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, source_ip, event_type FROM auth_events ORDER BY event_time DESC LIMIT 20;"
```

The result is also expected when the source has fewer than five failures in the
window or when the identical evidence set was already analyzed.

### A high-risk result is suppressed instead of `WOULD_BLOCK`

Inspect the printed reason, health, and allowlist:

```bash
ssh-guard --config config/local.json allowlist-list
sqlite3 -header -column data/ssh_guard.db \
  "SELECT component, status, last_error FROM component_health ORDER BY component;"
```

High-risk action is deliberately suppressed when evidence lacks TCP/22
corroboration, a source is ineligible or allowlisted, an active block exists, or
a required sensor/database health check fails.

### SQLite reports `database is locked`

Stop duplicate collectors with `Ctrl+C`, then inspect only this project's
processes and database health:

```bash
ps -ef | sed -n '/[s]sh-guard/p'
sqlite3 data/ssh_guard.db "PRAGMA quick_check;"
```

Increase `database.busy_timeout_seconds` if a slow lab disk needs more time.

### SQLite reports a read-only database

```bash
ls -ld data
ls -l data/ssh_guard.db
```

The database and parent directory must be writable by the normal application
account. Avoid creating the database with `sudo`.

### Start with an empty database without deleting evidence

Stop collectors, then:

```bash
mkdir -p backups
cp -a data/ssh_guard.db backups/ssh_guard.db.backup
mv data/ssh_guard.db data/ssh_guard.db.previous
ssh-guard --config config/local.json init-db
```

The previous evidence remains recoverable in both paths.

### Tests cannot import `ssh_guard`

```bash
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
```

## Security decisions currently enforced

- Simulation Mode is the default.
- Stages 1–4 contain no firewall execution.
- External processes use argument arrays and `shell=False`.
- Live network capture is filtered to the configured TCP destination port.
- Snapshot length defaults to 96 bytes and only parsed metadata is stored.
- Parsers never inspect or infer passwords.
- IP validation uses Python's standard `ipaddress` module.
- IPv6 evidence may be stored but is ineligible for version 1 automatic action.
- Private IPv4 is eligible only because the intended environment is a
  controlled lab.
- Protected, allowlisted, special-purpose, or unhealthy cases fail safely.
- The future dashboard will be unprivileged and use SQLite action requests
  instead of executing firewall commands.

## Final target workflow

```text
Controlled failed SSH attempts
        |
        v
Authentication and TCP/22 evidence collected
        |
        v
Evidence correlated and risk scored
        |
        v
Safety gates and operating mode evaluated
        |
        +---------------- current Stages 1–4 ----------------+
        |                                                    |
        v                                                    v
Detection stored and audited                 Simulation reports WOULD_BLOCK
        |
        +---------------- future Stages 5–8 -----------------+
        |
        v
Dedicated SSH_BRUTE_GUARD rule added
        |
        v
Dashboard shows block, evidence, audit, and health
        |
        v
Expiration or approved manual request removes project rule
```
