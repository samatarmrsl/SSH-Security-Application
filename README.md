# SSH Brute Guard

SSH Brute Guard is a defensive cybersecurity application for detecting repeated
OpenSSH login failures and, in later stages, temporarily blocking high-risk IPv4
sources. It is designed for an authorized Ubuntu virtual lab and the SPR888 SSH
Security Monitoring and Response project.

The final system will combine OpenSSH authentication records with TCP port 22
connection metadata, correlate the evidence by source IP and time window, produce
an explainable risk score from 0 to 100, and safely manage temporary rules in a
dedicated `SSH_BRUTE_GUARD` iptables chain. A Streamlit dashboard will display the
evidence, decisions, health, allowlist, audit history, and active blocks.

The repository currently contains the completed **Stage 1 foundation** and
**Stage 2 authentication-evidence pipeline**. It does not modify the firewall.

## What the project is used for

The project helps a lab administrator or cybersecurity student:

- Collect successful and failed OpenSSH authentication activity.
- Distinguish supported events from unsupported or malformed journal records.
- Normalize, validate, and classify source IP addresses.
- Preserve authentication evidence and parser failures in SQLite.
- Maintain initial per-IP success and failure history.
- Audit application and parser activity.
- Monitor whether the authentication collector is healthy.
- Test the collection pipeline safely with sanitized fixture files.
- Build toward correlated brute-force detection and temporary blocking.

This project must only be used on systems and networks you own or are explicitly
authorized to test. It does not collect attempted passwords, decrypt SSH traffic,
or inspect SSH payload contents.

## Current implementation status

### Completed: Stage 1 — Foundation

- Python `src` package layout and command-line entry point.
- JSON default configuration and local override support.
- Strict validation for modes, thresholds, ports, paths, firewall-chain names,
  protected IPv4 addresses, and numeric ranges.
- Simulation Mode as the safe default.
- Typed dataclasses and enums for events, validation, detections, blocks, action
  requests, decisions, and health states.
- SQLite connection management with:
  - foreign keys;
  - configurable busy timeout;
  - WAL mode;
  - short transactions;
  - parameterized statements.
- Complete forward-looking SQLite schema for authentication events, network
  events, IP profiles, detections, evidence links, allowlist entries, blocks,
  action requests, audit records, parser errors, and component health.
- Repository APIs that keep SQL out of collectors and controllers.
- Structured JSON console/file logging.
- Database-backed audit logging and component-health storage.
- Database initialization script and CLI command.
- Unit and integration test framework with coverage reporting and Ruff.

### Completed: Stage 2 — Authentication evidence

- Pure OpenSSH journal parser for:
  - failed password for a valid user;
  - failed password for an invalid user;
  - invalid user;
  - accepted password;
  - accepted public key;
  - connection closed;
  - unsupported records;
  - malformed records.
- UTC normalization for `journalctl -o short-iso` timestamps.
- Explicit IPv4/IPv6 validation and technical classification.
- Automatic-block eligibility explanations.
- Protection for loopback, link-local, multicast, unspecified, special-purpose,
  IPv6, allowlisted, and SSH-server-owned addresses.
- Private IPv4 eligibility for the controlled virtual lab.
- OpenSSH journal collector with:
  - sanitized fixture mode;
  - one-shot recent-record mode;
  - continuous follow mode;
  - safe subprocess argument lists;
  - `shell=False`;
  - stderr and exit-status handling;
  - clean termination;
  - health reporting.
- Authentication event storage, parser-error quarantine, IP-profile updates,
  and parser-failure audit records.
- Sanitized normal-login, invalid-user, brute-force, and malformed fixtures.
- End-to-end fixture-to-SQLite integration tests.

### Remaining work

| Stage | Work still to be completed |
|---|---|
| 3 — Network evidence | TCP port 22 parser, `tcpdump` collector, network event storage, restart handling, and network-sensor health |
| 4 — Detection | Normalization, deduplication, IP profiles, allowlist manager, five-minute correlation, explainable risk scoring, classification, and decision engine |
| 5 — Safe modes | Complete Simulation Mode, Log Only Mode, detection audit events, and initial detection dashboard |
| 6 — Firewall response | Dedicated-chain command builder, chain initialization, rule checks, block manager, and guarded Automatic Response Mode |
| 7 — Block removal | Expiration worker, dashboard action requests, manual-unblock worker, startup reconciliation, recovery, and cleanup |
| 8 — Final dashboard and validation | Blocks, allowlist, audit and health pages, systemd units, full integration tests, live-lab validation, and final documentation |

Until those stages are implemented, the application does **not** collect packet
metadata, calculate brute-force risk scores, show a Streamlit dashboard, or add
and remove iptables rules.

## Current data flow

```text
Sanitized fixture or OpenSSH systemd journal
                    |
                    v
          Pure authentication parser
                    |
          +---------+----------+
          |                    |
          v                    v
    Supported event     Unsupported/malformed
          |                    |
          v                    v
      IP validation       parser_errors table
          |                    |
          v                    v
   Normalized auth event    audit_log
          |
          +----------+-----------+
                     |           |
                     v           v
               auth_events   ip_profiles
                     |
                     v
              component_health
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
│   └── run_auth_collector.py
├── src/
│   └── ssh_guard/
│       ├── audit.py
│       ├── config.py
│       ├── constants.py
│       ├── health.py
│       ├── main.py
│       ├── models.py
│       ├── collectors/
│       │   ├── auth_ingestor.py
│       │   ├── auth_journal.py
│       │   └── auth_parser.py
│       ├── core/
│       │   └── ip_validation.py
│       └── db/
│           ├── database.py
│           ├── repositories.py
│           └── schema.sql
└── tests/
    ├── fixtures/
    ├── integration/
    └── unit/
```

## Complete Ubuntu setup

The following commands assume Ubuntu 20.04 or newer and Python 3.8 or newer.
Run each command in order.

### 1. Update Ubuntu package information

```bash
sudo apt update
```

### 2. Install the Stage 1–2 operating-system prerequisites

```bash
sudo apt install -y git python3 python3-venv python3-pip openssh-server sqlite3
```

The network and firewall packages are not needed by Stages 1–2. They will be
added to the setup instructions when the corresponding code exists.

### 3. Verify the installed tools

```bash
python3 --version
git --version
sqlite3 --version
systemctl --version
```

### 4. Enable and start OpenSSH

```bash
sudo systemctl enable --now ssh.service
```

Verify it:

```bash
systemctl status ssh.service --no-pager
```

Confirm that port 22 is listening:

```bash
ss -lnt
```

Look for a line whose local port is `:22`.

### 5. Clone this GitHub repository

```bash
cd "$HOME"
git clone https://github.com/samatarmrsl/SSH-Security-Application.git
cd SSH-Security-Application
```

If it is already cloned, update it without overwriting local work:

```bash
cd "$HOME/SSH-Security-Application"
git status
git pull --ff-only
```

### 6. Create and activate a Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Confirm that the virtual-environment interpreter is active:

```bash
which python
python --version
```

The `which python` output should end with
`SSH-Security-Application/.venv/bin/python`.

### 7. Upgrade pip and install the project

```bash
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

The optional future dashboard packages can also be installed:

```bash
python -m pip install -e '.[dev,dashboard]'
```

They are not required for Stages 1–2 because the Streamlit dashboard is still
future work.

### 8. Create the untracked local configuration

```bash
cp config/local.example.json config/local.json
```

List the VM's addresses and interface names:

```bash
ip -br address
```

Open the local configuration:

```bash
nano config/local.json
```

Update:

- `network_sensor.interface` to the interface that will later observe the lab.
- `network_sensor.protected_ipv4_addresses` to the SSH server's own IPv4
  address or addresses.
- `dashboard.host` to a lab-only address if desired for the future dashboard.
- `authentication_sensor.systemd_unit` if the host calls the service
  `sshd.service` instead of `ssh.service`.

Save in nano with `Ctrl+O`, press `Enter`, then exit with `Ctrl+X`.

Check the JSON syntax:

```bash
python -m json.tool config/local.json
```

Validate every configuration rule:

```bash
ssh-guard --config config/local.json validate-config
```

Expected result:

```text
Configuration is valid. Mode=simulation; environment=ubuntu-lab
```

### 9. Confirm journal access

First try reading OpenSSH records as the current non-root user:

```bash
journalctl -u ssh.service -n 10 -o short-iso --no-pager
```

If the command reports insufficient permissions, add the current user to the
systemd journal group:

```bash
sudo usermod -aG systemd-journal "$USER"
```

Apply the new group in the current terminal:

```bash
newgrp systemd-journal
```

Activate the virtual environment again after `newgrp` starts the new shell:

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
```

Test journal access again:

```bash
journalctl -u ssh.service -n 10 -o short-iso --no-pager
```

Do not run the whole application or a future dashboard as root merely to bypass
journal permissions.

### 10. Initialize SQLite

```bash
ssh-guard --config config/local.json init-db
```

Equivalent script command:

```bash
python scripts/initialize_database.py --config config/local.json
```

Expected result:

```text
Database initialized: data/ssh_guard.db
```

Verify that the file exists:

```bash
ls -lh data/ssh_guard.db
```

List its tables:

```bash
sqlite3 data/ssh_guard.db ".tables"
```

## Safe fixture demonstration

Fixture mode proves the Stage 2 pipeline without requiring live SSH attempts.
It never invokes `journalctl` and never changes the firewall.

### Run normal authentication evidence

```bash
ssh-guard --config config/local.json collect-auth --fixture tests/fixtures/auth_normal.log
```

### Run invalid-user evidence

```bash
ssh-guard --config config/local.json collect-auth --fixture tests/fixtures/auth_invalid_users.log
```

### Run the sanitized ten-failure fixture

```bash
ssh-guard --config config/local.json collect-auth --fixture tests/fixtures/auth_bruteforce.log
```

### Run malformed and unsupported records

```bash
ssh-guard --config config/local.json collect-auth --fixture tests/fixtures/auth_malformed.log
```

The command reports processed lines, stored authentication events, and parser
errors. Repeating a fixture creates new evidence IDs and therefore adds another
copy; short-window duplicate detection belongs to Stage 4.

The equivalent collector script is:

```bash
python scripts/run_auth_collector.py --config config/local.json --fixture tests/fixtures/auth_normal.log
```

## Inspect collected evidence

Show the most recent authentication events:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, source_ip, username, event_type, success FROM auth_events ORDER BY event_time DESC LIMIT 20;"
```

Show accumulated IP history:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT source_ip, ip_category, failed_count_total, successful_count_total, last_success_at FROM ip_profiles ORDER BY last_seen DESC;"
```

Show quarantined parser failures:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, sensor, error_message, raw_message FROM parser_errors ORDER BY event_time DESC LIMIT 20;"
```

Show recent audit records:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, component, action, result, target FROM audit_log ORDER BY event_time DESC LIMIT 20;"
```

Show component health:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT component, status, last_success, last_error, details FROM component_health ORDER BY component;"
```

Check that foreign keys and WAL are active:

```bash
sqlite3 data/ssh_guard.db "PRAGMA foreign_keys;"
sqlite3 data/ssh_guard.db "PRAGMA journal_mode;"
```

The second command should print `wal`. Foreign keys are enabled on every
application connection; the standalone SQLite CLI opens a separate connection,
so its first output may be `0`.

## Collect live OpenSSH records

Use live collection only on the authorized Ubuntu lab.

### One-shot collection

By default, this reads the configured lookback period and exits:

```bash
ssh-guard --config config/local.json collect-auth --once
```

Use a custom journal time:

```bash
ssh-guard --config config/local.json collect-auth --once --since="today"
```

Or:

```bash
ssh-guard --config config/local.json collect-auth --once --since="-15 minutes"
```

### Continuous follow mode

```bash
ssh-guard --config config/local.json collect-auth --follow
```

Stop cleanly with `Ctrl+C`.

### Generate one controlled failed login

From a separate authorized lab client, set the server address:

```bash
SSH_GUARD_SERVER_IP=192.168.56.10
```

Attempt an SSH login with a deliberately nonexistent lab username:

```bash
ssh ssh_guard_test_user@"$SSH_GUARD_SERVER_IP"
```

Enter one intentionally incorrect test password, then stop the client with
`Ctrl+C`. Return to the server and inspect the event:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, source_ip, username, event_type, success FROM auth_events ORDER BY collected_at DESC LIMIT 5;"
```

Do not test accounts, hosts, or networks outside the authorized lab.

## Configuration reference

The committed defaults are in `config/default.json`. `config/local.json` is
ignored by Git and merged over those defaults.

| Section | Important settings |
|---|---|
| `application` | Display name and environment label |
| `detection` | Five-minute window, failure thresholds, high-risk score, recent-success period |
| `response` | Safe mode, future block duration, expiration check, firewall backend, dedicated chain |
| `authentication_sensor` | Enable flag, SSH service unit, `journalctl` executable, lookback |
| `network_sensor` | Future interface and port, plus the server's protected IPv4 addresses |
| `database` | SQLite path, lock timeout, and WAL enable flag |
| `dashboard` | Future Streamlit bind host and port |
| `logging` | Level, rotating log path, maximum size, and backup count |

Valid response modes are:

- `simulation` — the safe default; future decisions say what would happen.
- `log_only` — store and display detections without a firewall change.
- `automatic_response` — future mode; will require every safety check.

Stages 1–2 load and audit the configured mode but do not execute any response.

## Database design

SQLite timestamps are stored as timezone-aware ISO 8601 text. Booleans are
stored as constrained `0`/`1` integers. JSON details are serialized into text
columns. The schema is idempotent, so initialization can be run repeatedly
without deleting data.

The main evidence tables are:

- `auth_events` — successfully parsed authentication records.
- `parser_errors` — unsupported, malformed, or invalid-IP records.
- `ip_profiles` — first/last seen and accumulated authentication outcomes.
- `audit_log` — security-relevant application activity.
- `component_health` — latest health state for each component.

The remaining tables are established for later stages but are not populated
until those stages are implemented.

All application SQL uses parameters. User-controlled values are never joined
into SQL strings.

## Logging

The default application log is:

```text
logs/ssh_guard.log
```

Follow it:

```bash
tail -f logs/ssh_guard.log
```

Each line is JSON with timestamp, severity, logger, and message. Logs rotate at
the configured size and keep the configured number of backups.

## Run the automated checks

Activate the virtual environment:

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
```

Run all unit and integration tests with coverage:

```bash
python -m pytest --cov=ssh_guard --cov-report=term-missing
```

Run lint checks:

```bash
ruff check .
```

Verify formatting:

```bash
ruff format --check .
```

Compile every Python source file:

```bash
python -m compileall -q src scripts
```

At completion of Stages 1–2, the suite contains 57 passing tests and reports 80%
overall statement/branch coverage on Python 3.8. The exact number may grow as
later stages add behavior and tests.

## Troubleshooting

### `python3 -m venv .venv` says `ensurepip` is unavailable

Install Ubuntu's virtual-environment package:

```bash
sudo apt update
sudo apt install -y python3-venv
```

Remove only the incomplete local environment and recreate it:

```bash
mv .venv .venv.incomplete
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

### `ssh-guard: command not found`

Confirm that the environment is active and reinstall the editable package:

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
python -m pip install -e '.[dev]'
which ssh-guard
```

You can also use:

```bash
python -m ssh_guard.main validate-config
```

### `Configuration error` or invalid JSON

Print the JSON parser's exact location:

```bash
python -m json.tool config/local.json
```

Compare the local file with the example:

```bash
diff -u config/local.example.json config/local.json
```

Then run validation again:

```bash
ssh-guard --config config/local.json validate-config
```

### `Unit ssh.service could not be found`

List likely OpenSSH unit names:

```bash
systemctl list-unit-files 'ssh*.service'
```

Check the alternative unit:

```bash
systemctl status sshd.service --no-pager
```

If `sshd.service` is the real unit, edit:

```bash
nano config/local.json
```

Set:

```json
"systemd_unit": "sshd.service"
```

### `journalctl` reports insufficient permissions

Add the account to the journal group and enter a new group shell:

```bash
sudo usermod -aG systemd-journal "$USER"
newgrp systemd-journal
```

Then reactivate the environment:

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
```

### No SSH records are returned

Confirm the service is active:

```bash
systemctl is-active ssh.service
```

Check recent service records directly:

```bash
journalctl -u ssh.service -n 50 -o short-iso --no-pager
```

Check whether SSH is listening:

```bash
ss -lnt
```

Then use a wider one-shot window:

```bash
ssh-guard --config config/local.json collect-auth --once --since="yesterday"
```

### Records appear in `parser_errors`

Inspect their error messages:

```bash
sqlite3 -header -column data/ssh_guard.db \
  "SELECT event_time, error_message, raw_message FROM parser_errors ORDER BY event_time DESC LIMIT 20;"
```

Unsupported OpenSSH messages are deliberately quarantined instead of guessed.
Open an issue with a sanitized example if a common Ubuntu OpenSSH message should
become a supported type. Never include passwords, private keys, public IPs you
are not permitted to disclose, or other secrets.

### SQLite reports `database is locked`

Stop duplicate collectors with `Ctrl+C`. Identify only this project's running
commands:

```bash
ps -ef | sed -n '/[s]sh-guard/p'
```

Check database health:

```bash
sqlite3 data/ssh_guard.db "PRAGMA quick_check;"
```

The application already uses WAL and a configurable busy timeout. Increase
`database.busy_timeout_seconds` in `config/local.json` if a slow lab disk needs
more time.

### SQLite reports a read-only database

Inspect ownership and directory permissions:

```bash
ls -ld data
ls -l data/ssh_guard.db
```

The database and its parent directory must be writable by the normal service
account. Avoid creating the database with `sudo`.

### Start again with an empty database without deleting evidence

Stop collectors first. Create a backup directory:

```bash
mkdir -p backups
```

Copy the current database:

```bash
cp -a data/ssh_guard.db backups/ssh_guard.db.backup
```

Move the current database out of the active path:

```bash
mv data/ssh_guard.db data/ssh_guard.db.previous
```

Initialize a new database:

```bash
ssh-guard --config config/local.json init-db
```

The old evidence remains recoverable in `data/ssh_guard.db.previous` and
`backups/ssh_guard.db.backup`.

### Tests cannot import `ssh_guard`

Activate the environment and reinstall the package:

```bash
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
```

## Security design decisions already enforced

- The default mode is Simulation Mode.
- Stages 1–2 contain no iptables execution.
- Subprocesses use argument arrays and `shell=False`.
- Only the configured `journalctl` executable is invoked.
- Parsers never inspect or infer passwords.
- IPv4 validation uses the standard `ipaddress` module.
- IPv6 evidence may be stored but is ineligible for version 1 detection and
  automatic blocking.
- Private IPv4 is permitted only because the intended environment is a
  controlled lab.
- Allowlisting will suppress only future firewall action, not collection,
  scoring, or display.
- The future dashboard will run unprivileged and write action requests to
  SQLite rather than execute firewall commands.
- Automatic response will remain disabled whenever required sensors, SQLite,
  or the firewall manager are unhealthy.

## Final target workflow

When all remaining stages are complete, the demonstration will be:

```text
Controlled failed SSH attempts
        |
        v
Authentication and TCP/22 evidence collected
        |
        v
Source IPv4 validated
        |
        v
Evidence correlated in a five-minute window
        |
        v
Explainable risk score and classification produced
        |
        v
High-risk source temporarily added to SSH_BRUTE_GUARD
        |
        v
Block displayed in Streamlit
        |
        +-------------------------+
        |                         |
        v                         v
Automatic expiration      Manual dashboard request
        |                         |
        +------------+------------+
                     |
                     v
Project firewall rule removed
                     |
                     v
SQLite and audit history updated
```

The firewall portion will not be enabled until the network evidence,
correlation, scoring, operating-mode, health, and dedicated-chain safety checks
are implemented and tested.
