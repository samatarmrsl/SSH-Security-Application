# SSH Security Application

SSH Security Application is a defensive Python application that collects OpenSSH
authentication records and TCP destination-port 22 metadata, correlates both
evidence sources by IP address and time, and creates explainable brute-force
risk detections.

The application collects, normalizes, deduplicates,
stores, correlates, scores, classifies, displays, and audits evidence; creates
guarded temporary blocks; automatically expires them; processes SQLite-backed
manual-unblock requests; reconciles database and firewall state; and provides
managed services and a complete dashboard. Simulation Mode remains the safe
default: a high-risk result says `WOULD_BLOCK`, but no firewall command is
executed unless Automatic Response Mode and an explicit response path are
selected.


## Purpose and use cases

The project helps:

- Collect successful and failed OpenSSH authentication events.
- Collect only metadata summaries for TCP connections to the configured SSH
  port; it does not inspect packet payloads.
- Quarantine unsupported, malformed, or invalid evidence instead of guessing.
- Normalizing timestamps and IP addresses and rejecting duplicate records.
- Maintain a history profile for each observed source IP.
- Correlate authentication and network evidence in a five-minute window.
- Calculate an explainable risk score from 0 to 100.
- Classify activity as Low Concern, Unusual, Suspicious, or High Risk.
- Suppress unsafe responses for allowlisted, ineligible, already blocked, or
  insufficiently corroborated sources.
- Record evidence, detections, decisions, health, and audit history in SQLite.
- Review detections, active blocks, allowlist history, action requests, audits,
  and component health in a project-owned, unprivileged web dashboard.
- Follow each firewall block through its complete lifecycle, including the
  removal time and whether it expired automatically or was removed manually.
- Display the exact project-owned iptables `INPUT` jump and source-specific
  TCP/22 DROP rule associated with each block.
- Select an observed source IP to review its stored profile, risk explanation,
  detection history, sanitized authentication evidence, network metadata, and
  block history without using an external IP-enrichment service.
- In explicitly enabled Automatic Response Mode, add a validated high-risk IPv4
  source to the dedicated project firewall chain for automatic expiration.
- Request an early manual unblock through SQLite without giving the dashboard
  firewall capabilities.
- Reconcile active SQLite blocks with project-owned rules after worker startup.
- Reproduce the pipeline safely with sanitized fixture files.


## Work completed so far

### Stage 1 — Foundation

- Python `src` package layout and `ssh-security-app` command-line entry point.
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

- Decision logic for store, display, log, suppress, `WOULD_BLOCK`, and guarded
  `BLOCK` results.
- Safety gates for failure count, risk threshold, address eligibility,
  allowlisting, existing blocks, TCP/22 corroboration, database health, and both
  sensor health records.
- Validated IPv4 allowlist add/list/disable operations with optional expiration
  and an audit trail. Allowlisting suppresses response only; collection,
  correlation, scoring, and display remain intact.
- Evidence-to-detection links, duplicate-detection prevention, IP-profile
  detection counts, detection audits, CLI commands, and end-to-end tests.

### Stage 5 — Safe modes and detection dashboard

- Persistent operating-mode state with audited transitions between Simulation,
  Log Only, and Automatic Response modes.
- Simulation Mode runs the complete detection pipeline, reports how long a
  source would be blocked, and performs no firewall operation.
- Log Only Mode collects, correlates, scores, stores, audits, and displays
  detections without changing the firewall.
- Dedicated risk-score, block-decision, and detection-creation audit records.
- A read-only first-party overview showing configured mode, sensor/firewall
  health, evidence totals, detection totals, block totals, and recent parser
  errors.
- A detections page showing source context, counts, rate, score,
  classification, allowlist state, decision, and creation time.
- A pure dashboard data service that is tested without requiring a browser.
- The dashboard refuses to run as root and never imports or calls the firewall
  manager.

### Stage 6 — Guarded firewall response

- Strict iptables command construction using argument arrays and `shell=False`.
- Configurable absolute iptables path, command timeout, SSH port, and dedicated
  `SSH_SECURITY_APP` chain.
- Idempotent project-chain creation and idempotent TCP/22 jump creation from
  `INPUT`.
- Read-only firewall readiness inspection and project-chain rule listing.
- Exact duplicate checks, insertion, confirmation, deletion, and confirmation
  for source-specific TCP/22 DROP rules.
- No flush commands, policy changes, unrelated-chain mutation, shell command
  strings, or unvalidated source IPs.
- A block manager that independently revalidates eligibility, allowlisting,
  protected server addresses, active database blocks, and existing firewall
  rules.
- Confirmed temporary block storage, expiration calculation, IP-profile block
  history, block audits, and compensating firewall deletion if database
  activation fails.
- Automatic Response requires all Stage 4 safety gates, healthy collectors and
  database, a ready firewall manager, the chain and jump, Automatic Response
  Mode, and the explicit `--apply-response` CLI flag.
- Unit tests use an in-memory iptables runner. Integration tests prove the
  Automatic Response pipeline without changing the host firewall.

### Stage 7 — Block removal and reconciliation

- A dashboard/CLI request service that validates an active block and inserts
  only a `Pending` SQLite manual-unblock request.
- A separate response worker that revalidates the request, source, block, and
  exact project rule before removal.
- Automatic expiration cycles that confirm/delete exact rules, store
  `Expired`, `removed_at`, and `Automatic`, and leave failures active for retry.
- Startup reconciliation for consistent active state, expired state, missing
  rules, and unknown project-chain rules.
- Unknown rules are audited and never automatically deleted.
- A recovery helper that removes recognized exact project rules, the exact
  TCP/SSH jump, and the empty chain; it refuses unknown or duplicate rules.

### Stage 8 — Final dashboard, services, tests, and documentation

- Dashboard pages for overview, detections, firewall-block lifecycle,
  allowlist management/history, security audit/action history, and health.
- Active-block countdowns plus retained removed-block rows that clearly show
  when and how the rule was removed.
- Exact, copyable iptables rule text for the project-chain jump and each
  offending source's DROP rule; the dashboard derives this from validated
  configuration and stored block data without gaining firewall privileges.
- Selectable source IPs with an owned detail drawer for locally stored profile,
  risk, detection, block, authentication, and network evidence.
- Project-owned responsive HTML, CSS, and JavaScript served by Python's standard
  library; no Streamlit, pandas, CDN, or external dashboard runtime.
- Same-origin JSON endpoints with CSRF protection, request-size limits,
  restrictive response headers, and no direct firewall API.
- The dashboard remains a normal-user process and has no firewall execution
  path.
- A controller that starts collectors, periodic correlation, startup
  reconciliation, expiration, and action-request processing; handles signals;
  stops subprocesses; and records health.
- Hardened main-application and dashboard systemd unit templates.
- Automated expiration, retry, manual-unblock, reconciliation, cleanup,
  dashboard, and shutdown tests.
- Architecture, database, testing, recovery, setup, live-validation, and
  troubleshooting documentation.


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
          +----------------------+----------------------+
          |                      |                      |
          v                      v                      v
  Simulation: WOULD_BLOCK  Log Only: store/log  Automatic Response
          |                      |                      |
          |                      |                      v
          |                      |              all safety gates
          |                      |                      |
          |                      |                      v
          |                      |         SSH_SECURITY_APP exact rule
          |                      |                      |
          +----------------------+----------------------+
                                 |
                                 v
             detections + evidence links + audit + IP profile
                                 |
                  +--------------+--------------+
                  |                             |
                  v                             v
       unprivileged Stage 8 dashboard   response worker
           SQLite manual request        expiration/reconciliation
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
├── docs/
│   ├── architecture.md
│   ├── database.md
│   ├── recovery.md
│   └── testing.md
├── data/
│   └── .gitkeep
├── logs/
│   └── .gitkeep
├── scripts/
│   ├── cleanup_firewall.py
│   ├── initialize_database.py
│   ├── initialize_firewall.py
│   ├── run_auth_collector.py
│   ├── run_dashboard.py
│   ├── run_detection.py
│   ├── run_network_collector.py
│   ├── setup_live_lab.py
│   └── setup_test_environment.py
├── systemd/
│   ├── ssh-security-app-firewall.service
│   ├── ssh-security-app-tmpfiles.conf
│   ├── ssh-security-app.service
│   └── ssh-security-app-dashboard.service
├── src/ssh_security_app/
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
│   │   ├── modes.py
│   │   ├── normalization.py
│   │   └── risk_score.py
│   ├── db/
│   │   ├── database.py
│   │   ├── repositories.py
│   │   └── schema.sql
│   ├── response/
│   │   ├── action_request_worker.py
│   │   ├── block_manager.py
│   │   ├── expiration_worker.py
│   │   ├── firewall_manager.py
│   │   ├── reconciliation.py
│   │   ├── response_worker.py
│   │   └── rules.py
│   └── ui/
│       ├── action_requests.py
│       ├── dashboard.py
│       ├── dashboard_data.py
│       └── static/
│           ├── app.css
│           ├── app.js
│           └── index.html
└── tests/
    ├── fixtures/
    ├── integration/
    └── unit/
```

## Get Started - Guide


### 1. Understand the two machines

This project uses two virtual machines on an isolated lab network:

| Role | Operating system | Interface | IPv4 address | Purpose |
|---|---|---|---|---|
| Security VM | **Ubuntu 20.04 LTS** | `ens37` | `192.168.12.1/24` | Runs OpenSSH, detection, SQLite, dashboard, and iptables response |
| Attacker VM | **Kali Linux** | `eth0` | `192.168.12.3/24` | Generates authorized failed SSH logins |

The dashboard URL is `http://192.168.12.1:8501` and the SSH service listens at
`192.168.12.1:22`. The temporary block lasts 120 seconds by default.

The names `ens37` and `eth0` are not universal. A hypervisor or Linux
installation may call them `ens33`, `enp0s8`, or something similar.


### 2. Create and connect the virtual machines

Create the following VMs in VMware:

- Ubuntu 20.04 LTS with at least 2 virtual CPUs, 4 GB RAM, and 20 GB disk.
- Kali Linux with at least 2 virtual CPUs, 2 GB RAM, and 20 GB disk.
- One isolated/host-only virtual network shared by both VMs.
- An *optional separate NAT adapter for software downloads if needed.
- An *optional Windows 10 machine as a client for brute-force detection and response evaluation.

Configure the isolated adapters so Ubuntu uses `192.168.12.1/24` and Kali uses
`192.168.12.3/24`. Leave the gateway empty on an isolated adapter. If the
addresses are already supplied by the lab or hypervisor, do not change them.

Take a snapshot of both VMs before changing firewall configuration in case something does not function as intended.

### 3. Verify the isolated network

On the **Ubuntu 20.04 security VM**, open a terminal and run:

```bash
hostname
ip -br -4 address
ip route
```

Confirm that the output contains:

```text
ens37    UP    192.168.12.1/24
```

On the **Kali attacker VM**, run:

```bash
hostname
ip -br -4 address
ip route
```

Confirm that the output contains:

```text
eth0    UP    192.168.12.3/24
```

Test basic connectivity from Kali:

```bash
ping -c 4 192.168.12.1
```

If this fails, stop here and correct the virtual adapters, interface names, IP
addresses, and subnet masks. Both addresses must be unique and inside
`192.168.12.0/24`.

If Ubuntu's isolated interface does not yet have an address, create a narrow
Netplan file on **Ubuntu 20.04**:

```bash
sudo nano /etc/netplan/99-ssh-security-lab.yaml
```

Enter the following, replacing `ens37` only if Ubuntu reported a different lab
interface:

```yaml
network:
  version: 2
  ethernets:
    ens37:
      dhcp4: false
      addresses:
        - 192.168.12.1/24
```

Save with `Ctrl+O`, press `Enter`, exit with `Ctrl+X`, and validate:

```bash
sudo netplan generate
sudo netplan try
```

Confirm the proposed configuration when prompted, then verify:

```bash
ip -br -4 address show ens37
```

If Kali's isolated `eth0` does not yet have an address, use NetworkManager on
**Kali**:

```bash
nmcli device status
sudo nmcli connection add \
  type ethernet \
  con-name ssh-security-lab \
  ifname eth0 \
  ipv4.method manual \
  ipv4.addresses 192.168.12.3/24 \
  ipv4.never-default yes \
  ipv6.method disabled
sudo nmcli connection up ssh-security-lab
ip -br -4 address show eth0
```

Run those configuration commands only on the isolated lab adapters. If a
profile named `ssh-security-lab` already exists, inspect it instead of adding a
duplicate:

```bash
nmcli connection show ssh-security-lab
```

### 4. Prepare Ubuntu 20.04

Run these commands on the **Ubuntu security VM**:

```bash
sudo apt update
sudo apt install -y git ca-certificates
```

When `sudo` asks for a password, type the Ubuntu user's password and press
`Enter`. Linux does not display dots or asterisks while a sudo password is
being typed; this is normal.

Create a workspace, clone the final `main` branch, and enter the project:

```bash
mkdir -p "$HOME/Documents"
cd "$HOME/Documents"
git clone --branch main --single-branch \
  https://github.com/samatarmrsl/SSH-Security-Application.git
cd SSH-Security-Application
git status
git branch --show-current
```

Expected branch:

```text
main
```

If the repository already exists, update it without overwriting local work:

```bash
cd "$HOME/Documents/SSH-Security-Application"
git status
git fetch origin
git switch main
git pull --ff-only origin main
```

Do not pull over files reported as locally modified. Back up, commit, or stash
your own changes first.

### 5. Understand the firewall choice

The application uses **iptables**, not firewalld or SSHGuard, to block an
offending source. It creates only the dedicated `SSH_SECURITY_APP` chain, an
SSH-port jump from `INPUT`, and exact source-specific DROP rules.

Check optional firewall frontends:

```bash
systemctl is-active firewalld.service || true
systemctl is-enabled firewalld.service || true
sudo ufw status
```

On this isolated teaching lab, firewalld is intentionally stopped to prevent it
from reconstructing iptables rules during the demonstration:

```bash
sudo systemctl disable --now firewalld.service
```

If Ubuntu says the unit does not exist, firewalld is not installed and no
action is required. Confirm the resulting state:

```bash
systemctl is-active firewalld.service || true
systemctl is-enabled firewalld.service || true
```

Expected output is `inactive` and `disabled`. Notice that a service can be
*disabled* at boot but still *active* right now; `disable --now` handles both.

UFW may remain active because the installer can add source-limited lab access
rules. On this specific isolated VM it is currently disabled. Do not disable a
host firewall on an Internet-facing or production system merely to follow this
tutorial.

### 6. Preview the automated installation

The installer works with the operating-system `python3`; a virtual environment
does not need to be created manually. First run its read-only preview:

```bash
cd "$HOME/Documents/SSH-Security-Application"
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3
```

The arguments mean:

- `--lab-interface ens37`: capture TCP/22 metadata on Ubuntu's isolated
  interface.
- `--server-ip 192.168.12.1`: protect and serve the Ubuntu lab address.
- `--client-ip 192.168.12.3`: allow only this disposable Kali address to be
  used as the controlled test source.
- no `--apply`: print the plan without changing the VM.

The important preview lines should resemble:

```text
server IPv4: 192.168.12.1
disposable client IPv4: 192.168.12.3
SSH endpoint: 192.168.12.1:22
dashboard: http://192.168.12.1:8501
response mode: automatic_response
block duration: 120 seconds
project chain: SSH_SECURITY_APP
```

Do not continue if the interface or addresses are wrong.

### 7. Install the complete security application

Apply the plan from the Ubuntu project directory:

```bash
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --apply \
  --confirm-firewall-changes
```

The explicit firewall confirmation is required because the script creates the
project-owned iptables chain. The installer then:

1. Installs Python, OpenSSH, SQLite, tcpdump, iptables, and supporting packages.
2. Enables and starts the detected OpenSSH service.
3. Grants tcpdump only the packet-capture capabilities it requires.
4. Creates the unprivileged `sshsecurityapp` service account.
5. Copies the application to `/opt/ssh-security-application`.
6. Writes production configuration to `/etc/ssh-security-app/config.json`.
7. Creates or upgrades `/var/lib/ssh-security-app/ssh_security_app.db`.
8. Installs and starts the firewall, detector/response, and dashboard services.
9. Creates and verifies `SSH_SECURITY_APP` without flushing `INPUT`.
10. Verifies the dashboard and SSH listener.

The script does not run Hydra and does not generate attack traffic.

When packages are already installed, a later code redeployment can skip only
the apt step:

```bash
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --skip-package-install \
  --apply \
  --confirm-firewall-changes
```

### 8. Verify Ubuntu before using Kali

Run the installer verifier:

```bash
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --verify-only
```

Every reported item should say `PASS`. Then inspect the services:

```bash
systemctl status ssh.service --no-pager
systemctl status ssh-security-app-firewall.service --no-pager
systemctl status ssh-security-app.service --no-pager
systemctl status ssh-security-app-dashboard.service --no-pager
```

Press `q` if a status command opens a pager. Verify listeners:

```bash
ss -lnt | grep -E ':22|:8501'
```

Inspect the dedicated firewall state:

```bash
sudo iptables -S SSH_SECURITY_APP
sudo iptables -L SSH_SECURITY_APP -n -v --line-numbers
sudo iptables -L INPUT -n -v --line-numbers
```

Before the attack, the project chain should exist but should not contain a DROP
rule for `192.168.12.3`.

Open the dashboard on Ubuntu or another authorized lab workstation:

```text
http://192.168.12.1:8501
```

Use `Ctrl+Shift+R` for a hard refresh if an older dashboard was previously
loaded.

### 9. Prepare the Kali attacker VM

Run only on **Kali**:

```bash
sudo apt update
sudo apt install -y hydra netcat-openbsd openssh-client
mkdir -p "$HOME/ssh-security-demo"
cd "$HOME/ssh-security-demo"
```

Confirm that Ubuntu SSH is reachable before starting the controlled test:

```bash
nc -vz -w 5 192.168.12.1 22
```

Expected result:

```text
Connection to 192.168.12.1 22 port [tcp/ssh] succeeded!
```

Do not run Hydra if this initial connection test fails. A pre-test timeout is a
network or service problem, not successful brute-force blocking.

Create lab-only username and password candidate files:

```bash
printf '%s\n' \
demo_admin \
demo_backup \
demo_database \
demo_operator \
demo_service \
demo_support > usernames.txt

printf '%s\n' \
WrongPassword1 \
WrongPassword2 \
WrongPassword3 \
WrongPassword4 \
WrongPassword5 > passwords.txt
```

These are deliberately fake values. Never put a real password in the test
files.

### 10. Open the Ubuntu monitoring views

Before launching Hydra, open three Ubuntu terminals.

In Ubuntu terminal 1, follow application activity:

```bash
journalctl -u ssh-security-app.service -f
```

In Ubuntu terminal 2, watch only the project chain:

```bash
sudo watch -n 1 'iptables -S SSH_SECURITY_APP'
```

In a browser, open:

```text
http://192.168.12.1:8501
```

Stop either terminal view later with `Ctrl+C`.

### 11. Run the authorized Kali demonstration

From `~/ssh-security-demo` on Kali:

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

Hydra begins failed SSH logins. Once the application detects enough
corroborated activity, Ubuntu inserts this source-specific rule:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp -m tcp --dport 22 -j DROP
```

Hydra will then report timeouts because the temporary block is working. That is
the expected end of this controlled test.

On Ubuntu, confirm the rule independently:

```bash
sudo iptables -C SSH_SECURITY_APP \
  -s 192.168.12.3 \
  -p tcp \
  --dport 22 \
  -j DROP
echo "iptables check status=$?"
```

Status `0` means the exact rule exists. Display the complete chain:

```bash
sudo iptables -S SSH_SECURITY_APP
sudo iptables -L SSH_SECURITY_APP -n -v --line-numbers
```

In the dashboard:

1. Open **Detections** and confirm `192.168.12.3` is High Risk with decision
   `BLOCK`.
2. Open **Firewall Blocks** and confirm the active 120-second countdown.
3. Confirm the exact `INPUT` jump and source-specific DROP rule are displayed.
4. Select `192.168.12.3` to view its stored evidence and risk breakdown.

### 12. Confirm automatic removal

Wait approximately two minutes. The response worker checks expiration every
ten seconds, so removal can occur a few seconds after the displayed countdown
reaches zero.

On Ubuntu:

```bash
sudo iptables -C SSH_SECURITY_APP \
  -s 192.168.12.3 \
  -p tcp \
  --dport 22 \
  -j DROP
echo "iptables check status=$?"
```

Status `1` now means the exact rule is absent. The dashboard's active card
should disappear, while block history should retain:

```text
Status: Expired
Removal method: Automatic
Outcome: Temporary rule removed automatically
```

The exact original DROP rule remains visible for demonstration and audit
purposes.

From Kali, confirm SSH is reachable again:

```bash
nc -vz -w 5 192.168.12.1 22
```

### 13. Inspect stored results

Run on Ubuntu:

```bash
sudo -u sshsecurityapp \
  /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  inspect detections \
  --limit 10
```

Inspect current active blocks:

```bash
sudo -u sshsecurityapp \
  /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  inspect active-blocks
```

After automatic expiration, the second command should return an empty list.
Historical results remain in SQLite and on the dashboard.

### 14. Restart or shut down cleanly

The installed services start automatically on future Ubuntu boots. Verify them
after a restart with:

```bash
systemctl status ssh-security-app-firewall.service --no-pager
systemctl status ssh-security-app.service --no-pager
systemctl status ssh-security-app-dashboard.service --no-pager
```

For an orderly lab shutdown:

```bash
sudo systemctl stop ssh-security-app-dashboard.service
sudo systemctl stop ssh-security-app.service
sudo systemctl stop ssh-security-app-firewall.service
```

Stopping the firewall service removes only recognized project-owned rules. It
does not flush `INPUT` or change the host's default policy.

## Alternative setup and installer reference

The documented security VM uses Ubuntu 20.04 LTS and Python 3.8. These
alternative/manual commands also work on many newer Ubuntu releases. Run each
command in order. Commands beginning with `sudo` change host configuration and
should be run manually only on the authorized lab VM.

### Recommended one-command live-lab installation

`scripts/setup_live_lab.py` replaces the manual production-installation
sequence with one idempotent entry point. It runs directly with the operating
system's `python3`; an activated development virtual environment is not
required. The default invocation is a read-only preview.

For the current authorized lab:

```text
Security VM: ens37 / 192.168.12.1
Kali VM:     eth0  / 192.168.12.3
Dashboard:         http://192.168.12.1:8501/
SSH:               192.168.12.1:22
```

Preview everything that will be configured:

```bash
cd /home/et-1/Documents/SSH-Security-Application
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --client-ip 192.168.12.3
```

The server address is selected automatically when `ens37` has exactly one IPv4
address. To require an exact match explicitly, add
`--server-ip 192.168.12.1`.

Apply the complete installation:

```bash
cd /home/et-1/Documents/SSH-Security-Application
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --apply \
  --confirm-firewall-changes
```

The script asks for sudo once and then:

- validates the interface, server address, disposable-client address, subnet,
  repository assets, and protected server addresses;
- installs the Ubuntu packages, starts OpenSSH, and grants only tcpdump's
  required capture capabilities;
- detects the host firewall correctly, including the Ubuntu case where
  `ufw.service` is active but `/etc/ufw/ufw.conf` says `ENABLED=no`;
- when firewalld is active, adds permanent rich rules limited to
  `192.168.12.3 -> 192.168.12.1` on TCP ports 22 and 8501; when UFW is actually
  enabled, adds equivalent interface/source/destination-limited rules;
- creates the unprivileged `sshsecurityapp` account and protected `/opt`,
  `/etc`, `/var/lib`, and `/var/log` paths;
- copies the current source, creates the production virtual environment, and
  installs the first-party application and dashboard;
- backs up an existing production configuration, writes a validated Automatic
  Response configuration, and initializes or upgrades the SQLite database;
- safely removes recognized stale project rules without flushing INPUT or
  changing its default policy;
- installs a capability-limited oneshot firewall service that recreates the
  dedicated `SSH_SECURITY_APP` chain at boot and cleans it during an orderly
  stop;
- installs, enables, and starts the firewall initializer, combined detector and
  response service, and unprivileged first-party dashboard;
- verifies the configuration, all services, dedicated chain and INPUT jump,
  absence of a pre-existing block for the disposable client, SSH listener, and
  dashboard JSON API.

It does not generate failed logins or launch Hydra. Kali remains separate until
the infrastructure checks pass.

After installation, run the complete verifier at any time:

```bash
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --verify-only
```

If the packages are already installed and the package repositories are
temporarily unavailable, a deliberate reinstall can skip only the apt step:

```bash
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --skip-package-install \
  --apply \
  --confirm-firewall-changes
```

The firewall frontend must not be reloaded casually during a running
demonstration because firewalld may reconstruct its iptables state. If a
deliberate firewalld reload occurs, restore and verify the project chain with:

```bash
sudo systemctl restart ssh-security-app-firewall.service
sudo systemctl restart ssh-security-app.service
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --verify-only
```

For an orderly shutdown that removes recognized project-owned rules:

```bash
sudo systemctl stop ssh-security-app-dashboard.service
sudo systemctl stop ssh-security-app.service
sudo systemctl stop ssh-security-app-firewall.service
```

The longer manual installation below remains available for learning,
troubleshooting, and environments that intentionally use Simulation or Log
Only Mode.

### Automated test-environment preparation

After cloning the repository and creating/activating `.venv`, the guarded setup
helper automates the four immediate test prerequisites:

- detects `ssh.service` or `sshd.service`, installing `openssh-server` first
  when neither exists, then enables and starts the detected unit;
- installs the current project into the active virtual environment so the
  renamed command and first-party dashboard assets are available;
- grants `cap_net_raw,cap_net_admin` only to the resolved `tcpdump` executable;
- creates a protected Simulation Mode `config/local.json`, validates it, and
  initializes its test database.

It must run as the normal project user. It asks for sudo once for an optional
`apt-get` OpenSSH installation, systemd activation, and `setcap`; it never runs
Python, the collectors, or the dashboard as root. The lab interface is
mandatory so the script cannot guess between multiple active interfaces.

Preview the detected plan without changing anything:

```bash
cd /home/et-1/Documents/SSH-Security-Application
source .venv/bin/activate
python -m pip install -e .
python scripts/setup_test_environment.py --lab-interface ens37
```

For this VM, the preview should identify `ens37`, `/usr/sbin/tcpdump`,
`/usr/sbin/iptables`, and protected server addresses `192.168.13.128` and
`192.168.12.1`.

Apply the plan:

```bash
python scripts/setup_test_environment.py \
  --lab-interface ens37 \
  --apply
```

The generated test configuration uses
`data/ssh_security_app_test.db`, `logs/ssh_security_app_test.log`, a
120-second block duration, and a 10-second expiration check. Commands using
`--config config/local.json` automatically use those paths. If you run one of
the direct SQLite examples later in this README, substitute the database path
shown in your own `config/local.json`; the `inspect` command avoids that
problem.

The command is idempotent: it preserves an existing `config/local.json`. To
deliberately replace one, it first makes
`config/local.json.before-test-setup` and requires:

```bash
python scripts/setup_test_environment.py \
  --lab-interface ens37 \
  --overwrite-config \
  --apply
```

Do not use `--overwrite-config` unless you have reviewed the existing local
configuration and the backup path does not already exist.

### 1. Update package information

```bash
sudo apt update
```

### 2. Install operating-system prerequisites

```bash
sudo apt install -y git python3 python3-venv python3-pip openssh-server
sudo apt install -y sqlite3 tcpdump libcap2-bin iptables
```

### 3. Verify the installed tools

```bash
python3 --version
git --version
sqlite3 --version
tcpdump --version
iptables --version
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

### 5. Clone the repository and select `main`

For a new clone:

```bash
cd "$HOME"
git clone https://github.com/samatarmrsl/SSH-Security-Application.git
cd SSH-Security-Application
git fetch origin
git switch main
git pull --ff-only origin main
```

For an existing clone:

```bash
cd "$HOME/SSH-Security-Application"
git status
git fetch origin
git switch main
git pull --ff-only origin main
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

The first-party dashboard is included in the base application; it has no
separate runtime packages to install.

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
- `response.iptables_path` if `command -v iptables` is not
  `/usr/sbin/iptables`.
- `response.mode` to `simulation` for the safe demonstration.

Save with `Ctrl+O`, press `Enter`, and exit nano with `Ctrl+X`.

Check the JSON and application-level validation:

```bash
python -m json.tool config/local.json
ssh-security-app --config config/local.json validate-config
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
ssh-security-app --config config/local.json init-db
```

Equivalent script:

```bash
python scripts/initialize_database.py --config config/local.json
```

Expected output:

```text
Database initialized: data/ssh_security_app.db
```

Verify the database:

```bash
ls -lh data/ssh_security_app.db
sqlite3 data/ssh_security_app.db ".tables"
sqlite3 data/ssh_security_app.db "PRAGMA journal_mode;"
```

Initialization is idempotent and migrates an earlier-stage database without deleting
its evidence.

## Safe fixture demonstration

Fixture mode never invokes `journalctl` or `tcpdump` and never changes the
firewall. Start from the initialized database above.

### 1. Ingest ten sanitized failed authentications

```bash
ssh-security-app --config config/local.json collect-auth --fixture tests/fixtures/auth_bruteforce.log
```

### 2. Ingest the matching sanitized TCP/22 records

```bash
ssh-security-app --config config/local.json collect-network --fixture tests/fixtures/network_bruteforce.log
```

### 3. Run correlation at the fixture's fixed window end

```bash
ssh-security-app --config config/local.json detect --source-ip 192.168.56.40 --window-end "2026-07-24T08:25:00+00:00"
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
ssh-security-app --config config/local.json detect --all --window-end "2026-07-24T08:25:00+00:00"
```

Replaying the same fixtures or detection window is safely ignored by the stable
evidence and detection fingerprints.

### Additional parser fixtures

```bash
ssh-security-app --config config/local.json collect-auth --fixture tests/fixtures/auth_normal.log
ssh-security-app --config config/local.json collect-auth --fixture tests/fixtures/auth_invalid_users.log
ssh-security-app --config config/local.json collect-auth --fixture tests/fixtures/auth_malformed.log
ssh-security-app --config config/local.json collect-network --fixture tests/fixtures/network_normal.log
ssh-security-app --config config/local.json collect-network --fixture tests/fixtures/network_malformed.log
```

Equivalent helper scripts:

```bash
python scripts/run_auth_collector.py --config config/local.json --fixture tests/fixtures/auth_normal.log
python scripts/run_network_collector.py --config config/local.json --fixture tests/fixtures/network_normal.log
python scripts/run_detection.py --config config/local.json --source-ip 192.168.56.40 --window-end "2026-07-24T08:25:00+00:00"
```

## Stage 5 operating modes

Show the configured mode and persist it as the active mode:

```bash
ssh-security-app --config config/local.json mode-status
```

To use Log Only Mode, edit the local configuration:

```bash
nano config/local.json
```

Set:

```json
"mode": "log_only"
```

Then validate and activate it:

```bash
python -m json.tool config/local.json
ssh-security-app --config config/local.json validate-config
ssh-security-app --config config/local.json mode-status
```

Mode transitions are written to `application_state` and `audit_log`. Log Only
Mode continues collection, correlation, scoring, storage, audit, and dashboard
display, but its decision is `LOG_DETECTION` and it never invokes iptables.

Return to the safe default by setting `"mode": "simulation"` and running:

```bash
ssh-security-app --config config/local.json validate-config
ssh-security-app --config config/local.json mode-status
```

## Stage 8 dashboard

The dashboard is implemented in this repository using Python's standard
library plus owned HTML, CSS, and JavaScript. It has no Streamlit, pandas, CDN,
or third-party dashboard dependency. Install the current source and launch it
as the normal application user:

```bash
python -m pip install -e .
python scripts/run_dashboard.py --config config/local.json
```

Open the configured lab-only URL from an authorized workstation. With the
example configuration:

```text
http://192.168.56.10:8501
```

Stop it with `Ctrl+C`. Never launch the dashboard with `sudo`; the launcher
refuses to run as root. The interface refreshes every five seconds and includes
Overview, Detections, Firewall Blocks, Allowlist, Audit Trail, and System
Health. Firewall Blocks shows both active countdowns and retained lifecycle
history. An expired or manually removed row includes its removal time, method,
firewall result, and a plain-language status. Select a source IP in a detection
or block view to open its detail drawer with:

- first/last seen times and cumulative local counters;
- current allowlist and block status;
- the latest stored score, classification, decision reason, and risk
  breakdown;
- detection and block history;
- sanitized authentication evidence and TCP/22 metadata.

Each active block card also shows the exact `iptables -S`-style rules involved:
the TCP/22 jump from `INPUT` into the dedicated project chain and the
source-specific DROP rule. The DROP rule remains visible in block history and
the IP detail drawer after its removal. This is a display of validated
configuration and stored state; the dashboard never executes `iptables`.

The IP detail view uses only the application's SQLite evidence. It makes no
external reputation or geolocation request and never exposes captured
passwords, payloads, or raw journal messages.

The dashboard can update the allowlist and queue manual-unblock requests in
SQLite, but it has no firewall execution path. The separate response worker
performs every firewall validation and mutation.

## Stage 6 firewall response

The default Simulation Mode performs no firewall command. Stage 6 firewall
mutation requires all of the following:

- `response.mode` is exactly `automatic_response`;
- the explicit firewall confirmation or response flag is present;
- the iptables executable is healthy;
- `SSH_SECURITY_APP` and its TCP/22 `INPUT` jump exist;
- authentication sensor, network sensor, and SQLite health checks pass;
- the source is validated, eligible, not protected, not allowlisted, not
  already blocked, and has matching network evidence;
- at least ten failures and a score of at least 70 exist in the five-minute
  window.

### Read-only firewall inspection

Confirm the configured executable:

```bash
command -v iptables
python -m json.tool config/local.json
```

Run the application inspection:

```bash
ssh-security-app --config config/local.json firewall-status
```

If the normal account lacks permission to inspect iptables, do not give the
dashboard firewall capabilities. Use the capability-limited systemd service
described below, or run only this narrow lab inspection with privilege:

```bash
sudo "$(pwd)/.venv/bin/ssh-security-app" --config "$(pwd)/config/local.json" firewall-status
```

### Deliberate dedicated-chain initialization

First make a recoverable snapshot:

```bash
mkdir -p backups
sudo iptables-save > backups/iptables.before-ssh-security-app.rules
```

Edit `config/local.json`, change the mode to `automatic_response`, validate it,
and activate the audited mode:

```bash
nano config/local.json
python -m json.tool config/local.json
ssh-security-app --config config/local.json validate-config
ssh-security-app --config config/local.json mode-status
```

The initialization command refuses to mutate the firewall without the explicit
confirmation flag:

```bash
sudo "$(pwd)/.venv/bin/ssh-security-app" --config "$(pwd)/config/local.json" firewall-init --confirm-firewall-changes
```

Equivalent helper:

```bash
sudo "$(pwd)/.venv/bin/python" scripts/initialize_firewall.py --config "$(pwd)/config/local.json" --confirm-firewall-changes
```

The command creates only `SSH_SECURITY_APP` when missing and adds only its
TCP/22 jump from `INPUT` when missing. It is idempotent. It never flushes a
chain, changes a policy, or edits an unrelated rule.

Inspect the result:

```bash
sudo iptables -S SSH_SECURITY_APP
sudo iptables -C INPUT -p tcp --dport 22 -j SSH_SECURITY_APP
```

### Deliberate Automatic Response detection

Only after the dedicated chain is ready:

```bash
sudo "$(pwd)/.venv/bin/ssh-security-app" --config "$(pwd)/config/local.json" detect --all --apply-response
```

Or:

```bash
sudo "$(pwd)/.venv/bin/python" scripts/run_detection.py --config "$(pwd)/config/local.json" --all --apply-response
```

Without `--apply-response`, Automatic Response Mode fails closed with
`SUPPRESS_FIREWALL_UNAVAILABLE`; it does not silently mutate the firewall.
Use privilege only for these narrowly scoped firewall-manager/detector
commands. Never run the dashboard or evidence collectors with `sudo`.

After a controlled test, inspect active database blocks and project
rules:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT block_id, source_ip, blocked_at, expires_at, status FROM blocks ORDER BY blocked_at DESC;"
sudo iptables -S SSH_SECURITY_APP
```

Run expiration/manual-request processing independently of the dashboard:

```bash
sudo "$(pwd)/.venv/bin/ssh-security-app" --config "$(pwd)/config/local.json" response-reconcile
sudo "$(pwd)/.venv/bin/ssh-security-app" --config "$(pwd)/config/local.json" response-worker
```

Stop the foreground worker with `Ctrl+C`. Never use `iptables -F`, never change
a default policy, and never remove rules outside `SSH_SECURITY_APP`.

## Live evidence collection

Use live commands only inside the authorized Ubuntu lab.

### Authentication: one-shot

```bash
ssh-security-app --config config/local.json collect-auth --once
```

With a custom lookback:

```bash
ssh-security-app --config config/local.json collect-auth --once --since "-15 minutes"
```

### Authentication: continuous

```bash
ssh-security-app --config config/local.json collect-auth --follow
```

### TCP/22 metadata: continuous

```bash
ssh-security-app --config config/local.json collect-network --follow
```

`collect-network` with no fixture also starts live continuous mode:

```bash
ssh-security-app --config config/local.json collect-network
```

Stop either continuous collector cleanly with `Ctrl+C`.

In normal operation, run both collectors in separate terminals. In each
terminal:

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
```

Then run the authentication command in one and the network command in the
other. For normal operation, use the combined `service` command or the systemd
units below.

### Generate one controlled lab event

On a separate authorized lab client:

```bash
SSH_SECURITY_APP_SERVER_IP=192.168.56.10
ssh ssh_security_app_test_user@"$SSH_SECURITY_APP_SERVER_IP"
```

Enter one deliberately incorrect test password, stop with `Ctrl+C`, and return
to the server. Do not test an account or host outside the authorized lab.

Run detection for current evidence:

```bash
ssh-security-app --config config/local.json detect --all
```

The default suspicious threshold is five failures in five minutes, so one
controlled failure should be stored but should not create a detection.

## Allowlist operations

Add a permanent authorized lab address:

```bash
ssh-security-app --config config/local.json allowlist-add 192.168.56.20 --description "Lab administrator workstation" --reason "Trusted management source" --created-by "$USER"
```

Add an entry that expires at a UTC-aware time:

```bash
ssh-security-app --config config/local.json allowlist-add 192.168.56.21 --description "Temporary lab scanner" --reason "Authorized exercise" --created-by "$USER" --expires-at "2026-07-25T18:00:00+00:00" --notes "Remove after the exercise"
```

List active entries:

```bash
ssh-security-app --config config/local.json allowlist-list
```

Copy the returned entry ID and disable it:

```bash
SSH_SECURITY_APP_ALLOWLIST_ID="paste-entry-id-here"
ssh-security-app --config config/local.json allowlist-disable "$SSH_SECURITY_APP_ALLOWLIST_ID"
```

Only validated IPv4 addresses are accepted. An allowlisted source is still
collected and scored; its response decision becomes `SUPPRESS_ALLOWLIST`.

## Manual unblock and recovery

List active blocks and copy the intended block ID and source IP:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT block_id,source_ip,expires_at,status FROM blocks WHERE status='Active' ORDER BY expires_at;"
```

Queue a request as the normal application user:

```bash
SSH_SECURITY_APP_BLOCK_ID="paste-block-id-here"
SSH_SECURITY_APP_SOURCE_IP="192.168.56.40"
ssh-security-app --config config/local.json manual-unblock-request \
  "$SSH_SECURITY_APP_BLOCK_ID" \
  "$SSH_SECURITY_APP_SOURCE_IP" \
  --reason "Authorized lab test complete"
```

The command writes SQLite only. The running response worker will validate and
process it. For a foreground test:

```bash
sudo "$(pwd)/.venv/bin/ssh-security-app" \
  --config "$(pwd)/config/local.json" \
  response-worker
```

Inspect the request and block results:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT request_id,source_ip,status,result_message FROM action_requests ORDER BY requested_at DESC;"
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT source_ip,status,removed_at,removal_method,error_message FROM blocks ORDER BY blocked_at DESC;"
```

To remove all recognized SSH Security Application state after a lab exercise:

```bash
sudo "$(pwd)/.venv/bin/python" scripts/cleanup_firewall.py \
  --config "$(pwd)/config/local.json" \
  --confirm-firewall-changes
```

Cleanup refuses to run if the project chain contains an unknown or duplicate
rule. See [docs/recovery.md](docs/recovery.md) before resolving any refusal.

## Managed systemd installation

The unit templates use `/opt/ssh-security-application` for code,
`/etc/ssh-security-app/config.json` for configuration, `/var/lib/ssh-security-app` for
SQLite, `/var/log/ssh-security-app` for logs, and the unprivileged `sshsecurityapp` account.
Run these commands from the repository root:

```bash
sudo apt update
sudo apt install -y rsync python3 python3-venv python3-pip
sudo useradd --system --home-dir /var/lib/ssh-security-app --shell /usr/sbin/nologin sshsecurityapp
sudo usermod -aG systemd-journal sshsecurityapp
sudo install -d -o root -g root -m 0755 /opt/ssh-security-application
sudo install -d -o root -g sshsecurityapp -m 0750 /etc/ssh-security-app
sudo install -d -o sshsecurityapp -g sshsecurityapp -m 0750 /var/lib/ssh-security-app
sudo install -d -o sshsecurityapp -g sshsecurityapp -m 0750 /var/log/ssh-security-app
sudo rsync -a --delete \
  --exclude '.git/' \
  --exclude '.venv/' \
  --exclude 'config/local.json' \
  --exclude 'data/' \
  --exclude 'logs/' \
  "$PWD/" /opt/ssh-security-application/
sudo python3 -m venv /opt/ssh-security-application/.venv
sudo /opt/ssh-security-application/.venv/bin/python -m pip install --upgrade pip
sudo /opt/ssh-security-application/.venv/bin/python -m pip install \
  -e /opt/ssh-security-application
sudo cp config/local.example.json /etc/ssh-security-app/config.json
sudo nano /etc/ssh-security-app/config.json
```

In `/etc/ssh-security-app/config.json`, set the real interface, protected server
addresses, SSH unit, dashboard address, and tool paths. Also set:

```json
{
  "database": {
    "path": "/var/lib/ssh-security-app/ssh_security_app.db"
  },
  "logging": {
    "path": "/var/log/ssh-security-app/ssh_security_app.log"
  }
}
```

Then validate permissions, configuration, units, and startup:

```bash
sudo chown root:sshsecurityapp /etc/ssh-security-app/config.json
sudo chmod 0640 /etc/ssh-security-app/config.json
sudo -u sshsecurityapp /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json validate-config
sudo cp systemd/ssh-security-app-firewall.service \
  /etc/systemd/system/ssh-security-app-firewall.service
sudo cp systemd/ssh-security-app.service /etc/systemd/system/ssh-security-app.service
sudo cp systemd/ssh-security-app-dashboard.service \
  /etc/systemd/system/ssh-security-app-dashboard.service
sudo cp systemd/ssh-security-app-tmpfiles.conf \
  /etc/tmpfiles.d/ssh-security-app.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/ssh-security-app.conf
ls -l /run/xtables.lock
sudo systemd-analyze verify /etc/systemd/system/ssh-security-app-firewall.service
sudo systemd-analyze verify /etc/systemd/system/ssh-security-app.service
sudo systemd-analyze verify /etc/systemd/system/ssh-security-app-dashboard.service
sudo systemctl daemon-reload
sudo systemctl enable ssh-security-app.service
sudo systemctl enable ssh-security-app-dashboard.service
sudo systemctl start ssh-security-app.service
sudo systemctl start ssh-security-app-dashboard.service
systemctl status ssh-security-app.service --no-pager
systemctl status ssh-security-app-dashboard.service --no-pager
```

Simulation and Log Only services need no firewall initialization. Before
starting Automatic Response, enable and start the capability-limited firewall
initializer before the main service:

```bash
sudo systemctl stop ssh-security-app.service
sudo systemctl enable --now ssh-security-app-firewall.service
sudo systemctl start ssh-security-app.service
```

Follow logs and stop/disable the services:

```bash
journalctl -u ssh-security-app-firewall.service -f
journalctl -u ssh-security-app.service -f
journalctl -u ssh-security-app-dashboard.service -f
sudo systemctl stop ssh-security-app-dashboard.service
sudo systemctl stop ssh-security-app.service
sudo systemctl stop ssh-security-app-firewall.service
sudo systemctl disable ssh-security-app-dashboard.service
sudo systemctl disable ssh-security-app.service
sudo systemctl disable ssh-security-app-firewall.service
```

## Full authorized-lab test

Use one server VM, one disposable client VM, and—if you administer the server
over SSH—a different trusted management client. Complete the managed systemd
installation above first.

### 1. Record addresses and protect management access

On the server:

```bash
ip -4 -br address
who -u
printf '%s\n' "$SSH_CONNECTION"
sudo ss -tnp | grep ':22'
```

On the disposable client:

```bash
ip -4 -br address
```

Set the addresses on the server:

```bash
SSH_SECURITY_APP_SERVER_IP="192.168.56.10"
SSH_SECURITY_APP_TEST_IP="192.168.56.40"
SSH_SECURITY_APP_ADMIN_IP="192.168.56.20"
printf 'server=%s test=%s admin=%s\n' \
  "$SSH_SECURITY_APP_SERVER_IP" "$SSH_SECURITY_APP_TEST_IP" "$SSH_SECURITY_APP_ADMIN_IP"
```

The test IP must not match the client address shown in `SSH_CONNECTION` or any
active management connection. Add the management client to the allowlist:

```bash
sudo -u sshsecurityapp /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  allowlist-add "$SSH_SECURITY_APP_ADMIN_IP" \
  --description "Lab management workstation" \
  --reason "Prevent management lockout during controlled test" \
  --created-by "$USER"
```

Edit and validate the local configuration:

```bash
sudo nano /etc/ssh-security-app/config.json
sudo python3 -m json.tool /etc/ssh-security-app/config.json
sudo -u sshsecurityapp /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  validate-config
```

Set `response.mode` to `automatic_response`,
`response.block_duration_seconds` to `120`,
`response.expiration_check_seconds` to `10`, and include the server's own
addresses in `network_sensor.protected_ipv4_addresses`.

### 2. Back up and initialize only the project chain

```bash
mkdir -p backups
sudo iptables-save > backups/iptables.before-full-test.rules
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  firewall-init \
  --confirm-firewall-changes
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  firewall-status
```

### 3. Start the complete application

Use the installed capability-limited service so collectors do not run as root:

```bash
sudo systemctl restart ssh-security-app.service
systemctl status ssh-security-app.service --no-pager
journalctl -u ssh-security-app.service -f
```

Start the separate unprivileged dashboard service:

```bash
sudo systemctl restart ssh-security-app-dashboard.service
systemctl status ssh-security-app-dashboard.service --no-pager
```

### 4. Generate controlled failures from the disposable client

On the disposable client only:

```bash
SSH_SECURITY_APP_SERVER_IP="192.168.56.10"
ssh -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  ssh_security_app_nonexistent@"$SSH_SECURITY_APP_SERVER_IP"
```

Enter a deliberately incorrect lab-only password at each prompt. Repeat the
command until the server records at least ten failures. Do not use a real
password or test from the management client.

### 5. Confirm collection, detection, and the exact block

On the server:

```bash
sudo -u sshsecurityapp /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  inspect detections \
  --limit 5
sudo -u sshsecurityapp /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  inspect active-blocks
sudo -u sshsecurityapp sqlite3 /var/lib/ssh-security-app/ssh_security_app.db \
  "SELECT COUNT(*) FROM auth_events WHERE source_ip='$SSH_SECURITY_APP_TEST_IP' AND success=0;"
sudo -u sshsecurityapp sqlite3 /var/lib/ssh-security-app/ssh_security_app.db \
  "SELECT COUNT(*) FROM network_events WHERE source_ip='$SSH_SECURITY_APP_TEST_IP' AND destination_port=22;"
sudo -u sshsecurityapp sqlite3 -header -column /var/lib/ssh-security-app/ssh_security_app.db \
  "SELECT source_ip,risk_score,classification,decision FROM detections WHERE source_ip='$SSH_SECURITY_APP_TEST_IP' ORDER BY created_at DESC LIMIT 1;"
sudo -u sshsecurityapp sqlite3 -header -column /var/lib/ssh-security-app/ssh_security_app.db \
  "SELECT block_id,source_ip,status,expires_at FROM blocks WHERE source_ip='$SSH_SECURITY_APP_TEST_IP' ORDER BY blocked_at DESC LIMIT 1;"
sudo iptables -C SSH_SECURITY_APP \
  -s "$SSH_SECURITY_APP_TEST_IP" \
  -p tcp \
  --dport 22 \
  -j DROP
sudo iptables -S SSH_SECURITY_APP
```

The detection should be `High Risk`/`BLOCK`, the database block should be
`Active`, and the exact check should return status 0.

Open `http://192.168.12.1:8501` from the authorized lab network. The new
detection should appear on Overview and Detections. Open Firewall Blocks to
confirm that `192.168.12.3` has an active countdown, then select the IP address.
Its detail drawer should show the stored score and risk breakdown, failed
authentication evidence, TCP/22 metadata, active block record, and exact DROP
rule:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp -m tcp --dport 22 -j DROP
```

### 6. Test manual removal or automatic expiration

While the block is active, retry once from the disposable client:

```bash
time ssh -o ConnectTimeout=5 \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  ssh_security_app_nonexistent@"$SSH_SECURITY_APP_SERVER_IP"
```

The connection should time out before an SSH password prompt. This confirms
that the exact temporary iptables rule is affecting only the disposable
source.

For manual removal, copy the active block ID, queue the request as the normal
user, and let the running response worker process it:

```bash
SSH_SECURITY_APP_BLOCK_ID="$(
  sudo -u sshsecurityapp sqlite3 /var/lib/ssh-security-app/ssh_security_app.db \
    "SELECT block_id FROM blocks WHERE source_ip='$SSH_SECURITY_APP_TEST_IP' AND status='Active' ORDER BY blocked_at DESC LIMIT 1;"
)"
sudo -u sshsecurityapp /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  manual-unblock-request \
  "$SSH_SECURITY_APP_BLOCK_ID" \
  "$SSH_SECURITY_APP_TEST_IP" \
  --reason "Controlled Stage 8 manual-unblock test"
```

Confirm the result:

```bash
sudo -u sshsecurityapp sqlite3 -header -column /var/lib/ssh-security-app/ssh_security_app.db \
  "SELECT source_ip,status,removed_at,removal_method FROM blocks WHERE block_id='$SSH_SECURITY_APP_BLOCK_ID';"
sudo iptables -C SSH_SECURITY_APP \
  -s "$SSH_SECURITY_APP_TEST_IP" \
  -p tcp \
  --dport 22 \
  -j DROP
```

For automatic expiration instead, do not queue the request. Wait longer than
the configured 120-second duration and run the same two checks. The block
should be `Expired` with removal method `Automatic`; the iptables check should
return status 1 because the exact rule is absent. You can watch the countdown
without writing SQL:

```bash
watch -n 5 'sudo -u sshsecurityapp \
  /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json inspect active-blocks'
```

Stop `watch` with `Ctrl+C`. After roughly two minutes, retry the client SSH
command. It should reach the password prompt again, confirming automatic
expiration and rule removal.

Return to Firewall Blocks or select Refresh data. The active card should be
gone, but the retained block-history row must now show `Expired`, the removal
time, `Automatic`, and `Temporary rule removed automatically`. Select
`192.168.12.3` again to confirm that the same completed lifecycle is retained
in its IP detail drawer.

### 7. Test restart reconciliation and cleanup

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  response-reconcile
sudo /opt/ssh-security-application/.venv/bin/python \
  /opt/ssh-security-application/scripts/cleanup_firewall.py \
  --config /etc/ssh-security-app/config.json \
  --confirm-firewall-changes
sudo iptables -S SSH_SECURITY_APP
sudo iptables -C INPUT \
  -p tcp \
  --dport 22 \
  -j SSH_SECURITY_APP
```

After cleanup, both inspection commands should return status 1 because the
project chain and its exact jump are absent. The backup remains available for
comparison; do not restore it wholesale over unrelated firewall changes.

## Inspect SQLite evidence and decisions

Prefer the application's schema-aware inspection command. It returns JSON and
does not require remembering physical SQLite column names:

```bash
ssh-security-app --config config/local.json inspect overview
ssh-security-app --config config/local.json inspect detections --limit 20
ssh-security-app --config config/local.json inspect active-blocks
ssh-security-app --config config/local.json inspect allowlist
ssh-security-app --config config/local.json inspect actions
ssh-security-app --config config/local.json inspect audit --limit 20
ssh-security-app --config config/local.json inspect health
```

The earlier `no such column: network_connection_count` error was caused by a
documentation query using the domain-model name. The physical column in
`detections` is `network_event_count`. The application inspection command maps
that value to the clearer JSON field `network_connections`.

Direct SQLite queries remain useful for detailed investigation:

Authentication events:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT event_time, source_ip, username, event_type, success FROM auth_events ORDER BY event_time DESC LIMIT 20;"
```

Network metadata:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT event_time, source_ip, destination_ip, destination_port, tcp_flags, interface_name FROM network_events ORDER BY event_time DESC LIMIT 20;"
```

Risk detections and decisions:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT window_end, source_ip, failed_count, network_event_count, risk_score, classification, decision FROM detections ORDER BY created_at DESC LIMIT 20;"
```

Linked evidence counts:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT detection_id, 'authentication' AS evidence_type, COUNT(*) AS evidence_count FROM detection_auth_events GROUP BY detection_id UNION ALL SELECT detection_id, 'network', COUNT(*) FROM detection_network_events GROUP BY detection_id ORDER BY detection_id, evidence_type;"
```

IP profiles:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT source_ip, ip_category, failed_count_total, successful_count_total, detection_count, last_seen FROM ip_profiles ORDER BY last_seen DESC;"
```

Blocks:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT block_id, source_ip, detection_id, blocked_at, expires_at, status, firewall_result FROM blocks ORDER BY blocked_at DESC;"
```

Persisted operating mode:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT state_key, state_value, updated_at FROM application_state ORDER BY state_key;"
```

Parser failures:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT event_time, sensor, error_message, raw_message FROM parser_errors ORDER BY event_time DESC LIMIT 20;"
```

Audit records:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT event_time, component, action, result, target FROM audit_log ORDER BY event_time DESC LIMIT 20;"
```

Component health:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT component, status, last_success, last_error, details FROM component_health ORDER BY component;"
```

Database health:

```bash
sqlite3 data/ssh_security_app.db "PRAGMA quick_check;"
sqlite3 data/ssh_security_app.db "PRAGMA journal_mode;"
```

## Configuration reference

`config/default.json` contains committed defaults. The ignored
`config/local.json` is recursively merged over them.

| Section | Important settings |
|---|---|
| `application` | Display name and environment |
| `detection` | Five-minute window, detection/blocking failure thresholds, high-risk score, and recent-success period |
| `response` | Mode, block duration, expiration interval, backend, dedicated chain, absolute iptables path, and command timeout |
| `authentication_sensor` | Enable flag, SSH unit, `journalctl` path, and lookback |
| `network_sensor` | Enable flag, interface, SSH port, `tcpdump` path, snapshot length, restart policy, and protected server IPv4 addresses |
| `database` | SQLite path, busy timeout, and WAL |
| `dashboard` | Lab-only first-party dashboard bind address and port |
| `logging` | Level, rotating JSON log path, size, and backups |

Valid response modes:

- `simulation`: creates and audits decisions such as `WOULD_BLOCK`; never
  changes the firewall.
- `log_only`: stores and logs detections; never changes the firewall.
- `automatic_response`: permits guarded response only after every safety gate
  and firewall readiness check passes. One-shot detection also requires
  `--apply-response`; the managed service is the explicit continuous response
  path.

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
python -m pytest --cov=ssh_security_app --cov-report=term-missing
ruff check .
ruff format --check .
python -m compileall -q src scripts
```

At completion of Stages 1–8, the suite contains 172 passing unit and integration
tests with 80% overall statement/branch coverage on Python 3.8. It covers safe
modes, all dashboard pages, exact firewall commands, idempotent chain/rule
handling, failure rollback, Automatic Response, expiration retry, manual
unblocking, reconciliation, safe cleanup, and managed shutdown.

## Logging

The default rotating JSON log is `logs/ssh_security_app.log`.

```bash
tail -f logs/ssh_security_app.log
```

## Troubleshooting

### Start here: collect a small diagnostic snapshot

Run these commands on Ubuntu before changing anything. They identify most
network, service, permission, and configuration problems:

```bash
date -Is
timedatectl status
ip -br -4 address
ip route
systemctl is-active ssh.service
systemctl is-active ssh-security-app-firewall.service
systemctl is-active ssh-security-app.service
systemctl is-active ssh-security-app-dashboard.service
sudo iptables -S SSH_SECURITY_APP
sudo iptables -L INPUT -n -v --line-numbers
```

Then run the application verifier from the repository:

```bash
cd "$HOME/Documents/SSH-Security-Application"
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --verify-only
```

Read the first `FAIL` line and use the matching subsection below. Avoid
flushing iptables, deleting the database, or running the complete application
as root as a first response.

### The setup script rejects the interface or server address

List active IPv4 interfaces:

```bash
ip -br -4 address
ip -j -4 address show up
```

The value passed to `--lab-interface` must be the interface that owns the
security VM's lab address. If Ubuntu shows:

```text
ens37    UP    192.168.12.1/24
```

use:

```bash
--lab-interface ens37 --server-ip 192.168.12.1
```

Do not copy `ens37` blindly if your VM uses a different name.

### The setup script says the client is outside the lab subnet

Compare both addresses and subnet masks:

```bash
# Ubuntu
ip -br -4 address show ens37

# Kali
ip -br -4 address show eth0
```

For this tutorial they must be `192.168.12.1/24` and
`192.168.12.3/24`. An address such as `192.168.13.3` is not in the same `/24`
subnet. Correct the virtual-network configuration instead of bypassing the
installer's validation.

### The setup script says the client is a protected server address

The value passed to `--client-ip` must belong to Kali, not Ubuntu. Recheck:

```bash
# Ubuntu
ip -br -4 address

# Kali
ip -br -4 address
```

Use `--server-ip 192.168.12.1 --client-ip 192.168.12.3`. The installer refuses
to block any address assigned to the security VM.

### Kali cannot ping Ubuntu

On both VMs, confirm the isolated adapter is connected in the hypervisor and
has the expected address:

```bash
ip -br -4 address
ip route
```

From Kali:

```bash
ip route get 192.168.12.1
ping -c 4 192.168.12.1
```

The selected route should use `eth0`, not a NAT or management interface. Verify
that both VM adapters are attached to the exact same host-only/internal network
and that the VMs do not share an IP address.

### Kali reaches Ubuntu, but TCP port 22 times out before testing

This is not an application block unless the source-specific DROP rule already
exists. On Ubuntu:

```bash
systemctl status ssh.service --no-pager
ss -lnt | sed -n '/:22/p'
sudo iptables -S SSH_SECURITY_APP
sudo ufw status
systemctl is-active firewalld.service || true
```

Start OpenSSH if necessary:

```bash
sudo systemctl enable --now ssh.service
```

If a stale project rule for the disposable client exists, first let its worker
expire it. For an authorized lab recovery, restart and verify the managed
services:

```bash
sudo systemctl restart ssh-security-app-firewall.service
sudo systemctl restart ssh-security-app.service
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --verify-only
```

Do not flush `INPUT`.

### Hydra times out immediately

Always establish the baseline from Kali before Hydra:

```bash
nc -vz -w 5 192.168.12.1 22
```

If this times out before any failed login is generated, troubleshoot the
network and SSH listener. If it succeeds initially and begins timing out only
after several failures, inspect Ubuntu:

```bash
sudo iptables -C SSH_SECURITY_APP \
  -s 192.168.12.3 \
  -p tcp \
  --dport 22 \
  -j DROP
echo "iptables check status=$?"
```

Status `0` means Hydra's timeout is expected because the application block is
active.

### Hydra finishes but no detection or block appears

Check the managed service and sensor health on Ubuntu:

```bash
systemctl status ssh-security-app.service --no-pager
journalctl -u ssh-security-app.service -n 150 --no-pager
sudo -u sshsecurityapp \
  /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  inspect health
```

Confirm the production mode:

```bash
sudo -u sshsecurityapp \
  /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  mode-status
```

The live installer should report `automatic_response`. Simulation Mode creates
`WOULD_BLOCK`, and Log Only Mode creates `LOG_DETECTION`; neither modifies
iptables. Also confirm that Kali is attacking `192.168.12.1`, not the security
VM's NAT or management address.

### The application services fail after installation

Inspect the exact failure rather than repeatedly reinstalling:

```bash
systemctl status ssh-security-app-firewall.service --no-pager
systemctl status ssh-security-app.service --no-pager
systemctl status ssh-security-app-dashboard.service --no-pager
journalctl -u ssh-security-app-firewall.service -n 100 --no-pager
journalctl -u ssh-security-app.service -n 150 --no-pager
journalctl -u ssh-security-app-dashboard.service -n 100 --no-pager
```

Validate the installed configuration as the service account:

```bash
sudo -u sshsecurityapp \
  /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  validate-config
```

If the repository was updated, rerun the idempotent installer with
`--skip-package-install` so `/opt` and the systemd services receive the new
source.

### Firewalld says `disabled`, but the installer still detects it

`disabled` controls the next boot; it does not necessarily stop the current
process. Check both values:

```bash
systemctl is-enabled firewalld.service || true
systemctl is-active firewalld.service || true
firewall-cmd --state 2>/dev/null || true
```

For this isolated iptables-only lab, stop it now and at future boots:

```bash
sudo systemctl disable --now firewalld.service
systemctl is-active firewalld.service || true
```

Expected state is `inactive`. Do not run `firewall-cmd --reload` during the
demonstration because firewalld can reconstruct iptables state.

### The dashboard shows an older layout or omits exact rules

First hard-refresh the browser with `Ctrl+Shift+R`. Then redeploy the current
repository source:

```bash
cd "$HOME/Documents/SSH-Security-Application"
git status
git pull --ff-only origin main
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --skip-package-install \
  --apply \
  --confirm-firewall-changes
```

Confirm that the owned JavaScript asset is reachable:

```bash
python3 - <<'PY'
import urllib.request

url = "http://192.168.12.1:8501/assets/app.js"
with urllib.request.urlopen(url, timeout=5) as response:
    body = response.read().decode("utf-8")
print(response.status, "SOURCE-SPECIFIC DROP" in body)
PY
```

Expected output is `200 True`.

### The dashboard and CLI appear to show different data

The development configuration and production services use different SQLite
files:

```text
Development: data/ssh_security_app_test.db or data/ssh_security_app.db
Production:  /var/lib/ssh-security-app/ssh_security_app.db
```

For live-lab results, use the installed command and configuration:

```bash
sudo -u sshsecurityapp \
  /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json \
  inspect detections \
  --limit 10
```

Running `.venv/bin/ssh-security-app --config config/local.json` queries the
development database instead.

### A two-minute block does not disappear exactly at 120 seconds

The block duration is 120 seconds and the expiration worker wakes every ten
seconds. A small delay after the countdown reaches zero is expected. Wait
another ten seconds, refresh the dashboard, and inspect:

```bash
systemctl status ssh-security-app.service --no-pager
journalctl -u ssh-security-app.service -n 100 --no-pager
sudo iptables -S SSH_SECURITY_APP
```

If the rule remains substantially longer, follow the later section titled
“A block reached its database expiration time but the rule remains.”

### Detections are inconsistent between the two VMs

Large clock differences can move events outside the five-minute correlation
window. Check both Ubuntu and Kali:

```bash
date -Is
timedatectl status
```

Enable network time synchronization on each VM:

```bash
sudo timedatectl set-ntp true
timedatectl status
```

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

### `ssh-security-app: command not found`

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
python -m pip install -e '.[dev]'
which ssh-security-app
```

Fallback invocation:

```bash
python -m ssh_security_app.main validate-config
```

### Configuration error or invalid JSON

```bash
python -m json.tool config/local.json
diff -u config/local.example.json config/local.json
ssh-security-app --config config/local.json validate-config
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
ssh-security-app --config config/local.json collect-auth --once --since "yesterday"
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

Do not solve this by running the whole application or dashboard as root.

### `tcpdump` reports that the interface does not exist

```bash
ip -br link
ip -br address
```

Copy the correct interface name into `network_sensor.interface`, then:

```bash
ssh-security-app --config config/local.json validate-config
ssh-security-app --config config/local.json collect-network --follow
```

### The network collector repeatedly restarts

Inspect sensor health and the application log:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT component, status, last_error, details FROM component_health WHERE component = 'network_sensor';"
tail -n 100 logs/ssh_security_app.log
```

Confirm the executable, capability, interface, and SSH port:

```bash
command -v tcpdump
getcap "$(command -v tcpdump)"
ip -br address
python -m json.tool config/local.json
```

### The dashboard module or assets are missing

```bash
cd "$HOME/SSH-Security-Application"
source .venv/bin/activate
python -m pip install -e .
python -c "from ssh_security_app.ui.dashboard import STATIC_DIRECTORY; print(STATIC_DIRECTORY)"
test -f src/ssh_security_app/ui/static/index.html
python scripts/run_dashboard.py --config config/local.json
```

### The dashboard is not reachable

Confirm the configured lab address exists on the server:

```bash
ip -br address
python -m json.tool config/local.json
ss -lnt | sed -n '/:8501/p'
```

Set `dashboard.host` to an address assigned to the lab VM, restart the
dashboard, and connect only from the authorized lab network. If
`dashboard.host` is `127.0.0.1`, it is intentionally reachable only from the
server itself. To reach it from the disposable lab client, use the server's
private lab-interface address and confirm the port is listening:

```bash
python scripts/run_dashboard.py --config config/local.json
curl -I "http://127.0.0.1:8501/"
```

### Dashboard startup reports `Address already in use`

Identify what owns the configured port:

```bash
ss -lntp '( sport = :8501 )'
ps -fp PASTE_PID_HERE
```

If it is an earlier project dashboard, stop it with `Ctrl+C` in the terminal
that launched it. Do not kill an unidentified process. Then run:

```bash
python scripts/run_dashboard.py --config config/local.json
```

### SQLite reports `no such column: network_connection_count`

Use the schema-aware command:

```bash
ssh-security-app --config config/local.json inspect detections --limit 20
```

If a raw SQL query is required, use the physical column
`network_event_count`; `network_connection_count` is the Python domain-model
attribute, not a SQLite column.

### Live-lab setup reports `--get-zone-of-interface ...: no zone`

An interface that has no explicit firewalld zone uses firewalld's configured
default zone. The setup script recognizes firewalld's status-2 `no zone`
response and safely falls back to that default without permanently reassigning
the interface. Inspect and preview the selection:

```bash
firewall-cmd --get-zone-of-interface ens37 || true
firewall-cmd --get-default-zone
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --skip-package-install
```

The preview should report `host firewall frontend: firewalld` and
`firewalld zone: public` on the documented lab VM. Do not manually reassign the
interface merely to work around this message.

### `iptables` is missing or the configured path is wrong

```bash
sudo apt update
sudo apt install -y iptables
command -v iptables
```

Update `response.iptables_path` to the absolute result and validate:

```bash
ssh-security-app --config config/local.json validate-config
```

### Firewall status reports that the project chain or jump is missing

First confirm the current mode and inspect the host state:

```bash
ssh-security-app --config config/local.json mode-status
sudo iptables -S SSH_SECURITY_APP
sudo iptables -C INPUT -p tcp --dport 22 -j SSH_SECURITY_APP
```

If this is a deliberate authorized lab validation, follow the dedicated
chain initialization procedure above. Do not create a similarly named chain by
hand and do not flush `INPUT`.

### Firewall initialization reports permission denied

The dashboard and collectors must remain unprivileged. For this narrow
initialization command only:

```bash
sudo "$(pwd)/.venv/bin/ssh-security-app" --config "$(pwd)/config/local.json" firewall-init --confirm-firewall-changes
```

If it still fails, inspect the stored health and audit reason:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT component, status, last_error, details FROM component_health WHERE component = 'firewall_manager';"
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT event_time, action, result, details FROM audit_log WHERE component = 'firewall_manager' ORDER BY event_time DESC LIMIT 10;"
```

### A block reached its database expiration time but the rule remains

The expiration worker leaves a block Active after a deletion failure so it can
retry safely. Inspect worker health, the stored error, and exact project state:

```bash
systemctl status ssh-security-app.service --no-pager
journalctl -u ssh-security-app.service -n 100 --no-pager
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT source_ip,status,expires_at,error_message FROM blocks WHERE status='Active' ORDER BY expires_at;"
sudo iptables -S SSH_SECURITY_APP
sudo "$(pwd)/.venv/bin/ssh-security-app" \
  --config "$(pwd)/config/local.json" \
  response-reconcile
```

Fix the reported permission/path/state problem and leave the worker running for
its next retry. Do not flush the chain or change a default policy.

### Evidence appears in `parser_errors`

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT event_time, sensor, error_message, raw_message FROM parser_errors ORDER BY event_time DESC LIMIT 20;"
```

Unsupported messages are deliberately quarantined. If a common format should be
supported, open an issue with a sanitized example. Never include passwords,
keys, or unauthorized public addresses.

### Detection says no new result was created

Check whether the threshold was met:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT source_ip, COUNT(*) AS failures FROM auth_events WHERE success = 0 GROUP BY source_ip;"
```

Check the evidence timestamps:

```bash
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT event_time, source_ip, event_type FROM auth_events ORDER BY event_time DESC LIMIT 20;"
```

The result is also expected when the source has fewer than five failures in the
window or when the identical evidence set was already analyzed.

### A high-risk result is suppressed instead of `WOULD_BLOCK`

Inspect the printed reason, health, and allowlist:

```bash
ssh-security-app --config config/local.json allowlist-list
sqlite3 -header -column data/ssh_security_app.db \
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
sqlite3 data/ssh_security_app.db "PRAGMA quick_check;"
```

Increase `database.busy_timeout_seconds` if a slow lab disk needs more time.

### SQLite reports a read-only database

```bash
ls -ld data
ls -l data/ssh_security_app.db
```

The database and parent directory must be writable by the normal application
account. Avoid creating the database with `sudo`.

### Start with an empty database without deleting evidence

Stop collectors, then:

```bash
mkdir -p backups
cp -a data/ssh_security_app.db backups/ssh_security_app.db.backup
mv data/ssh_security_app.db data/ssh_security_app.db.previous
ssh-security-app --config config/local.json init-db
```

The previous evidence remains recoverable in both paths.

### Tests cannot import `ssh_security_app`

```bash
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
```

## Security decisions currently enforced

- Simulation Mode is the default.
- Simulation and Log Only modes contain no firewall execution.
- Firewall mutation requires Automatic Response Mode and an explicit
  confirmation or response flag.
- External processes use argument arrays and `shell=False`.
- Live network capture is filtered to the configured TCP destination port.
- Snapshot length defaults to 96 bytes and only parsed metadata is stored.
- Parsers never inspect or infer passwords.
- IP validation uses Python's standard `ipaddress` module.
- IPv6 evidence may be stored but is ineligible for version 1 automatic action.
- Private IPv4 is eligible only because the intended environment is a
  controlled lab.
- Protected, allowlisted, special-purpose, or unhealthy cases fail safely.
- Firewall commands are limited to the dedicated project chain and its TCP/22
  jump. There is no flush or policy-changing command.
- The Stage 8 dashboard is unprivileged and has no firewall execution path; its
  manual-unblock action writes a validated SQLite request.
- Expiration and manual-unblock failures are recorded for review and never
  trigger broad firewall cleanup.
- Reconciliation never automatically deletes an unknown project-chain rule.

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
        +-------------------------------------------------------+
        |                         |                             |
        v                         v                             v
Simulation: WOULD_BLOCK    Log Only: store/log       Automatic Response gates
        |                         |                             |
        +-------------------------+                             v
        |                                  Dedicated SSH_SECURITY_APP rule added
        v                                                    |
Detection stored, audited, and shown in dashboard            v
        |                                      Confirmed block stored in SQLite
        |                                                    |
        +------------------------+---------------------------+
                                 |
                                 v
             Expiration or approved manual request
                                 |
                                 v
                   Exact project rule removed
```
