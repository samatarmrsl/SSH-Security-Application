# SSH Security Application — Complete Context for a Final Report

## How to use this document with ChatGPT

Give this entire Markdown file to ChatGPT before asking it to help write the
final report. Treat this document as the factual project source.

Suggested instruction:

> Use the attached project context as the authoritative description of my
> implementation. Help me write an academic final report in clear language.
> Explain the design decisions and how the components interact, not merely
> list features. Do not invent tests, results, technologies, Windows support,
> machine-learning features, external threat intelligence, or production
> deployments that are not documented. Clearly distinguish completed work
> from limitations and proposed future work.

This context describes the final implementation at Git commit
`ceec14c6ed36e5b3a57dbe1abb4aa29bbf18b1fd`, dated July 27, 2026. At that
release, both `main` and `Dev` pointed to the same tested implementation.
`main` is the stable branch; `Dev` is intended for later experimental work.

---

## 1. Project identity

**Project name:** SSH Security Application

**Project type:** Defensive cybersecurity monitoring, detection, and temporary
firewall-response application for an authorized virtual lab.

**Primary language:** Python 3.8 or newer.

**Python runtime dependencies:** None outside the Python standard library.
Development-only tools include pytest, pytest-cov, and Ruff. The host still
requires operating-system tools such as OpenSSH, journalctl, tcpdump, iptables,
SQLite, systemd, and Linux capabilities.

**Documented security VM:** Ubuntu 20.04 LTS.

**Documented attack-simulation VM:** Kali Linux.

**Primary protected service:** OpenSSH on TCP port 22.

**Firewall backend:** Linux iptables.

**Database:** SQLite.

**Dashboard:** A first-party dashboard built with Python's standard-library
HTTP server and repository-owned HTML, CSS, and JavaScript.

**Important naming clarification:** This is an original implementation. It
does not install, import, invoke, wrap, or depend on the existing SSHGuard or
`sshguard` product. Earlier naming was changed to avoid that confusion. The
final package, command, service names, and firewall chain use
`ssh_security_app`, `ssh-security-app`, and `SSH_SECURITY_APP`.

---

## 2. Problem being addressed

Repeated SSH authentication failures can indicate password guessing,
credential stuffing, username enumeration, or brute-force activity. A single
failed login is not sufficient proof of an attack, and reacting to incomplete
evidence can block legitimate administrators.

The project addresses this problem by combining two independent evidence
sources:

1. OpenSSH authentication records from the Ubuntu system journal.
2. TCP connection metadata for traffic whose destination is SSH port 22.

The application correlates the evidence by source IP and time, calculates an
explainable risk score, stores the full decision trail, and can temporarily
block a validated high-risk IPv4 source in a dedicated iptables chain.

The design emphasizes:

- explainable deterministic decisions;
- least privilege;
- safe defaults;
- narrow firewall scope;
- evidence preservation;
- automatic recovery;
- auditable actions;
- reproducible lab testing.

---

## 3. Project aim and objectives

### Aim

Design and implement an original, explainable SSH brute-force detection and
temporary response platform for an isolated Ubuntu/Kali virtual lab.

### Objectives

The completed system was designed to:

1. Collect and normalize OpenSSH authentication events.
2. Collect only TCP/22 connection metadata, not packet payloads.
3. Correlate authentication and network evidence by IP and time.
4. Deduplicate replayed evidence.
5. Build a history profile for each observed source IP.
6. Calculate an explainable risk score between 0 and 100.
7. Classify activity as Low Concern, Unusual, Suspicious, or High Risk.
8. Support Simulation, Log Only, and Automatic Response operating modes.
9. Validate safety conditions before any firewall action.
10. Insert exact, temporary source-specific DROP rules into a dedicated
    project chain.
11. Remove blocks automatically or through validated manual requests.
12. Reconcile SQLite state with firewall state after startup.
13. Expose detections, evidence, health, audits, and block lifecycle through a
    first-party dashboard.
14. Automate complete Ubuntu lab installation and verification.
15. Provide unit, integration, fixture, and live acceptance testing.

---

## 4. Implemented scope

The final project implements eight stages:

| Stage | Completed capability |
|---|---|
| 1 | Foundation, configuration, models, SQLite, logging, health, and audit |
| 2 | OpenSSH journal parsing and authentication evidence collection |
| 3 | Filtered TCP/22 metadata collection and parsing |
| 4 | Correlation, IP validation, deterministic scoring, and decisions |
| 5 | Persistent operating modes and detection/dashboard data |
| 6 | Guarded iptables response and temporary block creation |
| 7 | Expiration, manual unblock requests, reconciliation, and recovery |
| 8 | First-party dashboard, managed services, automated setup, tests, and documentation |

No implementation stage remains for the documented Ubuntu OpenSSH use case.

---

## 5. Lab infrastructure

### 5.1 Main two-VM topology

| Role | Operating system | Interface | Address | Function |
|---|---|---|---|---|
| Security VM | Ubuntu 20.04 LTS | `ens37` | `192.168.12.1/24` | OpenSSH server, sensor, detector, database, dashboard, and response |
| Attack-simulation VM | Kali Linux | `eth0` | `192.168.12.3/24` | Generates authorized failed SSH logins |

Additional Ubuntu address observed and protected by configuration:

```text
192.168.13.128
```

The installer treats every Ubuntu-owned non-loopback IPv4 address as protected.
Therefore, neither `192.168.12.1` nor `192.168.13.128` is eligible for an
automatic source block.

### 5.2 Service endpoints

```text
OpenSSH:   192.168.12.1:22
Dashboard: http://192.168.12.1:8501
Kali:      192.168.12.3
```

### 5.3 Network placement

The Ubuntu VM is the SSH server being protected. Traffic from Kali reaches
Ubuntu directly over the isolated `192.168.12.0/24` network.

This distinction is important: the current Ubuntu security VM is a protected
host with host-based evidence and response. It is not currently an inline
gateway protecting an unrelated third machine.

### 5.4 Hypervisor design

The recommended virtual setup uses:

- one isolated, host-only, or internal lab network shared by Ubuntu and Kali;
- optionally, a separate NAT adapter for package downloads;
- no public or production target;
- VM snapshots before firewall testing.

### 5.5 Firewall frontend versus response backend

The block engine is always iptables. Firewalld and UFW are optional host
firewall frontends detected by the installer so that SSH and dashboard access
can be handled safely when those tools are active.

For the simplest isolated demonstration, firewalld is stopped. The project
still creates and uses `SSH_SECURITY_APP` through iptables.

---

## 6. High-level architecture

```text
Kali 192.168.12.3
        |
        | failed SSH connections to 192.168.12.1:22
        v
+---------------------------------------------------------------+
| Ubuntu 20.04 security VM                                      |
|                                                               |
|  OpenSSH journal                    ens37 TCP/22 metadata      |
|         |                                      |              |
|         v                                      v              |
|  Authentication collector              Network collector      |
|         |                                      |              |
|         v                                      v              |
|  Authentication parser                  Network parser         |
|         |                                      |              |
|         +---------------+  +-------------------+              |
|                         v  v                                  |
|                       SQLite                                 |
|                         |                                     |
|                         v                                     |
|              Five-minute correlation engine                  |
|                         |                                     |
|                         v                                     |
|           Risk score + classification + decision              |
|                         |                                     |
|          +--------------+----------------+                    |
|          |                               |                    |
|          v                               v                    |
|  First-party dashboard            Guarded block manager       |
|  and SQLite actions                      |                    |
|                                          v                    |
|                               SSH_SECURITY_APP iptables chain |
|                                          |                    |
|                            expiration / manual removal /       |
|                                 startup reconciliation         |
+---------------------------------------------------------------+
```

### Main architectural boundary

SQLite is the durable coordination boundary between collectors, correlation,
the dashboard, and response workers.

The dashboard does not execute iptables. A manual-unblock button writes a
validated request to SQLite. A separate capability-bearing worker revalidates
that request before changing the firewall.

---

## 7. End-to-end processing sequence

### 7.1 Collection

The authentication collector follows the configured OpenSSH systemd journal
using `journalctl`.

The network collector runs a deliberately narrow tcpdump capture equivalent
to:

```text
/usr/bin/tcpdump -i ens37 -nn -l -tt -s 96 tcp dst port 22
```

The capture:

- disables name resolution;
- uses line-buffered output;
- records epoch timestamps;
- limits snapshots to 96 bytes;
- filters for TCP traffic whose destination is SSH port 22.

The application parses metadata only. It does not parse or retain packet
payloads.

### 7.2 Parsing

The authentication parser recognizes:

- failed passwords;
- failed passwords for invalid users;
- invalid-user events;
- accepted passwords;
- accepted public keys;
- connection-closed events.

Unsupported, malformed, or invalid-IP records are quarantined in
`parser_errors` instead of being interpreted through guesswork.

The network parser extracts:

- source and destination IP;
- source and destination TCP port;
- TCP flags;
- event time;
- interface and sensor identity.

### 7.3 Normalization and deduplication

Timestamps are normalized to UTC. IP addresses are normalized through Python's
IP-address types.

Stable fingerprints prevent duplicate evidence from being inserted when a
fixture, journal window, or detection window is replayed. Database uniqueness
provides a second deduplication boundary.

### 7.4 IP profiling

The system maintains a profile for each source IP containing:

- category;
- first and last seen times;
- total failures and successes;
- latest successful authentication;
- previous detection count;
- previous block count;
- current block status;
- optional notes.

### 7.5 Correlation

The correlation engine reads authentication and TCP/22 evidence for the same
source IP within a five-minute window.

It calculates:

- failed authentication count;
- successful authentication count;
- invalid-user count;
- number of unique usernames;
- network connection count;
- attempt rate;
- whether a successful login occurred recently;
- prior detection count;
- prior block count;
- allowlist state;
- current block state.

The managed service runs correlation every 30 seconds.

### 7.6 Decision and response

The risk-scoring function produces a 0–100 score and stored breakdown. The
classification and decision engine then applies safety gates.

In Automatic Response Mode, an eligible High Risk result can be passed to the
block manager. The block manager revalidates the source, checks the allowlist,
protected addresses, duplicate database blocks, and existing exact firewall
rules before inserting anything.

---

## 8. Explainable risk-scoring model

The scoring model is deterministic, not machine learning. Every contribution
is stored with the detection.

### 8.1 Failed authentication volume

| Failed authentications | Points |
|---:|---:|
| 0–2 | 0 |
| 3–4 | 10 |
| 5–7 | 20 |
| 8–9 | 30 |
| 10 or more | 40 |

### 8.2 Username diversity

| Unique usernames | Points |
|---:|---:|
| 0–1 | 0 |
| 2 | 5 |
| 3 | 10 |
| 4–5 | 15 |
| 6 or more | 20 |

### 8.3 Network corroboration

| Matching TCP/22 connections | Points |
|---:|---:|
| 0 | 0 |
| 1–4 | 5 |
| 5–9 | 10 |
| 10 or more | 15 |

### 8.4 Attempt rate

| Attempts per minute | Points |
|---:|---:|
| Less than 1 | 0 |
| At least 1 but less than 2 | 5 |
| At least 2 | 10 |

### 8.5 Previous history

| History | Points |
|---|---:|
| No previous detection or block | 0 |
| At least one previous detection | 5 |
| At least one previous block | 10 |

Previous-block points take precedence over previous-detection points.

### 8.6 Invalid-user activity

| Invalid-user events | Points |
|---:|---:|
| 0 | 0 |
| 1–2 | 2 |
| 3 or more | 5 |

### 8.7 Recent-success adjustment

If the source had a successful authentication within the configured recent
period, 10 points are subtracted.

### 8.8 Final score

All contributions are summed and clamped to the inclusive range 0–100.

### 8.9 Classification

| Score | Classification |
|---:|---|
| 0–29 | Low Concern |
| 30–49 | Unusual |
| 50–69 | Suspicious |
| 70–100 | High Risk |

### 8.10 Deterministic fixture example

The sanitized brute-force fixture produces:

```text
10 failures                 = 40
4 unique usernames          = 15
10 network connections      = 15
attempt rate >= 2 per minute = 10
other factors                = 0
total                        = 80 (High Risk)
```

In Simulation Mode, the resulting decision is `WOULD_BLOCK` and no firewall
operation occurs.

---

## 9. Decision logic and safety gates

A high numerical score alone does not authorize a block.

### 9.1 Detection thresholds

Committed defaults include:

```text
Correlation window:              300 seconds
Suspicious failure threshold:    5
Blocking failure threshold:      10
High Risk threshold:             70
Recent-success history period:   30 days
```

### 9.2 Classification decisions

- Below the failure threshold: `STORE_ONLY`.
- Low Concern: `STORE_ONLY`.
- Unusual: `DISPLAY`.
- Suspicious: `LOG_DETECTION`.
- High Risk: continue through response safety gates.

### 9.3 Automatic-response safety gates

Before a `BLOCK` decision is possible, all of the following must pass:

1. At least the configured blocking number of failures exists.
2. The risk score meets the High Risk threshold.
3. No active allowlist entry suppresses response.
4. The source is eligible for automatic blocking.
5. The source is not already blocked.
6. Matching TCP/22 network evidence exists.
7. The authentication sensor is healthy.
8. The network sensor is healthy.
9. SQLite/database health is acceptable.
10. Automatic Response Mode is configured.
11. The firewall manager is healthy.
12. The project chain exists.
13. The guarded response path is explicitly selected.

### 9.4 Address eligibility

The project classifies private, globally reachable, loopback, link-local,
multicast, unspecified, reserved/special-purpose, and invalid addresses.

Automatic blocking is limited to validated eligible IPv4 sources. Server-owned
protected addresses, loopback, link-local, multicast, unspecified,
special-purpose, allowlisted, and unsupported IPv6 response candidates are not
automatically blocked.

---

## 10. Operating modes

### Simulation Mode

- Safe default in committed configuration.
- Runs collection, correlation, scoring, storage, display, and audit.
- Produces `WOULD_BLOCK` when all response conditions pass.
- Executes no firewall command.

### Log Only Mode

- Performs collection, scoring, storage, logging, audit, and display.
- Produces `LOG_DETECTION`.
- Never changes the firewall.

### Automatic Response Mode

- Used by the automated live-lab deployment.
- Enables guarded block decisions after all safety gates pass.
- The documented lab uses a two-minute block for rapid demonstration.

The active operating mode is persisted in `application_state` and mode changes
are audited.

---

## 11. iptables response design

### 11.1 Dedicated chain

The project owns one chain:

```text
SSH_SECURITY_APP
```

The project does not flush `INPUT`, change the default policy, or manage
unrelated chains.

### 11.2 INPUT jump

The logical `iptables -S` representation is:

```text
-A INPUT -p tcp -m tcp --dport 22 -j SSH_SECURITY_APP
```

This routes inbound SSH traffic through the dedicated chain.

### 11.3 Source-specific block

For the Kali demonstration source:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp -m tcp --dport 22 -j DROP
```

The actual insertion command is constructed as an argument list equivalent to:

```text
/usr/sbin/iptables -w 5 -I SSH_SECURITY_APP 1 -s 192.168.12.3 -p tcp --dport 22 -j DROP
```

### 11.4 Command safety

`FirewallCommandBuilder`:

- requires an absolute iptables executable;
- validates the project chain name;
- validates the SSH port;
- normalizes the source as IPv4;
- constructs argument arrays;
- uses `shell=False`;
- sets a command timeout;
- checks before changing;
- confirms after changing.

### 11.5 Idempotence and duplicate prevention

Chain initialization checks whether the chain and INPUT jump already exist.
Source blocking checks both SQLite active blocks and the exact firewall rule.
Repeated initialization does not create duplicate state.

### 11.6 Database rollback protection

The rule is inserted and confirmed before the block becomes active in SQLite.
If database activation then fails, the block manager attempts compensating
deletion of the exact rule.

---

## 12. Block lifecycle

### 12.1 Active block creation

On a successful response:

1. A UUID block ID is created.
2. The source and originating detection ID are stored.
3. `blocked_at` is recorded.
4. `expires_at` is calculated.
5. Status becomes `Active`.
6. The firewall result is stored.
7. The IP profile's block history is updated.
8. An audit event is written.

### 12.2 Automatic expiration

The documented live configuration uses:

```text
Block duration:            120 seconds
Expiration check interval: 10 seconds
```

The expiration worker:

1. selects active blocks whose expiration time has passed;
2. verifies whether the exact rule exists;
3. deletes the exact rule if present;
4. confirms the removal;
5. records status `Expired`;
6. records removal method `Automatic`;
7. records `removed_at`;
8. writes audit and health results.

If deletion fails, the block remains Active with an error so the worker can
retry. The database is not falsely marked expired.

### 12.3 Manual removal

The dashboard does not delete a rule. It writes a `Pending` manual-unblock
request to SQLite.

The action worker independently verifies:

- the action type;
- source IPv4 validity;
- the selected block exists;
- the block is still Active;
- the request source matches the block;
- the exact firewall rule exists.

After successful deletion, the block becomes `Manually Removed`, the method is
`Manual`, and the action request becomes `Completed`.

### 12.4 Reconciliation

At response-worker startup, the reconciler compares active SQLite blocks with
the project-chain rules.

It handles:

- active block plus matching rule: consistent;
- expired active block plus rule: delete and expire;
- expired active block without rule: expire;
- active block without a rule: mark `Inconsistent`;
- rule without an active database block: audit for review;
- unknown project-chain rule: audit and do not automatically delete.

### 12.5 Cleanup

The guarded cleanup helper parses the chain before changing it. It refuses
automatic cleanup if unknown or duplicate rules are present.

If the chain is recognized, cleanup deletes:

1. recognized source rules one at a time;
2. the exact TCP/22 INPUT jump;
3. the empty project chain.

It never flushes a chain or restores a complete firewall ruleset.

---

## 13. Database design

SQLite is configured with:

- foreign keys;
- WAL mode;
- busy timeout;
- short transactions;
- parameterized SQL;
- schema initialization and in-place migration.

### Tables

| Table | Purpose |
|---|---|
| `auth_events` | Parsed OpenSSH authentication evidence |
| `network_events` | Parsed TCP/22 metadata |
| `ip_profiles` | Source history and aggregate counters |
| `detections` | Window, score, breakdown, classification, decision, and reason |
| `detection_auth_events` | Authentication evidence linked to a detection |
| `detection_network_events` | Network evidence linked to a detection |
| `allowlist` | Active and historical trusted IPv4 entries |
| `blocks` | Block timestamps, lifecycle, result, and errors |
| `action_requests` | Manual-unblock queue and history |
| `audit_log` | Security-relevant actions and outcomes |
| `parser_errors` | Unsupported/malformed evidence quarantine |
| `component_health` | Latest health for each component |
| `application_state` | Persistent operating mode and other state |

### Important database relationships

- A detection links to all authentication and network events used as evidence.
- A block references the detection that authorized it.
- An action request references a block.
- IP profiles accumulate source-level history.

### Production database location

```text
/var/lib/ssh-security-app/ssh_security_app.db
```

Development and fixture configurations use databases inside the repository's
`data/` directory. These must not be confused with production results.

---

## 14. Audit, health, and logging

### Audit

Security-relevant events are written to `audit_log`, including:

- operating-mode activation/change;
- evidence ingestion;
- risk scoring and decisions;
- successful or rejected blocks;
- automatic unblocks;
- manual requests and results;
- reconciliation;
- unknown firewall rules;
- component failure;
- application startup and shutdown.

### Health

`component_health` tracks components such as:

- authentication sensor;
- network sensor;
- database;
- correlation engine;
- firewall manager;
- firewall reconciler;
- expiration worker;
- action-request worker;
- response worker;
- application controller;
- dashboard.

States are `HEALTHY`, `DEGRADED`, `FAILED`, or `STOPPED`.

### Logging

The application emits structured JSON logs with rotation. The production log
is:

```text
/var/log/ssh-security-app/ssh_security_app.log
```

The committed default rotation is 10 MiB with five backups.

---

## 15. First-party dashboard

### 15.1 Technology

The final dashboard does not use Streamlit, pandas, a CDN, or an external
dashboard product.

It uses:

- Python standard-library `ThreadingHTTPServer`;
- owned `index.html`;
- owned `app.css`;
- owned `app.js`;
- same-origin JSON APIs.

### 15.2 Pages

The interface includes:

- Overview;
- Detections;
- Firewall Blocks;
- Allowlist;
- Audit Trail;
- System Health.

### 15.3 Block lifecycle display

Firewall Blocks shows:

- active block cards;
- seconds remaining;
- source;
- block and expiration times;
- firewall/reconciliation state;
- last result;
- manual-unblock action;
- retained active and removed block history;
- removed time and method;
- exact INPUT jump;
- exact source-specific DROP rule.

After an automatic unblock, the active card disappears but the history row
remains `Expired` with method `Automatic`.

### 15.4 IP detail drawer

Source IPs are selectable. The drawer shows locally stored:

- IP category;
- first and last seen;
- failure and success totals;
- usernames;
- detection and block totals;
- current block and allowlist state;
- latest score and risk breakdown;
- decision and reason;
- detection history;
- block history;
- sanitized authentication evidence;
- TCP/22 metadata.

The detail view does not call an external reputation, WHOIS, geolocation, or
threat-intelligence service.

### 15.5 API routes

Read routes:

```text
GET /api/session
GET /api/snapshot
GET /api/ip-details?source_ip=...
```

Action routes:

```text
POST /api/actions/manual-unblock
POST /api/actions/allowlist-add
POST /api/actions/allowlist-disable
```

The dashboard implements CSRF protection, request-size limits, no-store
responses, restrictive headers, and same-origin actions.

### 15.6 Privilege boundary

The dashboard runs as `sshsecurityapp` without firewall capabilities. Its
manual action is a database request, not direct firewall control.

---

## 16. Application services and least privilege

### 16.1 Installation paths

```text
Application:  /opt/ssh-security-application
Configuration: /etc/ssh-security-app/config.json
Database:      /var/lib/ssh-security-app/ssh_security_app.db
Logs:          /var/log/ssh-security-app
```

### 16.2 Service account

The installer creates:

```text
sshsecurityapp
```

It is a system account with no normal login shell.

### 16.3 systemd units

#### `ssh-security-app-firewall.service`

- One-shot project-chain initialization.
- Runs guarded cleanup on orderly stop.
- Has only `CAP_NET_ADMIN` and `CAP_NET_RAW`.
- Starts before the application service.

#### `ssh-security-app.service`

- Runs authentication collector.
- Runs network collector.
- Runs correlation every 30 seconds.
- Runs response worker in Automatic Response Mode.
- Uses the `systemd-journal` supplementary group.
- Has only `CAP_NET_ADMIN` and `CAP_NET_RAW`.

#### `ssh-security-app-dashboard.service`

- Runs the first-party dashboard.
- Has no firewall capabilities.
- Starts after and wants the main application service.

### 16.4 Service hardening

The units use controls including:

- `NoNewPrivileges=true`;
- `PrivateTmp=true`;
- `ProtectSystem=strict`;
- `ProtectHome=true`;
- restricted writable paths;
- restricted address families;
- restart-on-failure for long-running services.

---

## 17. Configuration model

Committed configuration is safe by default:

```text
Mode:                       simulation
Correlation window:         300 seconds
Block duration:             1800 seconds
Expiration check:           60 seconds
Firewall chain:             SSH_SECURITY_APP
Firewall executable:        /usr/sbin/iptables
SSH port:                   22
SQLite WAL:                 enabled
Dashboard:                  127.0.0.1:8501
```

The automated live-lab installer writes a production override:

```text
Environment:                 ubuntu-live-demo
Mode:                        automatic_response
Interface:                   ens37
Protected addresses:         Ubuntu-owned IPv4 addresses
Dashboard:                   192.168.12.1:8501
Block duration:              120 seconds
Expiration interval:         10 seconds
Database:                    /var/lib/ssh-security-app/ssh_security_app.db
Log:                         /var/log/ssh-security-app/ssh_security_app.log
```

The committed default and live production configuration differ deliberately:
the repository defaults cannot modify a firewall, while live Automatic
Response must be explicitly installed.

---

## 18. Important source-code modules

| Path | Responsibility |
|---|---|
| `src/ssh_security_app/config.py` | Load, merge, type, and validate configuration |
| `src/ssh_security_app/constants.py` | Shared modes, classifications, decisions, statuses, and health enums |
| `src/ssh_security_app/models.py` | Typed domain records |
| `src/ssh_security_app/audit.py` | Structured logging and audit service |
| `src/ssh_security_app/health.py` | Component health persistence |
| `collectors/auth_parser.py` | Pure OpenSSH record parsing |
| `collectors/auth_journal.py` | One-shot, fixture, and continuous journal collection |
| `collectors/auth_ingestor.py` | Store authentication evidence and profiles |
| `collectors/network_parser.py` | Pure tcpdump-line parsing |
| `collectors/network_tcpdump.py` | Filtered live/fixture TCP collector |
| `collectors/network_ingestor.py` | Store network evidence and profiles |
| `core/normalization.py` | UTC/IP normalization and fingerprints |
| `core/deduplication.py` | Short-window duplicate suppression |
| `core/ip_validation.py` | IP category and response eligibility |
| `core/correlation.py` | Five-minute evidence correlation and detection creation |
| `core/risk_score.py` | Explainable 0–100 scoring |
| `core/classification.py` | Classification and decision safety gates |
| `core/allowlist.py` | Trusted-source management |
| `db/database.py` | SQLite connection and transaction boundary |
| `db/repositories.py` | Parameterized persistence/query APIs |
| `db/schema.sql` | Durable schema and indexes |
| `response/firewall_manager.py` | Strict iptables commands and confirmation |
| `response/block_manager.py` | Revalidated block creation and rollback |
| `response/expiration_worker.py` | Automatic rule removal |
| `response/action_request_worker.py` | Privileged manual-request processor |
| `response/reconciliation.py` | SQLite/firewall state reconciliation |
| `response/rules.py` | Parse recognized project-owned rules |
| `response/response_worker.py` | Response lifecycle loop |
| `service.py` | Collector/detector/response thread controller |
| `ui/dashboard_data.py` | Serializable dashboard/IP/block views |
| `ui/dashboard.py` | HTTP application, API, CSRF, and action boundary |
| `ui/static/` | First-party HTML, CSS, and JavaScript |
| `live_lab_setup.py` | Complete Ubuntu install, service setup, and verification |
| `main.py` | CLI and component composition |

---

## 19. CLI capabilities

The `ssh-security-app` command provides:

```text
validate-config
init-db
mode-status
inspect
service
collect-auth
collect-network
detect
allowlist-add
allowlist-list
allowlist-disable
firewall-status
firewall-init
firewall-cleanup
response-reconcile
response-worker
manual-unblock-request
```

The `inspect` command returns JSON views for:

```text
overview
detections
active-blocks
allowlist
actions
audit
health
```

---

## 20. Automated setup

The main installer is:

```text
scripts/setup_live_lab.py
```

It:

1. validates repository assets;
2. validates the lab interface and subnet;
3. distinguishes server and disposable client addresses;
4. protects all Ubuntu-owned addresses;
5. detects UFW/firewalld state;
6. installs required Ubuntu packages;
7. installs and starts OpenSSH if needed;
8. grants narrow tcpdump capture capability;
9. creates the service account and directories;
10. copies and installs the current source;
11. writes and validates production configuration;
12. initializes/migrates SQLite;
13. installs hardened systemd units;
14. safely cleans recognized stale project state;
15. starts all services;
16. verifies services, firewall, SSH, dashboard, and client baseline.

The read-only plan:

```bash
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3
```

The applied lab setup:

```bash
python3 scripts/setup_live_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --apply \
  --confirm-firewall-changes
```

The explicit confirmation prevents accidental firewall mutation.

---

## 21. Test strategy and results

### 21.1 Final automated result

```text
174 tests passed
80% total statement/branch coverage
Ruff lint passed
Ruff format check passed
Python compileall passed
JavaScript syntax check passed
```

### 21.2 Unit tests

Unit tests cover:

- configuration validation;
- parsers;
- normalization;
- deduplication;
- IP classification and safety;
- risk-score thresholds;
- classification and decisions;
- allowlist;
- SQLite repositories;
- modes;
- dashboard data and HTTP APIs;
- exact firewall commands;
- block creation and rollback;
- expiration;
- action requests;
- reconciliation;
- cleanup;
- service shutdown;
- automated environment setup.

### 21.3 Integration tests

Integration tests cover:

- authentication fixture ingestion;
- network fixture ingestion;
- detection creation;
- evidence links;
- high-risk Automatic Response with an in-memory iptables runner;
- block expiration.

### 21.4 Test isolation

Automated tests use:

- sanitized fixtures;
- temporary SQLite databases;
- an in-memory fake iptables command runner.

The ordinary automated test suite does not alter the host firewall.

### 21.5 Additional acceptance validation

Acceptance work also covered:

- clean project installation;
- packaged defaults and static dashboard assets;
- fresh and migrated database startup;
- fixture replay and deduplication;
- live Ubuntu OpenSSH journal collection;
- live tcpdump collection;
- managed service startup/shutdown;
- dashboard restart and persistence;
- real iptables lifecycle in an isolated namespace;
- exact block insertion and confirmation;
- automatic expiration;
- manual unblock;
- reconciliation;
- guarded cleanup.

---

## 22. Live Kali demonstration

### 22.1 Kali test data

Six fake usernames and five deliberately wrong passwords were used:

```text
demo_admin
demo_backup
demo_database
demo_operator
demo_service
demo_support
```

No real password was used.

### 22.2 Hydra command

The authorized lab command was:

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

### 22.3 Expected/observed sequence

1. Kali could initially connect to Ubuntu port 22.
2. Hydra generated failed logins.
3. Ubuntu collected authentication and network evidence.
4. Correlation created a High Risk detection.
5. The guarded decision was `BLOCK`.
6. iptables inserted the exact Kali source rule.
7. Subsequent Kali SSH attempts timed out.
8. The dashboard displayed detection, evidence, countdown, and exact rules.
9. Approximately two minutes later, the worker removed the rule.
10. The block history changed to `Expired` and `Automatic`.
11. Kali could reach SSH again.

### 22.4 Rule verification

Active:

```bash
sudo iptables -C SSH_SECURITY_APP \
  -s 192.168.12.3 \
  -p tcp \
  --dport 22 \
  -j DROP
```

Return status `0` means the exact rule exists.

After expiration, return status `1` means it is absent.

---

## 23. Security and privacy decisions

The implementation deliberately:

- does not collect attempted passwords;
- does not collect private keys;
- does not decrypt SSH;
- does not inspect application payloads;
- limits packet snapshots and parses metadata only;
- keeps unsupported records rather than guessing;
- uses parameterized SQL;
- uses subprocess argument lists and `shell=False`;
- validates absolute executable paths;
- uses a dedicated firewall chain;
- does not flush firewall chains;
- does not change default policies;
- protects server-owned addresses;
- supports allowlisting;
- requires corroborating network evidence;
- requires healthy sensors and database;
- separates the unprivileged dashboard from response capabilities;
- audits decisions and mutations;
- automatically expires temporary rules;
- preserves unknown firewall state for human review.

---

## 24. Design rationale

### Why use two evidence sources?

Authentication logs show failed login outcomes, while network metadata confirms
that the same source was making TCP connections to SSH. Requiring both reduces
the risk of acting on incomplete or replayed log evidence.

### Why deterministic scoring?

The project is a teaching and demonstration platform. Fixed weights make every
decision reproducible and explainable. A report can show exactly why a source
received a score.

### Why SQLite?

SQLite provides durable coordination without requiring a separate database
server. WAL, a busy timeout, short transactions, and repositories make it
appropriate for this single-host lab.

### Why a dedicated iptables chain?

It gives the application a narrow ownership boundary. Rules can be listed,
verified, reconciled, and cleaned without flushing or changing unrelated host
firewall policy.

### Why temporary blocks?

Temporary blocks demonstrate active defense without requiring permanent
blacklisting. They reduce the impact of a mistaken classification and make a
short classroom demonstration practical.

### Why separate the dashboard from firewall mutation?

A network-facing interface should not receive firewall privileges. SQLite
action requests allow the dashboard to request an operation while a separate
worker applies the security checks.

### Why not use SSHGuard?

The learning objective was to create an original alternative and understand
collection, correlation, response, recovery, and auditing rather than install
an existing product.

---

## 25. Known limitations

The final report should state these honestly:

1. The implemented target is Ubuntu OpenSSH, not every authentication service.
2. Live authentication evidence comes from the local Ubuntu journal.
3. Automatic response is IPv4-only.
4. The Ubuntu VM protects itself; it is not an inline gateway for another host.
5. The project is designed for an isolated authorized lab, not production.
6. SQLite is appropriate for one host but not a distributed enterprise sensor
   fleet.
7. Risk weights are manually defined, not statistically trained.
8. No external reputation, geolocation, WHOIS, or threat feed is used.
9. The dashboard has lab-oriented same-origin controls, not a full enterprise
   identity system.
10. Network evidence is TCP/22 metadata and does not identify password content.
11. Detection depends on correct time, interface, sensor, and protected-address
    configuration.
12. Firewalld or UFW reloads can reconstruct host firewall state, so the
    project service must be restarted/reconciled afterward.

---

## 26. Windows 10 extension context

Windows support is not implemented in the final release.

There are two different possible Windows roles:

### Windows as another attack-simulation client

If Windows 10 attempts SSH logins against the Ubuntu VM, the current Ubuntu
application can detect and temporarily block the Windows source IPv4 address.

A suitable label is:

> Optional Windows 10 attack-simulation client for cross-platform source
> testing.

### Windows as the protected target

If the goal is to brute-force a Windows service such as RDP or Windows-hosted
OpenSSH and have Ubuntu protect Windows, the current design is insufficient.

That extension would require either:

1. An inline Ubuntu gateway through which Windows-bound traffic passes,
   producing a Network Intrusion Prevention System (NIPS) or inline security
   gateway; or
2. A Windows agent that forwards Windows authentication events and applies
   response through Windows Firewall, producing a centralized host intrusion
   detection/prevention design.

A suitable future-work label is:

> Optional Windows 10 protected endpoint for cross-platform brute-force
> detection and response evaluation.

Do not describe Windows target protection as completed functionality.

---

## 27. Possible future work

Reasonable future extensions include:

- Windows Event Log ingestion and Windows Firewall response;
- Windows 10 as a protected endpoint;
- protecting multiple Ubuntu servers;
- a central event API or message queue;
- PostgreSQL for multi-sensor deployment;
- configurable scoring policies through the dashboard;
- additional services such as RDP, web authentication, or VPN login;
- optional offline IP reputation enrichment;
- authenticated dashboard users and roles;
- notifications through email or a messaging platform;
- metrics export and long-term trend analysis;
- IPv6 automatic response with equivalent validation;
- signed evidence export for report appendices;
- performance testing at larger event volumes.

These are proposals, not current features.

---

## 28. Suggested final-report structure

ChatGPT can use this outline:

1. **Abstract**
   - Problem, approach, implementation, and primary result.
2. **Introduction**
   - SSH brute-force risk and project motivation.
3. **Aim and Objectives**
   - Use the completed objectives in this context.
4. **Background**
   - OpenSSH logs, network metadata, host-based detection, iptables, and
     explainable scoring.
5. **Requirements and Scope**
   - Functional, safety, and lab constraints.
6. **Infrastructure**
   - Ubuntu 20.04, Kali, interfaces, addresses, endpoints, and topology.
7. **System Architecture**
   - Collectors, SQLite, correlation, response, dashboard, and privilege
     boundaries.
8. **Implementation**
   - Explain Stages 1–8 and important modules.
9. **Detection Method**
   - Five-minute correlation, score weights, classifications, and gates.
10. **Firewall Response**
    - Dedicated chain, exact rules, lifecycle, rollback, and reconciliation.
11. **Dashboard and Usability**
    - First-party UI, block lifecycle, IP details, and manual requests.
12. **Security and Privacy**
    - Least privilege, metadata-only collection, audit, and safe firewall
      ownership.
13. **Testing Methodology**
    - Unit, integration, fixtures, fake firewall, namespace, and live Kali
      test.
14. **Results**
    - 174 tests, 80% coverage, successful detection/block/expiration.
15. **Discussion**
    - Explain strengths, tradeoffs, and why the design is reproducible.
16. **Limitations**
    - Use the limitations listed above.
17. **Future Work**
    - Clearly mark Windows and distributed monitoring as future extensions.
18. **Conclusion**
    - Restate the original implementation and demonstrated outcome.
19. **Appendices**
    - Commands, configuration, database tables, rule examples, screenshots,
      and selected test output.

---

## 29. Suggested report claims that are supported

These claims are supported by the implementation and tests:

- The application correlates OpenSSH and TCP/22 evidence by source IP.
- The score is deterministic and explainable.
- The committed default cannot modify iptables.
- Automatic blocking requires multiple independent safety gates.
- Blocks are limited to exact IPv4 sources and SSH TCP/22.
- The application owns only `SSH_SECURITY_APP`.
- The dashboard does not receive firewall capabilities.
- Blocks can expire automatically or be removed through validated requests.
- Firewall and database state are reconciled at startup.
- Unknown rules are audited rather than automatically deleted.
- The final test suite contains 174 passing tests at 80% coverage.
- The controlled Kali demonstration successfully produced detection, block,
  timeout, automatic removal, and restored connectivity.
- The dashboard and protection system are original project components rather
  than wrappers around SSHGuard or Streamlit.

---

## 30. Claims that must not be made

Do not claim that the project currently:

- protects a Windows target;
- blocks RDP attacks;
- is a production enterprise IPS;
- uses artificial intelligence or machine learning;
- decrypts SSH;
- captures attempted passwords;
- analyzes packet payloads;
- uses SSHGuard;
- uses Streamlit;
- queries live geolocation or reputation services;
- automatically removes unknown firewall rules;
- supports distributed sensors;
- guarantees prevention of every SSH attack;
- replaces defense-in-depth controls such as strong authentication, keys, MFA,
  patching, segmentation, or rate limiting.

---

## 31. Glossary

| Term | Meaning in this project |
|---|---|
| Authentication evidence | Parsed OpenSSH success, failure, invalid-user, or connection event |
| Network evidence | TCP/22 metadata observed by tcpdump |
| Correlation window | Five-minute period used to combine evidence by source IP |
| Risk score | Deterministic 0–100 total with a stored breakdown |
| Classification | Low Concern, Unusual, Suspicious, or High Risk |
| Decision | Store, display, log, suppress, would block, or block |
| Protected address | Ubuntu-owned address that must never be automatically blocked |
| Allowlist | Trusted IPv4 source whose automatic response is suppressed |
| Dedicated chain | Project-owned `SSH_SECURITY_APP` iptables chain |
| Active block | Confirmed source DROP rule with an unexpired database record |
| Expiration | Automatic deletion of a temporary exact rule |
| Reconciliation | Comparison of active SQLite blocks and project-chain rules |
| Inconsistent | Database and firewall state no longer agree |
| Action request | SQLite record asking the privileged worker to perform a manual unblock |
| Simulation Mode | Full detection with `WOULD_BLOCK` and no firewall change |
| Log Only Mode | Detection and logging without firewall response |
| Automatic Response | Guarded mode that permits a confirmed temporary block |

---

## 32. Concise project summary

SSH Security Application is an original Python defensive tool deployed on an
Ubuntu 20.04 security VM. It reads OpenSSH authentication events and filtered
TCP/22 metadata, normalizes and deduplicates both sources, correlates them in a
five-minute source-IP window, calculates an explainable risk score, and stores
the evidence and decision in SQLite. In Automatic Response Mode, a High Risk
IPv4 source is temporarily blocked only after address, allowlist, duplicate,
sensor, database, network-corroboration, and firewall checks pass. Response is
limited to a dedicated `SSH_SECURITY_APP` iptables chain. A separate worker
expires or manually removes rules and reconciles firewall state after startup.
A first-party unprivileged dashboard displays detections, local IP profiles,
evidence, exact rules, block lifecycle, audits, and health. The final
implementation passed 174 automated tests with 80% coverage and was validated
in an isolated Ubuntu/Kali lab where Kali `192.168.12.3` triggered a temporary
two-minute SSH block on Ubuntu `192.168.12.1`, after which the exact DROP rule
was removed and connectivity returned.
