# Beginner Code Walkthrough

This document explains the project files in plain language. It is written for
someone who is new to programming and Python.

The main idea of the project is simple:

```text
1. Watch SSH login activity on the Ubuntu Security VM.
2. Watch SSH network traffic going to port 22.
3. Store both types of evidence in SQLite.
4. Compare the evidence by source IP address.
5. Decide whether the source IP looks like a brute-force attacker.
6. If Automatic Response Mode is enabled, temporarily block that IP with iptables.
7. Remove the block automatically after the timer expires.
```

## Simple Python Terms Used in This Project

Before looking at files, these are the basic Python ideas used throughout the
code.

| Term | Plain explanation |
|---|---|
| Function | A named set of steps. Example: `load_config()` loads the config file. |
| Class | A reusable object definition. Example: `FirewallManager` knows how to manage iptables rules. |
| Dataclass | A simple class mainly used to hold data. Example: `Detection` stores the result of one detection. |
| Enum | A fixed list of allowed names. Example: `Decision.BLOCK` means the app decided to block an IP. |
| Import | Lets one file use code from another file. |
| Repository | In this project, a small database helper that saves or loads one kind of data. |
| CLI | Command-line interface. This is the terminal command `ssh-security-app`. |
| Systemd service | A Linux background service that starts and keeps the app running. |

## The Main Folders

| Folder | What it contains |
|---|---|
| `application_source_code/ssh_security_application/` | The actual Python application. |
| `application_configuration/` | Safe default and example configuration files. |
| `installation_and_service_setup/` | Helper scripts and systemd service files. |
| `project_documentation/` | Human-readable documentation. |
| `verification_and_validation/` | Automated tests and sample evidence files. |

## How the Main Application Files Work Together

When you run:

```bash
python3 run_lab.py --apply --watch
```

the flow is:

```text
run_lab.py
  -> lab.py
    -> live_lab_setup.py
      -> installs app, writes config, starts systemd
        -> ssh-security-app monitor
          -> main.py
            -> service.py
              -> auth.py + network.py collect evidence
              -> detection.py scores source IPs
              -> firewall.py blocks and unblocks IPs
              -> storage.py saves everything in SQLite
              -> terminal.py prints readable output
```

## Root-Level File

### `run_lab.py`

This is the simplest file for you to run.

It exists so you do not have to remember a long setup command. It adds the
project source folder to Python's search path and then runs the real lab setup
code in `lab.py`.

You use it like this:

```bash
python3 run_lab.py --apply --watch
```

In plain language, this means:

- `python3` runs Python.
- `run_lab.py` is the project setup script.
- `--apply` tells it to actually make changes.
- `--watch` tells it to keep showing the live service logs.

## Top-Level Application Source Files

These files are in:

```text
application_source_code/ssh_security_application/
```

### `__init__.py`

This marks the folder as a Python package. A Python package is a folder that
Python can import code from.

This file does not contain business logic. It mainly identifies the application
package.

### `default_config.json`

This is the default configuration that gets installed with the Python package.

This file is important because the app must still know its safe defaults after
it is installed into `/opt/ssh-security-application`. Without this file packaged
inside the app, the installed version can fail to find its default config.

The committed default mode is Simulation Mode, meaning a fresh install does not
block IPs unless the live-lab installer writes an Automatic Response config.

### `config.py`

This file loads and checks configuration.

It does three main things:

1. Reads `default_config.json`.
2. Optionally reads a local override config, such as `/etc/ssh-security-app/config.json`.
3. Checks that all settings are valid before the app runs.

Important classes in this file:

| Class | Meaning |
|---|---|
| `Settings` | The complete application configuration after defaults and overrides are merged. |
| `ApplicationConfig` | Basic app name and environment label. |
| `DetectionConfig` | Settings for detection thresholds and scoring window. |
| `ResponseConfig` | Settings for Simulation Mode, Automatic Response Mode, iptables, and block duration. |
| `AuthenticationSensorConfig` | Settings for reading OpenSSH logs. |
| `NetworkSensorConfig` | Settings for tcpdump and protected server IPs. |
| `DatabaseConfig` | SQLite database path and behavior. |
| `LoggingConfig` | Log file path and logging level. |

Important function:

| Function | What it does |
|---|---|
| `load_config()` | Loads default config, merges local overrides, validates everything, and returns a `Settings` object. |

### `constants.py`

This file defines fixed allowed names used throughout the app.

Examples:

| Enum | What it means |
|---|---|
| `OperatingMode` | Whether the app is in `simulation`, `log_only`, or `automatic_response`. |
| `Decision` | Whether a detection should be logged, would block, or should block. |
| `BlockStatus` | Whether a firewall block is active, expired, removed, or inconsistent. |
| `HealthState` | Whether a component is healthy, failed, stopped, or degraded. |
| `ParseStatus` | Whether a log line was parsed, malformed, unsupported, or had an invalid IP. |

Using these fixed names prevents spelling mistakes like `"blok"` instead of
`"block"`.

### `models.py`

This file defines the main records the application passes around.

Think of these as forms with named fields.

Examples:

| Dataclass | What it stores |
|---|---|
| `AuthenticationEvent` | One SSH login-related event from OpenSSH logs. |
| `NetworkEvent` | One SSH network connection event from tcpdump. |
| `Detection` | One detection result for a source IP. |
| `BlockRecord` | One temporary firewall block stored in SQLite. |
| `HealthStatus` | Health information for one app component. |
| `AuditRecord` | One security/audit log entry. |
| `BlockResponse` | Result of trying to block an IP. |

Without these models, the code would pass around loose dictionaries, which is
harder to understand and easier to break.

### `main.py`

This is the command-line controller for `ssh-security-app`.

When you run:

```bash
ssh-security-app --config /etc/ssh-security-app/config.json status
```

this file decides what `status` means and calls the correct code.

Commands handled here include:

| Command | What it does |
|---|---|
| `validate-config` | Checks the config file. |
| `init-db` | Creates or updates SQLite tables. |
| `status` | Shows current mode, database state, firewall state, and counters. |
| `detections` | Shows recent detections. |
| `blocks` | Shows active and recently removed blocks. |
| `rules` | Shows app-owned iptables rules. |
| `unblock` | Manually removes a temporary block for an IP. |
| `allowlist` | Adds, lists, or removes trusted IP addresses. |
| `monitor` | Starts the live collector/detection/firewall loop. |
| `collect-auth` | Collects OpenSSH authentication evidence. |
| `collect-network` | Collects tcpdump network evidence. |
| `detect` | Runs detection against stored evidence. |
| `firewall-init` | Creates the dedicated iptables chain. |
| `firewall-cleanup` | Removes project-owned firewall rules. |

This file is the main bridge between terminal commands and the rest of the
application.

### `lab.py`

This file powers the easy one-command lab setup.

It wraps the more detailed installer in `live_lab_setup.py` and gives it
friendly defaults for your lab:

```text
interface: ens37
Ubuntu IP: 192.168.12.1
Kali IP: 192.168.12.3
block time: 120 seconds
```

Important functions:

| Function | What it does |
|---|---|
| `build_parser()` | Defines the options accepted by `run_lab.py`. |
| `main()` | Converts the easy command into the full live-lab install command. |
| `watch_application_service_log()` | Runs `journalctl -fu ssh-security-application.service` after setup. |

### `live_lab_setup.py`

This is the full Ubuntu/Kali production lab installer.

It is longer because it handles many system-level tasks safely.

It does the following:

1. Checks that the lab interface exists.
2. Checks that the Kali IP is in the same subnet.
3. Installs required Ubuntu packages.
4. Enables OpenSSH.
5. Grants tcpdump capture capability.
6. Creates the service user `sshsecurityapp`.
7. Copies the project into `/opt/ssh-security-application`.
8. Creates a production virtual environment.
9. Installs the Python package into that environment.
10. Writes `/etc/ssh-security-app/config.json`.
11. Initializes the SQLite database.
12. Installs systemd services.
13. Creates the dedicated iptables chain.
14. Starts the app.
15. Runs post-install verification.

Important class:

| Class | What it stores |
|---|---|
| `LiveLabPlan` | The complete plan for the live lab: interface, server IP, client IP, SSH port, block duration, and firewall frontend. |

### `setup_environment.py`

This prepares a local testing environment inside the repo.

It is useful for development or simulation mode, not necessarily the final
systemd live demo.

It can:

- install OpenSSH if missing;
- enable SSH;
- grant tcpdump capability;
- install the project into the local `.venv`;
- create `config/local.json`;
- initialize a local SQLite database.

### `service.py`

This file coordinates the long-running app.

It starts and stops these pieces together:

- authentication collector;
- network collector;
- detection runner;
- response worker.

Think of this file as the supervisor for the live monitoring loop.

Important class:

| Class | What it does |
|---|---|
| `ApplicationController` | Starts all live components, waits while they run, and shuts them down cleanly. |

### `terminal.py`

This file controls what the user sees in the terminal.

It prints:

- startup status;
- auth events;
- network events;
- detections;
- risk score details;
- block messages;
- exact iptables DROP rules;
- expired block messages;
- tables for detections, blocks, rules, and allowlist entries.

This file is important because the project no longer uses a browser dashboard.
The terminal is now the main interface.

### `audit.py`

This file records important security actions.

Examples of audit events:

- mode changed;
- database initialized;
- detection created;
- IP blocked;
- block expired;
- manual unblock performed;
- firewall reconciliation ran.

It can write logs in JSON format and save audit records in SQLite.

### `health.py`

This records whether parts of the app are working.

Examples:

- database is healthy;
- authentication collector is healthy;
- tcpdump collector failed;
- firewall reconciler is healthy;
- response worker stopped.

This supports the `status` command.

### `modes.py`

This manages the current operating mode.

Important modes:

| Mode | Meaning |
|---|---|
| `simulation` | Detect and explain, but do not touch iptables. |
| `log_only` | Log detections without blocking. |
| `automatic_response` | Detect and temporarily block high-risk IPs. |

The live lab installer writes Automatic Response Mode because you want to test
real iptables blocking.

### `ip_validation.py`

This file decides whether an IP address is safe and eligible to block.

It rejects IPs that should not be blocked, such as:

- invalid strings;
- loopback addresses like `127.0.0.1`;
- multicast or reserved addresses;
- protected server addresses;
- allowlisted addresses.

This is a safety layer before any firewall rule is created.

## Evidence Collection

These files are in:

```text
application_source_code/ssh_security_application/evidence_collection/
```

### `auth.py`

This file handles OpenSSH authentication evidence.

It combines three responsibilities:

1. Parse raw OpenSSH log lines.
2. Read log lines from `journalctl` or fixture files.
3. Validate and store parsed authentication events.

Important pieces:

| Class or function | What it does |
|---|---|
| `parse_authentication_line()` | Converts one OpenSSH log line into an `AuthenticationEvent`. |
| `AuthenticationJournalCollector` | Reads OpenSSH logs from `journalctl` or a fixture file. |
| `AuthenticationIngestor` | Validates, deduplicates, and saves authentication events into SQLite. |
| `CollectorError` | Error used when log collection fails. |

Example evidence this file understands:

```text
Failed password for invalid user demo_admin from 192.168.12.3
```

The file does not collect real passwords. It only reads the system log message.

### `network.py`

This file handles SSH network metadata.

It combines three responsibilities:

1. Parse raw tcpdump output.
2. Run tcpdump or read fixture files.
3. Validate and store network events.

Important pieces:

| Class or function | What it does |
|---|---|
| `parse_network_line()` | Converts one tcpdump line into a `NetworkEvent`. |
| `NetworkTcpdumpCollector` | Runs tcpdump for TCP destination port 22 traffic. |
| `NetworkIngestor` | Validates, deduplicates, and saves network events into SQLite. |

This file records metadata like:

- source IP;
- destination IP;
- source port;
- destination port;
- TCP flags;
- timestamp.

It does not read SSH payloads or passwords.

## Brute-Force Detection

These files are in:

```text
application_source_code/ssh_security_application/ssh_brute_force_detection/
```

### `normalization.py`

This file cleans evidence into a consistent format.

It does things like:

- convert timestamps to UTC;
- normalize IP addresses;
- create stable event IDs;
- create fingerprints for deduplication.

This helps the app avoid counting the same event twice.

### `deduplication.py`

This file has a small duplicate-event cache.

If the same event appears again, this file helps ignore it so the risk score
does not become falsely high.

Important class:

| Class | What it does |
|---|---|
| `EventDeduplicator` | Remembers recent event fingerprints and reports whether a new event is a duplicate. |

### `detection.py`

This is the main brute-force logic.

It combines:

- allowlist checks;
- source IP history;
- event correlation;
- risk scoring;
- classification;
- final block decision.

Important pieces:

| Class or function | What it does |
|---|---|
| `AllowlistManager` | Manages trusted IPs that should not be blocked. |
| `IPProfileManager` | Tracks long-term behavior for a source IP. |
| `correlate_events()` | Groups auth and network events by source IP. |
| `calculate_risk_score()` | Creates an explainable score from evidence. |
| `classify_score()` | Converts the score into a label like `High Risk`. |
| `decide()` | Decides whether to log, simulate a block, or block for real. |
| `DetectionEngine` | Coordinates detection for one IP or all IPs. |

The score considers things like:

- number of failed logins;
- number of usernames tried;
- network connection volume;
- rate of attempts;
- invalid usernames;
- prior history.

## Firewall Response

This file is in:

```text
application_source_code/ssh_security_application/iptables_firewall_response/firewall.py
```

### `firewall.py`

This file contains all real firewall behavior.

It is intentionally centralized so iptables logic is not scattered around the
project.

It handles:

- creating the project chain `SSH_SECURITY_APP`;
- inserting the INPUT jump to that chain;
- creating exact DROP rules;
- checking whether a rule exists;
- removing exact DROP rules;
- reading/parsing existing project rules;
- saving block records in SQLite;
- expiring old blocks;
- reconciling database records with live iptables state.

Important pieces:

| Class or function | What it does |
|---|---|
| `FirewallCommandBuilder` | Builds safe iptables command lists. |
| `FirewallManager` | Runs iptables commands and reports results. |
| `BlockManager` | Creates a temporary block for a detection. |
| `ExpirationWorker` | Removes expired blocks. |
| `FirewallReconciler` | Compares SQLite block state with live iptables rules. |
| `ResponseWorker` | Runs expiration/reconciliation repeatedly in the background. |
| `parse_project_rules()` | Reads project-owned iptables rules and identifies source IPs. |

The expected block rule looks like:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp --dport 22 -j DROP
```

The file is designed to only manage project-owned rules, not flush or rewrite
the whole firewall.

## SQLite Storage

These files are in:

```text
application_source_code/ssh_security_application/sqlite_data_storage/
```

### `schema.sql`

This file defines the database tables.

Tables include:

- authentication events;
- network events;
- IP profiles;
- detections;
- allowlist entries;
- blocks;
- audit records;
- parser errors;
- component health;
- application state.

### `storage.py`

This file handles SQLite.

It combines:

1. Opening database connections.
2. Creating/upgrading tables.
3. Saving and querying all app data.

Important pieces:

| Class | What it stores or manages |
|---|---|
| `Database` | Opens SQLite and runs transactions. |
| `AuthenticationEventRepository` | Saves and queries SSH login events. |
| `NetworkEventRepository` | Saves and queries network events. |
| `DetectionRepository` | Saves and lists detections. |
| `AllowlistRepository` | Saves trusted IPs. |
| `BlockRepository` | Saves active/expired/removed firewall blocks. |
| `AuditRepository` | Saves audit records. |
| `HealthRepository` | Saves component health state. |
| `ApplicationStateRepository` | Saves app-wide state such as current operating mode. |
| `RepositorySet` | Groups all repositories together so other code can access them easily. |

## Configuration Files

### `application_configuration/safe_default_configuration.json`

This is the safe committed default config.

Important point:

```json
"mode": "simulation"
```

Simulation Mode means the app can detect and explain attacks without changing
iptables.

### `application_configuration/ubuntu_kali_lab_configuration.example.json`

This is an example config for the Ubuntu/Kali lab.

It shows values like:

- Ubuntu interface;
- tcpdump path;
- iptables path;
- protected Ubuntu IP addresses;
- database path;
- log path.

### `application_source_code/ssh_security_application/default_config.json`

This is the packaged copy of the safe default config.

It exists so the installed version in `/opt/ssh-security-application` can load
defaults even when it is no longer running directly from the Git repo.

## Installation and Service Setup Scripts

These files are in:

```text
installation_and_service_setup/
```

### `setup_live_lab.py`

Advanced direct live-lab installer.

It calls `live_lab_setup.py` and is useful if you want the full command instead
of the simpler `run_lab.py`.

### `setup_test_environment.py`

Prepares local simulation testing.

Use this when you want local config and database setup without installing the
full production service under `/opt`.

### `initialize_database.py`

Runs the app's `init-db` command.

It creates or updates SQLite tables.

### `initialize_firewall.py`

Runs the app's `firewall-init` command.

It creates only the dedicated project chain and jump needed for blocking.

### `cleanup_firewall.py`

Runs the app's `firewall-cleanup` command.

It removes only recognized project-owned firewall rules and the project chain.

### `run_auth_collector.py`

Runs only authentication collection.

Useful for testing OpenSSH log parsing by itself.

### `run_network_collector.py`

Runs only network metadata collection.

Useful for testing tcpdump parsing by itself.

### `run_detection.py`

Runs detection against stored evidence.

Useful after manually collecting fixture or live evidence.

## Systemd Files

### `ssh-security-application-firewall.service`

This service initializes the project firewall chain before the main app runs.

It exists so the main app can safely add temporary DROP rules later.

### `ssh-security-application.service`

This is the main background service.

It runs:

```bash
ssh-security-app --config /etc/ssh-security-app/config.json monitor
```

That starts continuous evidence collection, detection, blocking, and expiration.

### `ssh-security-application-tmpfiles.conf`

This tells Linux to create runtime directories with the correct owner and
permissions.

## Documentation Files

### `README.md`

The main tutorial.

It explains:

- project purpose;
- lab topology;
- setup;
- live demo;
- troubleshooting.

### `project_documentation/code_file_guide.md`

A shorter map of the source files and what they do.

### `project_documentation/beginner_code_walkthrough.md`

This file. It gives a more beginner-friendly explanation of the whole codebase.

### `project_documentation/project_overview.md`

Explains the project goal and final terminal-first design.

### `project_documentation/system_architecture.md`

Explains the high-level design and how data moves through the system.

### `project_documentation/database_structure.md`

Explains the SQLite tables.

### `project_documentation/firewall_safety_rules.md`

Explains the firewall safety rules and why the app only manages its own chain.

### `project_documentation/terminal_commands.md`

Lists useful terminal commands.

### `project_documentation/verification_procedures.md`

Explains how to test the app.

### `project_documentation/recovery_and_cleanup.md`

Explains how to recover if something goes wrong or clean up firewall state.

## Verification and Validation Files

These files are automated tests. They are not part of the running app, but they
prove the app still works after changes.

### `verification_and_validation/conftest.py`

Shared pytest setup.

Pytest automatically loads this file before tests run.

### Complete Workflow Tests

These files test whole workflows, not just one small function.

| File | What it checks |
|---|---|
| `verify_authentication_pipeline.py` | Auth log collection, parsing, storage, and health updates. |
| `verify_network_pipeline.py` | Network fixture parsing, storage, and health updates. |
| `verify_detection_pipeline.py` | Evidence collection plus detection/scoring. |
| `verify_automatic_response_pipeline.py` | Detection plus firewall-block behavior in a safe fake firewall. |

### Individual Component Tests

These files test smaller parts of the system.

| File | What it checks |
|---|---|
| `verify_allowlist.py` | Trusted IP add/list/remove behavior. |
| `verify_auth_journal.py` | OpenSSH journal collector behavior. |
| `verify_auth_parser.py` | OpenSSH log parser behavior. |
| `verify_block_manager.py` | Temporary block creation logic. |
| `verify_classification.py` | Score-to-decision logic. |
| `verify_config.py` | Config loading and validation. |
| `verify_correlation.py` | Matching auth and network events by source IP. |
| `verify_database.py` | SQLite schema and repository behavior. |
| `verify_firewall_manager.py` | Safe iptables command construction and rule handling. |
| `verify_ip_validation.py` | IP validation and safety checks. |
| `verify_live_lab_setup.py` | Live-lab installer planning and safety behavior. |
| `verify_main.py` | CLI commands. |
| `verify_modes.py` | Simulation/log-only/automatic response mode tracking. |
| `verify_network_collector.py` | tcpdump collector behavior. |
| `verify_network_parser.py` | tcpdump line parser behavior. |
| `verify_normalization.py` | Timestamp/IP normalization and fingerprints. |
| `verify_one_command_ubuntu_kali_lab_workflow.py` | `run_lab.py` one-command workflow behavior. |
| `verify_response_worker.py` | Background expiration and reconciliation worker. |
| `verify_risk_score.py` | Risk score calculation. |
| `verify_service.py` | Long-running app controller. |
| `verify_setup_environment.py` | Local setup helper behavior. |
| `verify_stage7_response.py` | Firewall response, expiration, reconciliation, and manual unblock behavior. |

### Sample Input Evidence

These are fake log files used by tests and fixture demos.

| File | What it contains |
|---|---|
| `auth_bruteforce.log` | OpenSSH auth messages that look like brute force. |
| `auth_invalid_users.log` | OpenSSH auth messages with invalid usernames. |
| `auth_malformed.log` | Bad auth lines used to test parser errors. |
| `auth_normal.log` | Normal auth activity. |
| `network_bruteforce.log` | tcpdump-style network events that match brute-force activity. |
| `network_malformed.log` | Bad network lines used to test parser errors. |
| `network_normal.log` | Normal network activity. |

## How to Read the Project Without Getting Lost

Use this order:

1. Start with `README.md` to understand the project goal.
2. Read `run_lab.py` to see the easiest startup command.
3. Read `lab.py` and `live_lab_setup.py` to understand setup.
4. Read `main.py` to understand the terminal commands.
5. Read `auth.py` and `network.py` to understand evidence collection.
6. Read `detection.py` to understand brute-force detection.
7. Read `firewall.py` to understand blocking and unblocking.
8. Read `storage.py` and `schema.sql` to understand saved data.
9. Read the tests only when you want to see examples of expected behavior.

## The Short Version

If someone asks what the code does, say:

> The project is a terminal-based SSH brute-force detection and response tool.
> It runs on an Ubuntu Security VM, watches OpenSSH logs and SSH network
> metadata, stores evidence in SQLite, scores source IPs for brute-force
> behavior, and temporarily blocks high-risk IPs with a dedicated iptables
> chain. It includes a one-command Ubuntu/Kali lab setup and automated tests.
