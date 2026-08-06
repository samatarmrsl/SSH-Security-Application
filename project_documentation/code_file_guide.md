# Code File Guide

This guide keeps filenames short while explaining what each file is responsible
for. Use this as the map when you want to find a specific part of the project.

For a more detailed beginner explanation, read
`project_documentation/beginner_code_walkthrough.md`.

## Top-Level Application Files

| File | Purpose |
|---|---|
| `main.py` | Defines the `ssh-security-app` terminal command and routes each subcommand to the correct code. |
| `lab.py` | Provides the simple one-command Ubuntu/Kali setup wrapper used by `run_lab.py`. |
| `live_lab_setup.py` | Installs the production lab under `/opt`, writes `/etc/ssh-security-app/config.json`, starts services, and verifies the live lab. |
| `setup_environment.py` | Prepares a local development/simulation setup with SSH, tcpdump capability, config, and database. |
| `service.py` | Runs the long-lived monitor loop that collects evidence, detects attacks, and manages response workers. |
| `terminal.py` | Prints readable terminal tables, alerts, block rules, and unblock messages. |
| `config.py` | Loads the default JSON config and merges local overrides. |
| `models.py` | Defines the data records used across the app, such as events, detections, and blocks. |
| `constants.py` | Defines fixed status/decision names such as `BLOCK`, `WOULD_BLOCK`, and health states. |
| `audit.py` | Writes security/audit records to logs and SQLite. |
| `health.py` | Records whether collectors, detection, firewall, and database components are healthy. |
| `modes.py` | Tracks whether the app is in Simulation Mode or Automatic Response Mode. |
| `ip_validation.py` | Validates IP addresses before they are stored, allowlisted, or blocked. |

## Evidence Collection Files

| File | Purpose |
|---|---|
| `auth.py` | Reads OpenSSH logs, parses authentication messages, validates them, deduplicates them, and stores them in SQLite. |
| `network.py` | Captures TCP/22 metadata with tcpdump, parses packet lines, validates them, deduplicates them, and stores them in SQLite. |

## Detection Files

| File | Purpose |
|---|---|
| `detection.py` | Handles allowlist checks, groups events by source IP, calculates risk score, classifies the result, and decides whether to block. |
| `normalization.py` | Normalizes timestamps/IPs and creates stable event IDs/fingerprints. |
| `deduplication.py` | Prevents the same evidence event from being counted twice. |

## Firewall Response Files

| File | Purpose |
|---|---|
| `firewall.py` | Creates project-owned `iptables` rules, parses rules, blocks offending IPs, removes expired blocks, and reconciles SQLite with live firewall state. |

## SQLite Storage Files

| File | Purpose |
|---|---|
| `storage.py` | Opens SQLite connections, initializes tables, manages transactions, and saves/queries all app data. |
| `schema.sql` | Defines the SQLite tables and indexes. |

## Setup Helper Scripts

| File | Purpose |
|---|---|
| `run_lab.py` | Main one-command setup/start/watch entry point from the repo root. |
| `setup_live_lab.py` | Advanced direct live-lab installer script. |
| `setup_test_environment.py` | Advanced local simulation setup script. |
| `initialize_database.py` | Initializes the SQLite database. |
| `initialize_firewall.py` | Creates the dedicated project firewall chain. |
| `cleanup_firewall.py` | Removes only project-owned firewall rules and chain. |
| `run_auth_collector.py` | Runs only the OpenSSH authentication collector. |
| `run_network_collector.py` | Runs only the TCP/22 network metadata collector. |
| `run_detection.py` | Runs stored-evidence detection manually. |
