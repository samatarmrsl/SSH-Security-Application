# SSH Security Application Walkthrough for Presentation

This document explains the full process of the SSH Security Application in plain language. It is written so you can read it before a demonstration and explain the project clearly to someone else, such as a professor.

## 1. Project Purpose

The SSH Security Application is a custom Python tool that detects SSH brute-force attacks in an authorized lab environment.

The project watches an Ubuntu Security VM for suspicious SSH activity. When another machine repeatedly tries to log in over SSH with wrong usernames or passwords, the application:

1. collects SSH login failure evidence from the Ubuntu authentication logs;
2. collects network connection metadata for traffic going to TCP port 22;
3. stores the evidence in a SQLite database;
4. groups activity by source IP address;
5. calculates a risk score;
6. decides whether the activity looks like a brute-force attack;
7. temporarily blocks the attacking IP address using `iptables`;
8. removes the block automatically after a short demo-friendly timeout.

The important point is that this is not the existing Linux tool called `sshguard`. This is a custom Python implementation made for this project.

## 2. Lab Infrastructure

The reference demonstration uses two virtual machines.

| Machine | Operating system | Example IP address | Purpose |
|---|---|---|---|
| Security VM | Ubuntu 20.04 | `192.168.12.1` | Runs OpenSSH and the SSH Security Application |
| Attacker VM | Kali Linux | `192.168.12.3` | Runs authorized test traffic against the Security VM |

The Security VM is the protected machine. The Kali VM is used only to generate controlled test traffic in the lab.

The protected service is SSH, which normally listens on TCP port `22`.

## 3. Main Command Used for the Demo

On the Ubuntu Security VM, the main command is:

```bash
cd /home/et-1/Documents/SSH-Security-Application
python3 run_lab.py --apply --watch
```

This command is designed to make the setup simple. Instead of running many commands manually, `run_lab.py` handles setup, installation, service startup, firewall preparation, and live log watching.

## 4. What Happens When `run_lab.py --apply --watch` Starts

When the command starts, it prints a live-lab plan similar to this:

```text
SSH Security Application live-lab plan:
  repository: /home/et-1/Documents/SSH-Security-Application
  lab interface: ens37
  server IPv4: 192.168.12.1
  disposable client IPv4: 192.168.12.3
  protected server addresses: 192.168.13.128, 192.168.12.1
  SSH endpoint: 192.168.12.1:22
  response mode: automatic_response
  block duration: 120 seconds
  host firewall frontend: none
  lab iptables reset: yes; filter table policies set to ACCEPT and custom chains flushed
  project chain: SSH_SECURITY_APP
```

This plan is the application telling you what it is about to configure.

The important fields are:

- `repository`: where the project source code is located.
- `lab interface`: the Ubuntu network interface connected to the Kali lab network.
- `server IPv4`: the Ubuntu Security VM address that Kali attacks.
- `disposable client IPv4`: the Kali attacker address that is allowed to be blocked during testing.
- `SSH endpoint`: the exact target service being protected.
- `response mode`: `automatic_response` means the application can block attackers automatically.
- `block duration`: how long the temporary block lasts.
- `lab iptables reset`: old firewall rules are cleared from the filter table so the demo starts from a clean state.
- `project chain`: the custom `iptables` chain used by this application.

## 5. Why the Lab iptables Reset Exists

Earlier testing showed that Kali could sometimes be blocked before the new test started. That can happen when old firewall rules are left over from previous experiments.

To make the demonstration predictable, the setup now resets the lab firewall filter table before installing the project firewall chain.

The setup sets the filter-table policies to `ACCEPT`, flushes old filter rules, and deletes old custom filter chains. After that, the application creates its own project-owned chain named:

```text
SSH_SECURITY_APP
```

This makes the starting point clear:

1. Kali should be able to reach Ubuntu SSH before detection.
2. The application watches the evidence.
3. The application blocks Kali only after the brute-force conditions are met.

This reset is intended for the isolated lab environment, not for a production server.

## 6. Package and Service Setup

The setup installs or verifies required Ubuntu packages:

```text
python3
python3-venv
python3-pip
iptables
libcap2-bin
openssh-server
rsync
sqlite3
tcpdump
```

These packages are used for:

- Python execution and virtual environment support;
- OpenSSH server so there is an SSH service to protect;
- `iptables` so the app can block an attacking IP;
- `tcpdump` so the app can observe TCP/22 connection metadata;
- SQLite so detections and blocks can be stored locally;
- system tools needed for installation and verification.

The setup also enables and starts OpenSSH:

```text
Synchronizing state of ssh.service with SysV service script...
```

That means Ubuntu is making sure the SSH service starts now and also starts automatically after reboot.

## 7. Application Installation Location

The setup installs the project into:

```text
/opt/ssh-security-application
```

The production Python virtual environment is:

```text
/opt/ssh-security-application/.venv
```

The production command-line tool is:

```text
/opt/ssh-security-application/.venv/bin/ssh-security-app
```

The production configuration file is:

```text
/etc/ssh-security-app/config.json
```

The production SQLite database is:

```text
/var/lib/ssh-security-app/ssh_security_application.db
```

## 8. Post-Install Verification

After setup, the command prints checks like this:

```text
Post-install verification:
  [PASS] ssh.service: active
  [PASS] ssh-security-application-firewall.service: active
  [PASS] ssh-security-application.service: active
  [PASS] production configuration: /etc/ssh-security-app/config.json
  [PASS] project firewall chain: SSH_SECURITY_APP
  [PASS] host firewall access path: none
  [PASS] disposable client baseline: not blocked
  [PASS] SSH listener: 192.168.12.1:22
```

These checks mean:

- OpenSSH is running.
- The firewall setup service ran successfully.
- The main monitoring service is running.
- The configuration file exists and is valid.
- The project `iptables` chain exists.
- No separate UFW or firewalld path is currently controlling access.
- The Kali IP is not blocked at the start.
- Ubuntu is listening for SSH connections on `192.168.12.1:22`.

If all of these are marked `[PASS]`, the infrastructure is ready for testing.

## 9. Live Monitoring Output

After setup, the command follows the systemd logs:

```text
Following ssh-security-application.service. Press Ctrl+C to stop watching logs.
```

The application then prints startup information:

```text
SSH SECURITY APPLICATION
Mode: AUTOMATIC_RESPONSE
Protected service: 192.168.13.128, 192.168.12.1:22
Authentication source: ssh.service
Network interface: ens37
Firewall chain: SSH_SECURITY_APP
Firewall ready: YES
Press Ctrl+C to stop monitoring.
```

This means the monitoring service is running and ready to observe SSH activity.

## 10. Network Evidence

When Kali connects to SSH, the app may print network metadata like this:

```text
[11:00:57] NETWORK  TCP/22 metadata
                     Source IP: 192.168.12.3:37134
                     Destination: 192.168.12.1:22
                     Interface: ens37
                     TCP flags: S
```

This is not a login failure yet. It is network-level evidence.

It means:

- source IP `192.168.12.3` opened a connection;
- source port `37134` was used by Kali for that connection;
- destination was Ubuntu SSH on `192.168.12.1:22`;
- the traffic arrived on interface `ens37`;
- TCP flag `S` means a connection attempt started.

Other TCP flags may appear:

- `S`: connection start/SYN;
- `.`: acknowledgement/normal packet;
- `R`: reset;
- `F`: finish/close.

The application uses this information as supporting evidence. Network packets alone do not prove a brute-force attack. The strongest evidence comes from repeated SSH authentication failures.

## 11. Authentication Evidence

When Hydra or another test tool tries invalid SSH usernames or passwords, OpenSSH records failed login messages in the system journal.

The application reads those SSH authentication messages from `ssh.service`, parses them, and stores the important parts:

- source IP;
- username attempted;
- whether the login failed or succeeded;
- timestamp;
- authentication message type.

This is what lets the application distinguish normal network scanning from actual failed login attempts.

## 12. Detection Alert

When enough suspicious evidence is collected, the app prints an alert like this:

```text
[11:04:07] ALERT    Possible SSH brute-force activity
                     Source IP: 192.168.12.3
                     Window: 2026-08-06 10:59:07 PDT -> 2026-08-06 11:04:07 PDT
                     Failures: 10
                     Unique usernames: 2
                     TCP/22 connections: 155
                     Attempts per minute: 2.0
```

This means the app grouped recent activity from `192.168.12.3` and decided it looked suspicious.

The fields mean:

- `Source IP`: the machine being evaluated.
- `Window`: the time period being analyzed.
- `Failures`: how many failed SSH logins were seen during that window.
- `Unique usernames`: how many different usernames were tried.
- `TCP/22 connections`: how much SSH network traffic was observed.
- `Attempts per minute`: the approximate rate of failed attempts.

For a brute-force demo, the key sign is many failures from the same source IP in a short period of time.

## 13. Source Machine Information

The alert also shows local information about the source:

```text
Source machine info: local observations only
IP category: Private
First seen: 2026-08-06 10:34:27 PDT
Last seen: 2026-08-06 11:04:02 PDT
Total failed SSH logins: 10
Total successful SSH logins: 0
Detections recorded: 21
Blocks recorded: 2
Current block status: Active
Usernames attempted: demo_admin, demo_backup
TCP source ports seen: 32846, 34934, 42042, 49486, 49496, 55760
TCP flags seen: ., FP., R, S
```

This section explains what the Security VM knows about the source based on local evidence.

It does not claim to know the attacker's operating system, hostname, owner, or real-world identity. Since `192.168.12.3` is a private lab IP address, the app correctly labels it as `Private`.

This information is useful during a demonstration because it shows:

- when the IP was first observed;
- when it was last observed;
- whether the source has failed or successful logins;
- how many detections and blocks have been recorded;
- which usernames were attempted;
- which TCP source ports appeared in network metadata.

## 14. Risk Score

The app prints a risk score like this:

```text
[11:04:07] SCORE    Risk score: 85/100
                     Classification: HIGH RISK
                     Attempt Rate: 10
                     Failed Authentication Volume: 40
                     Invalid User Activity: 5
                     Network Corroboration: 15
                     Previous History: 10
                     Recent Success Adjustment: 0
                     Total: 85
                     Username Diversity: 5
```

The score explains why the source was considered suspicious.

The categories mean:

- `Attempt Rate`: how fast the failed login attempts are happening.
- `Failed Authentication Volume`: how many failed SSH logins were seen.
- `Invalid User Activity`: whether invalid/nonexistent usernames were tried.
- `Network Corroboration`: whether TCP/22 network activity supports the login evidence.
- `Previous History`: whether the source IP has been suspicious before.
- `Recent Success Adjustment`: reduces risk if there was a legitimate recent successful login.
- `Total`: the final score out of 100.

In this example, `85/100` is classified as `HIGH RISK`.

## 15. Decision Output

After scoring, the app prints a decision.

Example:

```text
[11:06:18] DECISION BLOCK
                     Reason: All automatic-response safety conditions passed
```

This means the app decided to block the source IP.

Another example is:

```text
[11:03:57] DECISION SUPPRESS_ALREADY_BLOCKED
                     Reason: Source already has an active block
```

That means the app detected suspicious behavior, but it did not add another duplicate firewall rule because the IP was already blocked.

Another example is:

```text
[11:06:28] DECISION LOG_DETECTION
                     Reason: Suspicious activity is logged but does not meet the high-risk threshold
```

That means the app recorded the suspicious activity but did not block because the current evidence was not strong enough.

## 16. Blocking Output

When the application blocks Kali, it prints:

```text
[11:06:18] BLOCK    source blocked until 2026-08-06T18:08:18.759078+00:00
                     Source IP: 192.168.12.3
                     Expires: 2026-08-06 11:08:18 PDT
```

This means Kali has been temporarily blocked.

The block expiration is shown in local time so it is easy to explain during a live demo.

## 17. Exact iptables Rules

The app also prints the exact firewall rules:

```text
[11:06:18] RULE     INPUT jump: -A INPUT -p tcp --dport 22 -j SSH_SECURITY_APP
[11:06:18] RULE     DROP rule: -A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp --dport 22 -j DROP
```

These two rules work together.

The INPUT jump rule sends SSH traffic into the project chain:

```text
-A INPUT -p tcp --dport 22 -j SSH_SECURITY_APP
```

The DROP rule blocks the attacker IP from reaching SSH:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp --dport 22 -j DROP
```

This is the most important proof that the application took an actual firewall response action.

## 18. Automatic Unblock

After the temporary block expires, the app prints:

```text
[11:06:01] UNBLOCK  Temporary block expired
                     Source IP: 192.168.12.3
                     Exact rule removed: YES
                     Database updated: YES
                     Firewall: exact block rule deleted
```

This means:

- the temporary block timer ended;
- the exact `iptables` DROP rule was removed;
- the database record was updated;
- Kali should be able to connect to SSH again after the block expires.

For the demo configuration, the block duration is about 120 seconds.

## 19. Kali Demo Commands

On Kali, first create a demo folder:

```bash
mkdir -p ~/ssh-security-demo
cd ~/ssh-security-demo
```

Create test usernames:

```bash
printf '%s\n' \
demo_admin \
demo_backup \
demo_database \
demo_operator \
demo_service \
demo_support > usernames.txt
```

Create test passwords:

```bash
printf '%s\n' \
WrongPassword1 \
WrongPassword2 \
WrongPassword3 \
WrongPassword4 \
WrongPassword5 > passwords.txt
```

Before running Hydra, verify that SSH is reachable:

```bash
nc -vz -w 5 192.168.12.1 22
```

Run the authorized brute-force simulation:

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

Expected demo behavior:

1. The Security VM logs network metadata.
2. OpenSSH records failed login attempts.
3. The app groups the failures by Kali IP.
4. The risk score increases.
5. The app prints an alert.
6. The app blocks `192.168.12.3`.
7. Kali SSH attempts time out while blocked.
8. The app removes the block after about 120 seconds.

## 20. How to Manually Check the Firewall

On Ubuntu, show the project chain:

```bash
sudo iptables -S SSH_SECURITY_APP
```

During a block, you should see a rule similar to:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp -m tcp --dport 22 -j DROP
```

Show INPUT rules:

```bash
sudo iptables -S INPUT
```

You should see a jump rule similar to:

```text
-A INPUT -p tcp -m tcp --dport 22 -j SSH_SECURITY_APP
```

View active and past blocks from the application:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json blocks
```

View exact project rules from the application:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json rules
```

## 21. Main Project Files and What They Do

The project was simplified so the most important logic is easier to find.

| File | Purpose |
|---|---|
| `run_lab.py` | The main one-command launcher. This is the command you run for setup and live watching. |
| `application_source_code/ssh_security_application/lab.py` | Parses the simple lab command and forwards the correct options to the live-lab setup code. |
| `application_source_code/ssh_security_application/live_lab_setup.py` | Performs the full Ubuntu/Kali lab setup: package checks, SSH setup, iptables reset, app install, config creation, service install, and verification. |
| `application_source_code/ssh_security_application/main.py` | Main command-line application. Handles commands like `status`, `monitor`, `rules`, `blocks`, `unblock`, and `validate-config`. |
| `application_source_code/ssh_security_application/service.py` | Core monitoring logic. Coordinates authentication collection, network collection, detection, blocking, and unblock expiration. |
| `application_source_code/ssh_security_application/terminal.py` | Controls the human-readable terminal output shown during the live demo. |
| `application_source_code/ssh_security_application/config.py` | Loads and validates configuration files. |
| `application_source_code/ssh_security_application/models.py` | Defines the main data structures used by the app, such as events, detections, scores, and block responses. |
| `application_source_code/ssh_security_application/audit.py` | Handles structured audit logging. |
| `application_source_code/ssh_security_application/health.py` | Performs status checks for the app, database, firewall, and services. |
| `application_source_code/ssh_security_application/ip_validation.py` | Validates IP addresses and prevents unsafe firewall targeting. |
| `application_source_code/ssh_security_application/modes.py` | Defines safe operating modes, including simulation and automatic response. |
| `application_source_code/ssh_security_application/default_config.json` | Default packaged configuration used by the app. |
| `application_configuration/safe_default_configuration.json` | Safer default configuration example. |
| `application_configuration/ubuntu_kali_lab_configuration.example.json` | Example configuration for the Ubuntu/Kali lab. |
| `installation_and_service_setup/*.service` | systemd service files that keep the firewall chain and monitoring app running. |
| `verification_and_validation/` | Automated tests that verify components and full workflows. |

## 22. Which Code Handles Each Demo Step

| Demo step | Main code involved |
|---|---|
| Start one-command setup | `run_lab.py`, `lab.py` |
| Build setup plan | `live_lab_setup.py` |
| Install/check packages | `live_lab_setup.py` |
| Enable OpenSSH | `live_lab_setup.py` |
| Reset lab iptables | `live_lab_setup.py` |
| Install app to `/opt` | `live_lab_setup.py` |
| Write production config | `live_lab_setup.py`, `config.py` |
| Initialize database | `main.py`, `service.py` |
| Install/start systemd services | `live_lab_setup.py`, files in `installation_and_service_setup/` |
| Watch service logs | `live_lab_setup.py` |
| Read SSH auth logs | `service.py` |
| Read TCP/22 metadata | `service.py` |
| Store evidence in SQLite | `service.py`, `models.py` |
| Score suspicious IPs | `service.py`, `models.py` |
| Decide whether to block | `service.py`, `modes.py` |
| Add iptables DROP rule | `service.py`, `ip_validation.py` |
| Print live explanation | `terminal.py` |
| Remove expired block | `service.py` |
| Show status/rules/blocks | `main.py`, `health.py`, `terminal.py` |

## 23. Simple Explanation You Can Say During a Presentation

This project is a custom SSH brute-force detection and response application.

The Ubuntu VM runs OpenSSH and the security application. The Kali VM acts as the attacker in an authorized lab. When Kali tries many invalid SSH logins, Ubuntu records those failures. The application reads those logs, also watches network metadata for TCP port 22, stores the evidence, and calculates a risk score for the source IP address.

If the score and safety checks show a likely brute-force attack, the application creates an `iptables` DROP rule in its own chain named `SSH_SECURITY_APP`. That rule temporarily blocks the attacker from reaching SSH. The block is short, about two minutes, so the behavior can be demonstrated quickly. After the timer expires, the application removes the exact firewall rule and records the unblock in the database.

The terminal output is meant to make the process explainable. It shows the evidence, the risk score, the decision, the source IP information, the exact firewall rule, and the unblock event.

## 24. Common Troubleshooting Points

### Kali cannot reach SSH before the test

Check that SSH is running on Ubuntu:

```bash
sudo systemctl status ssh.service --no-pager
sudo ss -lntp | grep ':22'
```

Check from Kali:

```bash
nc -vz -w 5 192.168.12.1 22
```

If it times out before the test, rerun the lab setup so old filter rules are cleared:

```bash
cd /home/et-1/Documents/SSH-Security-Application
python3 run_lab.py --apply --watch
```

### The app says the source is already blocked

This means the database or firewall still has an active block record. Wait for the two-minute expiration or manually unblock:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json unblock 192.168.12.3
```

### The app logs network traffic but does not block

Network traffic alone is not enough. A real detection needs repeated SSH authentication failures. A simple `nc` connection test only proves that port 22 is reachable. Hydra or repeated invalid SSH logins create the authentication failures needed for detection.

### The output shows `LOG_DETECTION` instead of `BLOCK`

The app recorded suspicious activity, but the evidence did not meet the blocking threshold at that moment. Continue the authorized test or check the failed login count.

### The output shows systemd snap warnings

Warnings about `snapd` or snap mount units are unrelated to this project as long as the post-install verification checks show `[PASS]` for the SSH Security Application services.

## 25. Final Demo Checklist

Before presenting:

1. Start the Ubuntu Security VM.
2. Start the Kali VM.
3. Confirm Ubuntu IP is `192.168.12.1`.
4. Confirm Kali IP is `192.168.12.3`.
5. On Ubuntu, run:

```bash
cd /home/et-1/Documents/SSH-Security-Application
python3 run_lab.py --apply --watch
```

6. Wait for all post-install checks to show `[PASS]`.
7. On Kali, confirm SSH is reachable:

```bash
nc -vz -w 5 192.168.12.1 22
```

8. Run the Hydra test from Kali.
9. Watch Ubuntu terminal output for:

- `NETWORK`;
- `ALERT`;
- `SCORE`;
- `DECISION BLOCK`;
- `RULE`;
- `UNBLOCK`.

10. Explain that the project detected repeated failed SSH logins, scored the risk, blocked the attacker with `iptables`, and then removed the block automatically.
