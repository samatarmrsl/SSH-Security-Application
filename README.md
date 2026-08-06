> [!NOTE]
> This project was created with the help of OpenAI Codex.

# SSH Security Application

A simple terminal-based SSH brute-force detection and response tool for an
authorized Ubuntu/Kali lab.

## Purpose

This project helps detect SSH brute-force activity against an Ubuntu server. It
monitors OpenSSH login failures and SSH network metadata, calculates a risk
score for source IP addresses, and can temporarily block high-risk IPs with a
dedicated `iptables` chain.

The project is custom Python code. It is not `sshguard`, and it does not use a
browser dashboard.

## Intended Users

This tool is intended for students, instructors, lab administrators, and security
learners who want a clear demonstration of how SSH brute-force detection and
temporary firewall blocking can work.

It is designed for an isolated lab environment where you are authorized to test.
The reference setup is:

| Machine | OS | IP address | Purpose |
|---|---|---|---|
| Security VM | Ubuntu 20.04 | `192.168.12.1` | Runs OpenSSH and this application |
| Attacker VM | Kali Linux | `192.168.12.3` | Generates authorized test traffic |

## Quick Setup

Run this on the Ubuntu Security VM:

```bash
cd /home/et-1/Documents/SSH-Security-Application
python3 run_lab.py --apply --watch
```

This one command:

- installs required packages if needed;
- enables OpenSSH;
- gives `tcpdump` capture capability;
- installs the app under `/opt/ssh-security-application`;
- writes config to `/etc/ssh-security-app/config.json`;
- creates the SQLite database;
- creates the `SSH_SECURITY_APP` iptables chain;
- starts the systemd services;
- watches live logs.

Default lab values:

```text
Ubuntu interface: ens37
Ubuntu IP:        192.168.12.1
Kali IP:          192.168.12.3
SSH port:         22
Block duration:   120 seconds
```

If your lab values are different:

```bash
python3 run_lab.py \
  --lab-interface ens37 \
  --server-ip 192.168.12.1 \
  --client-ip 192.168.12.3 \
  --block-duration-seconds 120 \
  --apply \
  --watch
```

## Main Commands

After setup, use the production command:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json status
```

Useful commands:

| Command | What it does |
|---|---|
| `status` | Shows application mode, database status, firewall status, and counts. |
| `detections` | Shows recent SSH brute-force detections. |
| `blocks` | Shows active and recently removed IP blocks. |
| `rules` | Shows the exact project-owned iptables rules. |
| `unblock <ip>` | Manually removes an active temporary block. |
| `allowlist list` | Shows trusted IPs that should not be blocked. |
| `monitor` | Runs live evidence collection, detection, blocking, and expiration. |

Examples:

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json rules
```

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json blocks
```

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json unblock 192.168.12.3
```

Watch the running service:

```bash
sudo journalctl -fu ssh-security-application.service
```

## Kali Test

Run this only in your authorized lab.

On Kali:

```bash
mkdir -p ~/ssh-security-demo
cd ~/ssh-security-demo
```

```bash
printf '%s\n' \
demo_admin \
demo_backup \
demo_database \
demo_operator \
demo_service \
demo_support > usernames.txt
```

```bash
printf '%s\n' \
WrongPassword1 \
WrongPassword2 \
WrongPassword3 \
WrongPassword4 \
WrongPassword5 > passwords.txt
```

Check SSH access before the attack:

```bash
nc -vz -w 5 192.168.12.1 22
```

Run the test:

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

Expected result:

- Ubuntu logs show failed SSH login evidence.
- The app detects the brute-force behavior.
- The app adds a temporary iptables DROP rule for `192.168.12.3`.
- Kali SSH attempts time out during the block.
- The block is removed automatically after about 120 seconds.

Expected rule during the block:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp --dport 22 -j DROP
```

## Troubleshooting

### SSH is not reachable from Kali

On Ubuntu:

```bash
sudo systemctl status ssh.service --no-pager
sudo ss -lntp | grep ':22'
```

On Kali:

```bash
ping -c 3 192.168.12.1
nc -vz -w 5 192.168.12.1 22
```

### Project firewall chain is missing

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json rules
```

If needed, rerun:

```bash
cd /home/et-1/Documents/SSH-Security-Application
python3 run_lab.py --apply --watch
```

### Kali is blocked and you need to unblock it now

```bash
sudo /opt/ssh-security-application/.venv/bin/ssh-security-app \
  --config /etc/ssh-security-app/config.json unblock 192.168.12.3
```

### tcpdump cannot capture

```bash
getcap "$(command -v tcpdump)"
```

Expected output should include:

```text
cap_net_admin,cap_net_raw=eip
```

### Service logs

```bash
sudo journalctl -u ssh-security-application.service --no-pager -n 80
```

## More Documentation

- `project_documentation/beginner_code_walkthrough.md`
- `project_documentation/code_file_guide.md`
- `project_documentation/firewall_safety_rules.md`
