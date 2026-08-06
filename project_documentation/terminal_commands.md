# Terminal Commands

One-command full Ubuntu/Kali setup, startup, verification, and log watching:

```bash
python3 run_lab.py --apply --watch
```

Main commands:

```bash
ssh-security-app status
ssh-security-app detections --limit 20
ssh-security-app blocks --limit 20
sudo ssh-security-app rules
sudo ssh-security-app unblock 192.168.12.3
sudo ssh-security-app monitor
```

Allowlist:

```bash
ssh-security-app allowlist add 192.168.12.2 --reason "Administrator workstation"
ssh-security-app allowlist list
ssh-security-app allowlist remove <allowlist-id>
```

Setup and verification commands usually include an explicit config:

```bash
ssh-security-app --config config/local.json status
```

Automatic Response firewall setup:

```bash
sudo ssh-security-app --config config/local.json firewall-init \
  --confirm-firewall-changes
```
