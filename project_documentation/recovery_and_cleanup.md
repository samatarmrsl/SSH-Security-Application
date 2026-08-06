# Recovery and Cleanup

Show project-owned firewall state:

```bash
sudo ssh-security-app --config config/local.json rules
```

Remove one active block:

```bash
sudo ssh-security-app --config config/local.json unblock 192.168.12.3
```

Clean only recognized project firewall rules:

```bash
sudo ssh-security-app --config config/local.json firewall-cleanup \
  --confirm-firewall-changes
```

The cleanup command does not flush iptables, does not change default policies,
and refuses broad cleanup when rule ownership is uncertain.

If SQLite is damaged, move it aside instead of deleting it:

```bash
mkdir -p backups
cp -a data/ssh_security_application.db backups/ssh_security_application.db.damaged
mv data/ssh_security_application.db data/ssh_security_application.db.previous
ssh-security-app --config config/local.json init-db
```
