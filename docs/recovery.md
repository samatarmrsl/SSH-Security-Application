# Recovery

## Inspect before changing anything

```bash
sudo iptables -S INPUT
sudo iptables -S SSH_SECURITY_APP
ssh-security-app --config config/local.json firewall-status
ssh-security-app --config config/local.json response-reconcile
```

## Stop managed processes

```bash
sudo systemctl stop ssh-security-app-dashboard.service
sudo systemctl stop ssh-security-app.service
sudo systemctl stop ssh-security-app-firewall.service
```

For the automated production installation, stopping
`ssh-security-app-firewall.service` invokes the same guarded cleanup against
`/etc/ssh-security-app/config.json`. Continue with the direct helper only for a
foreground/development installation or when diagnosing why the unit stopped.

## Safe project cleanup

The cleanup helper parses every project-chain rule first. It refuses cleanup if
the chain contains an unknown or duplicate rule. If validation succeeds, it
deletes recognized exact source rules one at a time, removes the exact TCP/SSH
`INPUT` jump, and then removes the empty project chain.

```bash
sudo "$(pwd)/.venv/bin/python" scripts/cleanup_firewall.py \
  --config "$(pwd)/config/local.json" \
  --confirm-firewall-changes
```

It never flushes a chain, changes a policy, restores a whole firewall ruleset,
or deletes an unknown rule.

## An unknown rule prevents cleanup

Do not force cleanup. Preserve evidence and inspect the exact line:

```bash
mkdir -p backups
sudo iptables-save > backups/iptables.recovery-review.rules
sudo iptables -S SSH_SECURITY_APP
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT event_time,action,result,details FROM audit_log WHERE component='firewall_reconciler' ORDER BY event_time DESC;"
```

Resolve ownership with the lab operator before making a narrow, explicit
change.

## Database recovery

```bash
sudo systemctl stop ssh-security-app-dashboard.service ssh-security-app.service
sudo systemctl stop ssh-security-app-firewall.service
mkdir -p backups
cp -a data/ssh_security_app.db backups/ssh_security_app.db.damaged
ssh-security-app --config config/local.json init-db
sqlite3 data/ssh_security_app.db "PRAGMA integrity_check;"
```

If replacement is required, move the damaged file rather than deleting it:

```bash
mv data/ssh_security_app.db data/ssh_security_app.db.previous
ssh-security-app --config config/local.json init-db
```

## Service diagnostics

```bash
systemctl status ssh-security-app-firewall.service --no-pager
systemctl status ssh-security-app.service --no-pager
systemctl status ssh-security-app-dashboard.service --no-pager
journalctl -u ssh-security-app-firewall.service -n 100 --no-pager
journalctl -u ssh-security-app.service -n 100 --no-pager
journalctl -u ssh-security-app-dashboard.service -n 100 --no-pager
```
