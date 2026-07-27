# Database

SQLite is the durable coordination boundary between collectors, correlation,
response workers, and the dashboard. WAL mode, foreign keys, a busy timeout,
short transactions, and parameterized queries are enabled by
`ssh_security_app.db.Database`.

| Table | Purpose |
|---|---|
| `auth_events` | Parsed OpenSSH authentication evidence |
| `network_events` | Parsed TCP/SSH metadata |
| `ip_profiles` | Source history and aggregate counts |
| `detections` | Risk score, classification, decision, and evidence fingerprint |
| `detection_auth_events` / `detection_network_events` | Detection evidence links |
| `allowlist` | Active and historical trusted IPv4 entries |
| `blocks` | Block lifetime, status, firewall result, and removal method |
| `action_requests` | Dashboard-to-worker manual-unblock queue and history |
| `audit_log` | Security-relevant actions and results |
| `parser_errors` | Unsupported or malformed input quarantine |
| `component_health` | Latest component state and diagnostic details |
| `application_state` | Persistent operating mode |

Block status transitions are:

```text
Active -> Expired
Active -> Manually Removed
Active -> Inconsistent
```

A failed firewall deletion leaves the block `Active` and records an error so
expiration can retry. An active database block with a missing firewall rule is
marked `Inconsistent`. A firewall rule with no active database record is
audited for operator review and is not automatically deleted.

Initialize or migrate in place:

```bash
ssh-security-app --config config/local.json init-db
```

Create a consistent backup while services are stopped:

```bash
sudo systemctl stop ssh-security-app-dashboard.service ssh-security-app.service
mkdir -p backups
sqlite3 data/ssh_security_app.db ".backup 'backups/ssh_security_app.db'"
```

Inspect operational state:

```bash
ssh-security-app --config config/local.json inspect detections --limit 20
ssh-security-app --config config/local.json inspect active-blocks
ssh-security-app --config config/local.json inspect actions
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT source_ip,status,expires_at,removal_method,error_message FROM blocks ORDER BY blocked_at DESC;"
sqlite3 -header -column data/ssh_security_app.db \
  "SELECT action_type,source_ip,status,result_message FROM action_requests ORDER BY requested_at DESC;"
```
