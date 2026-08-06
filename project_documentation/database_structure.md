# Database Structure

SQLite stores evidence, detections, blocks, allowlist entries, audit records,
parser errors, component health, and application state.

Current terminal-first tables:

- `auth_events`
- `network_events`
- `ip_profiles`
- `detections`
- `detection_auth_events`
- `detection_network_events`
- `allowlist`
- `blocks`
- `audit_log`
- `parser_errors`
- `component_health`
- `application_state`

Dashboard-only `action_requests` are no longer created in new databases.
Existing old databases may still contain that table, but the terminal-first
application no longer reads or writes it.

The schema lives at:

```text
application_source_code/ssh_security_application/sqlite_data_storage/schema.sql
```

Initialize a database:

```bash
ssh-security-app --config config/local.json init-db
```

Inspect tables directly:

```bash
sqlite3 data/ssh_security_application.db ".tables"
```
