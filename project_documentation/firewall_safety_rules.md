# Firewall Safety Rules

The application manages only the dedicated `SSH_SECURITY_APP` chain.

Allowed firewall behavior:

- create the dedicated chain;
- add the exact TCP/22 INPUT jump to that chain;
- add exact source-specific TCP/22 DROP rules;
- delete exact source-specific TCP/22 DROP rules;
- remove recognized project-owned rules during guarded cleanup.

Forbidden firewall behavior:

- no iptables flush;
- no default-policy changes;
- no broad subnet blocking;
- no unrelated chain modification;
- no shell command strings;
- no automatic deletion of unknown rules.

Example owned block rule:

```text
-A SSH_SECURITY_APP -s 192.168.12.3/32 -p tcp --dport 22 -j DROP
```
