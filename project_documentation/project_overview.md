# Project Overview

This project is a terminal-based defensive SSH brute-force detector for an
authorized Ubuntu/Kali lab.

It collects OpenSSH authentication records and TCP/22 network metadata,
correlates evidence by source IPv4 address, calculates an explainable risk
score, stores results in SQLite, displays alerts in the terminal, and can
temporarily block high-risk sources through `iptables`.

The project is designed to be easy to demonstrate:

- Ubuntu 20.04 Security VM: `192.168.12.1`
- Kali attacker VM: `192.168.12.3`
- Default mode: Simulation Mode
- Demo block duration: 120 seconds
- Project firewall chain: `SSH_SECURITY_APP`

The browser dashboard was removed so the whole workflow can be explained and
demonstrated from the terminal.
