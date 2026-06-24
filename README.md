# wuhao

## Port and process audit script

This repo includes a defensive Linux triage script for reviewing local ports,
processes, and suspicious outbound TCP connections:

```bash
sudo python3 scripts/port_process_audit.py
```

Useful options:

- `--json` emits machine-readable output.
- `--show-all` includes every observed socket, not just heuristic findings.
- `--include-local` also reviews loopback/private established connections.
- `--fail-on medium` exits non-zero when findings at or above that severity
  exist, which is useful in automation.

The script is heuristic triage only. It can highlight network activity and
process metadata worth reviewing, but it cannot prove whether a host is clean or
infected.
