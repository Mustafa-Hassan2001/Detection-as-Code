# Sample logs: SYNTHETIC DATA

> **All events in this folder are synthetic.** They were written by hand in
> `generate_samples.py` to resemble Sysmon (Windows and Linux), auditd and Zeek output.
> None of them was captured from a real system, and the hosts, users and IPs are invented.
> Internal hosts use RFC 1918 lab ranges. "Attacker" hosts use the RFC 5737 documentation
> ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which belong to no one.

| File | Imitates | Events |
|---|---|---|
| `windows/sysmon.jsonl` | Sysmon EID 1 / 10 / 13, flattened EventData | 11 malicious, 8 benign |
| `linux/sysmon_linux_process_creation.jsonl` | Sysmon for Linux EID 1 | 6 malicious, 7 benign |
| `linux/auditd.jsonl` | auditd SYSCALL / PATH records | 2 malicious, 4 benign, 3 context |
| `zeek/http.jsonl` | Zeek http.log (JSON) | 3 malicious, 3 benign |
| `zeek/ssh.jsonl` | Zeek ssh.log (JSON) | 2 malicious, 2 benign |
| `zeek/dns.jsonl` | Zeek dns.log (JSON) | 2 malicious, 3 benign |

Every event carries three bookkeeping fields that real logs do not have:

- `_sample_id`: referenced from `mapping/detections.yml`.
- `_label`: one of three values.
  - `malicious`: some rule must fire on it.
  - `benign`: no rule may fire unless the event is a documented false positive.
  - `context`: supporting records, not scored.
- `_note`: a one-line explanation.

**Benign events are near-misses on purpose.** Each one resembles an attack closely enough
that it would match if a rule's filter or constraint were removed. Examples:

- PowerShell with `-ExecutionPolicy` (not `-enc`);
- conhost.exe under wsmprovhost;
- a `/dev/tcp/127.0.0.1` health check;
- a dpkg postinst that sets setuid;
- a Sophos lookup with a long hash label.

This is what lets the test harness catch rules that become too broad.

Field names follow the Sigma taxonomy (flat Sysmon `EventData` names, raw auditd keys,
Zeek JSON keys). That is the shape tools like Zircolite produce after flattening, so the
rules run against the files without a field-mapping step.

Regenerate the files with `make samples`. CI checks that the committed files match the
generator.
