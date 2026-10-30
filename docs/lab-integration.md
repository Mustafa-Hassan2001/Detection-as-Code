# Running the project: standalone mode and lab mode

The repository works in two modes:

- **Standalone (default).** You need nothing beyond this repo. The rules are validated,
  converted and tested against the synthetic logs in `sample-logs/`. This is what CI runs,
  and what a reviewer gets with `git clone && make setup && make ci`.
- **Lab mode.** The emulations in `atomics/` run on hosts in the **SecureNet Lab** (the
  containerlab network with Suricata, Zeek and the SIEM). Telemetry flows into the SIEM,
  where the converted queries look for it. This turns "the rule logic is right" into
  "the rule fires on real telemetry in my environment".

> **Ground rule.** Lab mode runs attack techniques. Run them only on lab hosts you own,
> inside the isolated lab network. `tools/run_atomic.py` refuses to execute unless
> `DAC_LAB_CONFIRM=isolated-lab` is set, and it refuses any host input that is not a
> loopback or private address.

Placeholders such as `[LAB: ...]` stand for values from your own SecureNet Lab
deployment.

---

## 1. Telemetry each rule needs

| Rule family | Required telemetry | How to enable it |
|---|---|---|
| Windows process creation (rules 1-7) | Sysmon EID 1 | `lab/sysmon-windows-dac.xml`, or sysmon-modular / SwiftOnSecurity |
| Windows registry (rules 8-9) | Sysmon EID 13 on the Run and `shell\open\command` keys | same config |
| LSASS access (rule 10) | Sysmon EID 10 with `TargetImage` lsass.exe | same config |
| Linux process creation (rules 11-15) | Sysmon for Linux EID 1 (or Elastic Defend / Auditbeat process events) | `lab/sysmon-linux-dac.xml` |
| Linux auditd (rules 16-17) | auditd PATH records from watch rules | `lab/auditd-dac.rules` |
| Zeek (rules 18-20) | Zeek `http.log`, `ssh.log`, `dns.log` as JSON | Zeek sensor on the mirrored lab segment, `LogAscii::use_json=T` |

Zeek only sees traffic that crosses the interface it monitors. Loopback traffic
(127.0.0.0/8) never reaches the sensor. The network atomics (T1190, T1110.001 and the DNS
part of T1048.003) must therefore target a host on the monitored segment.

## 2. Wazuh (SecureNet Lab SIEM)

### 2.1 Agents
**Windows victim** (`ossec.conf` on the agent). Sysmon is collected through the
eventchannel decoder:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Linux host.** Collect auditd with the `audit` log format:

```xml
<localfile>
  <location>/var/log/audit/audit.log</location>
  <log_format>audit</log_format>
</localfile>
```

**Zeek sensor.** Collect the JSON logs. Wazuh's JSON decoder puts the fields under
`data.*`:

```xml
<localfile><location>/opt/zeek/logs/current/http.log</location><log_format>json</log_format></localfile>
<localfile><location>/opt/zeek/logs/current/ssh.log</location><log_format>json</log_format></localfile>
<localfile><location>/opt/zeek/logs/current/dns.log</location><log_format>json</log_format></localfile>
```

### 2.2 Index raw events (archives)
Wazuh indexes only **alerts** by default, meaning events that matched a Wazuh XML rule.
The Sigma queries search raw events, so enable archives on the manager:

1. In `/var/ossec/etc/ossec.conf`, under `<global>`, set `<logall_json>yes</logall_json>`.
2. In `/etc/filebeat/filebeat.yml`, set `archives: enabled: true` in the wazuh module.
3. Restart `wazuh-manager` and `filebeat`. Then create the index pattern
   `wazuh-archives-*` in the dashboard.

### 2.3 Load the converted content
All of it is generated in `converted/wazuh/`:

- **Saved searches.** Go to Dashboards Management, then Saved objects, then Import, and
  choose `converted/wazuh/wazuh-dashboard-saved-searches.ndjson`.
- **Alerting monitors** (one per rule). Credentials come from your shell, never from the
  repo:

  ```bash
  for f in converted/wazuh/monitors/*.json; do
    curl -sk -u "$DAC_SIEM_USER:$DAC_SIEM_PASSWORD" -H 'Content-Type: application/json' \
      -X POST "$DAC_SIEM_URL/_plugins/_alerting/monitors" --data-binary @"$f"; echo; done
  ```

- **Ad-hoc hunting.** Paste any `converted/wazuh/lucene/*.lucene` query into Discover, or
  run `make hunt` (section 4).

**Known gap.** Linux `process_creation` rules are not converted for Wazuh, because stock
Wazuh has no Sysmon for Linux decoder. `converted/README.md` lists them. There are two
options:

- Send Linux process telemetry to Elastic instead.
- Write a Wazuh decoder for Sysmon for Linux, then add its field names to
  `pipelines/wazuh.yml` and remove the `rule_failure` transformation.

### 2.4 Field-name caveat
The Wazuh template stores most `data.win.eventdata.*` fields as **keyword** values, and
keyword matching in Lucene is case-sensitive. The Sigma rules are case-insensitive, so a
query can miss an event whose casing differs, for example `PSEXESVC.EXE` versus
`PSEXESVC.exe`. When a lab test does not fire, check casing first. The Elastic target
avoids this with ECS `.caseless` sub-fields where they exist.

## 3. Elastic (alternative SIEM)
- **Windows.** Use Winlogbeat or Elastic Agent with the Sysmon integration (ECS fields).
- **Linux.** Use Auditbeat with the auditd module (file watches end up in `file.path`) and
  Elastic Defend or Sysmon for Linux for process events.
- **Zeek.** Use the Filebeat zeek module (`event.dataset: zeek.*`).
- **Import.** In Kibana, go to Security, then Rules, then Import rules, and choose
  `converted/elastic/kibana-detection-rules.ndjson`. Each rule keeps its UUID, severity,
  false-positive notes and ATT&CK threat mapping.

## 4. End-to-end lab run

```bash
# On a Linux lab host, as the user whose ~/.ssh is watched (root for the defaults):
export DAC_LAB_CONFIRM=isolated-lab
python3 tools/run_atomic.py --list
python3 tools/run_atomic.py T1059.004                     # dry run: print the command
sudo -E python3 tools/run_atomic.py T1053.003 --execute   # run
sudo -E python3 tools/run_atomic.py T1053.003 --execute --cleanup
python3 tools/run_atomic.py T1190 -i target_host=[LAB: web server IP] -i target_port=80 --execute
```

On the Windows victim, use the Invoke-AtomicRedTeam PowerShell module. The YAML files use
its format:

```powershell
Install-Module -Name invoke-atomicredteam -Scope CurrentUser
Import-Module invoke-atomicredteam
$A = "C:\lab\Detection-as-Code\atomics"
Invoke-AtomicTest T1059.001 -PathToAtomicsFolder $A -ShowDetails
Invoke-AtomicTest T1059.001 -PathToAtomicsFolder $A -GetPrereqs
Invoke-AtomicTest T1059.001 -PathToAtomicsFolder $A
Invoke-AtomicTest T1059.001 -PathToAtomicsFolder $A -Cleanup
```

Then query the SIEM from your workstation:

```bash
export DAC_SIEM_URL=https://[LAB: wazuh indexer IP]:9200
export DAC_SIEM_USER=admin
read -rs DAC_SIEM_PASSWORD && export DAC_SIEM_PASSWORD
make hunt TARGET=wazuh SINCE=2h HUNT_ARGS="--insecure"   # writes build/lab-hunt-wazuh.md
```

Record the outcome:

1. In `mapping/detections.yml`, set `lab_validation` to `fired`, `not-fired` or `partial`.
2. Fill in `docs/results.md`.
3. Run `make coverage`. The Navigator layer metadata then shows the lab status.

## 5. Running on Windows 11 + WSL2
- Run all `make` commands inside the WSL2 Ubuntu shell. Clone the repo into the Linux
  filesystem (`~/src/...`), not `/mnt/c/...`. Both I/O speed and file permissions are
  better there.
- Ubuntu 22.04 ships Python 3.10, which is supported. Install the venv module once with
  `sudo apt install python3-venv make git`.
- Docker Desktop is only needed for the SecureNet Lab, not for standalone mode.
