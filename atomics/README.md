# Atomics: attack emulations for each rule

One file per ATT&CK technique, in the **Atomic Red Team YAML format**
(`atomics/<T#>/<T#>.yaml`). The files work with Red Canary's `Invoke-AtomicTest`
(`-PathToAtomicsFolder <this folder>`) and with the dependency-free Linux runner
`tools/run_atomic.py`. `mapping/detections.yml` names the exact test that should trigger
each rule.

> **Lab use only.** These tests emulate attacker behaviour. Run them only on hosts you
> own, inside the isolated lab. Each test is designed to be **harmless and reversible**:
>
> - benign payloads (`echo`, `/bin/true`, `whoami`);
> - non-existent service binaries;
> - a setuid bit on a copy of `/bin/true`;
> - comment lines instead of SSH keys;
> - random bytes instead of real data;
> - loopback, RFC 1918 and reserved `.example` targets;
> - a cleanup command that restores the previous state.
>
> The exception is `T1003.001`, which writes a real LSASS dump of the lab VM. Its cleanup
> deletes the dump. Never run it on a machine that holds real credentials.

| Technique | Test | Platform | Mode | Rule(s) it should trigger |
|---|---|---|---|---|
| T1204.002 | Office-named parent process spawns cmd.exe | Windows | standalone VM | office_spawn_shell |
| T1059.001 | PowerShell -EncodedCommand execution | Windows | standalone VM | powershell_encoded_command |
| T1053.005 | schtasks creates a task that runs cmd.exe /c | Windows | standalone VM | schtasks_create_suspicious |
| T1543.003 | sc.exe creates a service with a ProgramData binPath | Windows (admin) | standalone VM | sc_create_service_suspicious_path |
| T1003.001 | LSASS MiniDump via comsvcs.dll | Windows (admin) | standalone VM | rundll32_comsvcs_minidump, lsass_suspicious_access |
| T1021.002 | PsExec remote command against a lab host | Windows (admin) | lab (or localhost) | psexec_service_child |
| T1021.006 | Invoke-Command runs whoami over WinRM | Windows (admin) | lab (or localhost) | winrm_wsmprovhost_child |
| T1547.001 | HKCU Run key pointing to C:\Users\Public | Windows | standalone VM | run_key_suspicious_path |
| T1548.002 | ms-settings shell open command hijack | Windows | standalone VM | uac_bypass_shell_open_command |
| T1505.003 | #1 process named apache2 spawns /bin/sh; #2 allow-listed lab web shell | Linux | #1 standalone, #2 lab | webserver_spawn_shell |
| T1059.004 | Bash /dev/tcp reverse shell to a loopback listener | Linux | standalone | reverse_shell |
| T1548.001 | Set the setuid bit on a harmless test binary | Linux | standalone | chmod_setuid |
| T1003.008 | Read /etc/shadow with cat | Linux (root) | standalone | shadow_file_access |
| T1048.003 | #1 curl form upload of a dummy file; #2 DNS-encoded dummy data | Linux | #1 standalone, #2 lab | curl_wget_file_upload, dns_long_subdomain_tunneling |
| T1053.003 | Drop a file into /etc/cron.d | Linux (root) | standalone + auditd | auditd_cron_file_modification |
| T1098.004 | Append a marker line to authorized_keys | Linux | standalone + auditd | auditd_ssh_authorized_keys_modification |
| T1190 | Exploit-pattern HTTP requests to a lab web server | Linux | lab (Zeek) | zeek_http_web_exploitation_patterns |
| T1110.001 | Six wrong SSH passwords in a single connection | Linux | lab (Zeek) | zeek_ssh_password_guessing |

How to run them: see `docs/lab-integration.md`, section 4.

The `auto_generated_guid` values are this project's own UUIDs, not upstream ART GUIDs.
The mapping file names the closest upstream test for each technique.
