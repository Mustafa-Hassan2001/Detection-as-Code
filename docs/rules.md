# Rule reference: logic, telemetry, tuning, and blind spots

This file explains how each of the 20 rules works, so that every rule can be defended on its
merits. Each entry covers four things:

- **Behaviour**: what the attacker does and why it works.
- **Logic**: how the Sigma `detection` block maps onto that behaviour.
- **Noise and tuning**: where false positives come from and how to remove them without
  blinding the rule.
- **Blind spots**: what the rule will *not* catch. A detection engineer has to know this,
  because no single rule covers a whole technique.

How to read the Sigma logic:

- Inside one selection, keys are **AND**-ed.
- A list of values under one key is **OR**-ed.
- `|endswith`, `|contains`, `|startswith` and `|re` are value modifiers. Matching is
  **case-insensitive** unless a rule says `|cased`.
- `|windash` expands `-x` to the `/x` form and to the Unicode-dash forms that Windows
  tools also accept.
- `all of selection_*` and `1 of filter_*` quantify over the named groups.
- Naming follows SigmaHQ: a filter called `filter_main_*` removes structural noise that
  should never alert. A filter called `filter_optional_*` is environment tuning that you
  may decide to drop.

Every rule has positive **and** negative synthetic test events (see `mapping/detections.yml`
and `sample-logs/`). CI fails if a rule stops matching its positives or starts matching a
benign event.

---

## Windows (Sysmon)

### 1. Office application spawning a shell: `proc_creation_win_office_spawn_shell`
**ATT&CK:** T1566.001 Spearphishing Attachment (Initial Access) and T1204.002 Malicious
File (Execution). **Telemetry:** Sysmon EID 1.

- **Behaviour.** A malicious document runs a macro or embedded object. To fetch or run
  the next stage, the macro starts a shell, a script host or a LOLBin such as certutil or
  mshta. The *document* is the entry point, so the Office application becomes the parent
  process.
- **Logic.** `selection_parent` (ParentImage ends with one of six Office executables) AND
  `selection_child` (Image is one of ten interpreters or LOLBins).
- **Noise and tuning.** Legacy business macros sometimes call `cmd.exe`. Allow-list them by
  `ParentCommandLine` (the document path), not by user, so the rule still fires on a new
  document.
- **Blind spots.**
  - The macro may use WMI or COM so that the child's parent is `WmiPrvSE.exe` instead of
    Office.
  - The payload may be injected into the Office process with no child at all.
  - Container formats (ISO, LNK) start the payload from `explorer.exe`.

  Each of these needs its own rule.
- **Tests.** `win-001` must match. `win-101` must not: that is Word starting `splwow64`
  to print.

### 2. PowerShell `-EncodedCommand`: `proc_creation_win_powershell_encoded_command`
**ATT&CK:** T1059.001 PowerShell (Execution). **Telemetry:** Sysmon EID 1.

- **Behaviour.** `-EncodedCommand` accepts a Base64 UTF-16LE script. Attackers use it to
  avoid quoting problems and to hide intent from anyone reading the command line.
  PowerShell accepts **any unambiguous prefix** of a parameter name: `-e`, `-ec`, `-en`,
  `-enc`, `-enco…`.
- **Logic.**
  - `selection_img` matches either the image name or the PE `OriginalFileName`, so a
    renamed `powershell.exe` is still caught.
  - `selection_cli` uses `|windash|contains` on the space-delimited prefixes. The trailing
    space in `' -e '` stops it matching `-ExecutionPolicy`. The benign test `win-102`
    checks exactly that.
- **Noise and tuning.** Management agents (SCCM, Intune, Azure Guest Configuration) use
  encoded commands. Decode the command once, review it, and allow-list by `ParentImage`.
- **Blind spots.**
  - `powershell -c "IEX(...)"` with a plain-text payload.
  - Script-block content: you need PowerShell Script Block Logging (EID 4104) for that.
  - PowerShell hosted inside another process (System.Management.Automation.dll loaded by
    a custom binary).

### 3. Scheduled task with a suspicious action: `proc_creation_win_schtasks_create_suspicious`
**ATT&CK:** T1053.005 Scheduled Task (Execution, Persistence, Privilege Escalation).
**Telemetry:** Sysmon EID 1.

- **Behaviour.** `schtasks /create` registers a command to run at logon, on a timer, or as
  SYSTEM (`/ru SYSTEM`). One technique therefore covers three tactics.
- **Logic.** The rule requires all three of:
  - the image is schtasks.exe;
  - the command is a create (`' -create '` with windash, which also covers `/create`);
  - a **suspicious action**: a user-writable path, a script host or LOLBin, or a URL.

  The third condition separates attacker tasks from software updaters, which point to
  Program Files. The benign test `win-103` is the Google updater task.
- **Noise and tuning.** Per-user updaters installed under AppData (Teams, Zoom). Allow-list
  them by `/tn` task name.
- **Blind spots.** Tasks created through the COM API or PowerShell
  (`Register-ScheduledTask`) never start schtasks.exe. Use Security EID 4698 or the
  TaskScheduler/Operational log for those.

### 4. Service creation with a suspicious binPath: `proc_creation_win_sc_create_service_suspicious_path`
**ATT&CK:** T1543.003 Windows Service (Persistence, Privilege Escalation).
**Telemetry:** Sysmon EID 1.

- **Behaviour.** A new service runs as LocalSystem and can start automatically at boot,
  which gives both persistence and SYSTEM-level execution.
- **Logic.** All three must hold:
  - the image is sc.exe;
  - the command line contains **both** `' create '` and `binPath` (`contains|all`);
  - the binPath is user-writable or wraps cmd or PowerShell.
- **Noise and tuning.** RMM and vendor tools that stage binaries in ProgramData. Verify the
  binary's signer, then allow-list by service name.
- **Blind spots.** Services created through the API, PowerShell `New-Service`, or remote
  SCM (the PsExec and Impacket path). Complement with System EID 7045 or Security EID 4697.

### 5. LSASS dump via comsvcs.dll: `proc_creation_win_rundll32_comsvcs_minidump`
**ATT&CK:** T1003.001 LSASS Memory (Credential Access). **Telemetry:** Sysmon EID 1.

- **Behaviour.** `comsvcs.dll` exports `MiniDump` (ordinal 24). Calling it through
  rundll32 writes a full process dump of LSASS, without dropping any tool on disk.
- **Logic.** All three must hold: the image is rundll32; the command line contains
  `comsvcs`; and it contains `MiniDump`, `#24` or `#+24` (the ordinal forms).
- **Noise and tuning.** Practically none, which is why the level is `high`.
- **Blind spots.** Ordinal obfuscation that the list does not anticipate (for example
  `#-4294967272`), a renamed rundll32 (add an `OriginalFileName` selection), or a
  copied-and-renamed comsvcs.dll. The process-access rule (#10) covers these, because it
  does not depend on the command line.

### 6. PsExec service child: `proc_creation_win_psexec_service_child`
**ATT&CK:** T1021.002 SMB/Admin Shares (Lateral Movement) and T1569.002 Service Execution
(Execution). **Telemetry:** Sysmon EID 1 **on the target host**.

- **Behaviour.** PsExec copies `PSEXESVC.exe` to `ADMIN$`, creates a service, and runs the
  requested command as a child of that service.
- **Logic.** A single condition: `ParentImage` ends with `\PSEXESVC.exe`.
- **Noise and tuning.** Administrators use PsExec. Correlate with the type-3 logon (EID
  4624) to find the source host, and allow-list jump hosts.
- **Blind spots.** Impacket `psexec.py`, `smbexec` and PsExec's `-r` option use random or
  renamed service names. Detect those with EID 7045 (service created whose ImagePath is in
  `ADMIN$` or `%SystemRoot%` with a random name).

### 7. WinRM remote-shell child: `proc_creation_win_winrm_wsmprovhost_child`
**ATT&CK:** T1021.006 Windows Remote Management (Lateral Movement). **Telemetry:** Sysmon
EID 1 on the target host.

- **Behaviour.** `Enter-PSSession` and `Invoke-Command` execute inside `wsmprovhost.exe`
  on the target. Any external program they run becomes its child.
- **Logic.** `ParentImage` ends with `\wsmprovhost.exe`, AND NOT `filter_main_conhost`.
  conhost.exe is created for every console session and carries no signal. The benign test
  `win-106` proves the filter works.
- **Noise and tuning.** Ansible, DSC, and admin scripts over WinRM. Allow-list by the
  source account or the management server.
- **Blind spots.** Pure in-process PowerShell (cmdlets only, no external exe) produces no
  child process. Use EID 4104 and WinRM operational logs for that.

### 8. Run key pointing to a suspicious location: `registry_set_win_run_key_suspicious_path`
**ATT&CK:** T1547.001 Registry Run Keys (Persistence, Privilege Escalation).
**Telemetry:** Sysmon EID 13.

- **Behaviour.** Programs listed under the Run and RunOnce keys start at user logon.
- **Logic.** `selection_key` (TargetObject is under Run, RunOnce or WOW6432Node Run) AND
  `selection_details` (the value data is in a temp, public or ProgramData path, or invokes a
  script host). Without the second condition the rule would fire on every legitimate
  installer. The benign test `win-104` is OneDrive under `AppData\Local`.
- **Blind spots.**
  - Binaries in `AppData\Roaming` or other user folders not in the list. This is a
    deliberate noise-versus-coverage trade-off.
  - Startup-folder LNKs.
  - Other autostart locations (Winlogon, Services, IFEO).

### 9. UAC bypass via shell-open hijack: `registry_set_win_uac_bypass_shell_open_command`
**ATT&CK:** T1548.002 Bypass UAC (Privilege Escalation). **Telemetry:** Sysmon EID 13.

- **Behaviour.** Auto-elevating binaries resolve `ms-settings:` (fodhelper,
  computerdefaults) or `.msc` files (eventvwr) through `HKCU\Software\Classes` **before**
  `HKLM`. A normal user can therefore point them at any command, which then runs at high
  integrity with no UAC prompt.
- **Logic.** A single selection: TargetObject contains either hijack key path.
- **Noise and tuning.** None expected. Legitimate software has no reason to create these
  keys in HKCU.
- **Blind spots.** The many other UAC bypasses (DLL hijacks, the `sdclt` and Folder
  handlers, `SilentCleanup` environment-variable abuse).

### 10. Suspicious access to LSASS memory: `proc_access_win_lsass_suspicious_access`
**ATT&CK:** T1003.001 (Credential Access). **Telemetry:** Sysmon EID 10, which needs a
Sysmon config that includes `ProcessAccess` for `lsass.exe`.

- **Behaviour.** Reading credentials from LSASS requires a handle with `PROCESS_VM_READ`
  (0x0010) plus query rights. Mimikatz, ProcDump, nanodump and comsvcs all request one of
  a small set of masks: `0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`, `0x1f1fff`,
  `0x1f3fff`.
- **Logic.**
  - `selection`: TargetImage is lsass AND GrantedAccess is one of those masks.
  - Two `filter_main_*` groups remove OS processes, matched by **full path**, and
    Defender, matched by its platform directory.
  - **Design choice:** the rule does not filter all of `C:\Windows\System32\`. If it did,
    `rundll32.exe` doing a comsvcs dump would be invisible. The test `win-009` checks
    exactly that, and `win-105` (Defender) checks the filter.
- **Noise and tuning.** EDR, AV and backup agents. Add their exact paths after verifying
  the signer.
- **Blind spots.**
  - Handle duplication.
  - Dumping via a vulnerable driver.
  - PPL-protected LSASS, which blocks the attack but also changes the telemetry.
  - Masks not in the list.

---

## Linux (Sysmon for Linux and auditd)

### 11. Web server spawning a shell: `proc_creation_lnx_webserver_spawn_shell`
**ATT&CK:** T1505.003 Web Shell (Persistence) and T1190 (Initial Access).
**Telemetry:** Sysmon for Linux EID 1.

- **Behaviour.** A web shell, or a command-injection bug, makes the web server's worker
  run OS commands. The *parent/child* relationship is the same whatever the exploit was.
- **Logic.** `1 of selection_parent_*` and then `selection_child`:
  - The parent groups are `selection_parent_server` (apache2, httpd, nginx, lighttpd,
    caddy) and `selection_parent_phpfpm` (`contains '/php-fpm'`, because the binary is
    versioned, for example `php-fpm8.1`).
  - The child is a shell, a recon tool, or a download or networking tool.

  Java application servers are **deliberately excluded**: they spawn shells too often to
  include without per-application tuning.
- **Tests.** `lnx-001` must match. `lnx-107` must not: that is PHP-FPM running
  ImageMagick `convert`, a legitimate child that is not in the child list.
- **Blind spots.** Web shells that stay in-process (PHP `eval` with file or network
  functions only), and Java or Node applications.

### 12. Reverse shell command lines: `proc_creation_lnx_reverse_shell`
**ATT&CK:** T1059.004 Unix Shell (Execution). **Telemetry:** Sysmon for Linux EID 1.

- **Behaviour.** The attacker turns a single command execution into an interactive shell
  that connects **outbound**, which gets past inbound firewall rules.
- **Logic.** Four independent selections, any one of which matches (`1 of selection_*`):
  1. Bash `/dev/tcp` or `/dev/udp` redirection.
  2. netcat with `-e` or `-c` pointing at a shell (both conditions in one selection, so
     they are AND-ed).
  3. The `mkfifo` / `sh -i` / `nc` pipe (`contains|all`).
  4. The Python `socket` + `connect` + `pty.spawn` one-liner.

  `filter_optional_local_healthcheck` removes `/dev/tcp/127.0.0.1/…` and `localhost`.
  Container health checks use these, and a reverse shell to loopback is pointless. The
  test `lnx-102` checks this filter.
- **Blind spots.** Compiled reverse shells, socat or openssl variants, encoded one-liners
  (`echo … | base64 -d | sh`), and reverse shells to 127.0.0.1 through a local port
  forward.

### 13. Setuid or setgid via chmod: `proc_creation_lnx_chmod_setuid`
**ATT&CK:** T1548.001 Setuid and Setgid (Privilege Escalation). **Telemetry:** Sysmon for
Linux EID 1.

- **Behaviour.** An attacker who briefly has root leaves a setuid-root copy of a shell or
  interpreter behind, so that they can regain root later.
- **Logic.**
  - `selection`: the image is chmod AND the command line contains a symbolic (`u+s`,
    `g+s`, `+s`) or numeric (`4xxx`, `2xxx`, `6xxx`) setuid mode. The spaces around each
    mode avoid matching file names.
  - Two `filter_main_*` groups remove package managers. One matches the direct parent,
    for example dpkg. The other matches **maintainer scripts** through
    `ParentCommandLine` containing `/var/lib/dpkg/info/`. This second filter exists
    because in reality chmod's parent is `/bin/sh postinst`, not dpkg. The test `lnx-104`
    is exactly that case.
- **Blind spots.** `chmod` via a syscall from another binary (`python os.chmod`), `install
  -m 4755`, and `cp --preserve`. Use auditd `-a always,exit -F arch=b64 -S chmod,fchmodat`
  with `a1&04000` for full coverage.

### 14. Reading /etc/shadow: `proc_creation_lnx_shadow_file_access`
**ATT&CK:** T1003.008 (Credential Access). **Telemetry:** Sysmon for Linux EID 1.

- **Behaviour.** `/etc/shadow` holds the password hashes. Copying it lets the attacker
  crack the hashes offline.
- **Logic.** `(selection_file and selection_tool) or selection_unshadow`. The file path
  must appear on the command line of a reading, copying, encoding or transfer tool, **or**
  John the Ripper's `unshadow` must run. Administrators use `vipw` and `passwd`, which do
  not match.
- **Blind spots.** Any program reading the file through `open()` without the path on its
  command line, such as a Python script or an editor opened through a menu. Add an auditd
  watch (`-w /etc/shadow -p r -k shadow_read`) for that. It is noisier, because PAM reads
  the file on every login, so filter by `exe`.

### 15. File upload with curl or wget: `proc_creation_lnx_curl_wget_file_upload`
**ATT&CK:** T1048.003 (Exfiltration). **Telemetry:** Sysmon for Linux EID 1.

- **Behaviour.** curl and wget are on almost every host. Uploading a file with them needs
  no attacker tooling.
- **Logic.** Two selections, any one of which matches:
  - curl with `-T`, `--upload-file`, `=@` (covers `-F field=@file` and
    `--data-binary=@file`), or `-d @`, `--data @` or `--data-binary @`;
  - wget with `--post-file` or `--body-file`.

  The rule matches `=@` rather than `-F` on its own. This is deliberate: Sigma's default
  matching is case-insensitive, so `' -F '` would also match the very common
  `curl -f` (fail silently). Downloads, as in the benign test `lnx-105`, never match.
- **Blind spots.**
  - Uploads by other tools (python requests, scp, rclone).
  - File content inlined into the argument (`curl --data "$(cat loot)"`). Piping on stdin
    (`--data-binary @-`) *is* caught.
  - DNS or ICMP channels (see rule 20).

### 16. Cron file modified (auditd): `lnx_auditd_cron_file_modification`
**ATT&CK:** T1053.003 Cron (Execution, Persistence, Privilege Escalation). **Telemetry:**
auditd `PATH` records from `-w <path> -p wa` watches (see `lab/auditd-dac.rules`).

- **Behaviour.** Anything written into a system crontab or `/etc/cron.d` runs on a
  schedule, as root.
- **Logic.** `selection`: `type: PATH` AND `name` starts with one of the cron locations.
  `filter_main_parent_record`: when a file is created, auditd logs **two** PATH records,
  one for the directory (`nametype=PARENT`) and one for the file (`CREATE`). Dropping the
  PARENT record gives exactly one alert per change. The tests `aud-002`/`aud-003` check
  this.
- **Known false positive, documented:** package installs, such as logrotate dropping
  `/etc/cron.daily/logrotate` (`aud-104`). The mapping lists it as
  `known_false_positives`, so the test harness counts it as an accepted false positive
  instead of failing. In production, correlate with the same event's SYSCALL record
  (`exe=/usr/bin/dpkg`).
- **Blind spots.** systemd timers (T1053.006), `at` jobs, and paths that are not watched.

### 17. authorized_keys modified (auditd): `lnx_auditd_ssh_authorized_keys_modification`
**ATT&CK:** T1098.004 SSH Authorized Keys (Persistence, Privilege Escalation).
**Telemetry:** auditd PATH records from watches on `.ssh` directories.

- **Behaviour.** An attacker appends their public key to `authorized_keys`. This gives
  password-less access that survives a password reset.
- **Logic.** Same pattern as rule 16: `type: PATH`, `name` ends with `/.ssh/authorized_keys`
  or `authorized_keys2`, and the PARENT record is filtered out.
- **Blind spots.** auditd watches are per path, so a home directory that is not watched is
  invisible. So are `AuthorizedKeysFile` set to another location, and `AuthorizedKeysCommand`
  abuse.

---

## Network (Zeek)

### 18. Web exploitation patterns in the URI: `zeek_http_web_exploitation_patterns`
**ATT&CK:** T1190 Exploit Public-Facing Application (Initial Access). **Telemetry:** Zeek
`http.log`.

- **Behaviour.** Exploit payloads for common bug classes leave recognisable strings in the
  request URI: path traversal, `/etc/passwd` reads, SQL `UNION SELECT`, XSS `<script`,
  Log4Shell `${jndi:`, and command injection into `/bin/sh`.
- **Logic.** `uri|contains` any of the patterns, in both plain and **URL-encoded** forms,
  because Zeek logs the URI as it was sent. Example: `%24%7bjndi`. Matching is
  case-insensitive, so `%7B` and `%7b` are both covered.
- **Noise and tuning.** Detects **attempts**, not success. Triage with `status_code` and
  rule 11. Allow-list your own vulnerability scanner by `id.orig_h`. The benign test
  `zk-http-102` contains the words "select" and "union" in normal text and does not match.
- **Blind spots.**
  - Payloads in POST bodies, headers or cookies (Zeek logs only the URI by default).
  - HTTPS traffic, unless TLS is terminated before the sensor.
  - Double-encoding.

### 19. Many SSH authentication attempts in one connection: `zeek_ssh_password_guessing`
**ATT&CK:** T1110.001 Password Guessing (Credential Access). **Telemetry:** Zeek
`ssh.log`.

- **Behaviour.** Guessing tools retry passwords inside one connection, up to the server's
  `MaxAuthTries` limit (6 by default).
- **Logic.** `auth_attempts|gte: 5`, a numeric comparison modifier. Zeek **infers**
  attempts from the sizes of encrypted packets, so the value is an estimate.
- **Blind spots.** Tools that open a new connection for every password. Catching those
  needs **aggregation**: a Sigma *correlation* rule (`event_count` grouped by
  `id.orig_h` over, say, 5 minutes). That is listed under future work, because the target
  Lucene backends cannot express aggregations.

### 20. Long DNS labels (possible tunneling): `zeek_dns_long_subdomain_tunneling`
**ATT&CK:** T1048.003 (Exfiltration) and T1071.004 DNS (Command and Control).
**Telemetry:** Zeek `dns.log`.

- **Behaviour.** Tunneling tools encode data into the subdomain labels of a zone the
  attacker controls. The resolver then delivers that data to the attacker's name server.
- **Logic.**
  - `query|re: '.*[A-Za-z0-9_-]{40,}\..*'` matches a run of 40 or more label characters
    followed by a dot. Normal hostnames have short labels, and the protocol maximum is 63.
  - **Portability detail.** Sigma regexes are *search* semantics, but Lucene/Elasticsearch
    regexes are implicitly **anchored** to the whole value and do not support `^`. The
    explicit leading and trailing `.*` makes the pattern mean the same thing in both, so
    the SQLite test and the SIEM query agree.
  - `filter_optional_av_lookups` removes security vendors that put hashes in labels. The
    benign test `zk-dns-102` checks it.
  - **The filter has a cost.** Each excluded zone is a blind spot. `.amazonaws.com` is the
    clearest case: anyone can host an endpoint there (S3 buckets, API Gateway), so an
    attacker who tunnels through a name under it would not alert. The entry trades a
    recurring false positive for that blind spot, and it should be removed in an
    environment that does not produce long-label AWS lookups.
- **Blind spots.**
  - Low-and-slow tunnels with short labels.
  - DNS over HTTPS (encrypted, invisible to Zeek).
  - Entropy- or volume-based detection, which needs aggregation (future work).
