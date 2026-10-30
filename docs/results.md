# Results

> **Every value marked `[FILL FROM YOUR RUN]` must come from your own run.** Nothing on
> this page is pre-filled or estimated. Record the date, the commit hash and the lab
> configuration with the numbers, so that they can be reproduced.

Run metadata:

- Date: [FILL FROM YOUR RUN]
- Commit: [FILL FROM YOUR RUN] (`git rev-parse --short HEAD`)
- SIEM and version: [FILL FROM YOUR RUN] (e.g. Wazuh 4.x / Elastic 8.x)
- Victim hosts and OS: [FILL FROM YOUR RUN]
- Sysmon / Sysmon for Linux / Zeek versions: [FILL FROM YOUR RUN]

## 1. CI and synthetic tests (standalone mode)

Source: the output of `make ci` and `build/test-report.md`.

| Check | Result |
|---|---|
| `sigma check` (errors / issues) | [FILL FROM YOUR RUN] |
| `validate_rules.py` errors | [FILL FROM YOUR RUN] |
| Rules passing synthetic tests | [FILL FROM YOUR RUN] / 20 |
| Malicious sample events detected | [FILL FROM YOUR RUN] |
| Benign sample events alerted on (documented FP) | [FILL FROM YOUR RUN] |
| Conversions (elastic / wazuh / expected-unsupported) | [FILL FROM YOUR RUN] |
| GitHub Actions run URL | [FILL FROM YOUR RUN] |

## 2. Lab validation (lab mode)

Source: run each atomic, then `make hunt` (`build/lab-hunt-<target>.md`).

| # | Rule | Atomic | Fired? (Y/N/partial) | Hits | Time to visibility in SIEM | Notes |
|---|---|---|---|---|---|---|
| 1 | proc_creation_win_office_spawn_shell | T1204.002 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 2 | proc_creation_win_powershell_encoded_command | T1059.001 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 3 | proc_creation_win_schtasks_create_suspicious | T1053.005 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 4 | proc_creation_win_sc_create_service_suspicious_path | T1543.003 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 5 | proc_creation_win_rundll32_comsvcs_minidump | T1003.001 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 6 | proc_creation_win_psexec_service_child | T1021.002 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 7 | proc_creation_win_winrm_wsmprovhost_child | T1021.006 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 8 | registry_set_win_run_key_suspicious_path | T1547.001 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 9 | registry_set_win_uac_bypass_shell_open_command | T1548.002 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 10 | proc_access_win_lsass_suspicious_access | T1003.001 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 11 | proc_creation_lnx_webserver_spawn_shell | T1505.003 #1/#2 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 12 | proc_creation_lnx_reverse_shell | T1059.004 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 13 | proc_creation_lnx_chmod_setuid | T1548.001 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 14 | proc_creation_lnx_shadow_file_access | T1003.008 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 15 | proc_creation_lnx_curl_wget_file_upload | T1048.003 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 16 | lnx_auditd_cron_file_modification | T1053.003 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 17 | lnx_auditd_ssh_authorized_keys_modification | T1098.004 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 18 | zeek_http_web_exploitation_patterns | T1190 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 19 | zeek_ssh_password_guessing | T1110.001 #1 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |
| 20 | zeek_dns_long_subdomain_tunneling | T1048.003 #2 | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | |

## 3. False-positive measurement (benign baseline)

Method:

1. Run the lab with **normal activity only** (no atomics) for a fixed window, for example
   24 hours of a scripted user simulation plus package updates.
2. Run `make hunt SINCE=24h`.
3. Every hit is a false positive. Classify its cause.

| Rule | Hits in benign window | Events in window (denominator) | FP rate | Root cause / tuning applied |
|---|---|---|---|---|
| [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] | [FILL FROM YOUR RUN] |

Definition used: FP rate = alerts in the benign window ÷ events of that log source in the
window. State the denominator. Without one, an FP *rate* means nothing.

## 4. Final coverage numbers

Source: `coverage/coverage.md` after the final `make coverage`. Copy the numbers and add
the lab-validated subset.

| Metric | Value |
|---|---|
| Techniques / sub-techniques with a rule | [FILL FROM YOUR RUN] |
| ... of which validated in the lab (`lab_validation: fired`) | [FILL FROM YOUR RUN] |
| Tactics with at least one detection | [FILL FROM YOUR RUN] |
| Navigator layer screenshot | [FILL FROM YOUR RUN] (add `docs/img/navigator.png`) |

## 5. Observations

- Rules that did not fire, and why (telemetry gap, field mapping, casing, rule logic):
  [FILL FROM YOUR RUN]
- Changes made after the lab run (link the commits): [FILL FROM YOUR RUN]
