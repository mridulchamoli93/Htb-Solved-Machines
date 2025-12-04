# 🧠 Hack The Box (HTB) – Machine Writeups

Welcome to the collection of my **Hack The Box machine walkthroughs**. This folder documents my full exploitation process for each HTB machine — from enumeration to exploitation to privilege escalation.

---

## 🗂️ Machine Writeups Included

| 🔐 Machine Name | 🧱 Difficulty | ⚙️ Techniques Covered                                        | 🔗 HTB Link                                                                                        | 📄 Local Writeup                                                                          |
| --------------- | ------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Outbound**    | Easy          | Roundcube RCE, 3DES decryption, MySQL creds, Symlink PE      | [https://app.hackthebox.com/machines/Outbound](https://app.hackthebox.com/machines/Outbound)       | [Thanatos_HTB_Outbound_Writeup.md](htb%20machines/Thanatos_HTB_Outbound_Writeup.md)       |
| **Artificial**  | Easy          | Custom script exploitation, upload → RCE                     | [https://app.hackthebox.com/machines/Artificial](https://app.hackthebox.com/machines/Artificial)   | [Thanatos_HTB_Artificial_Writeup.md](htb%20machines/Thanatos_HTB_artificial_Writeup.md)   |
| **Nocturnal**   | Easy          | Vhosts, insecure upload, ISPConfig RCE                       | [https://app.hackthebox.com/machines/Nocturnal](https://app.hackthebox.com/machines/Nocturnal)     | [Thanatos_HTB_Nocturnal_Writeup.md](htb%20machines/Thanatos_HTB_Nocturnal_writeup.md)     |
| **Era**         | Medium        | IDOR backup leak, PHP RCE, cron PE                           | [https://app.hackthebox.com/machines/Era](https://app.hackthebox.com/machines/Era)                 | [Thanatos_HTB_Era_writeup.md](htb%20machines/Thanatos_HTB_Era_writeup.md)                 |
| **Editor**      | Easy          | XWiki RCE (CVE-2024-31982), PATH hijack                      | [https://app.hackthebox.com/machines/Editor](https://app.hackthebox.com/machines/Editor)           | [Thanatos_HTB_Editor_writeup.md](htb%20machines/Thanatos_HTB_Editor_writeup.md)           |
| **Planning**    | Medium        | Grafana RCE (CVE-2024-9264), container escape, Crontab UI PE | [https://app.hackthebox.com/machines/Planning](https://app.hackthebox.com/machines/Planning)       | [Thanatos_HTB_planning_writeup.md](htb%20machines/Thanatos_HTB_planning_writeup.md)       |
| **Cap**         | Easy          | PCAP extraction, FTP creds, capabilities PE                  | [https://app.hackthebox.com/machines/Cap](https://app.hackthebox.com/machines/Cap)                 | [Thanatos_HTB_cap_writeup.md](htb%20machines/Thanatos_HTB_cap_writeup.md)                 |
| **CodeTwo**     | Medium        | js2py Sandbox Escape (CVE-2024-28397), Python RCE            | [https://app.hackthebox.com/machines/CodeTwo](https://app.hackthebox.com/machines/CodeTwo)         | [Thanatos_HTB_CodeTwo_writeup.md](htb%20machines/Thanatos_HTB_CodeTwo_writeup.md)         |
| **Previous**    | Medium        | NextAuth bypass, Next.js LFI, Terraform PE                   | [https://app.hackthebox.com/machines/Previous](https://app.hackthebox.com/machines/Previous)       | [Thanatos_HTB_Previous_writeup.md](htb%20machines/Thanatos_HTB_Previous_writeup.md)       |
| **Alert**       | Medium        | Notification service exploit, API abuse                      | [https://app.hackthebox.com/machines/Alert](https://app.hackthebox.com/machines/Alert)             | [Thanatos_HTB_Alert_htb.md](htb%20machines/Thanatos_HTB_Alert_htb.md)                     |
| **Code**        | Medium        | Secure code editor bypass, RCE                               | [https://app.hackthebox.com/machines/Code](https://app.hackthebox.com/machines/Code)               | [Thanatos_HTB_Code_writeup.md](htb%20machines/Thanatos_HTB_Code_writeup.md)               |
| **Dog**         | Easy–Medium   | Web fuzzing, JWT abuse, sudo misconfig                       | [https://app.hackthebox.com/machines/Dog](https://app.hackthebox.com/machines/Dog)                 | [Thanatos_HTB_Dog_writeup.md](htb%20machines/Thanatos_HTB_Dog_writeup.md)                 |
| **Titanic**     | Medium        | File parsing exploit, unsafe deserialization                 | [https://app.hackthebox.com/machines/Titanic](https://app.hackthebox.com/machines/Titanic)         | [Thanatos_HTB_Titanic_writeup.md](htb%20machines/Thanatos_HTB_Titanic_writeup.md)         |
| **Enviourment** | Medium        | Env var injection, unsafe eval                               | [https://app.hackthebox.com/machines/Environment](https://app.hackthebox.com/machines/Environment) | [Thanatos_HTB_enviourment_writeup.md](htb%20machines/Thanatos_HTB_enviourment_writeup.md) |
| **Underpass**   | Medium        | SSH tunneling, cron abuse, LFI → RCE                         | [https://app.hackthebox.com/machines/Underpass](https://app.hackthebox.com/machines/Underpass)     | [Thanatos_HTB_underpass_Writeup.md](htb%20machines/Thanatos_HTB_underpass_Writeup.md)     |
| **LinkVortex**  | Easy          | Web routing misconfig, token leakage                         | [https://app.hackthebox.com/machines/LinkVortex](https://app.hackthebox.com/machines/LinkVortex)   | [Thanatos_htb_linkvortex_writeup.md](htb%20machines/Thanatos_htb_linkvortex_writeup.md)   |

## 📋 What You’ll Learn

Each writeup demonstrates:

* 🔍 **Enumeration** using Nmap, ffuf, gobuster, nuclei
* ⚔️ **Exploitation** of CVEs, logic flaws, and misconfigurations
* 🧬 **Credential Harvesting** via files, databases, memory, and tokens
* 🚀 **Privilege Escalation** via sudo, cron, LXC, symlinks, PATH hijack, capabilities
* 🧠 **Root-cause understanding** of how the vulnerabilities work

---

## 🛠 Tools Frequently Used

* `nmap`
* `ffuf`
* `nuclei`
* `Burp Suite`
* `rlwrap`
* `LinPEAS`
* `exploit-db`
* Custom Python & Bash scripts

---

## 👨‍💻 About Me

**Mridul Chamoli**
🎓 B.Tech CSE | Comptia Security+ | ISC2 Certified | 🛡️ Cybersecurity & CTF Enthusiast
🔗 GitHub: [https://github.com/mridulchamoli93](https://github.com/mridulchamoli93)

---

## ✨ Future Plans

* Add more Medium/Hard HTB writeups
* Add OS/technique-based categorization
* Automate CVE exploitation using custom tools
* Build personal HTB dashboard for progress tracking

---

## 🙌 Support

If you find this repo useful, please ⭐️ star it.

> *“Amateurs hack systems. Professionals hack people.” – Bruce Schneier*
