# 🧠 Hack The Box (HTB) – Machine Writeups

Welcome to the collection of my **Hack The Box machine walkthroughs**. This folder documents my full exploitation process for each HTB machine — from enumeration to exploitation to privilege escalation.

---

## 🗂️ Machine Writeups Included

| 🔐 Machine Name | 🧱 Difficulty | ⚙️ Techniques Covered                                                                                                                          | 🔗 HTB Link                                                                                      | 📄 Writeup (Local Markdown)                                                                                 |
| --------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| **Outbound**    | Easy          | Nmap, Nuclei scanning, CVE‑2025‑49113 Roundcube RCE, MySQL credential extraction, 3DES decryption, CVE‑2025‑27591 symlink privilege escalation | [https://app.hackthebox.com/machines/Outbound](https://app.hackthebox.com/machines/Outbound)     | [Thanatos_HTB_Outbound_Writeup.md](htb%20machines/Thanatos_HTB_Outbound_Writeup.md)                         |
| **Artificial**  | Easy          | HTTP enumeration, custom script exploitation, reverse shell via web upload, local enumeration                                                  | [https://app.hackthebox.com/machines/Artificial](https://app.hackthebox.com/machines/Artificial) | [Thanatos_HTB_Artificial_Writeup.md](htb%20machines/Thanatos_HTB_Artificial_Writeup.md)                     |
| **Nocturnal**   | Easy          | VHost discovery, insecure file upload → RCE, SQLite dump, ISPConfig RCE via local port forwarding                                              | [https://app.hackthebox.com/machines/Nocturnal](https://app.hackthebox.com/machines/Nocturnal)   | [Thanatos_HTB_Nocturnal_writeup.md](htb%20machines/Thanatos_HTB_Nocturnal_writeup.md)                       |
| **Era**         | Medium        | IDOR backup retrieval, PHP SSRF/RCE, SQLite credential extraction, admin takeover, cron-writable binary priv‑esc                               | [https://app.hackthebox.com/machines/Era](https://app.hackthebox.com/machines/Era)               | [Thanatos_HTB_Era_writeup.md](htb%20machines/Thanatos_HTB_Era_writeup.md)                                   |
| **Editor**      | Easy          | XWiki enum, CVE‑2024‑31982 Groovy RCE, reverse shell, config credential harvesting, PATH hijack via ndsudo                                     | [https://app.hackthebox.com/machines/Editor](https://app.hackthebox.com/machines/Editor)         | [Thanatos_HTB_Editor_Writeup.md](htb%20machines/Thanatos_HTB_Editor_Writeup.md)                             |
| **Planning**    | Easy–Medium   | Grafana CVE‑2024‑9264 RCE → container escape → cron UI → SUID bash escalation                                                                  | [https://app.hackthebox.com/machines/Planning](https://app.hackthebox.com/machines/Planning)     | [Planning - Writeup (Mridul Chamoli).md](htb%20machines/Planning%20-%20Writeup%20%28Mridul%20Chamoli%29.md) |
| **Cap**         | Easy          | PCAP analysis → FTP creds → SSH reuse → Linux capabilities privilege escalation                                                                | [https://app.hackthebox.com/machines/Cap](https://app.hackthebox.com/machines/Cap)               | [Cap - Writeup (Mridul).md](htb%20machines/Cap%20-%20Writeup%20%28Mridul%29.md)                             |
| **CodeTwo**     | Medium        | JS2Py sandbox escape (CVE‑2024‑28397), Flask LFI, SQLite cracking, npbackup‑cli root escalation                                                | [https://app.hackthebox.com/machines/CodeTwo](https://app.hackthebox.com/machines/CodeTwo)       | [CodeTwo - Writeup (Mridul).md](htb%20machines/CodeTwo%20-%20Writeup%20%28Mridul%29.md)                     |
| **Previous**    | Medium        | Next.js middleware bypass (CVE‑2025‑29927), LFI source extraction, credential discovery, Terraform provider takeover                           | [https://app.hackthebox.com/machines/Previous](https://app.hackthebox.com/machines/Previous)     | [Previous - Writeup (Mridul).md](htb%20machines/Previous%20-%20Writeup%20%28Mridul%29.md)                   |

---

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
