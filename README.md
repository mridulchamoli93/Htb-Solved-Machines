# 🧠 Hack The Box (HTB) – Machine Writeups

Welcome to the collection of my **Hack The Box machine walkthroughs**. This folder is dedicated to showcasing the step-by-step methodology I follow to enumerate, exploit, and escalate privileges on vulnerable HTB machines. The goal of each writeup is not just to capture the flag — but to understand *why* and *how* each vulnerability works.

---

## 🗂️ Machine Writeups Included
| 🔐 Machine Name | 🧱 Difficulty | ⚙️ Techniques Covered | 📄 Writeup |
|----------------|---------------|------------------------|------------|
| **Outbound**   | Easy          | Nmap, Nuclei, CVE-2025-49113 (Roundcube RCE), MySQL extraction, 3DES decryption, CVE-2025-27591 (Below arbitrary write) | [Thanatos_HTB_Outbound_Writeup.md](Thanatos_HTB_Outbound_Writeup.md) |
| **Artificial** | Easy          | Directory brute force, Login panel analysis, Custom script analysis, Reverse shell, Local enumeration | [Thanatos_HTB_artificial_Writeup.mdd](Thanatos_HTB_artificial_Writeup.md) |
| **Era**        | Easy          | Nmap, Gobuster, IDOR, Command Injection Bypass, Base64 DB Exfil, Local Port Forwarding, CVE-2023-46818 (ISPConfig RCE) | [Thanatos_HTB_Era_Writeup.md](Thanatos_HTB_Era_Writeup.md) |


---

## 📋 What You’ll Learn

Each writeup demonstrates:

- 🔍 **Enumeration** using tools like `nmap`, `ffuf`, and `nuclei`
- ⚔️ **Exploitation** of public CVEs or logic flaws in web services
- 🧬 **Credential Harvesting** via config files, databases, or tokens
- 🚀 **Privilege Escalation** using `sudo`, SUID, symlink abuse, or kernel exploits
- 💡 **Post-Exploitation Insights** for deeper understanding of Linux security

---

## 🛠 Tools Frequently Used

- `nmap` – Network scanning and port discovery  
- `ffuf` – Fuzzing hidden directories and files  
- `nuclei` – Vulnerability scanner for known CVEs  
- `Burp Suite` – Manual testing and intercepting traffic  
- `rlwrap` – Stabilizing reverse shells  
- `exploit-db`, `GTFOBins`, and custom Python/bash scripts

---

## 🚧 Folder Structure

htb-md-/
│
└───htb machines/
├── Thanatos_HTB_Outbound_Writeup.md
├── Thanatos_HTB_artificial_Writeup.mdd
└── README.md ← You are here


---

## 📌 Disclaimer

> ⚠️ These writeups are for **educational purposes only**.  
> All testing was done in a **controlled HTB environment**.  
> Never attempt these techniques on any system without **explicit permission**.

---

## 👨‍💻 About Me

**Mridul Chamoli**  
🎓 B.Tech CSE | Comptia Security + Certified | 🛡️ ISC2 Certified | 🔍 Cybersecurity & CTF Enthusiast 
🔗 GitHub: [@mridulchamoli93](https://github.com/mridulchamoli93)

---

## ✨ Future Plans

I aim to:

- Add Medium/Hard machine writeups
- Categorize machines based on OS & technique
- Possibly automate CVE exploitation via my own tools/scripts
- Build a personal HTB lab & dashboard

---

## 🙌 Support & Contributions

If you found these writeups useful, consider ⭐️ starring this repository or following me for more content.

---

> *“Amateurs hack systems. Professionals hack people.” – Bruce Schneier*

---
