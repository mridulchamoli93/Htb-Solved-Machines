# Underpass — HackTheBox Writeup

**Machine IP**: `10.10.11.48`
**Author**: Mridul Chamoli
**Skills Learned**: Daloradius enumeration, Mosh shell interaction, Nmap, SNMP enumeration

---

## Summary

This box demonstrates SNMP information disclosure leading to a daloradius web application. From daloradius we recover credentials, access the admin panel, find a user hash (svcMosh), crack it, obtain a foothold, and finally abuse `mosh-server` via sudo to escalate to root.

---

## 🔍 Enumeration

### Nmap (TCP)

Initial aggressive port discovery:

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/underpass$
nmap -sT -p- --min-rate 10000 10.10.11.48 -Pn -oA nmap_ports
thanatos@kali:/home/thanatos/Desktop/htb/machines/underpass$ nmap -sC -sV -p 22,80 10.10.11.48 -Pn -oA nmap_ports_details
```

Result highlights:

* `22/tcp` — SSH
* `80/tcp` — HTTP

### UDP scan

A quick UDP scan revealed SNMP on port 161:

```bash
sudo nmap -sUV -T4 10.10.11.48 -oA nmap_ports_udp
```

### SNMP enumeration

Using `snmpwalk` with the public community string:

```bash
snmpwalk -v 2c -c public 10.10.11.48
```

The SNMP output contained useful strings, including an email `steve@underpass.htb` and a note: "Underpass.htb is the only daloradius server in the basin!" — a strong hint to check for daloradius.

### Web discovery

I visited port 80 and found nothing interesting on the main page, but trying `/daloradius` returned `403 Forbidden` (indicating an existing directory). I fuzzed the daloradius path for hidden endpoints:

```bash
ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt -u "http://10.10.11.48/daloradius/app/FUZZ" -t 200
```

From the fuzzing results, the following endpoints were discovered:

* `/daloradius/app/`
* `/daloradius/app/contrib/`
* `/daloradius/app/operators/index.php` → redirects to `login.php`

---

## 🛠️ Foothold — daloradius admin panel

A quick search found default daloradius credentials: `administrator:radius`. Using those credentials we logged into the admin panel.

Inside the admin UI (Management → List Users) we found a user `svcMosh` and a corresponding 32-character hex password hash. I used CrackStation (or any suitable hash-cracking service/tool) to recover the plaintext password.

With the cracked credentials for `svcMosh`, I SSH'd into the server and retrieved `user.txt`.

---

## ⬆️ Privilege Escalation — abusing mosh-server via sudo

On the box, `svcMosh` has sudo rights for `mosh-server`:

```bash
sudo -l
# (ALL) NOPASSWD: /usr/bin/mosh-server
```

`mosh-server` is the server-side component of Mosh (a mobile shell). The mosh FAQ/documentation explains that the server prints a key and port which the client must use to connect. Importantly, you can launch `mosh-server` bound to `127.0.0.1` and then connect the mosh client locally using the provided key and port.

**Escalation approach**:

1. Run `mosh-server` as root with sudo (it will output a key and port to connect to).
2. Start a local `mosh-client` using the `MOSH_KEY=<KEY> mosh-client <IP> <PORT>` invocation and connect to the server on `127.0.0.1`.
3. The resulting session will be running with root privileges (because `mosh-server` was launched via sudo), effectively granting a root shell.

Example (conceptual):

```bash
# as svcMosh (allowed by sudo)
sudo /usr/bin/mosh-server
# mosh-server prints something like: PORT: 60123 KEY: ABCDEF...
# on the same host, run:
MOSH_KEY=ABCDEF mosh-client 127.0.0.1 60123
# you get a root shell
```

This yields root access when performed correctly.

---

## Notes & Mitigations

* **SNMP**: Disable or restrict SNMP, avoid using default community strings like `public`, and limit SNMP access via ACLs.
* **Web apps**: Secure daloradius installations, change default credentials, and limit administrative access.
* **Sudo**: Avoid allowing NOPASSWD execution of network-facing daemons or programs that spawn shells. If required, apply strict command argument validation.
* **Hash storage**: Use strong hashing algorithms and salts for stored passwords.

---

## Directory used

```
~/Boxes/Hackthebox/.../Underpass
```

---

**Terminal**: `thanatos@kali:/home/thanatos/Desktop/htb/machines/underpass`

*Happy hacking!*
