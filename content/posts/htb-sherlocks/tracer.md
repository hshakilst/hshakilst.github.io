---
title: "HTB Sherlock Tracer"
date: 2025-09-18T05:07:43-04:00
tags:
  - htb
  - sherlock
  - dfir
  - windows
  - evtx
  - usnjournal
  - prefetch
  - evtxecmd
  - pecmd
  - mftecmd
  - log
  - event
  - jq
  - zimmerman-tools
---

# Tracer - DFIR

### Scenario
A junior SOC analyst on duty has reported multiple alerts indicating the presence of PsExec on a workstation. They verified the alerts and escalated the alerts to tier II. As an Incident responder you triaged the endpoint for artifacts of interest. Now please answer the questions regarding this security event so you can report it to your incident manager.

### Artifacts
| Artifact                            | MD5 Hash                         | Password    | Remarks                                                           |
| ----------------------------------- | -------------------------------- | ----------- | ----------------------------------------------------------------- |
| tracer.zip                          | 8cceeed93b876b9c60e53a1f2f7a68a1 | hacktheblue | Contains Windows Event Logs, Prefetch files and UsnJournal files. |
| C/\$Extend/$J                       | 068a557274548bc88d2a9919c3195983 |             | UsnJournal file's ADS.                                            |
| 20240620050901_PECmd_Output.json    | 1b3cd6882263b86735ebf0024c1cfa3d |             | Converted prefetch files to a single JSON file format.            |
| 20240620051031_EvtxECmd_Output.json | 56c682158bd5e789558cf8a834313b60 |             | Converted all the Windows .evtx file to a single JSON file.       |
| 20240620054048_MFTECmd_J_Output.csv | 98eb829bfc6d7751aa1a51545a7ed430 |             | Converted the Usn Journal file's ADS to a CSV file format.        |

### Tools
+ EvtxECmd - Eric Zimmerman Tools: To convert the windows event logs into a single JSON file.
+ PECmd - Eric Zimmerman Tools: To convert the prefetch files into a single JSON file.
+ MFTECmd - Eric Zimmerman Tools: To convert the Usn Journal's alternate data stream file $J to a CSV file format.

### Tasks
1. The SOC Team suspects that an adversary is lurking in their environment and are using PsExec to move laterally. A junior SOC Analyst specifically reported the usage of PsExec on a Work Station. How many times was PsExec executed by the attacker on the system?
2. What is the name of the service binary dropped by PsExec tool allowing attacker to execute remote commands?
3. Now we have confirmed that PsExec ran multiple times, we are particularly interested in the 5th Last instance of the PsExec. What is the timestamp when the PsExec Service binary ran?
4. Can you confirm the hostname of the workstation from which attacker moved laterally?
5. What is full name of the Key File dropped by 5th last instance of the Psexec?
6. Can you confirm the timestamp when this key file was created on disk?
7. What is the full name of the Named Pipe ending with the "stderr" keyword for the 5th last instance of the PsExec?

### Forensic Analysis
For task 1, 2, 3, 4 and 5 we can run the `jq` lang query on the converted prefetch JSON file `20240620050901_PECmd_Output.json` for `PSEXESVC.EXE` this is the service binary that handles the PsExec commands remotely or locally.
```sh
$ cat 20240620050901_PECmd_Output.json | jq 'select(.ExecutableName=="PSEXESVC.EXE")'                          
{
  "SourceFilename": "prefetch\\PSEXESVC.EXE-AD70946C.pf",
  "SourceCreated": "2023-09-08 00:10:04",
  "SourceModified": "2024-06-20 05:04:51",
  "SourceAccessed": "2024-06-20 05:08:55",
  "ExecutableName": "PSEXESVC.EXE",
  "Hash": "AD70946C",
  "Size": "18142",
  "Version": "Windows 10 or Windows 11",
  "RunCount": "9",
  "LastRun": "2023-09-07 12:10:03",
  "PreviousRun0": "2023-09-07 12:09:09",
  "PreviousRun1": "2023-09-07 12:08:54",
  "PreviousRun2": "2023-09-07 12:08:23",
  "PreviousRun3": "2023-09-07 12:06:54",
  "PreviousRun4": "2023-09-07 11:57:53",
  "PreviousRun5": "2023-09-07 11:57:43",
  "PreviousRun6": "2023-09-07 11:55:44",
  "Volume0Name": "\\VOLUME{01d951602330db46-52233816}",
  "Volume0Serial": "52233816",
  "Volume0Created": "2023-03-08 01:48:53",
  "Directories": "\\VOLUME{01d951602330db46-52233816}\\PROGRAMDATA, \\VOLUME{01d951602330db46-52233816}\\PROGRAMDATA\\MICROSOFT, \\VOLUME{01d951602330db46-52233816}\\PROGRAMDATA\\MICROSOFT\\CRYPTO, \\VOLUME{01d951602330db46-52233816}\\PROGRAMDATA\\MICROSOFT\\CRYPTO\\RSA, \\VOLUME{01d951602330db46-52233816}\\PROGRAMDATA\\MICROSOFT\\CRYPTO\\RSA\\S-1-5-18, \\VOLUME{01d951602330db46-52233816}\\WINDOWS, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32",
  "FilesLoaded": "\\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\NTDLL.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\PSEXESVC.EXE, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\KERNELBASE.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\LOCALE.NLS, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\USER32.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\USERENV.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\WIN32U.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\UCRTBASE.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\GDI32.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\RPCRT4.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\GDI32FULL.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\MSVCP_WIN.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\ADVAPI32.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\MSVCRT.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\SECHOST.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\SHELL32.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\WTSAPI32.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\KERNEL.APPCORE.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\NTMARTA.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\PSEXEC-FORELA-WKSTN001-CAD5E7EF.KEY, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\CRYPTSP.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\RSAENH.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\BCRYPT.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\SSPICLI.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\PROFAPI.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\BCRYPTPRIMITIVES.DLL, \\VOLUME{01d951602330db46-52233816}\\PROGRAMDATA\\MICROSOFT\\CRYPTO\\RSA\\S-1-5-18\\F05260A40AE771219C4528E4628312CD_B02EC91E-ADE1-4F67-9328-AE89B0EBD197, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\CRYPTBASE.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\NETAPI32.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\LOGONCLI.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\NETUTILS.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\SYSTEM32\\WINSTA.DLL, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\PSEXEC-FORELA-WKSTN001-89A517EE.KEY, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\PSEXEC-FORELA-WKSTN001-415385DF.KEY, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\PSEXEC-FORELA-WKSTN001-C3E84A44.KEY, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\PSEXEC-FORELA-WKSTN001-95F03CFE.KEY, \\VOLUME{01d951602330db46-52233816}\\$MFT, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\PSEXEC-FORELA-WKSTN001-663BCB85.KEY, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\PSEXEC-FORELA-WKSTN001-7AA5D6C6.KEY, \\VOLUME{01d951602330db46-52233816}\\WINDOWS\\PSEXEC-FORELA-WKSTN001-EDCC783C.KEY",                                                
  "ParsingError": false
}
```

```ad-tip
A note to count the binary last runs, we should start from the LastRun as 1, PreviousRun0 as 2 and so on. The order of the FilesLoaded also follows this rule. The latest run's loaded files are on top and the first run's loaded files are in the bottom. 
```

To answer the question for Task 6 we can search the Usn Journal records and search for the update reason attribute which is `FileCreate`.
![[Pasted image 20240621073521.png]]

To answer the last Task's question we need search for `PipeEvent (Pipe Created)` which has an event ID of 17 and then search for pipe names that ends with `stderr` and that was created when the last 5th instance of PsExec was ran. We can do the following and compare the date created with the last 5th instance's run time.
```sh
$ cat 20240620051031_EvtxECmd_Output.json | jq '. | select(.TimeCreated >= "2023-09-07 12:06:54" and .EventId==17) | select(.PayloadData2 | test("stderr$"))' -c | head -n1
{"PayloadData1":"ProcessID: 6836, ProcessGUID: b02ec91e-bcde-64f9-0c02-000000003000","PayloadData2":"PipeName: \\PSEXESVC-FORELA-WKSTN001-3056-stderr","PayloadData5":"Image: C:\\WINDOWS\\PSEXESVC.exe","UserName":"NT AUTHORITY\\SYSTEM","MapDescription":"PipeEvent (Pipe Created)","ChunkNumber":5,"Computer":"Forela-Wkstn002.forela.local","Payload":"{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"EventType\",\"#text\":\"CreatePipe\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-09-07 12:06:55.069\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"b02ec91e-bcde-64f9-0c02-000000003000\"},{\"@Name\":\"ProcessId\",\"#text\":\"6836\"},{\"@Name\":\"PipeName\",\"#text\":\"\\\\PSEXESVC-FORELA-WKSTN001-3056-stderr\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\WINDOWS\\\\PSEXESVC.exe\"},{\"@Name\":\"User\",\"#text\":\"NT AUTHORITY\\\\SYSTEM\"}]}}","UserId":"S-1-5-18","Channel":"Microsoft-Windows-Sysmon/Operational","Provider":"Microsoft-Windows-Sysmon","EventId":17,"EventRecordId":"159603","ProcessId":3552,"ThreadId":4360,"Level":"Info","Keywords":"Classic","SourceFile":".\\System32\\winevt\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx","ExtraDataOffset":0,"HiddenRecord":false,"TimeCreated":"2023-09-07T12:06:55.0846666+00:00","RecordNumber":159603}
```

### Summary
In this Sherlock we explored the Usn Journal and deep dived into Windows prefetch files. Also, a moderate understanding of PsExec commands was necessary to answer the task question. Finally, I included some resources to read about more those two above mentioned artifacts.