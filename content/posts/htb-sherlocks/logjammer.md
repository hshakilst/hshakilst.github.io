---
title: "HTB Sherlock Logjammer"
date: 2024-06-13T04:39:51-04:00
tags:
  - htb
  - sherlock
  - dfir
  - windows
  - evtx
  - python-evtx
  - log
  - event
  - zimmerman-tools
  - evtxecmd
  - powershell-event
  - windows-defender-event
  - firewall-event
  - system-event
  - security-event
---

# LoLogjammer - DFIR

### Scenario
You have been presented with the opportunity to work as a junior DFIR consultant for a big consultancy. However, they have provided a technical assessment for you to complete. The consultancy Forela-Security would like to gauge your Windows Event Log Analysis knowledge. We believe the Cyberjunkie user logged in to his computer and may have taken malicious actions. Please analyze the given event logs and report back.

### Artifacts
| Name                                         | MD5 Hash                         | Password    |
| -------------------------------------------- | -------------------------------- | ----------- |
| logjammer.zip                                | 2ba794c406aee485186a959c840125af | hacktheblue |
| Event-Logs/Powershell-Operational.evtx       | 6739802c74adc7bf6432dfcec853397c | n/a         |
| Event-Logs/Security.evtx                     | 5b75f867d2107d04721ccaeea7914cfd | n/a         |
| Event-Logs/System.evtx                       | 34b0d7a505c880a8ae78405d581b2b1a | n/a         |
| Event-Logs/Windows Defender-Operational.evtx | a2f06faad866ac054705643b0e2c2364 | n/a         |
| Event-Logs/Windows Firewall-Firewall.evtx    | 7ff34616822baa259a8179ed3677173a | n/a         |

### Tools
+ [evtx_dump](https://github.com/omerbenamram/EVTX): For dumping the evtx file.
+ `jq`: For querying the dumped JSON files.

### Forensic Analysis
Let's dump the evtx file to JSON, after that we can determine if we should use any SIEM tool for analysis for the Linux command line will be sufficient based on the volume of the data.

To dump the evtx file to JSON we can use `evtx-dump`. Here are some resources for finding Windows Event Log's Event IDs, Event Names, Event Description, etc. - [[Windows Event Logs]].

Dump .evtx to JSONL
```bash
$ evtx_dump -f 'Windows Firewall-Firewall.json' -o jsonl Windows\ Firewall-Firewall.evtx
```

Analyze the logs using Event ID and search the converted JSON files using `jq`. To make this operation easy we can concatenate all the converted json files to a single log file.

Looking for a user with username `CyberJunkie` for a user logon event (4624) would be like the following:
```bash
$ cat all_events.json | jq 'select(.Event.System.EventID==4624 and .Event.EventData.TargetUserName=="CyberJunkie")' -c | wc -l
4
```

The user `CyberJunkie` logged in 4 times to the workstation that is compromised.

The user also modified the firewall setting and added a firewall rule `Metasploit C2 Bypass` to facilitate his C2 server communication. Here, Event ID 2004 for Event Source `Microsoft-Windows-Windows Firewall with Advanced Security` is logged when a rule has been added to the Windows Firewall exception list.

```bash
$ cat all_events.json | jq 'select(.Event.System.EventID==2004 and .Event.EventData.ModifyingUser=="S-1-5-21-3393683511-3463148672-371912004-1001") .Event.EventData.RuleName'       
"File and Printer Sharing (LLMNR-UDP-Out)"
"File and Printer Sharing (LLMNR-UDP-In)"
"File and Printer Sharing (Echo Request - ICMPv6-Out)"
"File and Printer Sharing (Echo Request - ICMPv6-In)"
"File and Printer Sharing (Echo Request - ICMPv4-Out)"
"File and Printer Sharing (Echo Request - ICMPv4-In)"
"File and Printer Sharing (Spooler Service - RPC-EPMAP)"
"File and Printer Sharing (Spooler Service - RPC)"
"File and Printer Sharing (NB-Datagram-Out)"
"File and Printer Sharing (NB-Datagram-In)"
"File and Printer Sharing (NB-Name-Out)"
"File and Printer Sharing (NB-Name-In)"
"File and Printer Sharing (SMB-Out)"
"File and Printer Sharing (SMB-In)"
"File and Printer Sharing (NB-Session-Out)"
"File and Printer Sharing (NB-Session-In)"
"Network Discovery (Pub WSD-Out)"
"Network Discovery (Pub-WSD-In)"
"Network Discovery (LLMNR-UDP-Out)"
"Network Discovery (LLMNR-UDP-In)"
"Network Discovery (WSD-Out)"
"Network Discovery (WSD-In)"
"Network Discovery (WSD-In)"
"Network Discovery (UPnPHost-Out)"
"Network Discovery (SSDP-Out)"
"Network Discovery (SSDP-In)"
"Firefox (C:\\Program Files\\Mozilla Firefox)"
"Firefox (C:\\Program Files\\Mozilla Firefox)"
"Metasploit C2 Bypass"
```

Here's the details of the malicious rule named added to the exception list.
```bash
$ cat all_events.json | jq 'select(.Event.System.EventID==2004 and .Event.EventData.ModifyingUser=="S-1-5-21-3393683511-3463148672-371912004-1001" and .Event.EventData.RuleName=="Metasploit C2 Bypass")'
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "Action": 3,
      "Active": 1,
      "ApplicationPath": "",
      "Direction": 2,
      "EdgeTraversal": 0,
      "EmbeddedContext": "",
      "Flags": 1,
      "LocalAddresses": "*",
      "LocalOnlyMapped": 0,
      "LocalPorts": "*",
      "LooseSourceMapped": 0,
      "ModifyingApplication": "C:\\Windows\\System32\\mmc.exe",
      "ModifyingUser": "S-1-5-21-3393683511-3463148672-371912004-1001",
      "Origin": 1,
      "Profiles": 2147483647,
      "Protocol": 6,
      "RemoteAddresses": "*",
      "RemoteMachineAuthorizationList": "",
      "RemotePorts": "4444",
      "RemoteUserAuthorizationList": "",
      "RuleId": "{11309293-FB68-4969-93F9-7F75A9032570}",
      "RuleName": "Metasploit C2 Bypass",
      "RuleStatus": 65536,
      "SchemaVersion": 542,
      "SecurityOptions": 0,
      "ServiceName": ""
    },
    "System": {
      "Channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
      "Computer": "DESKTOP-887GK2L",
      "Correlation": null,
      "EventID": 2004,
      "EventRecordID": 1120,
      "Execution": {
        "#attributes": {
          "ProcessID": 2384,
          "ThreadID": 2868
        }
      },
      "Keywords": "0x8000020000000000",
      "Level": 4,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85",
          "Name": "Microsoft-Windows-Windows Firewall With Advanced Security"
        }
      },
      "Security": {
        "#attributes": {
          "UserID": "S-1-5-19"
        }
      },
      "Task": 0,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2023-03-27T14:44:43.415702Z"
        }
      },
      "Version": 0
    }
  }
}
```

The firewall rule's direction was set to "2" which means "Outbound". So, I think "1" means "Inbound"? Unable to find documentation regarding the integer values.

Windows Policy Change Event ID is 4719:
```bash
$ cat all_events.json | jq 'select(.Event.System.EventID==4719)'       
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "AuditPolicyChanges": "%%8449",
      "CategoryId": "%%8274",
      "SubcategoryGuid": "0CCE9227-69AE-11D9-BED3-505054503030",
      "SubcategoryId": "%%12804",
      "SubjectDomainName": "WORKGROUP",
      "SubjectLogonId": "0x3e7",
      "SubjectUserName": "DESKTOP-887GK2L$",
      "SubjectUserSid": "S-1-5-18"
    },
    "System": {
      "Channel": "Security",
      "Computer": "DESKTOP-887GK2L",
      "Correlation": {
        "#attributes": {
          "ActivityID": "986A053F-60B9-0002-5B05-6A98B960D901"
        }
      },
      "EventID": 4719,
      "EventRecordID": 13102,
      "Execution": {
        "#attributes": {
          "ProcessID": 780,
          "ThreadID": 1488
        }
      },
      "Keywords": "0x8020000000000000",
      "Level": 0,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
          "Name": "Microsoft-Windows-Security-Auditing"
        }
      },
      "Security": null,
      "Task": 13568,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2023-03-27T14:50:03.721835Z"
        }
      },
      "Version": 0
    }
  }
}
```

Searching the sub category's GUID yielded the result `Other Object Access Events`.

Finding Scheduled Task Creation Events by the user CyberJunkie
```bash
$ cat all_events.json | jq 'select(.Event.System.EventID==4698 and .Event.EventData.SubjectUserName=="CyberJunkie")'
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "ClientProcessId": 9320,
      "ClientProcessStartKey": 4222124650660162,
      "FQDN": "DESKTOP-887GK2L",
      "ParentProcessId": 6112,
      "RpcCallClientLocality": 0,
      "SubjectDomainName": "DESKTOP-887GK2L",
      "SubjectLogonId": "0x25f28",
      "SubjectUserName": "CyberJunkie",
      "SubjectUserSid": "S-1-5-21-3393683511-3463148672-371912004-1001",
      "TaskContent": "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n  <RegistrationInfo>\r\n    <Date>2023-03-27T07:51:21.4599985</Date>\r\n    <Author>DESKTOP-887GK2L\\CyberJunkie</Author>\r\n    <Description>practice</Description>\r\n    <URI>\\HTB-AUTOMATION</URI>\r\n  </RegistrationInfo>\r\n  <Triggers>\r\n    <CalendarTrigger>\r\n      <StartBoundary>2023-03-27T09:00:00</StartBoundary>\r\n      <Enabled>true</Enabled>\r\n      <ScheduleByDay>\r\n        <DaysInterval>1</DaysInterval>\r\n      </ScheduleByDay>\r\n    </CalendarTrigger>\r\n  </Triggers>\r\n  <Principals>\r\n    <Principal id=\"Author\">\r\n      <RunLevel>LeastPrivilege</RunLevel>\r\n      <UserId>DESKTOP-887GK2L\\CyberJunkie</UserId>\r\n      <LogonType>InteractiveToken</LogonType>\r\n    </Principal>\r\n  </Principals>\r\n  <Settings>\r\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\r\n    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\r\n    <AllowHardTerminate>true</AllowHardTerminate>\r\n    <StartWhenAvailable>false</StartWhenAvailable>\r\n    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n    <IdleSettings>\r\n      <Duration>PT10M</Duration>\r\n      <WaitTimeout>PT1H</WaitTimeout>\r\n      <StopOnIdleEnd>true</StopOnIdleEnd>\r\n      <RestartOnIdle>false</RestartOnIdle>\r\n    </IdleSettings>\r\n    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n    <Enabled>true</Enabled>\r\n    <Hidden>false</Hidden>\r\n    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n    <WakeToRun>false</WakeToRun>\r\n    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>\r\n    <Priority>7</Priority>\r\n  </Settings>\r\n  <Actions Context=\"Author\">\r\n    <Exec>\r\n      <Command>C:\\Users\\CyberJunkie\\Desktop\\Automation-HTB.ps1</Command>\r\n      <Arguments>-A cyberjunkie@hackthebox.eu</Arguments>\r\n    </Exec>\r\n  </Actions>\r\n</Task>",
      "TaskName": "\\HTB-AUTOMATION"
    },
    "System": {
      "Channel": "Security",
      "Computer": "DESKTOP-887GK2L",
      "Correlation": {
        "#attributes": {
          "ActivityID": "986A053F-60B9-0002-5B05-6A98B960D901"
        }
      },
      "EventID": 4698,
      "EventRecordID": 13103,
      "Execution": {
        "#attributes": {
          "ProcessID": 780,
          "ThreadID": 4180
        }
      },
      "Keywords": "0x8020000000000000",
      "Level": 0,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
          "Name": "Microsoft-Windows-Security-Auditing"
        }
      },
      "Security": null,
      "Task": 12804,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2023-03-27T14:51:21.481720Z"
        }
      },
      "Version": 1
    }
  }
}
```

Task name was "HTB-AUTOMATION" and the contents were:
```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2"
xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo>
<Date>2023-03-27T07:51:21.4599985</Date>
<Author>DESKTOP-887GK2L\\CyberJunkie</Author>
<Description>practice</Description>
<URI>\\HTB-AUTOMATION</URI>
</RegistrationInfo>
<Triggers>
<CalendarTrigger>
<StartBoundary>2023-03-27T09:00:00</StartBoundary>
<Enabled>true</Enabled>
<ScheduleByDay>
<DaysInterval>1</DaysInterval>
</ScheduleByDay>
</CalendarTrigger>
</Triggers>
<Principals>
<Principal id="Author">
<RunLevel>LeastPrivilege</RunLevel>
<UserId>DESKTOP-887GK2L\\CyberJunkie</UserId>
<LogonType>InteractiveToken</LogonType>
</Principal>
</Principals>
<Settings>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
<AllowHardTerminate>true</AllowHardTerminate>
<StartWhenAvailable>false</StartWhenAvailable>
<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
<IdleSettings>
<Duration>PT10M</Duration>
<WaitTimeout>PT1H</WaitTimeout>
<StopOnIdleEnd>true</StopOnIdleEnd>
<RestartOnIdle>false</RestartOnIdle>
</IdleSettings>
<AllowStartOnDemand>true</AllowStartOnDemand>
<Enabled>true</Enabled>
<Hidden>false</Hidden>
<RunOnlyIfIdle>false</RunOnlyIfIdle>
<WakeToRun>false</WakeToRun>
<ExecutionTimeLimit>P3D</ExecutionTimeLimit>
<Priority>7</Priority>
</Settings>
<Actions Context="Author">
<Exec>
<Command>C:\\Users\\CyberJunkie\\Desktop\\Automation-HTB.ps1</Command>
<Arguments>-A cyberjunkie@hackthebox.eu</Arguments>
</Exec>
</Actions>
</Task>
```

Windows Defend Antivirus threat detection event ID is `1117`. To list these events invoked by the use CyberJunkie we can use the following command:
```bash
$ cat all_events.json | jq 'select(.Event.System.EventID==1117 and .Event.EventData."Detection User"=="DESKTOP-887GK2L\\CyberJunkie")' -c | tail -n1
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "Action ID": "2",
      "Action Name": "Quarantine",
      "Additional Actions ID": "0",
      "Additional Actions String": "No additional actions required",
      "Category ID": "34",
      "Category Name": "Tool",
      "Detection ID": "{0EBC4BEA-5532-4EFB-8A34-64F91CC8702E}",
      "Detection Time": "2023-03-27T14:42:34.272Z",
      "Detection User": "DESKTOP-887GK2L\\CyberJunkie",
      "Engine Version": "AM: 1.1.20100.6, NIS: 1.1.20100.6",
      "Error Code": "0x80508023",
      "Error Description": "The program could not find the malware and other potentially unwanted software on this device. ",
      "Execution ID": "0",
      "Execution Name": "Unknown",
      "FWLink": "https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:MSIL/SharpHound!MSR&threatid=2147814944&enterprise=0",
      "Origin ID": "4",
      "Origin Name": "Internet",
      "Path": "containerfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip; file:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip->SharpHound.exe; webfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230327%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230327T144228Z&X-Amz-Expires=300&X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=385323486&response-content-disposition=attachment%3B%20filename%3DSharpHound-v1.1.0.zip&response-content-type=application%2Foctet-stream|pid:3532,ProcessStart:133244017530289775",
      "Post Clean Status": "0",
      "Pre Execution Status": "0",
      "Process Name": "Unknown",
      "Product Name": "Microsoft Defender Antivirus",
      "Product Version": "4.18.2302.7",
      "Remediation User": "NT AUTHORITY\\SYSTEM",
      "Security intelligence Version": "AV: 1.385.1261.0, AS: 1.385.1261.0, NIS: 1.385.1261.0",
      "Severity ID": "4",
      "Severity Name": "High",
      "Source ID": "4",
      "Source Name": "Downloads and attachments",
      "State": "2",
      "Status Code": "103",
      "Status Description": "",
      "Threat ID": "2147814944",
      "Threat Name": "HackTool:MSIL/SharpHound!MSR",
      "Type ID": "0",
      "Type Name": "Concrete",
      "Unused": "",
      "Unused2": "",
      "Unused3": "",
      "Unused4": "",
      "Unused5": "",
      "Unused6": ""
    },
    "System": {
      "Channel": "Microsoft-Windows-Windows Defender/Operational",
      "Computer": "DESKTOP-887GK2L",
      "Correlation": null,
      "EventID": 1117,
      "EventRecordID": 444,
      "Execution": {
        "#attributes": {
          "ProcessID": 3300,
          "ThreadID": 3056
        }
      },
      "Keywords": "0x8000000000000000",
      "Level": 4,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78",
          "Name": "Microsoft-Windows-Windows Defender"
        }
      },
      "Security": {
        "#attributes": {
          "UserID": "S-1-5-18"
        }
      },
      "Task": 0,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2023-03-27T14:42:48.353664Z"
        }
      },
      "Version": 0
    }
  }
}
```

To List the commands executed on PowerShell by the user `CyberJunkie` we need two pieces of Information.
1. We need the time when CyberJunkie user logged on to the System.
2. We need the PowerShell Script Block Execution Event ID which is `4104`

Correlating this two pieces of data we can extract the commands ran by the user CyberJunkie.
```bash
$ cat all_events.json | jq 'select(.Event.System.EventID==4104 and .Event.System.TimeCreated."#attributes".SystemTime > "2023-03-27T14:38:32.937458Z") .Event.EventData.ScriptBlockText'       
"prompt"
"Get-FileHash -Algorithm md5 .\\Desktop\\Automation-HTB.ps1"
"prompt"
```

```ad-tip
Use Zimmerman's EvtxECmd.exe for future Windows Event Log Analysis. It flattens the JSON fields to almost 1 level deep, which can be very useful to query using **jq**
```

Finding the deleted System Event log after CyberJunkie logged on to the system.
```bash
$ cat all_events.json | jq 'select(.Event.System.EventID==104 and .Event.System.TimeCreated."#attributes".SystemTime > "2023-03-27T14:38:32.937458Z")'       
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "System": {
      "Channel": "System",
      "Computer": "DESKTOP-887GK2L",
      "Correlation": null,
      "EventID": 104,
      "EventRecordID": 2186,
      "Execution": {
        "#attributes": {
          "ProcessID": 1332,
          "ThreadID": 5332
        }
      },
      "Keywords": "0x8000000000000000",
      "Level": 4,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}",
          "Name": "Microsoft-Windows-Eventlog"
        }
      },
      "Security": {
        "#attributes": {
          "UserID": "S-1-5-21-3393683511-3463148672-371912004-1001"
        }
      },
      "Task": 104,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2023-03-27T15:01:56.515836Z"
        }
      },
      "Version": 0
    },
    "UserData": {
      "LogFileCleared": {
        "#attributes": {
          "xmlns": "http://manifests.microsoft.com/win/2004/08/windows/eventlog"
        },
        "BackupPath": "",
        "Channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "SubjectDomainName": "DESKTOP-887GK2L",
        "SubjectUserName": "CyberJunkie"
      }
    }
  }
}
```

### Summary
This Sherlock was tough for me to answer the Task 11, 12 questions. I get to study different kinds of Windows Event Logs specially Firewall, PowerShell, Windows Defender and System. I get to analyze what commands the TA ran, what malicious files they uploaded, what firewall rules were added and also how they tried to cover their tracks by removing certain log files. It was a fun experience.