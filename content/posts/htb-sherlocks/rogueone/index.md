---
title: "HTB Sherlock RogueOne"
date: 2024-06-11T15:18:00
tags:
  - htb
  - sherlock
  - dfir
  - memory
  - dump
  - volatility
  - forensic
  - malware
  - windows
image:
---

# RogueOne - DFIR

### Scenario

Your SIEM system generated multiple alerts in less than a minute, indicating potential C2 communication from Simon Stark's workstation. Despite Simon not noticing anything unusual, the IT team had him share screenshots of his task manager to check for any unusual processes. No suspicious processes were found, yet alerts about C2 communications persisted. The SOC manager then directed the immediate containment of the workstation and a memory dump for analysis. As a memory forensics expert, you are tasked with assisting the SOC team at Forela to investigate and resolve this urgent incident.

### Artifacts
|Artifact|MD5 Hash|Password|
|----|----|----|
|RogueOne.zip|5810aa928e827d5ab8373aa4e1107572|hacktheblue|
|220230810.mem|d34ed786f888c1da061399df6cbe9d7b|n/a|


### Tools

+ Volatility

### Analysis

Memory Dump Information
```bash
$ vol3 -f 20230810.mem windows.info
Volatility 3 Framework 2.7.1
Progress:  100.00		PDB scanning finished                                                                                              
Variable	Value

Kernel Base	0xf80178400000
DTB	0x16a000
Symbols	file:///opt/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/3789767E34B7A48A3FC80CE12DE18E65-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdVersionBlock	0xf8017900f398
Major/Minor	15.19041
MachineType	34404
KeNumberProcessors	8
SystemTime	2023-08-10 11:32:00
NtSystemRoot	C:\WINDOWS
NtProductType	NtProductWinNt
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Mon Nov 24 23:45:00 2070
```

**Profile Identification**
We are dealing with Windows 10.0 Build 19041 and x64 architecture.

**Malicious Process Identification**

Process Information
```bash
$ vol3 -f 20230810.mem windows.psscan
Volatility 3 Framework 2.7.1
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

4876	788	svchost.exe	0x9d80001bd1c0	4	-	0	False	2023-08-10 11:13:45.000000 	N/A	Disabled
4	0	System	0x9e8b87680040	225	-	N/A	False	2023-08-10 11:13:38.000000 	N/A	Disabled
140	4	Registry	0x9e8b876ce080	4	-	N/A	False	2023-08-10 11:13:32.000000 	N/A	Disabled
2240	928	ShellExperienc	0x9e8b8775c080	11	-	1	False	2023-08-10 11:27:30.000000 	N/A	Disabled
6812	7436	svchost.exe	0x9e8b87762080	3	-	1	False	2023-08-10 11:30:03.000000 	N/A	Disabled
564	548	csrss.exe	0x9e8b882f8140	13	-	0	False	2023-08-10 11:13:41.000000 	N/A	Disabled
436	4	smss.exe	0x9e8b8843f040	2	-	N/A	False	2023-08-10 11:13:38.000000 	N/A	Disabled
644	636	csrss.exe	0x9e8b893eb140	14	-	1	False	2023-08-10 11:13:41.000000 	N/A	Disabled
656	548	wininit.exe	0x9e8b89416080	1	-	0	False	2023-08-10 11:13:41.000000 	N/A	Disabled
744	636	winlogon.exe	0x9e8b89441080	4	-	1	False	2023-08-10 11:13:42.000000 	N/A	Disabled
4744	788	svchost.exe	0x9e8b8946d1c0	1	-	0	False	2023-08-10 11:13:45.000000 	N/A	Disabled
788	656	services.exe	0x9e8b8949e080	10	-	0	False	2023-08-10 11:13:42.000000 	N/A	Disabled
808	656	lsass.exe	0x9e8b894a2080	12	-	0	False	2023-08-10 11:13:42.000000 	N/A	Disabled
928	788	svchost.exe	0x9e8b89527240	13	-	0	False	2023-08-10 11:13:42.000000 	N/A	Disabled
964	656	fontdrvhost.ex	0x9e8b8952e180	5	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
956	744	fontdrvhost.ex	0x9e8b89530180	5	-	1	False	2023-08-10 11:13:43.000000 	N/A	Disabled
512	788	svchost.exe	0x9e8b895a72c0	11	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
864	788	svchost.exe	0x9e8b895a9240	6	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
7756	928	RuntimeBroker.	0x9e8b89c39080	4	-	1	False	2023-08-10 11:14:16.000000 	N/A	Disabled
1048	744	dwm.exe	0x9e8b89c520c0	14	-	1	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1148	788	svchost.exe	0x9e8b89c922c0	30	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1272	788	svchost.exe	0x9e8b89cf4280	3	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1280	788	svchost.exe	0x9e8b89cf5080	4	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1288	788	svchost.exe	0x9e8b89cf71c0	3	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1296	788	svchost.exe	0x9e8b89cf91c0	4	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1304	788	svchost.exe	0x9e8b89cfb200	4	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1432	788	svchost.exe	0x9e8b89d121c0	5	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1472	788	svchost.exe	0x9e8b89d3e1c0	7	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1500	788	svchost.exe	0x9e8b89d412c0	10	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1580	788	svchost.exe	0x9e8b89d900c0	7	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
8224	928	SearchApp.exe	0x9e8b89d92080	55	-	1	False	2023-08-10 11:14:14.000000 	N/A	Disabled
1588	788	svchost.exe	0x9e8b89d94080	6	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1712	788	svchost.exe	0x9e8b89dab1c0	2	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
5056	1580	MicrosoftEdgeU	0x9e8b89e21080	0	-	0	False	2023-08-10 11:20:44.000000 	2023-08-10 11:29:13.000000 	Disabled
1748	788	svchost.exe	0x9e8b89e541c0	11	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1756	788	svchost.exe	0x9e8b89e562c0	6	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1828	788	svchost.exe	0x9e8b89e70240	6	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
9204	4364	conhost.exe	0x9e8b89ec7080	3	-	1	False	2023-08-10 11:30:57.000000 	N/A	Disabled
2140	788	svchost.exe	0x9e8b89f6f200	2	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
1980	788	svchost.exe	0x9e8b89fbc240	3	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1988	788	svchost.exe	0x9e8b89fc1280	6	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
2044	788	svchost.exe	0x9e8b89fc2080	8	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
1996	788	svchost.exe	0x9e8b89fc4080	6	-	0	False	2023-08-10 11:13:43.000000 	N/A	Disabled
2184	4	MemCompression	0x9e8b8a038040	22	-	N/A	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2168	788	svchost.exe	0x9e8b8a039240	2	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
6344	788	svchost.exe	0x9e8b8a04f340	4	-	0	False	2023-08-10 11:26:32.000000 	N/A	Disabled
2256	788	svchost.exe	0x9e8b8a09c240	21	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2356	788	svchost.exe	0x9e8b8a106280	2	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2368	788	svchost.exe	0x9e8b8a108280	2	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2476	788	svchost.exe	0x9e8b8a131240	5	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2588	788	svchost.exe	0x9e8b8a18c240	4	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2704	788	svchost.exe	0x9e8b8a2581c0	1	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2740	788	svchost.exe	0x9e8b8a25b080	11	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2816	788	svchost.exe	0x9e8b8a2ed300	5	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2936	788	svchost.exe	0x9e8b8a327240	5	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2948	788	svchost.exe	0x9e8b8a33b1c0	3	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
2956	788	svchost.exe	0x9e8b8a33d1c0	4	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
6224	788	svchost.exe	0x9e8b8a33e080	4	-	0	False	2023-08-10 11:28:46.000000 	N/A	Disabled
2644	788	svchost.exe	0x9e8b8a3ea240	2	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3108	788	svchost.exe	0x9e8b8a42f240	3	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3204	788	spoolsv.exe	0x9e8b8a43f200	7	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3316	788	svchost.exe	0x9e8b8a510240	10	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3464	788	vm3dservice.ex	0x9e8b8a52d080	2	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3404	788	svchost.exe	0x9e8b8a562080	7	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3368	788	svchost.exe	0x9e8b8a5631c0	16	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3324	788	svchost.exe	0x9e8b8a5652c0	7	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3352	788	svchost.exe	0x9e8b8a574080	1	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3376	788	svchost.exe	0x9e8b8a575080	3	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3424	788	Sysmon64.exe	0x9e8b8a578200	13	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3416	788	vmtoolsd.exe	0x9e8b8a57a280	11	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3444	788	VGAuthService.	0x9e8b8a57c300	2	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3680	788	svchost.exe	0x9e8b8a60c2c0	3	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3756	788	svchost.exe	0x9e8b8a6a4240	6	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
3788	3464	vm3dservice.ex	0x9e8b8a71f200	2	-	1	False	2023-08-10 11:13:44.000000 	N/A	Disabled
1616	1576	msedgewebview2	0x9e8b8a74f080	22	-	1	False	2023-08-10 11:20:25.000000 	N/A	Disabled
3816	788	svchost.exe	0x9e8b8a761240	11	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled
4132	928	unsecapp.exe	0x9e8b8a9b00c0	3	-	0	False	2023-08-10 11:13:45.000000 	N/A	Disabled
4912	788	msdtc.exe	0x9e8b8a9b3300	9	-	0	False	2023-08-10 11:13:45.000000 	N/A	Disabled
2776	7436	RamCapture64.e	0x9e8b8aa66080	5	-	1	False	2023-08-10 11:31:52.000000 	N/A	Disabled
1552	1576	msedgewebview2	0x9e8b8aa85080	8	-	1	False	2023-08-10 11:20:25.000000 	N/A	Disabled
4416	928	WmiPrvSE.exe	0x9e8b8aac5280	15	-	0	False	2023-08-10 11:13:45.000000 	N/A	Disabled
4440	788	dllhost.exe	0x9e8b8aac8080	10	-	0	False	2023-08-10 11:13:45.000000 	N/A	Disabled
4876	788	svchost.exe	0x9e8b8aedb1c0	4	-	0	False	2023-08-10 11:13:45.000000 	N/A	Disabled
8260	936	cmd.exe	0x9e8b8afda300	2	-	1	False	2023-08-10 11:27:15.000000 	N/A	Disabled
6084	1576	msedgewebview2	0x9e8b8b0f1080	19	-	1	False	2023-08-10 11:20:25.000000 	N/A	Disabled
4308	788	svchost.exe	0x9e8b8b19a1c0	6	-	0	False	2023-08-10 11:13:46.000000 	N/A	Disabled
4160	788	svchost.exe	0x9e8b8b1ef280	2	-	0	False	2023-08-10 11:13:46.000000 	N/A	Disabled
1792	788	svchost.exe	0x9e8b8b2561c0	5	-	0	False	2023-08-10 11:13:46.000000 	N/A	Disabled
5292	928	WmiPrvSE.exe	0x9e8b8b30a280	4	-	0	False	2023-08-10 11:13:47.000000 	N/A	Disabled
6136	788	svchost.exe	0x9e8b8b34a080	11	-	0	False	2023-08-10 11:13:53.000000 	N/A	Disabled
5452	788	svchost.exe	0x9e8b8b34b240	28	-	0	False	2023-08-10 11:13:51.000000 	N/A	Disabled
5796	788	svchost.exe	0x9e8b8b4b61c0	5	-	0	False	2023-08-10 11:13:51.000000 	N/A	Disabled
5972	788	svchost.exe	0x9e8b8b4cb240	18	-	0	False	2023-08-10 11:13:52.000000 	N/A	Disabled
1576	5864	msedgewebview2	0x9e8b8b4cc080	47	-	1	False	2023-08-10 11:20:21.000000 	N/A	Disabled
7128	928	MoUsoCoreWorke	0x9e8b8b526280	10	-	0	False	2023-08-10 11:14:06.000000 	N/A	Disabled
7008	788	svchost.exe	0x9e8b8b5ea080	6	-	0	False	2023-08-10 11:14:05.000000 	N/A	Disabled
7072	788	svchost.exe	0x9e8b8b5f0240	9	-	0	False	2023-08-10 11:14:06.000000 	N/A	Disabled
4364	6812	cmd.exe	0x9e8b8b6ef080	1	-	1	False	2023-08-10 11:30:57.000000 	N/A	Disabled
8428	8680	SearchProtocol	0x9e8b8b742080	7	-	0	False	2023-08-10 11:29:25.000000 	N/A	Disabled
5628	788	svchost.exe	0x9e8b8b77e080	4	-	0	False	2023-08-10 11:13:53.000000 	N/A	Disabled
4272	1828	sihost.exe	0x9e8b8b872280	8	-	1	False	2023-08-10 11:14:07.000000 	N/A	Disabled
2284	1576	msedgewebview2	0x9e8b8b8dc080	14	-	1	False	2023-08-10 11:20:25.000000 	N/A	Disabled
4992	788	svchost.exe	0x9e8b8b9bd300	11	-	1	False	2023-08-10 11:14:07.000000 	N/A	Disabled
4372	788	svchost.exe	0x9e8b8b9ce300	5	-	1	False	2023-08-10 11:14:07.000000 	N/A	Disabled
9088	788	svchost.exe	0x9e8b8c4020c0	2	-	0	False	2023-08-10 11:26:32.000000 	N/A	Disabled
6692	788	svchost.exe	0x9e8b8c42c280	3	-	0	False	2023-08-10 11:14:07.000000 	N/A	Disabled
6768	6692	ctfmon.exe	0x9e8b8c452280	12	-	1	False	2023-08-10 11:14:07.000000 	N/A	Disabled
6324	1580	taskhostw.exe	0x9e8b8c45a300	8	-	1	False	2023-08-10 11:14:07.000000 	N/A	Disabled
7436	7400	explorer.exe	0x9e8b8c4d2080	75	-	1	False	2023-08-10 11:14:07.000000 	N/A	Disabled
7400	744	userinit.exe	0x9e8b8c608340	0	-	1	False	2023-08-10 11:14:07.000000 	2023-08-10 11:14:34.000000 	Disabled
7236	788	svchost.exe	0x9e8b8c6b2080	7	-	1	False	2023-08-10 11:14:11.000000 	N/A	Disabled
8560	788	svchost.exe	0x9e8b8c7430c0	7	-	0	False	2023-08-10 11:24:26.000000 	N/A	Disabled
4112	1580	GoogleUpdate.e	0x9e8b8c74c080	3	-	0	True	2023-08-10 11:20:19.000000 	N/A	Disabled
9612	788	SecurityHealth	0x9e8b8c7d6080	11	-	0	False	2023-08-10 11:14:25.000000 	N/A	Disabled
5196	788	svchost.exe	0x9e8b8ca65300	3	-	0	False	2023-08-10 11:27:43.000000 	N/A	Disabled
8488	928	RuntimeBroker.	0x9e8b8caa5080	8	-	1	False	2023-08-10 11:14:14.000000 	N/A	Disabled
3616	928	RuntimeBroker.	0x9e8b8cb62080	6	-	1	False	2023-08-10 11:27:38.000000 	N/A	Disabled
9712	7436	vmtoolsd.exe	0x9e8b8cbd5080	9	-	1	False	2023-08-10 11:14:26.000000 	N/A	Disabled
8116	788	svchost.exe	0x9e8b8cc6e240	10	-	0	False	2023-08-10 11:14:11.000000 	N/A	Disabled
936	7436	svchost.exe	0x9e8b8cd89080	0	-	1	False	2023-08-10 11:22:31.000000 	2023-08-10 11:27:51.000000 	Disabled
7704	928	StartMenuExper	0x9e8b8cd9e080	8	-	1	False	2023-08-10 11:14:13.000000 	N/A	Disabled
652	788	svchost.exe	0x9e8b8cee2080	5	-	0	False	2023-08-10 11:14:13.000000 	N/A	Disabled
7904	788	svchost.exe	0x9e8b8cf91080	3	-	0	False	2023-08-10 11:27:43.000000 	N/A	Disabled
4380	928	RuntimeBroker.	0x9e8b8cf95080	3	-	1	False	2023-08-10 11:14:13.000000 	N/A	Disabled
2728	1576	msedgewebview2	0x9e8b8cf97080	7	-	1	False	2023-08-10 11:20:21.000000 	N/A	Disabled
8828	928	smartscreen.ex	0x9e8b8cff5300	8	-	1	False	2023-08-10 11:14:15.000000 	N/A	Disabled
8680	788	SearchIndexer.	0x9e8b9010c240	15	-	0	False	2023-08-10 11:14:15.000000 	N/A	Disabled
9580	7436	SecurityHealth	0x9e8b90135340	1	-	1	False	2023-08-10 11:14:25.000000 	N/A	Disabled
10044	9952	OneDrive.exe	0x9e8b90507080	0	-	1	True	2023-08-10 11:15:31.000000 	2023-08-10 11:15:37.000000 	Disabled
9976	788	svchost.exe	0x9e8b90509080	0	-	0	False	2023-08-10 11:27:43.000000 	2023-08-10 11:31:46.000000 	Disabled
3024	928	TextInputHost.	0x9e8b9050d080	9	-	1	False	2023-08-10 11:17:11.000000 	N/A	Disabled
4200	788	svchost.exe	0x9e8b90554240	0	-	0	False	2023-08-10 11:14:19.000000 	2023-08-10 11:16:20.000000 	Disabled
6680	4364	whoami.exe	0x9e8b905f1080	0	-	1	False	2023-08-10 11:31:01.000000 	2023-08-10 11:31:01.000000 	Disabled
4664	928	dllhost.exe	0x9e8b907ef080	8	-	1	False	2023-08-10 11:14:21.000000 	N/A	Disabled
1908	2740	audiodg.exe	0x9e8b90ec9080	5	-	0	False	2023-08-10 11:27:38.000000 	N/A	Disabled
6620	928	SecurityHealth	0x9e8b911e2080	0	-	1	False	2023-08-10 11:28:47.000000 	2023-08-10 11:29:52.000000 	Disabled
9724	788	svchost.exe	0x9e8b911e3080	4	-	0	False	2023-08-10 11:28:20.000000 	N/A	Disabled
10176	788	SgrmBroker.exe	0x9e8b911e5080	7	-	0	False	2023-08-10 11:15:45.000000 	N/A	Disabled
3136	788	MsMpEng.exe	0x9e8b914f0300	10	-	0	False	2023-08-10 11:24:47.000000 	N/A	Disabled
9816	2776	conhost.exe	0x9e8b91cda080	6	-	1	False	2023-08-10 11:31:52.000000 	N/A	Disabled
6000	788	svchost.exe	0x9e8b926e7300	2	-	0	False	2023-08-10 11:27:43.000000 	N/A	Disabled
1244	788	svchost.exe	0x9e8b92987300	5	-	0	False	2023-08-10 11:26:35.000000 	N/A	Disabled
5864	7436	WinRAR.exe	0x9e8b92bdb0c0	5	-	1	False	2023-08-10 11:20:21.000000 	N/A	Disabled
1564	788	svchost.exe	0x9e8b92bdf080	1	-	0	False	2023-08-10 11:14:54.000000 	N/A	Disabled
1668	8260	conhost.exe	0x9e8b92c65300	3	-	1	False	2023-08-10 11:27:15.000000 	N/A	Disabled
7416	788	svchost.exe	0x9e8b92ddd340	1	-	1	False	2023-08-10 11:15:45.000000 	N/A	Disabled
10072	788	svchost.exe	0x9e8b92f1c340	9	-	0	False	2023-08-10 11:15:45.000000 	N/A	Disabled
9784	8680	SearchFilterHo	0x9e8b92fda080	4	-	0	False	2023-08-10 11:31:32.000000 	N/A	Disabled
1396	788	uhssvc.exe	0x9e8b930402c0	3	-	0	False	2023-08-10 11:15:45.000000 	N/A	Disabled
5232	928	ApplicationFra	0x9e8b9a26d080	3	-	1	False	2023-08-10 11:27:42.000000 	N/A	Disabled
3108	788	svchost.exe	0xb58d4b50f240	3	-	0	False	2023-08-10 11:13:44.000000 	N/A	Disabled

```

We see a process invoked the `whoami.exe` process. The PID is `6680`  and PPID is `4364`. Let's do a process tree on this PPID.

Process Tree on PID `4364`.
```bash
$ vol3 -f 20230810.mem windows.pstree --pid 4364
Volatility 3 Framework 2.7.1
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	Audit	Cmd	Path

744	636	winlogon.exe	0x9e8b89441080	4	-	1	False	2023-08-10 11:13:42.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\winlogon.exe	winlogon.exe	C:\WINDOWS\system32\winlogon.exe
* 7400	744	userinit.exe	0x9e8b8c608340	0	-	1	False	2023-08-10 11:14:07.000000 	2023-08-10 11:14:34.000000 	\Device\HarddiskVolume3\Windows\System32\userinit.exe	-	-
** 7436	7400	explorer.exe	0x9e8b8c4d2080	75	-	1	False	2023-08-10 11:14:07.000000 	N/A	\Device\HarddiskVolume3\Windows\explorer.exe	C:\WINDOWS\Explorer.EXE	C:\WINDOWS\Explorer.EXE
*** 6812	7436	svchost.exe	0x9e8b87762080	3	-	1	False	2023-08-10 11:30:03.000000 	N/A	\Device\HarddiskVolume3\Users\simon.stark\Downloads\svchost.exe	"C:\Users\simon.stark\Downloads\svchost.exe" 	C:\Users\simon.stark\Downloads\svchost.exe
**** 4364	6812	cmd.exe	0x9e8b8b6ef080	1	-	1	False	2023-08-10 11:30:57.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\cmd.exe	C:\WINDOWS\system32\cmd.exe	C:\WINDOWS\system32\cmd.exe
***** 9204	4364	conhost.exe	0x9e8b89ec7080	3	-	1	False	2023-08-10 11:30:57.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\conhost.exe	\??\C:\WINDOWS\system32\conhost.exe 0x4	C:\WINDOWS\system32\conhost.exe
```

We found the process's name that spawned `whoami.exe`. It was `cmd.exe`, and it was spawned from another process named `svchost.exe` which at a first glance looks like a legit windows process (mainly used to load windows services). But the file resides in `C:\Windows\System32` folder, which is a trusted and protected folder. But in this case, it was loaded from `C:\Users\simon.stark\Downloads\svchost.exe`. Which looks malicious and suspicious. Please skip to Step 2 to where I dump the malicious file.

**Search For The Malicious Files (Alternative Way):**

+ *Step 1: Search for open handles inside the malicious process*
```bash
$ vol3 -f 20230810.mem windows.handles --pid 6812
Volatility 3 Framework 2.7.1
Progress:  100.00		PDB scanning finished                        
PID	Process	Offset	HandleValue	Type	GrantedAccess	Name

6812	svchost.exe	0x9e8b8b8084e0	0x4	Event	0x1f0003	
6812	svchost.exe	0x9e8b96564d70	0xc	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b808fe0	0x10	Event	0x1f0003	
6812	svchost.exe	0x9e8b9619d890	0x14	텘࿲환࿲쨐࿲Ԑӎࡃ࿲ᴐҦࡃ࿲┐Ѿࡃ࿲쩙࿲	0x1	
6812	svchost.exe	0x9e8b96564140	0x18	IoCompletion	0x1f0003	
6812	svchost.exe	0x9e8b8c406510	0x1c	TpWorkerFactory	0xf00ff	
6812	svchost.exe	0x9e8b8cdda2f0	0x20	IRTimer	0x100002	
6812	svchost.exe	0x9e8b9619ef50	0x24	텘࿲환࿲쨐࿲Ԑӎࡃ࿲ᴐҦࡃ࿲┐Ѿࡃ࿲쩙࿲	0x1	
6812	svchost.exe	0x9e8b8cddb940	0x28	IRTimer	0x100002	
6812	svchost.exe	0x9e8b961a0a20	0x2c	텘࿲환࿲쨐࿲Ԑӎࡃ࿲ᴐҦࡃ࿲┐Ѿࡃ࿲쩙࿲	0x1	
6812	svchost.exe	0x9e8b96564210	0x30	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96563b10	0x34	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965642f0	0x38	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b808860	0x3c	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b8085e0	0x40	Event	0x1f0003	
6812	svchost.exe	0xb58d4a3b02a0	0x44	Directory	0x3	KnownDlls
6812	svchost.exe	0x9e8b90911280	0x48	File	0x100020	\Device\HarddiskVolume3\Users\simon.stark\Downloads
6812	svchost.exe	0x9e8b96563410	0x4c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b91697b50	0x50	Mutant	0x1f0001	SM0:6812:304:WilStaging_02
6812	svchost.exe	0x9e8b89f7d070	0x54	ALPC Port	0x1f0001	
6812	svchost.exe	0xb58d4a969480	0x58	Directory	0xf	BaseNamedObjects
6812	svchost.exe	0x9e8b8b66ee50	0x5c	Semaphore	0x1f0003	SM0:6812:304:WilStaging_02_p0
6812	svchost.exe	0x9e8b8b66f5d0	0x60	Semaphore	0x1f0003	SM0:6812:304:WilStaging_02_p0h
6812	svchost.exe	0x9e8b96563790	0x64	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965643d0	0x68	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965644b0	0x6c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965649f0	0x70	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96563940	0x74	IoCompletion	0x1f0003	
6812	svchost.exe	0x9e8b8b5ef510	0x78	TpWorkerFactory	0xf00ff	
6812	svchost.exe	0x9e8b8cdda730	0x7c	IRTimer	0x100002	
6812	svchost.exe	0x9e8b9619d480	0x80	텘࿲환࿲쨐࿲Ԑӎࡃ࿲ᴐҦࡃ࿲┐Ѿࡃ࿲쩙࿲	0x1	
6812	svchost.exe	0x9e8b89d05a10	0x84	IRTimer	0x100002	
6812	svchost.exe	0x9e8b961a0e30	0x88	텘࿲환࿲쨐࿲Ԑӎࡃ࿲ᴐҦࡃ࿲┐Ѿࡃ࿲쩙࿲	0x1	
6812	svchost.exe	0x9e8b96564830	0x8c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96564bb0	0x90	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b82b080	0x98	Thread	0x1fffff	Tid 2032 Pid 6812
6812	svchost.exe	0x9e8b8b806f60	0x9c	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b809060	0xa4	Event	0x1f0003	
6812	svchost.exe	0x9e8b96564590	0xac	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b8090e0	0xb0	Event	0x1f0003	
6812	svchost.exe	0x9e8b90903e00	0xb4	File	0x16019f	\Device\Afd\Endpoint
6812	svchost.exe	0x9e8b96564670	0xbc	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96564750	0xc4	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96563870	0xc8	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96563250	0xcc	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96564c90	0xd0	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965634f0	0xd4	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b8088e0	0xd8	Event	0x1f0003	
6812	svchost.exe	0x9e8b96188420	0xdc	텘࿲환࿲쨐࿲Ԑӎࡃ࿲ᴐҦࡃ࿲┐Ѿࡃ࿲쩙࿲	0x1	
6812	svchost.exe	0x9e8b96563330	0xe0	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965635d0	0xe4	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96563a30	0xe8	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96563bf0	0xec	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96563cd0	0xf0	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b88a4ad40	0xfc	WindowStation	0xf037f	WinSta0
6812	svchost.exe	0x9e8b88bfb810	0x100	Desktop	0xf01ff	Default
6812	svchost.exe	0x9e8b88a4ad40	0x104	WindowStation	0xf037f	WinSta0
6812	svchost.exe	0x9e8b8b808360	0x110	Event	0x1f0003	
6812	svchost.exe	0xb58d54a0c070	0x114	Key	0x20019	USER\S-1-5-21-3239415629-1862073780-2394361899-1602_CLASSES\LOCAL SETTINGS\SOFTWARE\MICROSOFT
6812	svchost.exe	0xb58d54a09920	0x118	Key	0x20019	USER\S-1-5-21-3239415629-1862073780-2394361899-1602_CLASSES\LOCAL SETTINGS
6812	svchost.exe	0x9e8b8b809160	0x11c	Event	0x1f0003	
6812	svchost.exe	0x9e8b96563f70	0x120	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96565470	0x124	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96565550	0x128	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b808a60	0x12c	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b808260	0x130	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b808ae0	0x134	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b808660	0x138	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b808760	0x13c	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b808ee0	0x140	Event	0x1f0003	
6812	svchost.exe	0x9e8b96565c50	0x144	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965666d0	0x148	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566970	0x14c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965650f0	0x150	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566430	0x154	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965659b0	0x158	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965657f0	0x15c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965651d0	0x160	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965658d0	0x164	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566350	0x168	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b808460	0x16c	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b82b080	0x170	Thread	0x1003	Tid 2032 Pid 6812
6812	svchost.exe	0x9e8b8b6746f0	0x174	Mutant	0x1f0001	
6812	svchost.exe	0x9e8b8b674790	0x178	Mutant	0x1f0001	
6812	svchost.exe	0xb58d4dc1e9b0	0x17c	Token	0xf01ff	
6812	svchost.exe	0x9e8b8b6748d0	0x180	Mutant	0x1f0001	
6812	svchost.exe	0x9e8b960de860	0x184	Semaphore	0x100003	
6812	svchost.exe	0x9e8b8c7032f0	0x188	Mutant	0x1f0001	
6812	svchost.exe	0x9e8b8b6754b0	0x18c	Mutant	0x1f0001	
6812	svchost.exe	0x9e8b96565630	0x190	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b0ae960	0x194	Semaphore	0x100003	
6812	svchost.exe	0x9e8b965667b0	0x198	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566890	0x19c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566510	0x1a0	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b8083e0	0x1a4	Semaphore	0x100003	
6812	svchost.exe	0x9e8b8b808f60	0x1a8	Semaphore	0x100003	
6812	svchost.exe	0x9e8b8b8086e0	0x1ac	Event	0x1f0003	
6812	svchost.exe	0x9e8b96565a90	0x1b4	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96564e50	0x1b8	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96565390	0x1bc	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b954232e0	0x1c0	Semaphore	0x100003	
6812	svchost.exe	0x9e8b95423b60	0x1c4	Semaphore	0x100003	
6812	svchost.exe	0x9e8b954234e0	0x1c8	Event	0x1f0003	
6812	svchost.exe	0x9e8b965652b0	0x1cc	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96564f30	0x1d0	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96565710	0x1d4	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b90127d90	0x1d8	TpWorkerFactory	0xf00ff	
6812	svchost.exe	0x9e8b96567cc0	0x1dc	IoCompletion	0x1f0003	
6812	svchost.exe	0x9e8b8b6dd070	0x1e0	ALPC Port	0x1f0001	
6812	svchost.exe	0x9e8b965665f0	0x1e4	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96565d30	0x1e8	EtwRegistration	0x804	
6812	svchost.exe	0xb58d54a0b4c0	0x1ec	Key	0x20019	USER
6812	svchost.exe	0x9e8b96565b70	0x1f0	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b913841e0	0x1f4	File	0x100001	\Device\KsecDD
6812	svchost.exe	0x9e8b913857c0	0x1f8	File	0x100001	\Device\CNG
6812	svchost.exe	0x9e8b8b0a7fe0	0x208	Event	0x1f0003	
6812	svchost.exe	0xb58d4dc1e9b0	0x20c	Token	0x8	
6812	svchost.exe	0x9e8b90910c44	0x210	VRegConfigurationContext	0x120189	
6812	svchost.exe	0x9e8b8af76e80	0x214	IRTimer	0x100002	
6812	svchost.exe	0x9e8b8b0a7ee0	0x218	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b0af3e0	0x21c	Semaphore	0x100003	
6812	svchost.exe	0x9e8b96565e10	0x220	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96565ef0	0x224	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965660b0	0x228	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b0af760	0x22c	Event	0x1f0003	
6812	svchost.exe	0x9e8b96566190	0x230	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566270	0x234	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566f90	0x238	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96567850	0x23c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965682d0	0x240	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96568570	0x244	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566c10	0x248	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96568110	0x24c	EtwRegistration	0x804	
6812	svchost.exe	0xb58d4dc1e9b0	0x250	Token	0x8	
6812	svchost.exe	0x9e8b8aec3080	0x254	Thread	0x1fffff	Tid 9240 Pid 6812
6812	svchost.exe	0x9e8b961a2de0	0x258	텘࿲환࿲쨐࿲Ԑӎࡃ࿲ᴐҦࡃ࿲┐Ѿࡃ࿲쩙࿲	0x1	
6812	svchost.exe	0x9e8b8af76930	0x25c	IRTimer	0x100002	
6812	svchost.exe	0x9e8b961a2c40	0x260	텘࿲환࿲쨐࿲Ԑӎࡃ࿲ᴐҦࡃ࿲┐Ѿࡃ࿲쩙࿲	0x1	
6812	svchost.exe	0x9e8b965673f0	0x264	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b960de1e0	0x268	Semaphore	0x100003	
6812	svchost.exe	0x9e8b8b3632c0	0x26c	Thread	0x1fffff	Tid 7980 Pid 6812
6812	svchost.exe	0x9e8b965674d0	0x278	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96567150	0x27c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96567af0	0x280	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96567070	0x284	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96567f50	0x288	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566b30	0x28c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b809360	0x290	Event	0x1f0003	
6812	svchost.exe	0x9e8b960d8c60	0x294	Event	0x1f0003	
6812	svchost.exe	0x9e8b90910790	0x298	File	0x100080	\Device\Nsi
6812	svchost.exe	0x9e8b96566a50	0x29c	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96567690	0x2ac	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96567230	0x2b4	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b96566eb0	0x2b8	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965683b0	0x2bc	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b965681f0	0x2c0	EtwRegistration	0x804	
6812	svchost.exe	0x9e8b8b808c60	0x2c4	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b0e2070	0x2d0	ALPC Port	0x1f0001	
6812	svchost.exe	0x9e8b960cff60	0x2d4	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b809ce0	0x2d8	Event	0x1f0003	
6812	svchost.exe	0x9e8b909042b0	0x2dc	File	0x120089	\Device\NamedPipe\
6812	svchost.exe	0x9e8b8aec3080	0x2e4	Thread	0x1fffff	Tid 9240 Pid 6812
6812	svchost.exe	0x9e8b9090dbd4	0x2e8	TmEn	0x120196	
6812	svchost.exe	0xb58d4a93e9b0	0x2ec	Token	0xf01ff	
6812	svchost.exe	0x9e8b90118080	0x2f0	Thread	0x1fffff	Tid 6328 Pid 6812
6812	svchost.exe	0x9e8b8b809960	0x2f4	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b809de0	0x2f8	Event	0x1f0003	
6812	svchost.exe	0x9e8b8b6ef080	0x2fc	Process	0x1fffff	cmd.exe Pid 4364
6812	svchost.exe	0x9e8b8cd46270	0x308	EtwRegistration	0x804	
6812	svchost.exe	0xb58d52d94180	0x30c	Key	0x8	USER\S-1-5-21-3239415629-1862073780-2394361899-1602\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION
```

Interesting location
```text
6812	svchost.exe	0xb58d4a3b02a0	0x44	Directory	0x3	KnownDlls
6812	svchost.exe	0x9e8b90911280	0x48	File	0x100020	\Device\HarddiskVolume3\Users\simon.stark\Downloads
```

+ *Step 2: Search for the file in the `\Device\HarddiskVolume3\Users\simon.stark\Downloads`.*
```bash
$ vol3 -f 20230810.mem windows.filescan | grep "Users" | grep "simon.stark" | grep "Downloads"
0x9e8b8ae28ca0.0\Users\simon.stark\Downloads	216
0x9e8b8ae29dd0	\Users\simon.stark\Downloads	216
0x9e8b909045d0	\Users\simon.stark\Downloads\svchost.exe	216
0x9e8b90911280	\Users\simon.stark\Downloads	216
0x9e8b909142f0	\Users\simon.stark\Downloads	216
0x9e8b91946a20	\Users\simon.stark\Downloads	216
0x9e8b91ec0140	\Users\simon.stark\Downloads\svchost.exe	216
```

Dump Malicious File
```bash
$ vol3 -f 20230810.mem windows.dumpfiles --virtaddr 0x9e8b909045d0              
Volatility 3 Framework 2.7.1
Progress:  100.00		PDB scanning finished                        
Cache	FileObject	FileName	Result

DataSectionObject	0x9e8b909045d0	svchost.exe	Error dumping file
ImageSectionObject	0x9e8b909045d0	svchost.exe	file.0x9e8b909045d0.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img
```

Don't need the DataSectionObject to analyze the Binary. We are after the ImageSectionObject.

Check the Malware's md5sum and send it to the reverse engineering team.
```bash
$ md5sum file.0x9e8b909045d0.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img 
5bd547c6f5bfc4858fe62c8867acfbb5  file.0x9e8b909045d0.0x9e8b957f24c0.ImageSectionObject.svchost.exe.img
```

**VirusTotal**

VirusTotal Detection Ratio:
![alt text](images/20240611200132.png)


### Summary

The TA used a legit Windows binary file name to blend into the processes. But in the we successfully discovered their C2 server and IoCs using memory forensics and from [VirusTotal](https://www.virustotal.com/gui/file/eaf09578d6eca82501aa2b3fcef473c3795ea365a9b33a252e5dc712c62981ea) platform.
