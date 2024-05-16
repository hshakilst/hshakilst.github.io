---
title: "HTB Sherlock Noted"
date: 2024-05-16T12:59:39+02:00
tags:
  - htb
  - sherlock
  - noted
  - dfir
  - windows
  - notepad++
  - file
  - time
image:
---

# Noted (DFIR)

### Scenario
Simon, a developer working at Forela, notified the CERT team about a note that appeared on his desktop. The note claimed that his system had been compromised and that sensitive data from Simon's workstation had been collected. The perpetrators performed data extortion on his workstation and are now threatening to release the data on the dark web unless their demands are met. Simon's workstation contained multiple sensitive files, including planned software projects, internal development plans, and application codebases. The threat intelligence team believes that the threat actor made some mistakes, but they have not found any way to contact the threat actors. The company's stakeholders are insisting that this incident be resolved and all sensitive data be recovered. They demand that under no circumstances should the data be leaked. As our junior security analyst, you have been assigned a specific type of DFIR (Digital Forensics and Incident Response) investigation in this case. The CERT lead, after triaging the workstation, has provided you with only the Notepad++ artifacts, suspecting that the attacker created the extortion note and conducted other activities with hands-on keyboard access. Your duty is to determine how the attack occurred and find a way to contact the threat actors, as they accidentally locked out their own contact information.

### Forensics 
- **Artifacts**: The artifacts are from `Notepad++` software. We have two XML files named `config.xml` and `session.xml`. We are also provided with two backup files of two text files `LootAndPurge.java@2023-07-24_145332` and `YOU HAVE BEEN HACKED.txt@2023-07-24_150548`.
  
- **Extraction**: The files were all in plaintext format and the volume of data was low, so extraction was not necessary. However, five files were created for classification purposes. They are [file history of recently opened files](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/file_history.txt), [edited files in the alleged Notepad++](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/edited_files.txt), [custom URIs the alleged Notepad++ was set to handle](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/custom_uris.txt), [malicious data extortion java file](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/LootAndPurge.java) and [a ransom note file](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/YOU%20HAVE%20BEEN%20HACKED.txt)
- **Analysis**: 
  
  First, I examined the `config.xml` file and found some file histories. The history contained the file addresses that were recently opened by the user. I have listed them in the [`file_history.txt`](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/file_history.txt) file. Also, I found some custom URIs that were set to handle files from different types of services. They are listed in the [`custom_uris.txt`](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/custom_uris.txt) file.

  Second, I analyzed the `session.xml` file and there I found two files that were being edited along with their backup file locations and last modified timestamps. I added them to a file named [`edited_files.txt`](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/edited_files.txt) with the findings.

  Finally, I inspected the backup files and discovered a malicious [Java source file](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/LootAndPurge.java)(LootAndPurge.java) that was used to encrypt the sensitive data and a [ransom note](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/YOU%20HAVE%20BEEN%20HACKED.txt) where two `Pastebin` links were given to contact the cybercriminals. A password for the zip file was left behind by the perpetrators. Which can be used to decrypt the content of the zip file. The same password can be used to decrypt the `Pastebin` notes to find their Ethereum wallet address and email address.

  

### Tools Used
- Visual Studio Code
- Python3

### Questions and Answers
- Q1: What is the full path of the script used by Simon for AWS operations?
  - A: `C:\Users\Simon.stark\Documents\Dev_Ops\AWS_objects migration.pl`

- Q2: The attacker duplicated some program code and compiled it on the system, knowing that the victim was a software engineer and had all the necessary utilities. They did this to blend into the environment and didn't bring any of their tools. This code gathered sensitive data and prepared it for exfiltration. What is the full path of the program's source file?
  - A: `C:\Users\simon.stark\Desktop\LootAndPurge.java`. 
  

- Q3: What's the name of the final archive file containing all the data to be exfiltrated?
  - A: `Forela-Dev-Data.zip`
  
- Q4: What's the timestamp in UTC when attacker last modified the program source file?
  - A: `2023-07-24 09:53:23`

- Q5: The attacker wrote a data extortion note after exfiltrating data. What is the crypto wallet address to which attackers demanded payment?
  - A: `0xca8fa8f0b631ecdb18cda619c4fc9d197c8affca`

- Q6: What's the email address of the person to contact for support?
  - A: `CyberJunkie@mail2torjgmxgexntbrmhvgluavhj7ouul5yar6ylbvjkxwqf6ixkwyd.onion`

### Summary
Using the artifacts provided I was able to answer the questions. It was pretty straightforward. But answering Question 4 was a little bit baffling to me. It was related to Windows's FileTime System. I did a little bit of research and piece together an article that you can read [here (FileTime)](https://hshakilst.github.io/posts/filetime/). Also, I added a [Python script](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Noted/convert_splitted_filetime.py) to convert it into UTC.


