---
title: "HTB Sherlock BFT"
date: 2024-05-16T12:44:59+02:00
tags:
  - htb
  - sherlock
  - bft
  - dfir
  - mft
  - windows
  - master
  - file
  - table
---

# BFT (DFIR)

### Scenario
In this Sherlock, you will become acquainted with MFT (Master File Table) forensics. You will be introduced to well-known tools and methodologies for analyzing MFT artifacts to identify malicious activity. During our analysis, you will utilize the MFTECmd tool to parse the provided MFT file, TimeLine Explorer to open and analyze the results from the parsed MFT, and a Hex editor to recover file contents from the MFT.

### Forensics 
- **Artifact**: An MFT file `$MFT` is provided. It's an NTFS file system's master file table. [Learn more about MFT here](https://hshakilst.github.io/posts/master-file-table/).
- **Extraction**: I used `MFTECmd` to extract the contents of it and saved it to a file in CSV format.
- **Analysis**: `Timeline Explorer` and `010Editor` were used to answer the questions.

### Tools Used
- [MFTECmd by Eric Zimmerman](https://github.com/EricZimmerman/MFTECmd)
- [Timeline Explorer](https://ericzimmerman.github.io/#!index.md)
- [010Editor Hex Editor](https://www.sweetscape.com/download/010editor/)

### Questions and Answers
- Q1: Simon Stark was targeted by attackers on February 13. He downloaded a ZIP file from a link received in an email. What was the name of the ZIP file he downloaded from the link?
  - A: The answer is `Stage-20240213T093324Z-001.zip`. I applied a filter on the header `Created0x10` with the date `2024-02-13` and on the header `Extension` with the value `.zip`.

- Q2: Examine the Zone Identifier contents for the initially downloaded ZIP file. This field reveals the HostUrl from where the file was downloaded, serving as a valuable Indicator of Compromise (IOC) in our investigation/analysis. What is the full Host URL from where this ZIP file was downloaded?
  - A: The answer is `https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser`. 
  
    To find the URL of the downloaded file I needed to locate the `Stage-20240213T093324Z-001.zip:Zone.Identifier` file by applying a filter on `Extension` with the value `.Identifier`. The `Zone.Identifier` file separated by a `:` after the original file is an **Alternate Data Stream (ADS)** file. It contains the file's origin Location. In this case, it was a URL. It can be found under the `Zone Id Contents` header.
  
- Q3: What is the full path and name of the malicious file that executed malicious code and connected to a C2 server?
  - A: The answer is `C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices\invoice.bat`. The file was found by applying a filter on the header `Parent Path` with the initial zip file's partial name `Stage` and a suspicious `.bat` file was discovered.
  
- Q4: Analyze the $Created0x30 timestamp for the previously identified file. When was this file created on disk?
  - A: The answer is `2024-02-13 16:38:39`. [Learn more about the difference between $Created0x10 and $Created0x30](https://hshakilst.github.io/posts/master-file-table/#timestamps).

- Q5: Finding the hex offset of an MFT record is beneficial in many investigative scenarios. Find the hex offset of the stager file from Question 3.
  - A: The answer is `16E3000`. To find the answer I needed to look for the malicious file's `Entry Number` which was `23436`. Then I multiplied it with 1024 `23436*1024` because each entry in the MFT is `1024 bytes` in size. After that, I converted the Decimal number to Hex.

- Q6: Each MFT record is 1024 bytes in size. If a file on disk has smaller size than 1024 bytes, they can be stored directly on MFT File itself. These are called MFT Resident files. During Windows File system Investigation, its crucial to look for any malicious/suspicious files that may be resident in MFT. This way we can find contents of malicious files/scripts. Find the contents of The malicious stager identified in Question3 and answer with the C2 IP and port.
  - A: The answer is `43.204.110.203:6666`.
  
    I had the hex offset for the `invoice.bat` file's entry and from the **Timeline Explorer**, and I discovered the `File Size` was `286 bytes`. So, it can be safely assumed it is an [`MFT Resident` file](https://hshakilst.github.io/posts/master-file-table/#mft-resident-files). The contents of this file can be viewed using a Hex Editor.

    I opened up my Hex Editor went to the offset `16E3000` and found the file's contents. It used `powershell` to download a payload from the above IP.

### Summary
Using the MFT file I was able to discover a stager file residing in MFT and the URL which was used to deliver it initially. I also discovered a C2 server by reading the contents of that file. A timeline for this incident was also established using Timeline Explorer.



