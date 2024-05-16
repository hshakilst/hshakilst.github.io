---
title: "HTB Sherlock Jingle Bell"
date: 2024-05-16T12:54:17+02:00
tags:
  - htb
  - sherlock
  - jingle
  - bell
  - dfir
  - windows
  - push
  - notification
  - database
  - wpndatabase
---

# Jingle Bell (DFIR)

### Scenario
  Torrin is suspected to be an insider threat in Forela. He is believed to have leaked some data and removed certain applications from their workstation. They managed to bypass some controls and installed unauthorized software. Despite the forensic team's efforts, no evidence of data leakage was found. As a senior incident responder, you have been tasked with investigating the incident to determine the conversation between the two parties involved.

### Forensics 
We are given a Windows push notification database file named `wpndatabase.db`. We can learn more about this database file on:

- [A Digital Forensic View of Windows 10 Notifications](https://www.mdpi.com/2673-6756/2/1/7)
- [Windows Push Notification (wpn) Database Parser Users Guide by TZWorks®](https://tzworks.com/prototypes/wpn/wpn.users.guide.pdf)
  
From reading these articles we discovered that in that db file, there's a table named `Notification`. It contains the information of the notifications shown by Windows's Notification Manager as `XML` payload.

Therefore, we used `sqlitebrowser` and manually dumped the `XML` data from the `Notification` table. And saved them in the [notifications.xml](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Jingle%20Bell/notifications.xml) file.

We need to analyze this XML file to answer the following questions.

### Questions and Answers
- Q: Which software/application did Torrin use to leak Forela's secrets?
  - A: Torrin used `Slack` to leak the secrets. We know this from the notification's `<toast launch="">` section.

- Q: What's the name of the rival company to which Torrin leaked the data?
  - A: The rival company's name is `PrimeTech Innovations`. We got this information from `<header title="">` section of the notification.
  
- Q: What is the username of the person from the competitor organization whom Torrin shared information with?
  - A: The username is `Cyberjunkie-PrimeTechDev`. We get this answer from `<binding>`'s second `<text>` tag where the attribute `hint-style="bodySubtle"` exists.
  
- Q: What's the channel name in which they conversed with each other?
  - A: The channel name is `forela-secrets-leak`. We can derive this from `<binding>`'s first `<text>` tag where the attribute `hint-maxLines="1"` exists.

- Q: What was the password for the archive server?
  - A: The password for the archive server is `Tobdaf8Qip$re@1`. We get this from reading the body of a notification.

- Q: What was the URL provided to Torrin to upload stolen data to?
  - A: The URL is `https://drive.google.com/drive/folders/1vW97VBmxDZUIEuEUG64g5DLZvFP-Pdll?usp=sharing`.

- Q: When was the above link shared with Torrin?
  - A: When answering this question we faced some difficulties. Two timestamps could be the answer to the question. Firstly, the `Notification` table has an `ArrivalTime` timestamp expressed in `Microsoft Filetime 64-bit` format. When converted to date it gave `GMT Thu Apr 20 2023 10:36:08`. But it wasn't the answer. Secondly, there was another timestamp embedded inside the `<toast launch="slack://channel?id=C05451QSQM8&amp;message=1681986889.660179&amp;team=T054518ADUJ&amp;origin=notification">` tag of the notification's XML structure. The `message=1681986889.660179` converts to `GMT Thu Apr 20 2023 10:34:49`. Turns out the latter one was the correct one. So, the answer is `2023-04-20 10:34:49`.

- Q: For how much money did Torrin leak Forela's secrets?
  - A: The answer is `£10000`. We could find it in the [notifications.xml](https://github.com/hshakilst/DFIR/blob/main/HTB%20Sherlocks/Jingle%20Bell/notifications.xml) file.


