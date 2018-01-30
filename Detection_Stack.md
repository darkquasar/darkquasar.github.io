---
layout: page
title: Detection Stack
subtitle: A compilation of IOC and SIEM rules for modern threats
tags: [security control, siem, ips, ioc, correlation rule, detection, mitigation, threat, darkquasar]
comments: true
---

* TOC
{:toc}

# Summary
This is my collection of detection logics for current threats as it results from personal research. As the list grows, I will develop a framework that will encapsulate everything in a table. Eventually this will also be retrievable in JSON format. 

# Detection Logics

## 001 - Powershell or Cmd spawned by Office Application
This IOC is meant to capture covert instances of cmd or powershell spawned by Microsoft Office applications as a result of exploit activity. The delivery method can be multiple: email with attachments, link in emails, Word documents, Power Point presentations, Excel spreadsheets, etc. 

**Logic**
```
Path of Parent Process *contains* "office"
Process Name *contains* "powershell" or "cmd"
Path of Parent Process *not equals* "C:\Program Files\Microsoft Office 15\ClientX64\officeclicktorun.exe" or "C:\Program Files\Microsoft Office Servers\15.0\Synchronization Service\Bin\miiserver.exe" or "C:\Program Files\Common Files\Microsoft Shared\OfficeSoftwareProtectionPlatform\OSPPSVC.EXE"

**False Positives**
Medium FP ratio
