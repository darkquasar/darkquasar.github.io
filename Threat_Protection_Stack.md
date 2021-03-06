---
layout: page
title: Threat Protection Stack
subtitle: A compilation of detective & mitigative controls for modern threats
tags: [security control, siem, ips, ioc, correlation rule, detection, mitigation, threat, darkquasar]
comments: true
---

* TOC
{:toc}

# Summary
This is my collection of detective and mitigating security controls as it results from personal research. The general idea is to classify these controls into categories and rank them so that they can be applied selectively in any corporative environment. As the list grows, I will develop a framework that will encapsulate everything in a table. Eventually this will also be retrievable in JSON format. 

## Legend
> **Topic**: represents the short description of the threat that requires a security control in order to reduce risk of exposure in your network. 
> **Criticality**: how critical (urgency/severity) the security control that mitigates the threat is for any organization. The scores are: low, medium, high, critical. 
> **IDS**: Implementation Difficulty Score, a simple measure of the effort involved into implementing proper security controls for this threat. The scores hare: easy, medium, hard, very hard.
> **TTP Cagetorization**: A broad schema to classify the threat type. 

## Threat Protection Stack Table v0.1

| Topic                                                                                                                                               | Criticality | IDS   | TTP Categorization                                                                                                                                                                                                                        | References                                                                                                                        | 
|-----------------------------------------------------------------------------------------------------------------------------------------------------|-------------|------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------| 
| [DDE Microsoft Office weaponization](https://www.eideon.com/Threat_Protection_Stack/#protect-against-dde-microsoft-office-weaponization-techniques) | High        | Easy | **Category**: Defense Evation <br><br> **Sub-Category**: Weaponized Document. <br><br> **MITRE**: Exploitation of Vulnerability [T1068](https://attack.mitre.org/wiki/Technique/T1068)                                                    | https://www.ghacks.net/2017/10/23/disable-office-ddeauto-to-mitigate-attacks                                                     | 
| [Prevent lateral movement I](https://www.eideon.com/Threat_Protection_Stack/#prevent-credential-harvesting-and-lateral-movement-in-AD-Environment)  | Critical    | Very Hard | **Category**: Lateral Movement, Credential Access <br><br> **Sub-Category**: Pass the Hash, Pass the Ticket, Credential Dumping. <br><br> **MITRE**: Exploitation of Vulnerability [T1068](https://attack.mitre.org/wiki/Technique/T1068) | https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material | 

<br>
<br>

## Protect Against DDE Microsoft Office weaponization techniques
There are two essential controls:

### Mitigative
* Disable Automated Link Update from Office apps

### Detective
* Use this [YARA](https://raw.githubusercontent.com/darkquasar/InfoSec_Tools/master/YARA_Rules/DDE_OfficeExploit.yar) rule
* Create a new rule using your EDR solution that draws on the patterns for the YARA rule

### References
* To mitigate DDE by disabling Automated Link Updates: https://www.ghacks.net/2017/10/23/disable-office-ddeauto-to-mitigate-attacks
* DDE Protocol: https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
* Yara Rules: https://blog.nviso.be/2017/10/12/yara-dde-rules-dde-command-execution-observed-in-the-wild
* McAfee Advisory: https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/27000/PD27325/en_US/McAfee_Labs_Threat_Advisory-W97MMacroLess.pdf

<br>
<br>

## Prevent credential harvesting and lateral movement in AD Environment
Security Controls: Mitigative, Detective. 

### Mitigative
* Apply Active Directory administrative tier model on your environment.

### Detective
* WIP

### References
* Great article by Microsoft: https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material
