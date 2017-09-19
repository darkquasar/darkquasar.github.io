---
layout: post
title: Tales of a Threat Hunter 2 
subtitle: Following the trace of WMI Backdoors & other nastyness
tags: [threat hunting, hunting, wmi, windows management instrumentation, backdoor, persistene, siem, ioc, splunk, elk, darkquasar, volatility]
comments: true
published: false
---
* TOC
{:toc}

# A few Links
- http://blog.trendmicro.com/trendlabs-security-intelligence/cryptocurrency-miner-uses-wmi-eternalblue-spread-filelessly/
- https://twitter.com/mattifestation/status/899646620148539397
- https://gist.github.com/mattifestation/e55843eef6c263608206 (Template)
- List of modules involved in each WMI event https://msdn.microsoft.com/en-us/library/aa940177(v=winembedded.5).aspx
- 

# What is WMI?

 
WMI is Microsoft's implementation of WBEM (Web Based Enterprise Management) which is based on [CIM](http://www.dmtf.org/standards/cim) and allows for the remote management of multiple system components in Windows environments. WMI is used on a daily basis by sysadmins across large domains due to its flexibility and scalability. Easy to deploy, scripts that leverage WMI can be seen everywhere. Unfortunately, as with everything that is widely deployed, has "remote" capabilities and runs on "windows": the dark force is strong around it [(just for fun: MS17-010)](https://technet.microsoft.com/en-us/library/security/ms17-010.aspx).
 
It is known that WMI can be abused in many ways to either gather information, make changes and create persistence mechanisms. An excellent article by Matt Graeber [(@mattifestation)](https://twitter.com/mattifestation?ref_src=twsrc%5Egoogle%7Ctwcamp%5Eserp%7Ctwgr%5Eauthor) called [Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf) was an eye opener for many of us in the cybersec world. We knew this was possible, but forgot how flexible it was. The main strength of WMI persistence is its stealthyness and effectiveness. When a command is executed by WMI as a result of "evil" the only thing you will see is **WmiPrvse.exe** as the process. Distinguishing a valid system action from an invalid one is very hard under these circumstances. In other words, WMI persistence defeats nonrepudiation!

What I will cover here are different methods for detecting WMI persistence that you could leverage within your network to hunt for this treat.

# Understanding WMI Persistence
First, rather than re-inventing the wheel, I will link here below the sources that I consulted to learn more about WMI: 
- Matt Graeber's article (mentioned above)
- Pentestarmoury article ["Creeping on Users with WMI Events"](https://pentestarmoury.com/2016/07/13/151/) by Sw4mp\_f0x. He also developed PowerLurk (see below)
- [Permanent WMI Subscriptions](https://learn-powershell.net/2013/08/14/powershell-and-events-permanent-wmi-event-subscriptions/)
- Derbycon 2015 [presentation](https://www.youtube.com/watch?v=HJLCvBq3oms) by Matt

# How does a WMI persistent object look like?
Let's use two scripts that allow us to easily create a malicious persistence without having to do it step by step (have a look at the PS files to understand all the bits and pieces involved), namely: 
- [PowerLurk](https://github.com/Sw4mpf0x/PowerLurk/blob/master/PowerLurk.ps1) by Sw4mp\_f0x
- [WMI Persistence Template](https://gist.github.com/mattifestation/e55843eef6c263608206) by Matt G.

## WMI Persistence Template by Matt G. 
We tweaked some of the parameters in the script to make sure the timer event launches every minute and that no cleanup is performed at the end. After launching it, we can inspect the newly created Event Consumers/Filters/Bindings as follows: 

**EventFilter**
{% highlight powershell %}
Get-WmiObject -Namespace root\subscription -Class __EventFilter
{% endhighlight %}

Result: 
{% highlight powershell %}
__GENUS          : 2
__CLASS          : __EventFilter
__SUPERCLASS     : __IndicationRelated
__DYNASTY        : __SystemClass
__RELPATH        : __EventFilter.Name="TimerTrigger"
__PROPERTY_COUNT : 6
__DERIVATION     : {__IndicationRelated, __SystemClass}
__SERVER         : W10B1
__NAMESPACE      : ROOT\subscription
__PATH           : \\W10B1\ROOT\subscription:__EventFilter.Name="TimerTrigger"
CreatorSID       : {1, 5, 0, 0...}
EventAccess      : 
EventNamespace   : root/cimv2
Name             : TimerTrigger
Query            : SELECT * FROM __TimerEvent WHERE TimerID = 'PayloadTrigger'
QueryLanguage    : WQL
PSComputerName   : W10B1
{% endhighlight %}

**EventConsumer**
{% highlight powershell %}
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
{% endhighlight %}

Result: 
{% highlight powershell %}
[snip]
__GENUS               : 2
__CLASS               : CommandLineEventConsumer
__SUPERCLASS          : __EventConsumer
__DYNASTY             : __SystemClass
__RELPATH             : CommandLineEventConsumer.Name="ExecuteEvilPowerShell"
__PROPERTY_COUNT      : 27
__DERIVATION          : {__EventConsumer, __IndicationRelated, __SystemClass}
__SERVER              : W10B1
__NAMESPACE           : ROOT\subscription
__PATH                : \\W10B1\ROOT\subscription:CommandLineEventConsumer.Name="ExecuteEvilPowerShell"
CommandLineTemplate   : powershell.exe -NoP -C "iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String((Get-ItemProperty -Path HKLM:\SOFTWARE\PayloadKey -Name PayloadValue).PayloadValue)))"
[snip]
{% endhighlight %}


**FilterToConsumerBinding**
{% highlight powershell %}
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
{% endhighlight %}

Result: 

{% highlight powershell %}
[snip]
__NAMESPACE             : ROOT\subscription
__PATH                  : \\W10B1\ROOT\subscription:__FilterToConsumerBinding.Consumer="CommandLineEventConsumer.Name=\"ExecuteEvilPowerShell\"",Filter="__EventFilter.Name=\"TimerTrigger\""
Consumer                : CommandLineEventConsumer.Name="ExecuteEvilPowerShell"
CreatorSID              : {1, 5, 0, 0...}
DeliverSynchronously    : False
DeliveryQoS             : 
Filter                  : __EventFilter.Name="TimerTrigger"
[snip]
{% endhighlight %}


As we can observe, this persistence is based off a Timer *intrinsic* Event type. If you launched it and head to C:\ you will see the *payload\_result.txt* file as per the script: 

{% highlight powershell %}
$TimerArgs = @{
    IntervalBetweenEvents = ([UInt32] 6000) # 6000 ms == 1 min
    SkipIfPassed = $False
    TimerId = $TimerName
}

$Payload = {
    # Prep your raw beacon stager along with Invoke-Shellcode here
    "Owned at $(Get-Date)" | Out-File C:\payload_result.txt
}
{% endhighlight %}

Let's look at the persistent registry key generated by the script via `Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name CreateKey -ArgumentList @($HiveVal, $PayloadKey)` (*creating the Registry Key*) & `Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name SetStringValue -ArgumentList @($HiveVal, $PayloadKey, $EncodedPayload, $PayloadValue)` (*storing the payload value inside the key*)

{% highlight powershell %}
PS C:\Windows\system32> Get-ItemProperty 'HKLM:\SOFTWARE\PayloadKey'

PayloadValue : DQAKACAAIAAgACAAIwAgAFAAcgBlAHAAIAB5AG8AdQByACAAcgBhAHcAIABiAGUAYQBjAG8AbgAgAHMAdABhAGcAZQByACAAYQBsAG8AbgBnACAAdwBpAHQAaAAgAEkAbgB2AG8AawBlAC0AUwBoAGUAbABsAGMAbwBkAGUAIABoAGUAcgBlAA0ACgANAAoAIAAgACAAIAAiAE8AdwBuAGUAZAAgAGEAdAAgACQAKABHAGUAdAAtAEQAYQB0AGUAKQAiACAAfAAgAE8AdQB0AC0ARgBpAGwAZQAgAEMAOgBcAHAAYQB5AGwAbwBhAGQAXwByAGUAcwB1AGwAdAAuAHQAeAB0AA0ACgA=
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\PayloadKey
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE
PSChildName  : PayloadKey
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
{% endhighlight %}

Alternatively: 
![THL02-01](../img/THL002/THL02-01.JPG)

We can observe the BASE64 ciphered payload (hold on to this, as it will become one of our detection artefacts later)

=======================================================================================================


Notes
- EventCode 600, "Provider LifeCycle", Message "Provider Registry Started", shows the powershell payload under "HostApplication"
- Sysmon Event 4, "Registry Object added or deleted" shows the creation of "HKLM\SOFTWARE\PayloadKey" by Image "C:\Windows\system32\wbem\wmiprvse.exe"
- Sysmon Event 4, "Registry Value Set" shows a BASE64 payload (include here the IOC to detect such B64 payloads as Artifact I)


Detection Artefacts: 
- Artifact 1: B64 payload in registry
- Artifact 2: wbemcons.dll called when WmiPrvse.exe invokes a CommandLineEventConsumer event
- Artifact 3: EventCode 600
- Artifact 4: 

