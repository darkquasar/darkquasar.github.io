---
layout: post
title: Cybersecurity Philosophy 
subtitle: Event, Incident & IOC: Operational Concepts to have with your morning coffee
tags: [incident, threat, event, alarm, ioc, attack, darkquassar, incident management, soc, siem, security, monitoring, operations]
comments: true
published: true
---

* TOC
{:toc}

> **Warning**: everything I say here is essentially **TL;DR**, close this page immediately and google pictures of cats or get a coffee and enjoy the ride!

# Triads
I love triads, everything should come in *three*. I will here explore two triads: 

- Event, Incident & IOC (1st part)
- Threat, Attack & Vulnerability (2nd part)

# Event, Incident & IOC

## Concepts, always those guys ruining the party
In this article, we will briefly explore the three concepts mentioned in the title in an attempt to shed some light over frequently misunderstood notions. As a phylosopher, I love concepts. As a cybersecurity dude, I thank them. 
Concepts are fun, think of them as a code, an abstraction layer. As Gilles Deleuze & Felix Guattari (amazing french minds) said "philosophy is the art of forming, inventing, and fabricating concepts" (refer to "What is Phylosophy?"). So like I said, we can think of concepts as "code" in the most restricted programming sense. A concept is a program, an interface, it can be helpful or destructive like a virus. It can infect other concepts, it can also affect the way you perceive reality. However this article is not about them, rather, about how we can make use of their potential to **express** the intertwining links of perceivable reality in order to capture practical states that aid our daily tasks. A a cybersec citizen, you are all the time developing, tuning and explaining procedures to either peers, clients, or people above and below the corporate chain. The efficiency of a procedure is defined by the clarity of the concepts that it binds together. A badly written one may lead to disastrous outcomes when you are hit by a SEV1 incident that you security analyst thought shouldn't be escalated because it didn't constitute an *incident* per se. 

## Definitions
So what are these guys? It is common to mistake incidents for events or threats, the latter for an alarm or this one for an incident. There are conceptual overlaps that make it even harder to clearly distinguish them. Nevertheless, it's not a futile exercize to attempt a definition that satisfies practical requirements. It is enough to define them in a way that allow us to put in motion the different phases of a plan/policy/procedure in order to achieve the expected outcome. I know you may be thinking "what the hell is this guy talking about?", "why am I loosing time with this nonsense?", if you are feeling that way, look I don't judge nor blame you, I would probably feel the same depending on the day of the week and direction of the wind. If you feel like this though, it's probably the best for you to stop reading on go find something that makes more immediate sense ;) 

### Event

> "A life contains only virtuals. It is made up of virtualities, events, singularities. What we call virtual is not something that lacks reality but something that is engaged in a process of actualization following the plane that gives it its particular reality... The plane of immanence is itself actualized in an object and a subject to which it attributes itself... but the plane of immanence is itself virtual" (Gilles Deleuze, Pure Immanence: Essays on A Life)

In the digital world, an event is an occurence in time with three important properties: 
> - (a) it originates in a digital system; 
> - (b) it is a collection of metadata about other events that occurr at the same or different levels; 
> - (c) it constitutes a logical entity in itself. 

What? Yeah, I know... take a guy we all know: Windows Event 4624 "An Account was Successfully Logged On", this guy classifies as an Event, why? because according to:

- (a) it was originated within a digital system
- (b) it is only the tip of the iceberg, it provides a collection of attributes that describe what happened in the background. Someone logged on, and successfully, but for that to happen, a call to a logon protocol must have been made (say Kerberos), credentials needed to be provided, encrypted and forwarded, network devices must have exchanged information in a few of the OSI layers, processors must have processed huge amounts of opcodes and many other systemic coordinations must have taken place for such a simple thing as "logging on" to happen. Windows Event 4624 is just an after-the-fact product of such activity (events).
- (c) the Windows Event 4624 is a logical unit that stands in front of you by itself, it has a structure, it is stored in a certain way within EVTX files, it consists of a series of fields and values that can be recalled by different querying methods: Event Viewer, Powershell, .NET, etc. 

So when we talk about "events" in our cybersphere, we do it in the sense described earlier. 
Events can be generated, collected and processed in many layers. On one layer we have an application generating an event, then a Windows service collecting it at a host level, then an agent like NXLog or WinLogBeat fetching that data, parsing it as syslog and submitting it to a SIEM solution that in turn re-arranges the syslog so that a presentation and application layer can display them in an orderly manner to the user. It doesn't matter how many transformations the original event went through, it remains the same event if, at the end of the process, the same information can be observed: the fact that the event has gone through multiple instances of itself (raw -> ordered -> syslog -> SIEM DB) doesn't mean the information refered by it has been altered. On the contrary, when an event is somehow **enriched** with or **stripped** from **data** then it becomes a new event. 

Events are not "good" or "bad" per se, they are just by-products of other things that happen in our systems. A SIEM platform in a SOC for example, will collect millions of events and perform a few operations on them: aggregation, ammendments, enrichment, adjustments. A Security Analyst observes these occurrences, he/she creates graphs with them and develops rules and visualizations that allow for the extraction of **meaningful** or **actionable** information from them. 

> TL;DR (*lol*;) We have often heard about "alert fatigue", and as you will see, this fatigue is very real and can happen as a result of badly managed event flows or the lack of a structure for the meaningful extraction of actionable data. And before you say it: you are right, it's people that make a difference here, not technology. 

### Indicator of Compromise (IOC)
> "What is a realtion? It is what makes us pass from a given impression or idea to the idea of something that is not presently given... Casuality requires that I go from something that is given to me to the idea of something that has never been given to me, that isn't even giveable in experience" (Gilles Deleuze, "Hume", Pure Immanence: Essays on A Life)

Collecting millions of events per second doesn't make much sense unless we actually **do something** with them. There are essentially three main ways of extracting meaningful information out of this flow of events. Unfortunately not many know how to do this and take an approach of *sending everything everywhere* which exponentially contributes to noise generation and alert fatigue. Succintly: 

1. Risk assessment and policy definitions. By doing this, you define which areas of your network carry the highest value in terms of sensitive data. You also define which entry vectors could pose risks to such data and which techniques can be leveraged to achieve this purpose. Consequently, you then use this information to define which logs you require in order to create a web of detection around designated system areas (for example user logons). This method is basically a top-down approach where you beginn with a high overview assessment of your systems and work your way down to the TTPs (*Tactics, Techniques and Procedures*)[https://attack.mitre.org/wiki/Main_Page] level. 
2. Indicators of Compromise. Contrary to (1), IOC involve a bottom-up approach. By leveraging IOC, you begin with the study and definition of TTPs from the most granular perspective. This analysis is then organized in structured units that become your IOC: you apply them to SIEM, IPS/IDS, Firewalls, Proxys, EDR solutions, etc. When using this approach, you are only concerned with those events that carry the potential to trigger your previously defined IOC thus, everything else can be considered noise. 
3. Experience. Plain and simply. Hire a Security Analyst that *knows* this stuff, put this person to the task and you will see what I mean. 

So an IOC is a logical unit of conditions that, when applied to a flow of events, is able to single out a discrete series which indicates a threat or attack to the CIA of your systems' data. IOC can be simple like a single MD5 hash or complex like SIEM correlation rules matchin against dozens of conditions. IOC can be structured in a formal framework ((Open IOC)[http://www.openioc.org/], (STIX/TAXII)[https://securityintelligence.com/how-stix-taxii-and-cybox-can-help-with-standardizing-threat-information/], (SIGMA)[https://github.com/Neo23x0/sigma], (YARA)[https://github.com/VirusTotal/yara], (SNORT)[https://www.snort.org/], etc.) or contained within the logic of a security solution (different SIEM platforms come with their own internal IOC building layers for example).


> An IOC is what defines which events constitute a threat or an attack. When an IOC conditions are met by an event, or series thereof, then an **alert** should be raised in your systems. However, take into consideration that **not every alert constitutes a security incident**

If you wonder: wouldn't the best option be to take a combination approach of (1)(2)(3)? Well, despite *the right and balanced center* not always being the best answer for problems, in this case it is: 

> TIP: organize your logs and data sources in levels of relevance according to a centraly managed list of IOC. These IOC should have been, in turn, previously selected according to a detailed analysis of (a) your security controls in place and (b) the TTPs that you are most likely to encounter due to your security controls' gaps. Once you have your logs categorized into relevance levels, proceed to a selection of those essential and a small sub-set of those that are considered of 2nd or 3rd degree but that could prove useful in terms of contextual information, should a security incident happen. 

So far, we've talked about events and IOCs, and we understand that their purpose is to provide visibility on the continuous alterations in the homeostasis of computing systems, such that activity patterns deemed threatening can be located, contained and any damage remediated. However, for **something** to happen at all after we successfully detect such damaging patterns, we need to define a new layer of systemic activity whose purpose is essentially *practical*. And so we flow naturally into incidents. 

### Incident
> "There are no facts, only interpretations. And this is also an interpretation" (Friedrich Nietzsche, Notebooks [Summer 1886 – Fall 1887])

> “The percept is the landscape before man, in the absence of man.” (Gilles Deleuze, What is Philosophy?)

> Note: When I talk about *incidents* in this section bear in mind that I refer to *security incidents* in particular. 

We are all familiar with incidents, we open them, handle them, lead them to resolution, close them and make reports about them. More often than not, however, the way we categorize incidents within the cybersecurity world is the same as the way we categorize them in the operational world. A SEV2 is the same for a core router failure that brings down a portion of our network or a WannaCry infection that threatens a file server. A SEV3 is the same for an application that malfunctions and needs to be escalated to the apps support guys or a malware that hasn't been removed properly by the AV. The problem is though, incidents in cybersecurity are more about the **potential** for damage than **actual** damage being done. We can define an Incident as an event, or correlation thereof, that threatens to or causes direct damage to the Confidentiality, Integrity or Availability of information. An Indicent must also comply with three characteristics: 

> - (a) it is originated as the result of an event, or correlation thereof, whose information complies with a set of conditions that indicate activity which can -or *has* already- damage the CIA triad of our systems. 
> - (b) it constitutes a logical unit in itself, it is not *just another event* or an *extension* of another entity.
> - (c) it's inherently comprised of two elements: (1) a data structure and (2) a series of actions that require human intervention. Unlike a mere event, that only has (1), an incident is a collection of data that not only points to and describes a situation, but also needs to go through multiple *transforms* in order to achieve its purpose. 

So as you can see, not every event is an incident but every incident *is*, by virtue of condition (c)(1) an event. An incident is an event that talks about other events (this is what an event is anyways), but demands actions to be taken that decide the outcome of the information contained within it. 

We shall define in another article a possible incident categorization scheme, but that's not the purpose here. The next thing we need to ask ourselves is, how does a series of events become an incident? Well as we said, because it threatens or damages the CIA of a system and a monitoring control (IOC) has been defined to identify such threats. Certainly unobjectionable, however, what *is* a threat?

In our next article, after I write the 2nd part of the Mimikatz one, and how to detect WMI Backdoors as well, I shall present these new concepts! (I know you don't believe me... but have faith)

