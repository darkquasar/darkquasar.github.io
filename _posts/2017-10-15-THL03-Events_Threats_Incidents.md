---
layout: post
title: Incident, Threat, Alert & Event 
subtitle: Concepts and other stuff
tags: [threat hunting, darkquassar, incident management, soc, siem, security analyst, monitoring, operations]
comments: true
published: false
---
* TOC
{:toc}

# Incident, Threat, Alert & Event

## Concepts, always those guys ruining the party
In this article, we will briefly explore the three concepts mentioned in the title in an attempt to shed some light over frequently misunderstood notions. As a phylosopher, I love concepts. As a cybersecurity dude, I thank them. 
Concepts are fun, think of them as a code, an abstraction layer. As Gilles Deleuze & Felix Guattari (amazing french minds) said "philosophy is the art of forming, inventing, and fabricating concepts" (refer to "What is Phylosophy?"). So like I said, we can think of concepts as "code" in the most restricted programming sense. A concept is a program, an interface, it can be helpful or destructive like a virus. It can infect other concepts, it can also affect the way you perceive reality. However this article is not about them, rather, about how we can make use of their potential to **express** the intertwining links of perceivable reality in order to capture practical states that aid our daily tasks. A a cybersec citizen, you are all the time developing, tuning and explaining procedures to either peers, clients, or people above and below the corporate chain. The efficiency of a procedure is defined by the clarity of the concepts that it binds together. A badly written one may lead to disastrous outcomes when you are hit by a SEV1 incident that you security analyst thought shouldn't be escalated because it didn't constitute an *incident* per se. 

## Definitions
So what are these guys? It is common to mistake incidents for events or threats, the latter for an alarm or this one for an incident. There are conceptual overlaps that make it even harder to clearly distinguish them. Nevertheless, it's not a futile exercize to attempt a definition that satisfies practical requirements. It is enough to define them in a way that allow us to put in motion the different phases of a plan/policy/procedure in order to achieve the expected outcome. I know you may be thinking "what the hell is this guy talking about?", "why am I loosing time with this nonsense?", if you are feeling that way, look I don't judge nor blame you, I would probably feel the same depending on the day of the week and direction of the wind. If you feel like this though, it's probably the best for you to stop reading on go find something that makes more immediate sense ;) 

### Event
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

> TL;DR (*lol, as if all that I'm writting here is not already TL;DR* ;) We have often heard about "alert fatigue", and as you will see, this fatigue is very real and can happen as a result of badly managed event flows or the lack of a structure for the meaningful extraction of actionable data. And before you say it: you are right, it's people that make a difference here, not technology. 

### Incident
We are all familiar with incidents, we open them, handle them, lead them to resolution, close them and make reports about them. More often than not, however, the way we categorize incidents within the cybersecurity world is the same as the way we categorize them in the operational world. A SEV2 is the same for a core router failure that brings down a portion of our network or a WannaCry infection that threatens a file server. A SEV3 is the same for an application that malfunctions and needs to be escalated to the apps support guys or a malware that hasn't been removed properly by the AV. The problem is though, incidents in cybersecurity are more about the **potential** for damage than **actual** damage being done. We can define an Incident as an event, or correlation thereof, that threatens to or causes direct damage to the Confidentiality, Integrity or Availability of information. An Indicent must also comply with three characteristics: 

> - (a) it is originated as the result of an event, or correlation thereof, whose information complies with a set of conditions that indicate activity which can -or *has* already- damage the CIA triad of our systems. 
> - (b) it constitutes a logical unit in itself, it is not *just another event* or an *extension* of another entity.
> - (c) it's inherently comprised of two elements: (1) a data structure and (2) a series of actions that require human intervention. Unlike a mere event, that only has (1), an incident is a collection of data that not only points to and describes a situation, but also needs to go through multiple *transforms* in order to achieve its purpose. 

So as you can see, not every event is an incident but every incident *is*, by virtue of condition (c)(1) an event. An incident is an event that talks about other events (this is what an event is anyways), but demands actions to be taken that decide the outcome of the information contained within it. 

We will define in another article a possible incident categorization but that's not the purpose here. So the next thing we need to ask is, how does a series of events become an incident? Well as we said, because it threatens or damages the CIA of a system. But what is  
