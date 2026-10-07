---
title: Microsoft Defender Hunting Packs
description: Microsoft Defender XDR and Sentinel hunting packs for threat hunting, investigation, and detection engineering
---

Welcome to Defender Hunting Packs.

This repository contains practical Microsoft Defender XDR and Sentinel hunting packs designed to support proactive threat hunting, investigation, and detection engineering workflows. Each pack includes focused KQL hunting rules and supporting documentation that you can tune for your environment.

## Hunting Packs

| Hunting pack | Focus area | Path |
|---|---|---|
| TeamPCP Threat Actor | Threat hunting for TeamPCP activity across supply chain compromise, CI/CD credential theft, cloud post-compromise discovery, and persistence behavior | [teampcp-threat-actor](teampcp-threat-actor) |
| TrapDoor Supply Chain | Threat hunting for TrapDoor supply chain activities across developer and package ecosystems | [trapdoor-supply-chain](trapdoor-supply-chain) |

## Research Reports

### Attack Techniques

| Report | Focus area | Path |
|---|---|---|
| Console Named-Pipe Process Injection Analysis | Analysis of a Windows process injection technique that delivers payload bytes through redirected console input without VirtualAllocEx or WriteProcessMemory, including behavioral detection opportunities for Microsoft Defender XDR and Sentinel | [Console Named-Pipe Process Injection Threat Research](research-reports/attack-techniques/named-pipe-process-injection/Console-Named-Pipe-Process-Injection-Threat-Research.md) |
| OpenSUpdater Recompiled 7-Zip SFX Analysis | Analysis of OpenSUpdater malware hidden in recompiled 7-Zip self-extracting installers, including its reflective loading chain, indicators, ATT&CK mapping, and defensive guidance | [OpenSUpdater Recompiled 7-Zip SFX Threat Research](research-reports/attack-techniques/recomplied-7zip-sfx/OpenSUpdater-Recompiled-7Zip-SFX-Threat-Research.md) |
| Phishing Techniques Analysis | Analysis of recent phishing tradecraft across device code, adversary-in-the-middle, OAuth consent, QR, ClickFix, Teams and phone social engineering, and rogue RDP lures, with hunting guidance for Microsoft Defender XDR and Sentinel | [Phishing Techniques Research for Hunting Development](research-reports/attack-techniques/clickfix-phishing/phishing-techniques-hunting-research.md) |
| Slopsquatting and HalluSquatting Analysis | Threat analysis of AI package hallucination exploitation, terminology, attack prerequisites, ecosystem exposure, evidence gaps, mitigations, and defensive research opportunities | [Slopsquatting and HalluSquatting Threat Research](research-reports/attack-techniques/slopsquatting/Slopsquatting-Hallusquatting-Threat-Research.md) |

### Campaigns

| Report | Focus area | Path |
|---|---|---|
| GlassWorm Campaign Analysis | Evidence-based analysis of GlassWorm software supply chain activity across Visual Studio Code and Open VSX extensions, npm packages, GitHub repositories, credential theft, propagation, indicators, and hunting hypotheses | [GlassWorm Campaign Threat Research and Hunting Hypotheses](research-reports/campaigns/glassworm-campaign/GlassWorm-Campaign-Threat-Research.md) |
| NovaCookies Campaign Analysis | Analysis of the NovaCookies adversary-in-the-middle phishing service, attack flow, indicators, infrastructure, actor profile, ATT&CK techniques, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [NovaCookies Campaign Hunting Research](research-reports/campaigns/novacookies-campaign/NovaCookies-Campaign-Hunting-Research.md) |
| Shai-Hulud Supply Chain Campaign Analysis | Analysis of Shai-Hulud software supply chain activity across npm packages, developer workstations, CI/CD runners, GitHub repositories, cloud environments, credential theft, persistence, propagation, and exfiltration | [Shai-Hulud Supply Chain Campaign Threat Research](research-reports/campaigns/shai-hulud-campaign/Shai-Hulud-Supply-Chain-Campaign-Threat-Research.md) |

### Malware

| Report | Focus area | Path |
|---|---|---|
| PromptSteal and LAMEHUG Malware Analysis | Threat analysis of APT28-associated PromptSteal and LAMEHUG malware, including runtime LLM-assisted command generation, attack flow, indicators, ATT&CK mappings, and hunting guidance for Microsoft Defender XDR and Sentinel | [PromptSteal and LAMEHUG Malware Research](research-reports/malware/promptsteal-malware/PromptSteal-LAMEHUG-Malware-Research.md) |

### Phishing Kits

| Report | Focus area | Path |
|---|---|---|
| BlueMoon Exploit Kit Analysis | Evidence-based analysis of BlueMoon browser exploitation, targeted campaigns, Chromium and Windows vulnerabilities, evasion methods, indicators, ATT&CK mappings, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [BlueMoon Exploit Kit Threat Research and Hunting Hypotheses](research-reports/phishing-kits/eviltokens-phishing-kit/BlueMoon-Exploit-Kit-Threat-Research.md) |
| EvilTokens Phishing Kit Analysis | Evidence-based analysis of EvilTokens phishing-as-a-service activity, device-code phishing, token theft, business email compromise preparation, evasion, ATT&CK mappings, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [EvilTokens Phishing Kit Threat Research](research-reports/phishing-kits/eviltokens-phishing-kit/EvilTokens-Phishing-Kit-Threat-Research.md) |

### Ransomware

| Report | Focus area | Path |
|---|---|---|
| DeadLock Ransomware Analysis | Evidence-backed analysis of DeadLock ransomware operations, attack flow, indicators, actor profile, decentralized recovery infrastructure, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [DeadLock Ransomware Hunting Research](research-reports/ransomware/deadlock-ransomware/DeadLock-Ransomware-Hunting-Research.md) |
| The Gentlemen RaaS Analysis | Evidence-backed analysis of The Gentlemen ransomware operations, attack flow, indicators, actor profile, propagation methods, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [The Gentlemen Ransomware Hunting Research](research-reports/ransomware/gentlemen-raas/Gentlemen-Ransomware-Hunting-Research.md) |
| Medusa Ransomware Analysis | Evidence-backed analysis of Medusa ransomware operations, attack flow, indicators, actor profiles, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [Medusa Ransomware Hunting Research](research-reports/ransomware/medusa-ransomware/Medusa-Ransomware-Hunting-Research.md) |

### Threat Actors

| Report | Focus area | Path |
|---|---|---|
| Lazarus Group Threat Actor Analysis | Cluster-aware analysis of Lazarus Group attack flows, campaigns, tooling, indicators, attribution boundaries, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [Lazarus Group Threat Actor Hunting Research](research-reports/threat-actors/lazarus-group-threat-actor/Lazarus-Group-Hunting-Research.md) |
| Scattered Spider Threat Group Analysis | Evidence-based analysis of Scattered Spider identity-led attacks, social engineering, cloud and SaaS abuse, ransomware relationships, indicators, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [Scattered Spider Threat Group Research and Hunting Hypotheses](research-reports/threat-actors/scattered-spider-threat-group/Scattered-Spider-Threat-Group-Research.md) |
| ShinyHunters Hacker Group Analysis | Behavior-focused analysis of ShinyHunters data theft, SaaS abuse, extortion, indicators, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [ShinyHunters Hacker Group Hunting Research](research-reports/threat-actors/shiny-hunters-hacker-group/ShinyHunters-Hacker-Group-Hunting-Research.md) |
| Transparent Tribe APT36 Threat Actor Analysis | Analysis of Transparent Tribe threat actor covering targeting, attack flows, indicators, campaigns, tooling, and hunting hypotheses across Windows, Linux, and Android environments | [Transparent Tribe APT36 Threat Actor Hunting Research](research-reports/threat-actors/transparent-tribe-threat-actor/Transparent-Tribe-APT36-Hunting-Research.md) |
| Zirconium and Violet Typhoon Threat Actor Analysis | Evidence-based analysis of Zirconium and Violet Typhoon target profiles, attack flows, tooling, indicators, attribution boundaries, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [Zirconium and Violet Typhoon Threat Actor Hunting Research](research-reports/threat-actors/zirconium-threat-group/Zirconium-Threat-Actor-Hunting-Research.md) |

### Tools

| Report | Focus area | Path |
|---|---|---|
| Cobalt Strike Tool Analysis | Evidence-backed analysis of adversary Cobalt Strike use, ATT&CK coverage, indicators, evasion methods, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [Cobalt Strike Threat Hunting Research](research-reports/tools/cobalt-strike-tool/Cobalt-Strike-Threat-Hunting-Research.md) |
| Mimikatz Tool Analysis | Evidence-based research on Mimikatz capabilities, ATT&CK flows, actor and campaign use, evasion methods, and detection hypotheses for Microsoft Defender XDR and Sentinel | [Mimikatz Threat Research and Detection Hypotheses](research-reports/tools/mimikatz-tool/Mimikatz-Threat-Research-and-Detection-Hypotheses.md) |
| NetExec Tool Analysis | Evidence-based research on NetExec capabilities, observed threat use, credential access, enumeration, lateral movement, remote execution, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [NetExec Threat Hunting Research](research-reports/tools/netexec-tool/NetExec-Threat-Hunting-Research.md) |
| RMM and Remote Access Tools Abuse Analysis | Evidence-based analysis of attacker abuse of prominent RMM and remote access tools, including attack flows, actor mappings, indicators, hunting hypotheses, and detection strategies | [Abuse of RMM and Remote Access Tools Threat Research](research-reports/tools/rmm-and-remote-access-tools/Abuse-of-RMM-and-Remote-Access-Tools-Threat-Research.md) |
| Rubeus Tool Analysis | Evidence-based research on Rubeus capabilities, Kerberos abuse, observed threat use, evasion, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [Rubeus Threat Hunting Research](research-reports/tools/rubeus-tool/Rubeus-Threat-Hunting-Research.md) |

### Vulnerability Reports

| Report | Focus area | Path |
|---|---|---|
| Plugin4Shell Vulnerability Analysis | Evidence-grounded analysis of commit-pinning bypasses in Claude Code, OpenAI Codex, GitHub Copilot CLI, and Gemini CLI, including affected versions, exploitation conditions, remediation, and hunting opportunities | [Plugin4Shell Vulnerability Report](research-reports/vulnerability-reports/Plugin4Shell-Vulnerability-Report.md) |

## Disclaimer

These hunting packs are provided for research and detection engineering use. Query results can vary based on telemetry quality, connector coverage, and environment-specific behavior. Always validate, tune, and test queries in your own environment before operational use.
