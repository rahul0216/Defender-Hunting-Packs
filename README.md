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
| Cobalt Strike Tool Analysis | Evidence-backed analysis of adversary Cobalt Strike use, ATT&CK coverage, indicators, evasion methods, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [Cobalt Strike Threat Hunting Research](cobat-strike-tool/Cobalt-Strike-Threat-Hunting-Research.md) |
| Mimikatz Tool Analysis | Evidence-based research on Mimikatz capabilities, ATT&CK flows, actor and campaign use, evasion methods, and detection hypotheses for Microsoft Defender XDR and Sentinel | [Mimikatz Threat Research and Detection Hypotheses](mimikatz-tool/Mimikatz-Threat-Research-and-Detection-Hypotheses.md) |
| DeadLock Ransomware Analysis | Evidence-backed analysis of DeadLock ransomware operations, attack flow, indicators, actor profile, decentralized recovery infrastructure, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [DeadLock Ransomware Hunting Research](deadlock-ransomware/DeadLock-Ransomware-Hunting-Research.md) |
| The Gentlemen RaaS Analysis | Evidence-backed analysis of The Gentlemen ransomware operations, attack flow, indicators, actor profile, propagation methods, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [The Gentlemen Ransomware Hunting Research](gentlemen-raas/Gentlemen-Ransomware-Hunting-Research.md) |
| Medusa Ransomware Analysis | Evidence-backed analysis of Medusa ransomware operations, attack flow, indicators, actor profiles, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [Medusa Ransomware Hunting Research](medusa-ransomware/Medusa-Ransomware-Hunting-Research.md) |
| Transparent Tribe APT36 Threat Actor Analysis | Analysis of Transparent Tribe threat actor covering targeting, attack flows, indicators, campaigns, tooling, and hunting hypotheses across Windows, Linux, and Android environments | [Transparent Tribe APT36 Threat Actor Hunting Research](trasparent-tribe-threat-actor/Transparent-Tribe-APT36-Hunting-Research.md) |
| NovaCookies Campaign Analysis | Analysis of the NovaCookies adversary-in-the-middle phishing service, attack flow, indicators, infrastructure, actor profile, ATT&CK techniques, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [NovaCookies Campaign Hunting Research](novacookies-campaign/NovaCookies-Campaign-Hunting-Research.md) |
| Shai-Hulud Supply Chain Campaign Analysis | Analysis of Shai-Hulud software supply chain activity across npm packages, developer workstations, CI/CD runners, GitHub repositories, cloud environments, credential theft, persistence, propagation, and exfiltration | [Shai-Hulud Supply Chain Campaign Threat Research](shai-hulud-campaign/Shai-Hulud-Supply-Chain-Campaign-Threat-Research.md) |

## Disclaimer

These hunting packs are provided for research and detection engineering use. Query results can vary based on telemetry quality, connector coverage, and environment-specific behavior. Always validate, tune, and test queries in your own environment before operational use.
