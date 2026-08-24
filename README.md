# Microsoft Defender Hunting Packs

Welcome to Defender Hunting Packs.

This repository contains practical Microsoft Defender XDR and Sentinel hunting packs designed to support proactive threat hunting, investigation, and detection engineering workflows. Each pack includes focused KQL hunting rules and supporting documentation that you can tune for your environment.

## Hunting Packs

| Hunting pack | Focus area | Path |
|---|---|---|
| TeamPCP Threat Actor | Threat hunting for TeamPCP activity across supply chain compromise, CI/CD credential theft, cloud post-compromise discovery, and persistence behavior | [teampcp-threat-actor](teampcp-threat-actor) |
| TrapDoor Supply Chain | Threat hunting for TrapDoor supply chain activities across developer and package ecosystems | [trapdoor-supply-chain](trapdoor-supply-chain) |
| Medusa Ransomware Analysis | Evidence-backed analysis of Medusa ransomware operations, attack flow, indicators, actor profiles, and hunting hypotheses for Microsoft Defender XDR and Sentinel | [Medusa Ransomware Hunting Research](medusa-ransomware/Medusa-Ransomware-Hunting-Research.md) |

## Disclaimer

These hunting packs are provided for research and detection engineering use. Query results can vary based on telemetry quality, connector coverage, and environment-specific behavior. Always validate, tune, and test queries in your own environment before operational use.
