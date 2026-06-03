---
title: TeamPCP Threat Actor Hunting Queries
description: Overview, usage guidance, rule summary, and detection caveats for TeamPCP threat actor hunts
author: rahul0216
date: 2026-06-03
keywords:
  - microsoft sentinel
  - microsoft defender xdr
  - hunting queries
  - teampcp
  - threat actor
  - supply chain
  - cloud exploitation
estimated_reading_time: 8
---

## Description

This folder contains hunting queries for TeamPCP threat actor activity across software supply chain compromise, CI/CD credential theft, cloud post-compromise discovery, and persistence behavior.

The rules focus on:

* Campaign-linked C2 and infrastructure egress
* Credential harvesting and secret collection command patterns
* Runner memory and filesystem secret sweep behavior
* Encrypted archive staging and exfiltration chains
* Linux persistence artifacts linked to TeamPCP tooling
* Suspicious preinstall or staged payload execution chains
* Cloud discovery, secret access, and data collection bursts
* GitHub workflow abuse and anti-forensics activity
* End-to-end sequence correlation across process, network, and cloud telemetry

## MITRE ATT&CK Alignment

This hunt pack aligns with ATT&CK techniques repeatedly associated with TeamPCP tradecraft across public reports.

| ATT&CK technique | Why it maps to TeamPCP behavior | Example rules |
|---|---|---|
| [T1195.002 Supply Chain Compromise: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/002/) | Abuse of trusted build, package, and action distribution channels | Rules 2, 6, 10 |
| [T1552.005 Unsecured Credentials: Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/) | Credential collection from metadata endpoints and cloud execution contexts | Rules 2, 7 |
| [T1552.007 Unsecured Credentials: Container API](https://attack.mitre.org/techniques/T1552/007/) | Secret and token harvesting in containerized workloads and orchestration contexts | Rules 2, 7, 8 |
| [T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/) | C2 and exfiltration over HTTP or HTTPS to actor infrastructure | Rules 1, 4 |
| [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Data staging and outbound transfer to campaign infrastructure | Rules 1, 4, 10 |
| [T1543.002 Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/) | Linux user-service persistence artifacts such as sysmon or pgmon style services | Rule 5 |
| [T1053.003 Scheduled Task or Job: Cron](https://attack.mitre.org/techniques/T1053/003/) | Recurring execution and persistence mechanisms in Linux workflows | Rule 5 |
| [T1609 Container Administration Command](https://attack.mitre.org/techniques/T1609/) | Command execution and control through container management interfaces | Rules 2, 7 |
| [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610/) | Malicious or unauthorized workload deployment for persistence or expansion | Rules 7, 10 |

> [!NOTE]
> ATT&CK mappings are behavior-based and meant for hunt prioritization. Confirm local evidence before final actor attribution.

## Rule Summary

| # | Rule file | Primary intent | Data sources |
|---|---|---|---|
| 1 | 01-known-c2-and-infrastructure-egress.yaml | Detect endpoint egress to TeamPCP-linked domains and IPs | DeviceNetworkEvents |
| 2 | 02-credential-harvest-command-patterns.yaml | Detect command-line patterns used for credential and secret harvesting | DeviceProcessEvents |
| 3 | 03-runner-memory-and-secret-sweep-signals.yaml | Detect runner-process targeting and broad filesystem secret sweeps | DeviceProcessEvents |
| 4 | 04-encrypted-archive-exfil-chain.yaml | Detect archive, encryption, and HTTP POST exfil chains | DeviceProcessEvents |
| 5 | 05-persistence-artifacts-on-linux-hosts.yaml | Detect Linux persistence artifacts such as sysmon and pgmon | DeviceFileEvents |
| 6 | 06-suspicious-preinstall-bun-node-staging.yaml | Detect suspicious preinstall, bun, and staged JS execution behavior | DeviceProcessEvents |
| 7 | 07-cloud-discovery-burst-after-key-validation.yaml | Detect high-rate cloud discovery bursts after key or token validation behavior | CloudAppEvents |
| 8 | 08-secret-access-and-object-read-burst.yaml | Detect concentrated secret and object access activity | CloudAppEvents |
| 9 | 09-github-workflow-abuse-and-log-deletion.yaml | Detect suspicious GitHub workflow abuse and workflow log deletion | CloudAppEvents |
| 10 | 10-sequence-install-to-egress-to-discovery.yaml | Correlate suspicious process execution with C2 egress and cloud discovery signals | DeviceProcessEvents, DeviceNetworkEvents, CloudAppEvents |

## Usage

1. Run Rule 1 and Rule 4 first to identify probable C2 and exfiltration hosts.
2. Pivot into Rules 2, 3, and 6 to validate malicious execution context.
3. Run Rules 7, 8, and 9 to determine cloud and source-control follow-on activity.
4. Use Rule 10 to prioritize incidents where multiple phases occur in close sequence.
5. Apply environment-specific allowlists before promoting any query to scheduled analytics.

## Detection Caveats FP and FN

> [!WARNING]
> These hunts can generate benign results and can also miss activity depending on telemetry depth, cloud connector coverage, and adversary adaptation.

### False Positives

Common false positive sources:

* Legitimate CI/CD scripts that query cloud metadata or enumerate resources
* Sanctioned security tools that inspect environment variables and secrets
* Expected GitHub workflow administration and repository automation
* Routine package installation or update activity on build hosts
* Approved remote administration activity on Linux hosts

Recommended FP tuning actions:

* Scope first to high-value build runners and release engineering hosts
* Baseline expected cloud API usage by automation identities
* Allowlist trusted internal repositories, package mirrors, and automation service accounts
* Filter on suspicious behavior sequences rather than single IOC matches

### False Negatives

Common false negative causes:

* Missing endpoint telemetry on developer workstations or self-hosted runners
* Incomplete cloud audit logging for data-plane events
* Adversary rotation to new domains, IPs, and tooling names
* Low-and-slow activity outside the selected hunt window
* Post-compromise abuse occurring only in cloud without endpoint traces

Recommended FN reduction actions:

* Expand telemetry coverage for runners, build hosts, and cloud connectors
* Refresh IOC sets and query indicators from current threat intelligence
* Correlate endpoint, cloud, and source-control telemetry during investigations
* Hunt on behavior chains and time-sequenced anomalies, not only static indicators

## Operational Notes

* Keep IOC lists synchronized with active TeamPCP intelligence updates.
* Validate each query in a test workspace before production use.
* Document local allowlists and tuning decisions next to each rule file.
