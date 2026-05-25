---
title: TrapDoor Supply Chain Hunting Queries
description: Overview, usage guidance, rule summary, and detection caveats for TrapDoor supply chain hunts
author: rahul0216
date: 2026-05-25
keywords:
  - microsoft sentinel
  - hunting queries
  - trapdoor
  - supply chain
  - npm
  - pypi
  - crates
estimated_reading_time: 6
---

## Description

This folder contains hunting queries for suspected TrapDoor-style supply chain activity targeting developer workflows across npm, PyPI, and Crates ecosystems.

The rules focus on:

* Suspicious package installation patterns
* Python to Node payload execution chains
* Known campaign infrastructure egress
* Prompt-file and hook-based persistence behaviors
* SSH key access and follow-on movement indicators
* Burst egress after suspicious installation events

## Rule Summary

| # | Rule file | Primary intent | Data sources |
|---|---|---|---|
| 1 | 01-suspicious-package-install-wave.yaml | Detect installs of known suspicious package names | DeviceProcessEvents |
| 2 | 02-python-import-node-e-remote-payload.yaml | Detect Python parent to Node inline execution behavior | DeviceProcessEvents |
| 3 | 03-trapdoor-campaign-infrastructure-egress.yaml | Detect endpoint traffic to campaign-linked infrastructure | DeviceNetworkEvents |
| 4 | 04-ai-prompt-file-persistence-on-dev-hosts.yaml | Detect suspicious writes to .cursorrules and CLAUDE.md | DeviceFileEvents |
| 5 | 05-git-hook-persistence-after-package-install.yaml | Correlate suspicious installs with Git hook writes | DeviceProcessEvents, DeviceFileEvents |
| 6 | 06-cron-systemd-shellhook-persistence-patterns.yaml | Detect shell and service persistence command patterns | DeviceProcessEvents |
| 7 | 07-ssh-key-access-followed-by-ssh-egress.yaml | Correlate SSH key access with outbound SSH | DeviceFileEvents, DeviceNetworkEvents |
| 8 | 08-suspicious-install-followed-by-public-egress-burst.yaml | Correlate suspicious install with short-window egress burst | DeviceProcessEvents, DeviceNetworkEvents |

## Usage

1. Set `StartTimeISO` and `EndTimeISO` to a bounded hunt window.
2. Run Rule 1 and Rule 3 first to establish candidate affected hosts.
3. Pivot into Rules 2, 4, 5, and 6 to validate execution and persistence context.
4. Run Rules 7 and 8 to assess lateral movement and probable data movement risk.
5. Prioritize hosts where two or more rules trigger in close time proximity.
6. Add environment-specific allowlists before operationalizing as scheduled analytics.

## Detection Caveats FP and FN

> [!WARNING]
> These hunts can generate benign results and can also miss activity depending on telemetry and adversary behavior.

### False Positives

Common false positive sources:

* Legitimate package installation or update automation
* Developer scripting that uses `node -e`, `python`, or shell wrappers
* Normal Git hook management during local development workflows
* Expected SSH administration, key rotation, and repository bootstrap actions
* Security tooling that inspects shell startup files or auth material

Recommended FP tuning actions:

* Scope to high-value developer endpoints and build agents first
* Allowlist known package registries, internal mirrors, and trusted automation accounts
* Exclude approved repositories and golden image provisioning workflows
* Baseline normal outbound destinations for build hosts before alerting on burst egress

### False Negatives

Common false negative causes:

* Missing or partial endpoint telemetry coverage
* Adversary use of package names, domains, or payload chains not in current indicators
* Execution through tooling not represented in current process filters
* Delayed or low-volume activity outside the selected hunt window
* Attack paths that rely only on cloud-side abuse without endpoint traces

Recommended FN reduction actions:

* Expand telemetry coverage for developer workstations and CI runners
* Refresh indicator lists frequently from current threat intelligence
* Correlate with identity, cloud audit, and source-control telemetry
* Hunt for sequence patterns across rules, not single-rule hits only

## Operational Notes

* Keep rule metadata and indicator lists synchronized with threat research updates.
* Validate query behavior in test workspaces before production deployment.
* Document local allowlists and tuning decisions next to each rule file for maintenance continuity.
