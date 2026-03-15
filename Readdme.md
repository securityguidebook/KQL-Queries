# KQL Detection Rule Library

> A collection of Microsoft Sentinel KQL analytics rules for detecting common attack techniques — each mapped to MITRE ATT&CK, with tuning notes and false positive guidance.

![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel-blue)
![Language](https://img.shields.io/badge/Language-KQL-teal)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)

---

## Why This Exists

These rules are drawn from real alert patterns I encountered as a Security Engineer at a managed security services provider and at Sony PlayStation. I've documented them here to:
- Provide ready-to-deploy Sentinel analytics rules with real-world context
- Show the *reasoning* behind each rule, not just the query
- Include tuning guidance that you only learn from running these in production

---

## Rule Index

| # | Rule Name | MITRE Technique | Severity |
|---|-----------|-----------------|----------|
| 01 | [SSH Brute Force Detection](rules/01-ssh-brute-force.md) | T1110.001 | Medium |
| 02 | [Impossible Travel / Sign-in Anomaly](rules/02-impossible-travel.md) | T1078 | High |
| 03 | [Mass File Download](rules/03-mass-file-download.md) | T1530 | High |
| 04 | [Suspicious Azure Sign-In](rules/04-suspicious-azure-signin.md) | T1078.004 | High |
| 05 | [Privilege Escalation — New Admin Account](rules/05-new-admin-account.md) | T1078.003 | Critical |
| 06 | [Repeated MFA Failures](rules/06-mfa-failures.md) | T1621 | Medium |
| 07 | [Suspicious PowerShell Execution](rules/07-suspicious-powershell.md) | T1059.001 | High |
| 08 | [Azure Resource Deletion Spike](rules/08-resource-deletion.md) | T1485 | High |
| 09 | [Service Account Sign-In from New Location](rules/09-service-account-location.md) | T1078 | Medium |
| 10 | [Outbound Data Exfiltration Volume](rules/10-data-exfiltration.md) | T1041 | Critical |

---

## Rule File Structure

Every rule follows the same format:

```
rules/
└── 01-ssh-brute-force.md
    ├── Description       — what the rule detects and why it matters
    ├── MITRE Mapping     — technique ID, tactic, sub-technique
    ├── KQL Query         — ready to paste into Sentinel Analytics
    ├── Tuning Notes      — how to reduce false positives
    ├── Triage Steps      — what to do when this fires
    └── References        — related rules, docs, ATT&CK entry
```

---

## How to Deploy in Microsoft Sentinel

1. Open **Microsoft Sentinel → Analytics → Create → Scheduled query rule**
2. Paste the KQL from any rule file
3. Set the frequency and lookback window as documented in each rule
4. Configure alert enrichment and playbook triggers as needed

---

## Related Projects

- [Incident Response Playbooks](https://github.com/securityguidebook/ir-playbooks) — what to do when these rules fire
- [Azure Honey Net SOC](https://github.com/securityguidebook/Azure-Honey-Net-SOC) — the lab environment where many of these were tested

---

## Author

**Pawarid Tupmongkol** | [LinkedIn](https://linkedin.com/in/pawaridtupmongkol) | [GitHub](https://github.com/securityguidebook)
