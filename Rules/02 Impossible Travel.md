# Rule 02 — Impossible Travel / Sign-in Anomaly

## Description

Detects when a user account signs in from two geographically distant locations within a timeframe that makes physical travel impossible — a strong indicator of credential compromise or account sharing.

This is one of the **highest-value** detections in any Azure/M365 environment. Unlike brute-force alerts which are noisy, impossible travel alerts are relatively rare and almost always worth investigating.

**Why it matters:** If an attacker steals credentials (via phishing, credential stuffing, or dark web purchase), they'll sign in from their own location while the legitimate user is elsewhere. This rule catches exactly that scenario.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | TA0001 — Initial Access |
| Technique | T1078 — Valid Accounts |
| Sub-technique | T1078.004 — Cloud Accounts |

---

## KQL Query

```kql
// Impossible Travel Detection — Azure AD Sign-ins
// Detects sign-ins from two countries within 1 hour for the same account

SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0  // Successful sign-ins only
| where isnotempty(Location)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    CountryOrRegion = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    AppDisplayName,
    DeviceDetail
| summarize
    Locations = make_set(CountryOrRegion),
    SignInTimes = make_list(TimeGenerated),
    IPAddresses = make_set(IPAddress),
    Apps = make_set(AppDisplayName),
    SignInCount = count()
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1  // More than one country in the window
| extend
    LocationCount = array_length(Locations),
    IPCount = array_length(IPAddresses)
| project
    TimeGenerated,
    UserPrincipalName,
    Locations,
    LocationCount,
    IPAddresses,
    IPCount,
    Apps,
    SignInCount
| sort by LocationCount desc
```

---

## Sentinel Configuration

| Setting | Recommended Value |
|---|---|
| Run frequency | Every 15 minutes |
| Lookback window | Last 2 hours |
| Alert threshold | Greater than 0 results |
| Severity | High |
| Tactics | Initial Access, Credential Access |

---

## Tuning Notes

**Common false positives:**
- VPN usage (user appears in multiple countries)
- Shared/service accounts used by teams across regions
- Business travellers signing in via airport/hotel networks

**How to reduce noise:**
- Exclude known VPN exit node IPs
- Exclude service accounts: `| where UserPrincipalName !has "svc-"`
- Add a minimum distance threshold if your SIEM enriches with coordinates

**Escalation trigger:**
Always escalate if one of the locations is a known high-risk country for your organisation, or if the account has admin privileges.

---

## Triage Steps

1. **Contact the user** — confirm whether they are travelling or used a VPN
2. **Check the IP addresses** — query both in VirusTotal/AbuseIPDB; check ASN (VPN provider vs residential vs datacenter)
3. **Review what was accessed** — check AuditLogs for any sensitive data access, mail forwarding rules, or permission changes
   ```kql
   AuditLogs
   | where TimeGenerated > ago(2h)
   | where InitiatedBy has "<UserPrincipalName>"
   | project TimeGenerated, OperationName, TargetResources, Result
   ```
4. **Check for persistence** — look for new inbox rules, OAuth app consents, or new MFA methods added
5. **Contain if unconfirmed** — disable account, revoke sessions, force MFA re-registration
6. **Document and report** — timeline, evidence, actions taken

---

## References

- [MITRE ATT&CK T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [Microsoft — Investigate risky sign-ins](https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk)
- [Related: Rule 04 — Suspicious Azure Sign-In](04-suspicious-azure-signin.md)
- [IR Playbook: Suspicious Azure Sign-In](https://github.com/securityguidebook/ir-playbooks/blob/main/playbooks/suspicious-azure-signin.md)
