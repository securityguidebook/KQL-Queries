# Rule 01 — SSH Brute Force Detection

## Description

Detects repeated failed SSH authentication attempts from a single source IP within a short time window — a strong indicator of an automated brute-force or credential stuffing attack.

This is one of the most common alerts in any SOC environment. The rule is intentionally simple — its value is in the **tuning** and **triage process**, not just the detection.

**Why it matters:** SSH brute-force is often a precursor to lateral movement. Even failed attempts are worth investigating if they originate from unexpected sources or target privileged accounts.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | TA0006 — Credential Access |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.001 — Password Guessing |

---

## KQL Query

```kql
// SSH Brute Force Detection
// Detects 5+ failed SSH logins from a single IP within 10 minutes
// Adjust threshold and window to match your environment's baseline

Syslog
| where TimeGenerated > ago(10m)
| where Facility == "auth"
| where SyslogMessage has "Failed password" or SyslogMessage has "Invalid user"
| extend SourceIP = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| extend TargetUser = extract(@"for (invalid user )?(\S+) from", 2, SyslogMessage)
| where isnotempty(SourceIP)
| summarize
    FailedAttempts = count(),
    TargetAccounts = make_set(TargetUser),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by SourceIP, Computer
| where FailedAttempts >= 5
| extend TimespanMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
| project
    Computer,
    SourceIP,
    FailedAttempts,
    TargetAccounts,
    FirstAttempt,
    LastAttempt,
    TimespanMinutes
| sort by FailedAttempts desc
```

---

## Sentinel Configuration

| Setting | Recommended Value |
|---|---|
| Run frequency | Every 5 minutes |
| Lookback window | Last 10 minutes |
| Alert threshold | Greater than 0 results |
| Severity | Medium |
| Tactics | Credential Access |

---

## Tuning Notes

**Common false positives:**
- Legitimate automated scripts with misconfigured credentials
- IT admin accounts after password rotation
- Monitoring tools that use SSH health checks

**How to reduce noise:**
- Add a whitelist for known internal IPs: `| where SourceIP !in ("10.0.0.1", "10.0.0.2")`
- Increase threshold to 10+ if environment is noisy
- Scope to external IPs only: `| where SourceIP !startswith "10." and SourceIP !startswith "192.168."`

**Escalation trigger:**
Escalate immediately if `TargetAccounts` contains `root`, `admin`, or any service account name.

---

## Triage Steps

When this alert fires:

1. **Check source IP reputation** — query it in VirusTotal or AbuseIPDB
2. **Review target accounts** — are they real accounts? Privileged?
3. **Check for successful login** — did any attempt succeed after the failures?
   ```kql
   Syslog
   | where SyslogMessage has "Accepted password" or SyslogMessage has "Accepted publickey"
   | where SyslogMessage has "<SOURCE_IP>"
   | where TimeGenerated > ago(1h)
   ```
4. **Check lateral movement** — did the source IP connect to other internal hosts?
5. **Contain if needed** — block source IP at perimeter firewall, isolate host if compromise confirmed
6. **Document** — log findings in your incident ticket with timeline and evidence

---

## References

- [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [Related: Rule 05 — New Admin Account Created](05-new-admin-account.md)
- [IR Playbook: SSH Brute Force Response](https://github.com/securityguidebook/ir-playbooks/blob/main/playbooks/ssh-brute-force.md)
