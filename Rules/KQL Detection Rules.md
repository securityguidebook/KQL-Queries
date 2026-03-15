# Rule 03 — After-Hours Interactive Logon Detection

## What This Detects
Successful interactive logons (LogonType 2) occurring outside of normal business hours (before 7am or after 7pm). Legitimate users occasionally log in after hours, but a pattern of after-hours access — especially from accounts that don't normally do this — warrants investigation.

**Why it matters:** Attackers who compromise credentials often operate from different time zones, or deliberately act after hours when security teams have reduced staffing.

## MITRE ATT&CK Mapping
| Field | Value |
|---|---|
| Tactic | TA0001 — Initial Access |
| Technique | T1078 — Valid Accounts |
| Sub-technique | T1078.002 — Domain Accounts |

## KQL Query
```kql
// After-Hours Interactive Logon Detection
// Builds on EventID 4624 (successful logon) but adds time-based anomaly detection
// Adjust business hours window to match your organisation (currently 07:00–19:00)

SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where AccountType == "User" and LogonType == 2
| extend HourOfDay = hourofday(TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated)
| extend IsAfterHours = iff(HourOfDay < 7 or HourOfDay > 19, true, false)
| extend IsWeekend = iff(DayOfWeek == 0d or DayOfWeek == 6d, true, false)
| where IsAfterHours == true or IsWeekend == true
| summarize
    LogonCount = count(),
    Computers = make_set(Computer),
    IPAddresses = make_set(IpAddress),
    LogonHours = make_set(HourOfDay),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Account, IsAfterHours, IsWeekend
| where LogonCount >= 1
| sort by LogonCount desc
```

## Tuning Notes
**Common false positives:**
- IT admins doing legitimate maintenance
- On-call staff responding to incidents
- Automated scheduled tasks running as user accounts

**How to reduce noise:**
```kql
// Exclude known admin accounts and service accounts
| where Account !in ("admin@domain.com", "svc-backup", "SYSTEM")
// Exclude accounts with a history of after-hours access (build a watchlist)
| where Account !in (AfterHoursWhitelist)
```

## Triage Steps
1. Identify the account — is it a user, admin, or service account?
2. Check if the user was on-call or approved to work after hours
3. Cross-reference the IP address — internal, VPN, or external?
4. Look for any sensitive data access or privilege escalation after the logon
5. Contact the user to confirm if the access was legitimate

## What a Finding Looks Like
- A standard user account logging in at 2am on a Saturday
- Multiple after-hours logons from the same account across different computers
- An account that has never logged in after hours suddenly doing so repeatedly

---

# Rule 04 — Multiple Failed Logons Followed by Success (Brute Force + Compromise)

## What This Detects
The most dangerous pattern in credential attacks: multiple failed logon attempts (EventID 4625) from the same account, followed by a successful logon (EventID 4624). Failed attempts alone are noisy — this rule focuses on the scenario where the attacker eventually succeeds.

**Why it matters:** This is the confirmation of a successful brute-force attack. By the time this fires, the account is likely compromised. Speed of response is critical.

## MITRE ATT&CK Mapping
| Field | Value |
|---|---|
| Tactic | TA0006 — Credential Access |
| Technique | T1110.001 — Brute Force: Password Guessing |

## KQL Query
```kql
// Brute Force Success — Failed Logons Followed by Successful Logon
// Correlates EventID 4625 (failure) and 4624 (success) for the same account
// within a 1-hour window

let FailedLogons = SecurityEvent
    | where TimeGenerated > ago(1h)
    | where EventID == 4625
    | where AccountType == "User"
    | summarize
        FailCount = count(),
        FailedIPs = make_set(IpAddress),
        FirstFail = min(TimeGenerated),
        LastFail = max(TimeGenerated)
        by TargetAccount, Computer;

let SuccessfulLogons = SecurityEvent
    | where TimeGenerated > ago(1h)
    | where EventID == 4624
    | where AccountType == "User" and LogonType == 2
    | summarize
        SuccessTime = min(TimeGenerated),
        SuccessIP = make_set(IpAddress)
        by TargetAccount, Computer;

FailedLogons
| join kind=inner SuccessfulLogons on TargetAccount, Computer
| where SuccessTime > LastFail
| where FailCount >= 3
| project
    TargetAccount,
    Computer,
    FailCount,
    FailedIPs,
    FirstFail,
    LastFail,
    SuccessTime,
    SuccessIP
| sort by FailCount desc
```

## Tuning Notes
**Adjust the failure threshold** based on your environment — 3 is sensitive, 10 is more conservative.

**Check if FailedIPs and SuccessIP match** — if the same IP failed then succeeded, it's almost certainly a brute-force. If the IPs differ, it may be a coincidence or a password spray followed by a different attacker succeeding.

## Triage Steps
1. **Immediately check what the account did after the successful logon** — file access, lateral movement, privilege changes
2. Disable the account if compromise is suspected — don't wait for confirmation
3. Reset the password and revoke all active sessions
4. Review the source IP in VirusTotal and AbuseIPDB
5. Escalate immediately — this is a confirmed credential attack with a successful outcome

---

# Rule 05 — New Local Administrator Account Created

## What This Detects
A new user account being added to the local Administrators group (EventID 4732 — member added to security-enabled local group). Creating a hidden admin account is one of the most common persistence techniques attackers use after gaining initial access.

**Why it matters:** If an attacker creates a local admin account, they maintain access even if the original compromised account's password is reset.

## MITRE ATT&CK Mapping
| Field | Value |
|---|---|
| Tactic | TA0003 — Persistence |
| Technique | T1136.001 — Create Account: Local Account |
| Also relevant | T1078.001 — Valid Accounts: Default Accounts |

## KQL Query
```kql
// New Member Added to Local Administrators Group
// EventID 4732 fires when a user is added to a security-enabled local group
// Filter for the Administrators group specifically

SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4732
| where TargetUserName == "Administrators"
| extend
    AddedAccount = MemberName,
    AddedBy = Account,
    AffectedComputer = Computer
| project
    TimeGenerated,
    AddedAccount,
    AddedBy,
    AffectedComputer,
    Activity
| sort by TimeGenerated desc
```

## Tuning Notes
**Legitimate scenarios:**
- IT provisioning a new admin workstation
- Helpdesk temporarily elevating a user for troubleshooting

**Red flags that should always escalate:**
- `AddedBy` is a standard user account (not IT admin)
- The new account name looks random or system-like (e.g., `svc_upd4te`, `win32host`)
- This happens outside business hours
- Multiple computers affected in a short window

## Triage Steps
1. Identify who added the account (`AddedBy`) — was it an IT admin?
2. Check if the new account (`AddedAccount`) is a known, legitimate account
3. If unknown — disable both the new account and the account that created it
4. Review all activity from `AddedBy` in the hour before this event fired
5. Check for other persistence mechanisms: scheduled tasks, registry run keys, new services

---

# Rule 06 — Repeated MFA Failures (MFA Fatigue Attack)

## What This Detects
Multiple MFA prompt failures for a single account in a short window. MFA fatigue (also called MFA push bombing) is when an attacker who has valid credentials sends repeated MFA push requests hoping the user will accidentally approve one.

**Why it matters:** This attack successfully compromised Uber in 2022 and has been used in numerous high-profile breaches. It requires valid credentials, so it often follows a successful phishing or credential stuffing attack.

## MITRE ATT&CK Mapping
| Field | Value |
|---|---|
| Tactic | TA0006 — Credential Access |
| Technique | T1621 — Multi-Factor Authentication Request Generation |

## KQL Query
```kql
// MFA Fatigue / Push Bombing Detection
// Detects repeated MFA failures for a single account within 10 minutes
// Requires Azure AD Sign-in logs ingested into Sentinel

SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 50074 or ResultType == 50076
    or ResultDescription has "MFA" and ResultType != 0
| summarize
    MFAFailures = count(),
    IPAddresses = make_set(IPAddress),
    Locations = make_set(Location),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    Apps = make_set(AppDisplayName)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where MFAFailures >= 3
| extend
    DurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt),
    UniqueLocations = array_length(Locations)
| sort by MFAFailures desc
```

## Tuning Notes
**Legitimate causes:** User genuinely trying to log in and having issues with their authenticator app.

**True attack indicators:**
- MFAFailures > 10 in a short window
- IPAddress is foreign or unfamiliar
- Attempts happening at 2am-5am (attacker in a different timezone)
- Followed shortly after by a successful sign-in

## Triage Steps
1. Contact the user immediately — "Are you trying to sign in right now?"
2. If they say no → account credentials are compromised, begin incident response
3. If they say yes but are confused by repeated prompts → attacker has their credentials
4. Temporarily block sign-ins for the account: Azure AD → User → Block sign-in
5. Force password reset and MFA re-registration from a trusted device
6. Review sign-in logs for any successful authentications between the failures

---

# Rule 07 — Suspicious PowerShell Execution

## What This Detects
PowerShell commands containing patterns commonly used in malicious scripts: encoded commands, download cradles (downloading and executing code from the internet), or attempts to bypass execution policy. PowerShell is the most commonly abused tool in post-exploitation because it's built into every Windows machine.

**Why it matters:** Ransomware, credential dumping tools, and C2 frameworks almost all use PowerShell at some stage. Detecting suspicious PowerShell early can stop an attack before it progresses to data exfiltration or encryption.

## MITRE ATT&CK Mapping
| Field | Value |
|---|---|
| Tactic | TA0002 — Execution |
| Technique | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Also relevant | T1027 — Obfuscated Files or Information |

## KQL Query
```kql
// Suspicious PowerShell Execution
// Detects encoded commands, download cradles, and execution policy bypasses
// Requires Security Events or Sysmon logs with process creation (EventID 4688 or Sysmon 1)

SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688  // Process creation
| where Process has "powershell" or Process has "pwsh"
| extend CommandLine = CommandLine
| where CommandLine has_any (
    "-EncodedCommand",    // Obfuscated/encoded payload
    "-enc ",              // Short form of EncodedCommand
    "-e ",                // Even shorter form
    "IEX",                // Invoke-Expression — executes strings as code
    "Invoke-Expression",
    "DownloadString",     // Downloads and executes from URL
    "WebClient",          // Network download
    "bypass",             // Execution policy bypass
    "hidden",             // Runs hidden from user
    "FromBase64String",   // Base64 decoding — obfuscation indicator
    "Net.WebClient"
    )
| project
    TimeGenerated,
    Account,
    Computer,
    Process,
    CommandLine,
    ParentProcessName
| sort by TimeGenerated desc
```

## Tuning Notes
**Legitimate tools that trigger this:**
- Chocolatey package manager uses `DownloadString`
- Some legitimate admin scripts use `-EncodedCommand`
- Microsoft endpoint management tools

**Add exceptions for known-good scripts:**
```kql
| where CommandLine !has "chocolatey"
| where CommandLine !has "WindowsUpdate"
| where Account !in ("svc-patching", "SYSTEM")
```

**Escalate immediately if:** `-EncodedCommand` is used AND the base64 decoded content contains URLs, or if `IEX` is combined with `WebClient` (classic download cradle).

## Triage Steps
1. Decode any base64 encoded commands — use CyberChef (https://gchq.github.io/CyberChef/)
2. Check the parent process — was PowerShell launched by Word, Excel, or a browser? That's a red flag for a macro or drive-by attack
3. Check for outbound network connections from that host at the same time
4. Isolate the host if you find a download cradle connecting to an unknown URL
5. Pull the full process tree — what did PowerShell spawn after it ran?

---

# Rule 08 — Azure Resource Mass Deletion

## What This Detects
A high volume of Azure resource deletions by a single identity within a short timeframe. Attackers who gain access to cloud environments sometimes attempt to destroy resources either for extortion (pay or lose your data) or to cover their tracks.

**Why it matters:** Resource deletion in Azure can be permanent. Even with soft-delete enabled on some services, recovery is time-consuming and not always complete. This needs to be caught and stopped fast.

## MITRE ATT&CK Mapping
| Field | Value |
|---|---|
| Tactic | TA0040 — Impact |
| Technique | T1485 — Data Destruction |

## KQL Query
```kql
// Azure Resource Mass Deletion Detection
// Detects a single identity deleting multiple resources within 15 minutes
// Requires Azure Activity Logs ingested into Sentinel

AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "delete" or OperationNameValue has "Delete"
| where ActivityStatusValue == "Success"
| where CategoryValue == "Administrative"
| summarize
    DeletionCount = count(),
    DeletedResources = make_set(Resource),
    ResourceTypes = make_set(ResourceProviderValue),
    FirstDeletion = min(TimeGenerated),
    LastDeletion = max(TimeGenerated)
    by Caller, SubscriptionId, bin(TimeGenerated, 15m)
| where DeletionCount >= 5
| extend DurationMinutes = datetime_diff('minute', LastDeletion, FirstDeletion)
| sort by DeletionCount desc
```

## Tuning Notes
**Legitimate scenarios:**
- DevOps teardown of a test environment
- Decommissioning of old resources
- Automated pipeline cleanup

**How to reduce noise:**
```kql
// Exclude known automation service principals
| where Caller !has "terraform"
| where Caller !has "pipeline"
// Scope to production subscriptions only via a watchlist
| where SubscriptionId in (ProductionSubscriptions)
```

**Always escalate if:** Production resources are being deleted, or if the `Caller` identity has never deleted resources before.

## Triage Steps
1. Identify the `Caller` — is it a human user, service principal, or automation account?
2. Check if there is a legitimate change request or pipeline run that matches the timing
3. If no change request exists — **immediately revoke the Caller's access** and escalate
4. Check Azure Activity Log for what else the Caller did in the preceding hour (recon, data access)
5. Initiate recovery from backup or soft-delete where available
6. Review if any secrets, keys, or storage accounts were accessed before deletion (possible exfil before destruction)

---

# Rule 09 — Service Account Logon from Unusual Location

## What This Detects
A service account (typically used only for automated processes from known internal IPs) signing in from an unexpected location or IP range. Service accounts rarely travel — if one suddenly appears in a new country or from a cloud IP, something is wrong.

**Why it matters:** Service accounts are high-value targets. They often have elevated permissions, don't have MFA enforced, and their logins are rarely monitored. Attackers who compromise a service account can move laterally with little friction.

## MITRE ATT&CK Mapping
| Field | Value |
|---|---|
| Tactic | TA0001 — Initial Access |
| Technique | T1078.002 — Valid Accounts: Domain Accounts |

## KQL Query
```kql
// Service Account Logon from Unusual Location
// Builds a baseline of known IPs for service accounts then alerts on deviation
// Requires Azure AD SigninLogs

// Step 1: Build baseline of known service account IPs (last 30 days)
let KnownServiceAccountIPs = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where UserPrincipalName has "svc-" or UserPrincipalName has "-svc"
        or UserPrincipalName has "service" or UserPrincipalName has "automation"
    | summarize KnownIPs = make_set(IPAddress) by UserPrincipalName;

// Step 2: Find recent logons from IPs not in the baseline
SigninLogs
| where TimeGenerated > ago(1d)
| where UserPrincipalName has "svc-" or UserPrincipalName has "-svc"
    or UserPrincipalName has "service" or UserPrincipalName has "automation"
| where ResultType == 0  // Successful only
| join kind=leftouter KnownServiceAccountIPs on UserPrincipalName
| where array_length(set_difference(pack_array(IPAddress), KnownIPs)) > 0
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    KnownIPs
| sort by TimeGenerated desc
```

## Tuning Notes
Tune the service account naming convention (`svc-`, `-svc`, `service`, `automation`) to match your organisation's actual naming standard. The better your naming convention, the more accurate this rule is.

## Triage Steps
1. Identify the service account and what system/application it belongs to
2. Check whether the application was recently moved to a new host or cloud environment
3. If no legitimate explanation — disable the service account immediately and rotate its credentials
4. Investigate what the account accessed after the unusual logon

---

# Rule 10 — Outbound Data Volume Anomaly (Potential Exfiltration)

## What This Detects
A single host generating significantly more outbound network traffic than its historical baseline — a potential indicator of data exfiltration. Attackers who have compromised a system will often stage and transfer large volumes of data before deploying ransomware or as the goal of the attack itself.

**Why it matters:** Data exfiltration is often the most damaging part of a breach. Detecting it before it completes — or catching it happening — limits the business impact significantly.

## MITRE ATT&CK Mapping
| Field | Value |
|---|---|
| Tactic | TA0010 — Exfiltration |
| Technique | T1041 — Exfiltration Over C2 Channel |
| Also relevant | T1048 — Exfiltration Over Alternative Protocol |

## KQL Query
```kql
// Outbound Data Volume Anomaly
// Compares current hour outbound traffic to 7-day hourly average
// Requires network flow logs (Azure NSG Flow Logs or equivalent)

let BaselinePeriod = 7d;
let DetectionWindow = 1h;
let AnomalyThresholdMultiplier = 3;  // Alert if current > 3x the average

// Build 7-day baseline
let Baseline = AzureNetworkAnalytics_CL
    | where TimeGenerated between (ago(BaselinePeriod) .. ago(DetectionWindow))
    | where FlowDirection_s == "O"  // Outbound
    | summarize
        AvgHourlyBytes = avg(BytesSentInFlow_d),
        StdDevBytes = stdev(BytesSentInFlow_d)
        by VM1_s;

// Check current window
let CurrentTraffic = AzureNetworkAnalytics_CL
    | where TimeGenerated > ago(DetectionWindow)
    | where FlowDirection_s == "O"
    | summarize
        CurrentBytes = sum(BytesSentInFlow_d),
        DestinationIPs = make_set(PublicIPs_s)
        by VM1_s;

// Join and find anomalies
CurrentTraffic
| join kind=inner Baseline on VM1_s
| extend AnomalyScore = CurrentBytes / AvgHourlyBytes
| where AnomalyScore > AnomalyThresholdMultiplier
| project
    VM1_s,
    CurrentBytes,
    AvgHourlyBytes,
    AnomalyScore,
    DestinationIPs
| sort by AnomalyScore desc
```

## Tuning Notes
**Adjust `AnomalyThresholdMultiplier`** based on your environment — 3x is a starting point. Some environments with variable workloads may need 5x or 10x to avoid excessive noise.

**Common false positives:**
- Scheduled backups to cloud storage
- Software update distribution
- End-of-month reporting processes

## Triage Steps
1. Identify the destination IPs — are they known backup/cloud services or unknown?
2. Check what process on the host is generating the traffic (endpoint agent or process creation logs)
3. If destination is unknown — isolate the host immediately
4. Check for signs of prior compromise on the host: new processes, scheduled tasks, PowerShell activity
5. Preserve memory and disk image before remediation if possible — evidence for forensics
