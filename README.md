# Enhancing Security with KQL: Understanding Successful User Logins and Logon Types
<br />
<br />


The KQL query below selects data from the SecurityEvent table in Azure Sentinel, where the EventID is equal to 4624, and the AccountType is equal to "User" and the LogonType is equal to 2. The query then projects this results in an easy to read table that displays ``TimeGenerated``, ``Account``, ``Computer``, ``LogonType``, and ``IpAddress`` columns.

```
SecurityEvent
| where EventID == 4624
| where AccountType == "User" and LogonType == 2
| project TimeGenerated, Account, Computer, LogonType, IpAddress
```
<br />

<h2> The results of this query should look like this if you have any successful login attempts: </h2>

![QUERY](https://user-images.githubusercontent.com/132176058/236953792-738232b0-3a97-418d-8b96-c68322ec0fa4.png)

<br />
<br />


This query can be used to detect and investigate successful interactive logon events in Windows systems. Specifically, it filters for successful logon events that are performed by users interactively (LogonType 2) rather than via a service account (LogonType 5) or batch job (LogonType 4).

The resulting data can help security analysts identify and investigate potential security incidents, such as unauthorized access or account compromise. By analyzing the ``Account`` and ``Computer`` fields, it is possible to determine which user logged into which machine, which can be valuable for identifying suspicious or anomalous behavior.

Furthermore, by analyzing the ```TimeGenerated``` and ```IPAddress``` fields, SOC analysts can detect potential patterns or trends in logon events that can help identify potential attacks or malicious activity. A good example of this would be if multiple successful logon events from the same IP address in a short period of time are discovered, this could indicate a brute-force attack.

In conclusion, this KQL query can be used as part of a larger cybersecurity monitoring strategy to detect and investigate successful logon events in Windows systems. It can help organizations identify and respond to potential security incidents, and ultimately strengthen their overall security posture.
