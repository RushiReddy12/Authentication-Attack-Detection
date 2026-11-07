# Detection Specification

## 1. Objective

Identify suspicious authentication behavior that may be consistent with brute force or password spraying using Microsoft Entra ID sign-in telemetry in Microsoft Sentinel.

## 2. Data source

| Attribute | Value |
|---|---|
| Workspace table | `SigninLogs` |
| Identity provider | Microsoft Entra ID |
| Time field | `TimeGenerated` |
| Account field | `UserPrincipalName` |
| Source field | `IPAddress` |
| Outcome field | `ResultType` |
| Context fields | `ResultDescription`, `AppDisplayName`, `Location`, `ClientAppUsed`, `ConditionalAccessStatus` |

Confirm that the table and fields are populated in the target workspace.

## 3. Result-code validation

The example rules use `ResultType == "50126"` as a candidate invalid-credential filter. This is a starting hypothesis, not a universal rule.

Before deployment:
1. Review the distribution of `ResultType` and `ResultDescription`.
2. Sample raw events for each frequent code.
3. Confirm meanings against current Microsoft Entra sign-in error documentation.
4. Decide which codes are appropriate for the behavior being detected.
5. Document exclusions and the coverage risk they introduce.

Do not equate every nonzero `ResultType` with an incorrect password.

### Initial data validation

```kql
SigninLogs
| where TimeGenerated >= ago(7d)
| summarize Events=count() by ResultType, ResultDescription
| order by Events desc
```

### Raw event review

```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| project TimeGenerated, UserPrincipalName, IPAddress,
          ResultType, ResultDescription, AppDisplayName,
          Location, ClientAppUsed, ConditionalAccessStatus
| order by TimeGenerated desc
| take 100
```

## 4. Detection definitions

### A. Single-source brute-force candidate

- Group by source IP, account and fixed five-minute bucket.
- Count candidate credential failures.
- Trigger when count is at least five.
- Intent: identify repeated failures from one source against one account.

### B. Distributed brute-force candidate

- Group by account and fixed five-minute bucket.
- Count candidate credential failures and distinct source IPs.
- Trigger when failures are at least five and source IP count is at least two.
- Intent: identify activity spread across multiple sources against one account.

### C. Password-spraying candidate

- Group by source IP and fixed five-minute bucket.
- Count candidate credential failures and distinct accounts.
- Trigger when failures are at least five and targeted account count is at least five.
- Intent: identify one source attempting authentication against many accounts.

## 5. Thresholds

All thresholds are illustrative lab values. Use historical tenant data, representative test cases and analyst feedback to tune them. See `threshold-tuning.md`.

## 6. Time semantics

`bin(TimeGenerated, 5m)` creates fixed, clock-aligned buckets. It does not implement a sliding five-minute window. Events near a bucket boundary may be split. Consider adjacent-bucket analysis, sliding-window techniques or a different schedule if low-latency boundary behavior matters.

## 7. Alert fields and entity mapping

Recommended output:
- Account: `UserPrincipalName`
- IP: `IPAddress`
- Time: latest event (`LastSeen`)
- Context: attempt count, first/last seen, source IP list or targeted account list.

In Sentinel analytics rule entity mapping, map the query output to supported Account and IP identifiers. For example, map `IPAddress` to IP Address/Address. Select Account identifiers supported by the workspace and query fields; validate the mapping in a generated alert.

## 8. Severity and response

Set severity based on organizational risk and confidence, not only event count. These detections should initially create investigation candidates. Do not automate containment without validated confidence, safeguards and approval.

## 9. MITRE ATT&CK

Potential mapping:
- T1110 Brute Force.
- T1110.001 Password Guessing when the behavior supports it.
- T1110.003 Password Spraying for spraying behavior.

Do not assign sub-techniques solely from a generic failure burst. Confirm the observed behavior.

## 10. Limitations

- Sign-in logs do not reveal the password submitted.
- Shared egress, VPNs, proxies and NAT can affect source-IP interpretation.
- Fixed time buckets can split activity.
- A one-IP spraying query does not detect all distributed spraying.
- A successful sign-in after failures is a lead, not proof of compromise.
- Synthetic tests are not a substitute for tenant validation.
