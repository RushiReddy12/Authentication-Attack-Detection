# SOC Analyst Investigation Runbook

## Alert types

- Single-source brute-force candidate
- Distributed brute-force candidate
- Password-spraying candidate

These alerts identify behavior for investigation. They do not prove malicious intent or compromise.

## 1. Initial triage

Record:
- Alert and incident identifiers.
- Detection name and severity.
- First seen and last seen.
- Target account(s).
- Source IP address(es).
- Failure count and result codes.
- Applications and client types.

Confirm the query time range and whether events are duplicated across overlapping rule executions.

## 2. Validate sign-in outcomes

Review `ResultType` and `ResultDescription` for each event. Confirm that the event represents the failure behavior intended by the detection. Nonzero outcomes are not all incorrect-password events.

## 3. Investigate the source

- Determine whether the IP is known corporate egress, VPN, proxy, hosting or consumer ISP.
- Use approved threat-intelligence and network-ownership sources.
- Check whether the same IP targeted other accounts.
- Check whether multiple IPs targeted the same account.
- Treat reputation as one signal, not a verdict.

## 4. Investigate the account

- Review recent successful and unsuccessful sign-ins.
- Check whether a success occurred after the failure sequence.
- Review application, device, location, client, MFA and Conditional Access context.
- Validate expected travel, remote work, automation or service-account activity through approved channels.

## 5. Pattern-specific questions

### Single-source brute force
- Did one IP repeatedly target one account?
- Are attempts concentrated in one bucket or split across buckets?
- Is the source expected infrastructure?

### Distributed brute force
- Did multiple distinct IPs target the same account?
- Are the IPs related to a known VPN/proxy or distributed infrastructure?
- Did any successful sign-in follow the failures?

### Password spraying
- Did one source target many distinct accounts?
- Are the accounts in a related population?
- Are failures low per account but high across the population?
- Could the source be a shared authentication gateway?

## 6. Investigation query

Replace the example values with values from the alert. `203.0.113.10` is a documentation-only IP range.

```kql
let SourceIP = "203.0.113.10";
let TargetUser = "alex@lab.invalid";
SigninLogs
| where TimeGenerated >= ago(24h)
| where IPAddress == SourceIP
| where UserPrincipalName == TargetUser
| project TimeGenerated, UserPrincipalName, IPAddress,
          ResultType, ResultDescription, AppDisplayName,
          Location, ClientAppUsed, ConditionalAccessStatus
| order by TimeGenerated desc
| take 200
```

## 7. Decision and escalation

Use the organization's approved severity and response matrix:
- Expected/benign: document supporting evidence and close per procedure.
- Suspicious: preserve evidence and escalate for further review.
- Likely malicious: follow incident-response procedures and obtain required approvals for containment.
- Inconclusive: document gaps and seek additional telemetry or owner validation.

Do not disable accounts, block IPs or revoke sessions solely because this query matched. Follow authorized response procedures.

## 8. Closure notes

Document:
- What happened and when.
- Accounts, IPs and applications involved.
- Result codes and event evidence.
- Whether successful sign-ins followed failures.
- Analyst assessment and confidence.
- Actions, approvals and follow-up work.
- Whether a detection tuning request is warranted.
