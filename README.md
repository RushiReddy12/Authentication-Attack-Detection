# Authentication Attack Detection — Microsoft Sentinel & KQL

A portfolio project demonstrating the Detection Engineering lifecycle for three authentication attack patterns using Microsoft Sentinel and Microsoft Entra ID sign-in logs.

## Project status

**Lab implementation and synthetic test harnesses:** Included  
**Production validation in a live tenant:** Not yet claimed  
**Deployment:** Requires tenant-specific validation, review and change approval

This project is designed to demonstrate how to develop, test, tune, operationalize and document detections—not merely write KQL queries.

## Detection coverage

| Detection | Behavior | Primary grouping |
|---|---|---|
| Single-source brute force | Repeated failed sign-ins from one IP against one account | IP + account + time bucket |
| Distributed brute force | Multiple IPs generating failures against one account | Account + time bucket |
| Password spraying candidate | One IP generating failures across multiple accounts | IP + time bucket |

These are behavioral candidates, not proof of malicious activity or account compromise.

## Repository structure

```text
Authentication-Attack-Detection/
│
├── README.md
│
├── detections/
│   ├── single-source-bruteforce.kql
│   ├── distributed-bruteforce.kql
│   └── password-spraying.kql
│
├── tests/
│   ├── single-source-tests.kql
│   ├── distributed-tests.kql
│   └── password-spraying-tests.kql
│
├── documentation/
│   ├── detection-specification.md
│   ├── threshold-tuning.md
│   ├── false-positive-analysis.md
│   ├── investigation-runbook.md
│   └── deployment-checklist.md
│
└── evidence/
    ├── test-results/
    └── sentinel-alert-screenshots/
```

## Architecture

```text
Microsoft Entra ID Sign-in Logs (SigninLogs)
                    |
                    v
       Validate fields and result codes
                    |
          +---------+---------+
          |         |         |
          v         v         v
      Single-    Distributed  Password
      source     brute force  spraying
      brute force
          |         |         |
          +---------+---------+
                    |
                    v
      Sentinel analytics rule alerts
                    |
                    v
       Account/IP entity mapping
                    |
                    v
      Incident grouping and SOC runbook
```

## Data source and assumptions

- Table: `SigninLogs`
- Important fields: `TimeGenerated`, `ResultType`, `ResultDescription`, `IPAddress`, `UserPrincipalName`, `AppDisplayName`, `Location`, `ClientAppUsed`, `ConditionalAccessStatus`.
- The example queries use `ResultType == "50126"` as an illustrative invalid-credential candidate. **Do not assume this is the complete or correct failure-code set for every tenant.** Review actual events and current Microsoft documentation before deployment.
- `ResultType != "0"` is broader than invalid-password failures. Nonzero outcomes can include interruptions and other authentication outcomes.
- The example thresholds (5 events, 5 minutes; spraying threshold of 5 accounts) are lab values, not universal recommendations.
- Fixed `bin(TimeGenerated, 5m)` buckets are clock-aligned. They are not sliding windows and can split activity across adjacent buckets.
- `dcount()` is an approximate distinct count. If exact counts are essential for a small test dataset, consider `count_distinct()` where supported by the workspace's KQL environment.

## Quick start

1. Open Microsoft Sentinel Logs in a lab workspace with `SigninLogs` data.
2. Run the data-validation queries in `documentation/detection-specification.md`.
3. Review and validate the failure-code filter for your tenant.
4. Run each query in `detections/`.
5. Run each synthetic test harness in `tests/`. These use `datatable()` and do not require live sign-in events.
6. Review the test output and document results under `evidence/test-results/`.
7. Configure analytics rules only after review, testing, approval and tuning.
8. Follow `documentation/deployment-checklist.md` and `documentation/investigation-runbook.md`.

## Synthetic test coverage

The test harnesses include positive and negative cases such as:
- Threshold met versus below threshold.
- One source versus multiple sources.
- One account versus multiple accounts.
- Successful sign-ins excluded from failed-credential candidates.
- Activity split across adjacent time buckets.

Synthetic tests prove only the behavior exercised by the test cases. They do not prove real-world detection coverage, performance, or production readiness.

## Operationalization guidance

For each scheduled analytics rule, review:
- Query frequency and lookback period.
- Overlapping executions and repeated matches.
- Alert grouping and incident creation.
- Suppression behavior and the risk of hiding new activity.
- Account and IP entity mappings.
- Severity, description, tactics/techniques and analyst instructions.
- Cost, query performance and data availability.

Do not automatically block IPs or disable accounts based solely on these candidate detections. Response actions must follow the organization's incident-response policy and approval process.

## MITRE ATT&CK mapping

- **T1110 — Brute Force**: broad mapping for relevant brute-force behavior.
- **T1110.001 — Password Guessing**: may be appropriate for repeated password guesses against an account.
- **T1110.003 — Password Spraying**: use when the observed behavior supports spraying.
- **T1110.004 — Credential Stuffing**: do not map automatically; requires evidence consistent with reused credential pairs.

Validate technique mapping against the actual behavior and current ATT&CK knowledge base.

## Known limitations

1. Result-code filtering may omit relevant attack activity or include benign outcomes.
2. Fixed time buckets can split events at bucket boundaries.
3. NAT, VPNs, proxies and shared egress can make one IP represent many users.
4. Distributed activity may use more than one account or be spread across longer periods.
5. Password-spraying behavior can be distributed across several source IPs; this simple rule focuses on one IP per time bucket.
6. `SigninLogs` does not expose the password submitted by the user.
7. A matching successful sign-in after failures is a clue for investigation, not proof of compromise.
8. Synthetic test data does not model every tenant-specific condition.

## Suggested evidence to add before publishing

- Screenshots of each query running in Sentinel (remove tenant names, email addresses, IPs and other sensitive data).
- Screenshots or exported output of synthetic test harnesses showing expected PASS results.
- Example alert and incident with sanitized Account/IP entities.
- A short tuning report with sample size, threshold comparison, false-positive findings and known blind spots.
- A change record or deployment note from an authorized lab environment.

Do not publish real user identifiers, tenant IDs, internal IP information, tokens, secrets or unredacted security telemetry.

## Interview talking points

Be prepared to explain:
1. Why the three behaviors require different grouping keys.
2. Why a nonzero `ResultType` is not synonymous with an incorrect password.
3. How thresholds were selected and what trade-offs they create.
4. How positive and negative test cases validate expected behavior.
5. How overlapping query windows can create repeated matches.
6. How Account and IP entities improve investigation.
7. How alert grouping differs from suppression.
8. How you would measure precision/recall if reliable labeled data were available.
9. How you would deploy, monitor, tune and roll back a rule.

## Disclaimer

This is an educational portfolio project. It is not a guarantee of detection, a substitute for a security review, or a ready-to-deploy production content pack. Validate KQL compatibility, schema, result codes, thresholds, analytics-rule behavior and response procedures in your own environment.
