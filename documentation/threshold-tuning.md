# Threshold Tuning Methodology

## Goal

Choose thresholds that provide useful detection coverage while keeping alert volume and analyst workload manageable.

## Starting lab values

| Detection | Time bucket | Attempt threshold | Diversity threshold |
|---|---:|---:|---:|
| Single-source brute force | 5 min | >= 5 failures | One IP + one account group |
| Distributed brute force | 5 min | >= 5 failures | >= 2 distinct IPs |
| Password spraying | 5 min | >= 5 failures | >= 5 distinct accounts |

These values are teaching examples, not recommended universal production thresholds.

## Tuning workflow

1. Establish data quality and event-code coverage.
2. Run broad discovery queries over a representative historical period.
3. Sample candidate groups at multiple thresholds.
4. Classify samples with analyst/domain-owner input:
   - Confirmed malicious
   - Suspicious
   - Expected/benign
   - Inconclusive
5. Compare alert volume and detection coverage at each candidate threshold.
6. Review missed or near-threshold cases.
7. Test time-boundary, VPN, proxy, service-account and shared-IP scenarios.
8. Select a threshold with documented rationale.
9. Re-run regression tests.
10. Monitor after deployment and schedule periodic review.

## Example threshold exploration: single-source

```kql
SigninLogs
| where TimeGenerated >= ago(7d)
| where ResultType == "50126" // Validate code for your tenant first.
| where isnotempty(IPAddress) and isnotempty(UserPrincipalName)
| summarize FailedAttempts=count()
    by IPAddress, UserPrincipalName, bin(TimeGenerated, 5m)
| summarize
    GroupsAt3=countif(FailedAttempts >= 3),
    GroupsAt5=countif(FailedAttempts >= 5),
    GroupsAt10=countif(FailedAttempts >= 10),
    GroupsAt15=countif(FailedAttempts >= 15)
```

This reports candidate group counts, not confirmed attacks or unique incidents.

## Precision and recall

If reliable labeled data is available:

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- False-positive rate = FP / (FP + TN)

Where:
- TP: malicious cases correctly detected.
- FP: benign cases incorrectly detected.
- FN: malicious cases missed.
- TN: benign cases correctly not detected.

Do not calculate meaningful precision or recall from unlabeled sign-in events alone. Candidate counts are not ground truth.

## Threshold trade-offs

- Raising a threshold may reduce false positives but increase false negatives.
- Lowering a threshold may improve sensitivity but increase alert volume.
- Adding a restrictive result-code filter may reduce noise but miss attacks using other relevant outcomes.
- Adding exclusions can hide attacker activity if the excluded infrastructure is compromised or abused.

## Required tuning record

For each change, record:
- Rule version and date.
- Previous and new threshold.
- Sample period and sample size.
- Number of alerts/candidate groups.
- Analyst classifications and evidence.
- Expected false-positive and false-negative impact.
- Regression test results.
- Approver and rollback plan.
