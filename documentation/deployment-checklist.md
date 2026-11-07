# Microsoft Sentinel Deployment Checklist

Use this checklist only after the detection has been reviewed and tested. Deployment must follow organizational change-management requirements.

## A. Data and query validation

- [ ] Confirm `SigninLogs` ingestion and retention.
- [ ] Confirm required columns are populated.
- [ ] Review result-code distribution and descriptions.
- [ ] Validate the candidate failure-code list against tenant telemetry and current Microsoft documentation.
- [ ] Run the query over representative historical data.
- [ ] Check query performance and expected cost.
- [ ] Review missing IP/account fields.

## B. Detection and test validation

- [ ] Review detection objective and grouping key.
- [ ] Run positive synthetic tests.
- [ ] Run negative synthetic tests.
- [ ] Test events around fixed time-bucket boundaries.
- [ ] Test VPN, NAT, proxy and service-account scenarios.
- [ ] Review possible overlap between the three rules.
- [ ] Document threshold rationale and known blind spots.
- [ ] Obtain peer review.

## C. Analytics rule configuration

- [ ] Configure rule name and clear description.
- [ ] Set severity based on organizational risk.
- [ ] Set MITRE ATT&CK mapping based on observed behavior.
- [ ] Configure query frequency.
- [ ] Configure query lookback period.
- [ ] Review overlapping execution behavior.
- [ ] Configure alert threshold and event grouping as appropriate.
- [ ] Configure incident creation.
- [ ] Configure alert grouping based on investigation needs.
- [ ] Evaluate suppression separately; document the risk of hiding new activity.
- [ ] Add analyst instructions and investigation link/runbook.

## D. Entity mapping

- [ ] Map `IPAddress` to the supported IP Address entity identifier.
- [ ] Map `UserPrincipalName` to an appropriate supported Account identifier.
- [ ] Verify mappings in a generated alert.
- [ ] Confirm multi-value IP/account output behaves as expected for distributed and spraying alerts.

## E. Deployment

- [ ] Deploy first in a lab/non-production workspace where possible.
- [ ] Obtain required approval.
- [ ] Record rule version, owner and deployment time.
- [ ] Enable the rule.
- [ ] Verify alerts and incidents are created.
- [ ] Verify entity mappings and alert grouping.
- [ ] Capture sanitized screenshots and test output.

## F. Monitoring and rollback

- [ ] Monitor alert volume and analyst disposition.
- [ ] Review false positives and potential false negatives.
- [ ] Check repeated alerts from overlapping lookback windows.
- [ ] Review query failures and ingestion delays.
- [ ] Define owner and review cadence.
- [ ] Document rollback/disable procedure.
- [ ] Confirm escalation path if alert volume or query cost becomes abnormal.

## Example lab scheduling starting point

A five-minute frequency with a ten-minute lookback may be useful for a lab exercise, but it is not a universal recommendation. Test duplicate matches, event latency, ingestion delays and suppression behavior before adopting any schedule.

## Rollback

If the rule behaves incorrectly:
1. Notify the designated owner and SOC according to change procedure.
2. Disable or revert the rule using approved Sentinel permissions.
3. Preserve query version, alert samples and diagnostics.
4. Determine the cause.
5. Fix and regression-test in a lab.
6. Re-deploy only after review and approval.
