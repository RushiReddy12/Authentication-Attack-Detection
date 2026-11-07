# False-Positive and False-Negative Analysis

## Purpose

Document likely benign patterns, detection blind spots and the evidence required before changing detection logic.

## Potential false-positive sources

| Pattern | Why it may alert | Investigation |
|---|---|---|
| Corporate VPN/shared egress | Many users appear from one IP | Confirm VPN ownership, user population and expected use |
| NAT/proxy | Several users share an address | Check proxy logs and identity context |
| User mistyping password | Repeated failures against one account | Contact user through approved process; inspect device and timing |
| Stale credentials in applications | Repeated authentication failures | Identify application, client and account type |
| Service account configuration issue | Automated repeated failures | Validate owner, workload and change history |
| MFA/Conditional Access interruptions | Non-success results may not mean wrong password | Inspect result code, description and CA/MFA details |

## Potential false-negative sources

| Blind spot | Why it may be missed | Possible improvement |
|---|---|---|
| Failure code not in candidate list | Rule filters it out | Validate code coverage and update filter |
| Activity split across 5-minute buckets | No individual bucket reaches threshold | Evaluate adjacent buckets or sliding windows |
| Low-and-slow activity | Threshold not reached quickly | Longer-window behavioral analytics and baselining |
| Distributed spraying | Simple spraying rule groups by one IP | Add account/IP graph or cross-source aggregation |
| Many IPs below per-account threshold | Single-source rule sees small groups | Use distributed detection and correlation |
| Missing IP/account fields | Events are filtered out | Measure missing-field rates and alternative telemetry |

## Analysis procedure

For each alert:
1. Preserve the raw event set and time range.
2. Verify the result code and description.
3. Identify the account, source, application and client.
4. Check successful events before and after the failures.
5. Review location, device, MFA and Conditional Access context where available.
6. Compare the activity with known business and network behavior.
7. Record the analyst disposition and evidence.
8. Decide whether the rule needs tuning, enrichment or no change.

## Safe tuning principles

- Avoid blanket allowlists for VPNs, proxies or corporate IP ranges.
- Prefer narrow, owner-approved, time-bounded exceptions with monitoring.
- Re-test excluded sources because trusted infrastructure can be abused.
- Never raise thresholds solely to reduce ticket volume.
- Re-run positive and negative regression tests after every logic change.
- Track both alert volume and missed-attack scenarios.

## Example analysis record

| Field | Example value |
|---|---|
| Rule | Single-source brute force candidate |
| Sample | Sanitized lab sample |
| Observation | Repeated failures from shared egress |
| Classification | Inconclusive pending owner validation |
| Proposed action | Enrich with network ownership; no broad exclusion |
| Regression tests | Re-run positive, negative and shared-IP tests |
| Decision | Pending review |

Replace the example with actual sanitized evidence from your own lab before presenting it as a finding.
