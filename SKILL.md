---
name: secops-risk-analytics
description: |
  Use when writing YARA-L 2.0 rules or search queries that leverage historical behavioral metrics
  (e.g., metrics.auth_attempts_total, metrics.network_bytes_outbound) to detect anomalies,
  perform behavioral baselining, calculate standard deviations, or evaluate risk scores.
  Triggers: "write a metrics rule", "historical baseline rule", "anomaly threshold detection",
  "detect anomalous network bytes", "auth attempts standard deviation", "metrics outcome".
compatibility: Requires access to a Google Security Operations (SecOps) SIEM instance with Metrics Ingestion enabled.
---

# SecOps Risk Analytics (YARA-L Metrics)

This skill guides the agent through writing anomalous detection rules using Google SecOps pre-computed daily/hourly behavioral metrics inside the `outcome` section. 

## Workflow Execution Checklist

- [ ] **Step 1: Identify target behavior & metric function.** Determine what activity to baseline (Authentication, DNS queries, Outbound network bytes, File executions, etc.).
- [ ] **Step 2: Audit Dimensions.** Look up the strict filter dimension combinations in `references/metrics-dimensions.md`. If the dimensions do not match a pre-computed set, you CANNOT write the metric join.
- [ ] **Step 3: Set Period & Window.** Enforce `period: 1d` and `window: 30d` for statistical baselines (standard deviations).
- [ ] **Step 4: Design Outcome Aggregation.** Build the metric joins in the `outcome` block.
- [ ] **Step 5: Enforce Outermost Aggregator.** Wrap every outcome assignment metric in an outer aggregator (`max`, `min`, `avg`, `sum`).
- [ ] **Step 6: Write Anomaly Trigger Condition.** In the `condition:` section, join the real-time event count or value against the outcome standard deviation threshold (e.g., `$actual_bytes > $avg_outbound_bytes + (3 * $stddev_outbound_bytes)`).
- [ ] **Step 7: Validate Syntax.** Verify metrics rules against YARA-L metrics limitations.

---

## Critical Metrics Constraints (Avoid Pitfalls)

### 1. Outermost Aggregator Requirement
You cannot assign a metric directly to an outcome variable. It **must** be wrapped in an outermost aggregator:
```yara
// ❌ WRONG: Direct assignment
$avg_bytes = metrics.network_bytes_outbound(period:1d, window:30d, metric:value_sum, agg:avg, ...)

// ✓ CORRECT: Wrapped in max() or sum()
$avg_bytes = max(metrics.network_bytes_outbound(period:1d, window:30d, metric:value_sum, agg:avg, ...))
```

### 2. Metrics belong ONLY in Outcome
Metric joins are evaluated as aggregated windows, so they cannot appear in the `events:` section. Declare UDM placeholders in `events:`, map them in `match:`, and run the historical lookup in `outcome:`.

### 3. Zero Value Joins
You cannot join a metric filter to a default/empty value (e.g., `""` for strings or `0` for integers). 

### 4. Period Limits
* Daily (`period: 1d`): Windows can only be `30d`.
* Hourly (`period: 1h`): Windows can only be `today`. Hourly metrics can **only** be used in queries that also call daily metrics.

### 5. Metric & Event Data Scope Alignment (Anti-Pattern Shield)
You must ensure the data filtered in the `events:` section matches the exact scope of the metric called in the `outcome:` section. **Mismatched scopes lead to silent detection failures or logic errors.**
*   **Log Event Type Alignment:** The UDM event type in the `events:` section must match the pre-computed metric scope.
    *   *Rule:* If using `metrics.auth_attempts_success` (which pre-computes only successful logons), your `events:` filter **must** explicitly isolate successful logins:
        ```yara
        events:
          $e.metadata.event_type = "USER_LOGIN"
          $e.security_result.action = "ALLOW" // Matches success scope!
        ```
    *   *Rule:* If using `metrics.auth_attempts_fail`, you **must** filter for failed logins:
        ```yara
        events:
          $e.metadata.event_type = "USER_LOGIN"
          $e.security_result.action = "FAIL" // Matches fail scope!
        ```
*   **Dimension Filter Alignment:** The values passed to metric dimensions must correspond logically to the event fields. For example, if querying `metrics.dns_bytes_outbound` filtered by `target.ip: $ip`, your `events:` block **must** strictly constrain `$ip` to target IPs mapping to port `53` (DNS port). Joining a DNS metric to standard HTTP target IPs is a severe anti-pattern.

### 6. Parameter Fixing (Outcome Mismatch Shield)
When querying related metrics (e.g., calling both `avg` and `stddev` in the same `outcome` block), all dimension variables **must be constant** to prevent outcome mismatch. Mismatch occurs when aggregators return statistical values from *different* dynamic combinations (e.g. average logins from the US, but standard deviation from CA).
*   *Enforcement Rule:* Dynamic dimension variables used inside metric functions (such as `$country` or `$app`) **must** either:
    1. Be listed inside your rule's **`match:`** section (which acts as a SQL-like group-by), OR
    2. Be fixed to a constant value inside your **`events:`** filters (e.g. `$country = "US"`).

---

## Target Anomaly Formula (Standard Deviation Threshold)
To calculate standard deviations (anomalous behavior):
```yara
events:
  $e.metadata.event_type = "USER_LOGIN"
  $e.security_result.action = "ALLOW"
  $user = $e.target.user.userid
  $country = $e.target.ip.country

match:
  // Dynamic country variable is in the match section to prevent parameter mismatch
  $user, $country over 1d

outcome:
  $actual_count = count($e.metadata.id)
  $avg_behavior = max(metrics.auth_attempts_success(period:1d, window:30d, metric:event_count_sum, agg:avg, target.user.userid: $user, principal.ip_geo_artifact.location.country_or_region: $country))
  $stddev_behavior = max(metrics.auth_attempts_success(period:1d, window:30d, metric:event_count_sum, agg:stddev, target.user.userid: $user, principal.ip_geo_artifact.location.country_or_region: $country))

condition:
  // Fire if actual count is 3 standard deviations above average
  $actual_count > $avg_behavior + (3 * $stddev_behavior)
```

## Critical UEBA & Risk Score Constraints
1. **Strict Risk Window:** For any entity risk score join (using `graph.risk_score`), you **must** explicitly filter by `graph.risk_score.risk_window_size.seconds`. Supported values are only `86400` (24 hours) or `604800` (7 days).
2. **Separate ECG Events:** Standard entity context (e.g., `graph.metadata.entity_type = "ASSET"`) and entity risk scores (`graph.risk_score.*`) are stored in **separate** tables. A joint rule must use two distinct `graph` events (e.g., `$context` and `$risk_score`) and join them on the entity key.

## Skill References
* Read `references/metrics-dimensions.md` for the? full list of supported metric functions and their strict dimension options.
* Read `references/metrics-functions.md` for metric named parameters, inline filter restrictions, and "first-seen" hourly/daily hybrid logic.
* Read `references/metrics-baselining.md` to understand Standard Deviation vs. Coefficient of Variation models and stability anomaly thresholds.
* Read `references/metrics-stats-search.md` to learn how to construct ad-hoc UDM Stats Searches with metrics, including the mandatory 24-hour query window.
* Read `references/risk-analytics-ueba.md` for UEBA log category maps (Authentication, Network, Process) and separate ECG/Risk Score event join structure.
* Read `references/ueba-anti-patterns.md` to understand how to prevent Outcome Mismatch, and how to evaluate baseline predictability.
* Read `examples/anomalous_outbound_bytes.yara` for a complete working template of a Standard Deviation threshold baseline rule.

## Related Skills
To complete your Google SecOps engineering capabilities, reference these sibling skills when implementing metrics rules:
*   Use **`secops`** (Detection Coverage) to automate threat intel blogs $\rightarrow$ synthetic logs $\rightarrow$ metric evaluations workflows.
*   Use **`secops-detection-engineering`** to test your rules using historical data (Retrohunts) and coordinate real-time run latency limits.
*   Use **`secops-siem-search`** to query the parsed UDM outcomes of your metrics rules or look up verified log sources.
*   Use **`secops-yara-l`** to review general YARA-L syntax (such as operators, map accesses, and transitive event joins).





