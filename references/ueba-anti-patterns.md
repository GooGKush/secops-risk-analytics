# UEBA & YARA-L Metrics Anti-Patterns Reference

This document outlines the critical detection engineering anti-patterns identified in the Google SecOps UEBA development guidelines. Understanding these concepts is key to preventing silent detection failures, logic mismatches, or inaccurate standard deviations.

---

## 1. Outcome Parameter Mismatch (The Group-By Trap)

### The Issue:
Aggregations in the `outcome` section operate on multiple values across the match window and return a single value. If you query multiple metrics (e.g., querying both `avg` and `stddev` together) without **fixing the dimension parameters**, the engine may evaluate them against *different* entity combinations.

#### Visualizing the Trap:
Imagine evaluating a user's authentication attempts across different countries:

| User | Country | Avg Logins | Stddev Logins |
| :--- | :--- | :--- | :--- |
| Alice | US | **50** | 1 |
| Alice | MX | 5 | 10 |
| Alice | CA | 1 | **20** |

If you evaluate:
```yara
$avg = max(metrics.logins(agg:avg, user:$user, country:$country))     // Evaluates to 50 (matches US)
$dev = max(metrics.logins(agg:stddev, user:$user, country:$country))  // Evaluates to 20 (matches CA)
```
*   **Mismatched Result:** Your rule evaluates a threshold using average logins from the **US** ($50$) but standard deviations from **Canada** ($20$). This renders the Z-score or standard deviation comparison mathematically invalid.

---

## 2. Enforcing Constant Parameters (The Fix)

When querying related metrics (e.g., `avg` + `stddev`, `max` + `first_seen`, `first_seen` + `last_seen`), the parameters passed to the metrics function **must be constant** to prevent outcome mismatching.

### The Two Ways to Enforce a Constant Variable:

### Method A: Group By in the `match:` Section (Recommended)
Place any dynamic dimension variables used in the metrics filter directly into your rule's `match:` section. This forces the engine to split calculations into separate, isolated buckets per distinct combination.

```yara
events:
  $e.metadata.event_type = "USER_LOGIN"
  $user = $e.target.user.userid
  $country = $e.target.ip.country // Dynamic dimension

match:
  // ✓ CORRECT: Forces separate buckets for each User + Country combination
  $user, $country over 1h 

outcome:
  $avg = max(metrics.logins(agg:avg, user:$user, country:$country))
  $dev = max(metrics.logins(agg:stddev, user:$user, country:$country))
```

### Method B: Fix the Variable in the `events:` Section
If a dimension variable is not in the `match:` block, it must be hardcoded or constrained to a single, fixed value within your event filters.

```yara
events:
  $e.metadata.event_type = "USER_LOGIN"
  $user = $e.target.user.userid
  $country = $e.target.ip.country
  
  // ✓ CORRECT: Constrains the variable to a single constant value
  $country = "US" 

match:
  $user over 1h

outcome:
  $avg = max(metrics.logins(agg:avg, user:$user, country:$country))
```

> [!IMPORTANT]
> **Best Practice:** Always fix the parameters. With rule chaining, a single rule with a single metric might become a related metric rule down the line. Getting into the habit of fixing parameters prevents future compilation issues.

---

## 3. Predictability & Resolution Pitfalls

### Pitfall A: Baselines on Infrequent Events
*   **Anti-Pattern:** Using UEBA standard deviations for highly sporadic, non-predictable activities (such as `RESOURCE_DELETION` or a rare document share).
*   **Why it fails:** Standard deviation calculations require a stable baseline of expected daily activity. If an action occurs once a month, the baseline is too erratic to calculate a meaningful anomaly.
*   **Better Alternative:** Use simple threshold-based alerts (e.g., `#deletions > 5`) instead of Z-score metrics for sporadic events.

### Pitfall B: Mismatched Resolution (Broad Metrics vs. Specific Events)
*   **Anti-Pattern:** Using a broad metric category to detect a highly specific anomaly (e.g., using `metrics.resource_creation_total` to flag anomalous AWS EC2 instance creations).
*   **Why it fails:** Because the baseline counts *all* resources created (GCP VMs, Azure keys, AWS storage, IAM accounts), a massive spike in EC2 instances will get diluted inside the total count and will likely never cross the anomaly threshold.
*   **The Rule:** Baseline metrics must match the specificity of the events they aim to monitor. Choose specific metrics functions (or filter dimensions) rather than broad aggregators.

---

## 4. Subset-to-Whole Baseline Skew (Part-to-Whole Distortion)

### The Issue:
Pre-computed risk metrics (such as `metrics.network_bytes_outbound`, `metrics.http_queries_total`, or `metrics.auth_attempts_total`) aggregate historical telemetry across **all ingesting log sources** within the tenant.

If your rule's `events:` block restricts telemetry to a specific subset, log type, or vendor (e.g., `metadata.log_type = "CHROME_MANAGEMENT"` or `metadata.vendor_name = "Palo Alto"`), you introduce an asymmetrical **Part-to-Whole baseline skew**:
* The real-time numerator reflects only Chrome or Palo Alto logs.
* The historical 30-day baseline denominator reflects the tenant-wide total across all log types and vendors.
* **Result**: The real-time observation will almost never exceed historical averages/thresholds, causing silent false negatives and distorted Z-scores.

### The Two-Tier Telemetry Audit:
1. **Tier 1 (Compatibility Check)**: Verify that the UDM event type in `events:` matches the metric's data foundation (e.g. `USER_LOGIN` with `metrics.auth_attempts_*`, `NETWORK_CONNECTION` with `metrics.network_bytes_*`).
2. **Tier 2 (Baseline Scope Check)**: Ensure you do not over-filter the real-time event scope with specific vendor/log type constraints unless the metric itself was pre-computed against that isolated log type dimension.
