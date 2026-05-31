# Mathematical Baselining & Modeling (Standard Deviation vs Coefficient of Variation)

To write a successful behavioral anomaly rule in Google SecOps, you must mathematically define "normal" so you can precisely alert on "abnormal" behavior.

This guide outlines the two primary methods of behavioral modeling in YARA-L 2.0, including the advanced **Coefficient of Variation (CV)** method.

---

## Method A: Standard Deviation Threshold (Simple Volatility)
Ideal for **high-frequency, low-volatility events** where the baseline has a consistent average and tight deviation.

### Mathematical Threshold:
$$\text{Threshold} = \text{Average} + (3 \times \text{Standard Deviation})$$

### YARA-L Implementation:
```yara
outcome:
  $avg_bytes = max(metrics.network_bytes_outbound(period:1d, window:30d, metric:value_sum, agg:avg, principal.asset.ip: $ip))
  $std_bytes = max(metrics.network_bytes_outbound(period:1d, window:30d, metric:value_sum, agg:stddev, principal.asset.ip: $ip))
  $threshold = $avg_bytes + (3 * $std_bytes)

condition:
  $actual_bytes > $threshold
```

---

## Method B: Coefficient of Variation (CV) & Stability Modeling (Advanced)
Ideal for **detecting anomalies in highly stable environments**. Standard deviation alone can be misleading if the baseline changes. We use the **Coefficient of Variation (CV)** to model stability first, ensuring we only alert on entities with a highly predictable baseline.

### Mathematical Formulas:
*   **Coefficient of Variation (CV):** Measures relative variability. It is the ratio of the standard deviation to the mean:
    $$\text{CV} = \frac{\sigma}{\mu} = \frac{\text{Standard Deviation}}{\text{Average}}$$
*   **Low CV ($< 0.1$):** Represents extreme baseline stability.
*   **Observations Threshold:** Establishes confidence by verifying the entity has been active for at least $X$ out of the last $30$ days.
*   **Anomalous Threshold:** Flags activity that is an extreme multiple of the historical maximum (e.g., $10 \times \text{historical max}$).

---

## Production Template: Stability Modeling (CV Method)

Observe how this pattern uses outcome thresholds to build a highly resilient, false-positive-free composite rule:

```yara
rule UEBA_StableEntity_AnomalyDetection {
  meta:
    author      = "SecOps Risk Analytics"
    description = "Alerts when a historically highly stable user exhibits a massive spike (10x max) in failed authentication."

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $user = $e.target.user.userid
    $app = $e.target.application
    $ns = $e.target.namespace

  match:
    // Dynamic dimensions are fixed in the match block to prevent outcome mismatch
    $user, $app, $ns over 24h

  outcome:
    $actual_failed_logins = count_distinct($e.metadata.id)

    // 1. Calculate 30-day Baseline Metrics
    $historical_avg = max(metrics.auth_attempts_fail(
      period: 1d, window: 30d, metric: event_count_sum, agg: avg,
      target.user.userid: $user, target.application: $app, target.namespace: $ns
    ))

    $historical_max = max(metrics.auth_attempts_fail(
      period: 1d, window: 30d, metric: event_count_sum, agg: max,
      target.user.userid: $user, target.application: $app, target.namespace: $ns
    ))

    $historical_stddev = max(metrics.auth_attempts_fail(
      period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
      target.user.userid: $user, target.application: $app, target.namespace: $ns
    ))

    $historical_observations = max(metrics.auth_attempts_fail(
      period: 1d, window: 30d, metric: event_count_sum, agg: num_metric_periods,
      target.user.userid: $user, target.application: $app, target.namespace: $ns
    ))

    // 2. Calculate Relative Variability (CV)
    // Division is performed inline between two metric queries
    $historical_cv = max(
      metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        target.user.userid: $user, target.application: $app, target.namespace: $ns
      ) /
      metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        target.user.userid: $user, target.application: $app, target.namespace: $ns
      )
    )

    // 3. Define Fixed Threshold Outcomes
    $observation_confidence_threshold = max(9)   // Active at least 9 of the last 30 days
    $stability_cv_threshold = max(0.1)           // CV < 0.1 models extreme stability
    $anomaly_multiplier_threshold = max(10 * $historical_max) // 10x historical maximum

  condition:
    $e and 
    // Rule 1: Trigger event count exceeds the historical multiplier threshold (10x max)
    ($actual_failed_logins > $anomaly_multiplier_threshold) and 
    // Rule 2: The entity's history models a highly stable baseline (low coefficient of variation)
    ($historical_cv < $stability_cv_threshold) and 
    // Rule 3: High confidence baseline (observed active for at least 9 days)
    ($historical_observations >= $observation_confidence_threshold)
}
```
