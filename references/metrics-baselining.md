# Mathematical Baselining & Modeling (Standard Deviation vs Advanced Models)

To write a successful behavioral anomaly rule in Google SecOps, you must mathematically define "normal" so you can precisely alert on "abnormal" behavior.

This guide outlines the core statistical models in YARA-L 2.0 (Standard Z-Score, Coefficient of Variation, Poisson Rarity, and Fano Factor) and enforces **Linear AST outcome syntax**.

---

## ⚠️ Malachite AST Compiler Math Rules (Mandatory)

The SecOps Malachite YARA-L engine enforces strict AST syntax for mathematical assignments in `outcome:`:

1. **No Nested Aggregators / Math**: Expressions like `max(metric1 / metric2)` or `max(metric1 + 2 * metric2)` are **illegal** and rejected by the AST parser.
2. **Linear Variable Assignments Only**: Each operation must be split into separate linear intermediate variables:
   ```yara
   // ❌ ILLEGAL (Fails compilation)
   $threshold = max(metrics.auth_attempts_fail(... agg: avg)) + (3 * max(metrics.auth_attempts_fail(... agg: stddev)))

   // ✓ CORRECT (Linear AST)
   $historical_avg = max(metrics.auth_attempts_fail(... agg: avg))
   $historical_stddev = max(metrics.auth_attempts_fail(... agg: stddev))
   $scaled_stddev = 3 * $historical_stddev
   $threshold = $historical_avg + $scaled_stddev
   ```
3. **No Parentheses `()` in Arithmetic**: Expressions like `$z = ($observed - $mu) / $sigma` fail parsing. You must compute the difference first, then divide:
   ```yara
   $diff = $observed_val - $historical_avg
   $z_score = $diff / $historical_stddev
   ```
4. **No Bare `if()` in Outcome Arithmetic**: Use `$historical_stddev > 0` guardrails inside the `condition:` block rather than ternary inline `if()` logic in `outcome:`.

---

## Model 1: Standard Z-Score ($Z > 3.0$)
Ideal for **high-frequency, symmetric baseline metrics** (e.g., authentication surges, HTTP query volume).

### Mathematical Formula:
$$Z = \frac{x - \mu}{\sigma}$$
Where $x$ is the current observed activity, $\mu$ is the 30-day historical mean, and $\sigma$ is the historical standard deviation.

### YARA-L Implementation:
```yara
outcome:
  $actual_bytes = sum($e.network.sent_bytes)
  $historical_avg = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: avg, principal.asset.ip: $ip))
  $historical_stddev = max(metrics.network_bytes_outbound(period: 1d, window: 30d, metric: value_sum, agg: stddev, principal.asset.ip: $ip))
  
  // Linear AST outcome arithmetic
  $diff = $actual_bytes - $historical_avg
  $z_score = $diff / $historical_stddev

condition:
  $e and $historical_stddev > 0 and $z_score >= 3
```

---

## Model 2: Coefficient of Variation (CV) & Stability Modeling
Ideal for **detecting anomalies in highly stable environments**. Standard deviation alone can be misleading if the baseline has high natural variance. We use the **Coefficient of Variation (CV)** to measure stability first ($\text{CV} = \sigma / \mu$).

### Mathematical Concept:
* **$\text{CV} < 0.10$**: Extreme baseline stability (robotic or consistent scheduled activity).
* **Confidence Floor**: Entity observed active for at least $X$ days out of 30 (`agg: num_metric_periods`).
* **Multiplier Threshold**: Alerts when activity exceeds $10 \times \text{historical maximum}$ on an otherwise ultra-stable entity.

### Production Rule Template:
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
    // Dynamic dimensions are fixed in match block to prevent outcome mismatch
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

    // 2. Linear AST Outcome Calculations
    $historical_cv = $historical_stddev / $historical_avg
    $anomaly_threshold = 10 * $historical_max

  condition:
    $e and 
    // Guardrail: baseline exists and non-zero
    $historical_avg > 0 and
    // Condition 1: Actual count exceeds 10x historical max
    $actual_failed_logins > $anomaly_threshold and 
    // Condition 2: Historical baseline is highly stable (CV < 0.10)
    $historical_cv < 0.10 and 
    // Condition 3: High confidence baseline (active at least 9 of 30 days)
    $historical_observations >= 9
}
```

---

## Model 3: Poisson Dispersion & Fano Factor ($F > 4.0$)
Ideal for **detecting bursty attack clustering** (e.g. automated password sprays vs. regular human mistyped passwords).

### Mathematical Formula:
$$F = \frac{\sigma^2}{\mu}$$
* $F \approx 1.0$: Steady, random human errors (Poisson distribution).
* $F > 4.0$: Super-Poisson burst clustering (automated attack waves).

### YARA-L Implementation:
```yara
outcome:
  $actual_attempts = count($e.metadata.id)
  $historical_avg = max(metrics.auth_attempts_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: $user))
  $historical_stddev = max(metrics.auth_attempts_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: $user))

  // Linear AST variance & Fano factor
  $variance = $historical_stddev * $historical_stddev
  $fano_factor = $variance / $historical_avg

condition:
  $e and $historical_avg > 0 and $actual_attempts >= 20 and $fano_factor >= 4.0
```

---

## Model 4: Discrete Poisson Rarity ($Z_P > 3.5$)
Ideal for **rare, low-frequency event anomalies** ($\lambda \le 2.0$, such as anomalous admin execution or rare privilege escalations).

### Mathematical Formula:
$$Z_P = \frac{k - \lambda}{\sqrt{\lambda}}$$
Where $k$ is the observed count and $\lambda$ is the expected 30-day daily historical average arrival rate.
