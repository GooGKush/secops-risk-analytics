# YARA-L 2.0 Pre-Computed Metrics Functions Reference

This reference details the syntax, pre-computed parameters, aggregation behaviors, and inline filters for metrics functions in Google SecOps.

---

## 1. Functional Parameters & Taxonomy

All metric functions use **named parameters** and must be structured strictly under these keys:

```yara
$outcome_variable = max(metrics.function_name(
  period: <1h|1d>,
  window: <today|30d>,
  metric: <metric_type>,
  agg: <agg_type>,
  <dimension_key>: <placeholder_or_value>,
  [filter: <logical_expression>]
))
```

### A. Period & Window Matrix
The allowed values for the `window` lookback are strictly bounded by the metric's aggregation `period`:

*   **Daily metrics:** `period: 1d` $\rightarrow$ **Window must be:** `window: 30d`
*   **Hourly metrics:** `period: 1h` $\rightarrow$ **Window must be:** `window: today`
    *   *Mandatory Dual-Anchor Rule:* Hourly metrics (`period: 1h, window: today`) **can only be used in queries that also bind at least one daily metric (`period: 1d, window: 30d`)** for that entity. Omitting the daily metric causes the compiler error: `Hourly UEBA metrics can only be used alongside daily UEBA metrics`.

### B. Metric Types (`metric` parameter)
This determines which raw pre-computed behavioral field is extracted from the baseline window:
*   `event_count_sum` — Standard event counts in the period.
*   `first_seen` — Timestamp of the oldest event in the period.
*   `last_seen` — Timestamp of the most recent event in the period.
*   `value_sum` — Sum of bytes within the period (Only valid for functions with `bytes` in the name).
*   `num_unique_filter_values` — Dynamic count of distinct values inside a dimension (requires wildcard `*` filter).

### C. Aggregations (`agg` parameter)
Defines how the daily observations inside the window (e.g., 30 days of values) are condensed:
*   `avg` — Statistical mean per period (excludes zero-value days).
*   `stddev` — Standard deviation per period (excludes zero-value days).
*   `max` — Highest value in the window.
*   `min` — Lowest value in the window.
*   `sum` — Cumulative sum of the metric over the entire window.
*   `num_metric_periods` — Count of periods (days) with non-zero values.

---

## 2. Inline Metric Filters

The `filter:` parameter allows you to filter the metric observations *before* running the outer aggregation.

### Indispensable Rules for Metric Filters:
1.  **No UDM Placeholders or Event Fields:** You **cannot** reference outside variables (like `$e.metadata.timestamp` or `$ph`) inside the inline filter.
2.  **Metric Variables Only:** The filter expression must strictly compare pre-computed metric parameters (`value_sum`, `event_count_sum`, `first_seen`, `last_seen`).
3.  **Function Support:** Standard timestamp calculations (e.g., `timestamp.get_day_of_week()`) are allowed on metric variables.

### Correct Inline Filters:
```yara
// Filter daily logs to only include days where bytes sent > 10 and event count > 2
filter: value_sum > 10 AND event_count_sum > 2

// Filter out days that don't have exactly 100 events OR have more than 1,000
filter: event_count_sum = 100 OR event_count_sum > 1000

// Filter observations to only include events seen on Wednesdays (Day 3)
filter: timestamp.get_day_of_week(first_seen) = 3
```

### Incorrect Inline Filters (Will fail compilation):
```yara
// ❌ WRONG: Uses an external event placeholder
filter: event_count_sum + $e.field > 10 

// ❌ WRONG: Uses a placeholder variable
filter: value_sum > $placeholder_var
```

---

## 3. "First-Seen" Logic (Hourly & Daily Hybrid)

To detect a true "first-seen" anomaly (e.g., user logs into an app for the first time today, and has no history in the last 30 days), you must query **both** daily and hourly baselines:

```yara
events:
  $e.metadata.event_type = "USER_LOGIN"
  $e.security_result.action = "ALLOW"
  $userid = $e.target.user.userid
  $app = $e.target.application

match:
  $userid, $app over 4h

outcome:
  // 1. Check hourly metric for the current day (since daily metrics lag up to 6h)
  $first_seen_today = max(metrics.auth_attempts_success(
    period: 1h, window: today, metric: first_seen, agg: max,
    target.user.userid: $userid, target.application: $app
  ))

  // 2. Check the daily metric over the past 30 days
  $first_seen_monthly = max(metrics.auth_attempts_success(
    period: 1d, window: 30d, metric: first_seen, agg: max,
    target.user.userid: $userid, target.application: $app
  ))

condition:
  $e and ($first_seen_today = 0) and ($first_seen_monthly = 0)
```
