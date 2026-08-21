# Google SecOps SIEM UDM Stats Search with Metrics

This reference details how to construct ad-hoc **UDM Stats Searches** that leverage pre-computed behavioral metrics in Google SecOps SIEM. 

While YARA-L *detection rules* run continuously on incoming live telemetry streams, **UDM Stats Searches** are ad-hoc analytics queries executed inside the Search interface or Curated Dashboards to hunt for anomalies over historic blocks.

---

## 1. Crucial Constraints for UDM Stats Search Metrics

To prevent query failures or blank results when joining metrics inside Stats Searches, you **must** adhere strictly to these rules:

1. **One-Day Search Window Limit:**
   * *The Rule:* When executing any UDM Stats Search that incorporates metric joins, the search query window **must be specified as exactly one day (24 hours)**. 
   * *Why:* Daily pre-computed metrics are compiled on a daily boundary schedule. Querying a larger or smaller time range causes mathematical alignment errors in the query engine when performing metric correlation.
2. **No `events:` Wrapper block:**
   * *The Rule:* Unlike YARA-L rules, UDM Stats Searches do **not** wrap variables inside an `events:` block. Telemetry filter predicates are declared globally at the very top of the query before `match:`.
3. **No timespan inside `match:` for Single-Stage Searches:**
   * *The Rule:* In a standard Stats Search, you **must omit the `over Xh` block entirely** (e.g., use simply `match: $host`).
   * *Why:* A Stats Search receives its active timeframe boundaries from the **global search query window picker** inside the SecOps UI, rather than hardcoding a sliding temporal window in the YARA-L syntax.
4. **Strict Linear AST Outcome Arithmetic:**
   * *The Rule:* Outcome calculations cannot contain nested aggregators (e.g. `max(m1 / m2)`) or nested arithmetic. Each operation must be assigned to an intermediate variable linearly.
5. **No `options:` Section in Searches:**
   * *The Rule:* The `options:` block is valid only for detection rules. Ad-hoc searches terminate after `condition:` or `order:`.
6. **Explicit Group-By (`match:`):**
   * All metric search queries require a matching group-by key (declared in the `match:` block) to tie the real-time log events to the metric baseline dimensions.

---

## 2. UDM Stats Search Template (Anomalous DNS Queries Hunt)

This query analyzes ad-hoc DNS connection rates over the past 24 hours, joining each active host to their 30-day pre-computed daily DNS baseline, and outputs only anomalous hosts sorted by relative stability:

```yara
// 1. TELEMETRY SCOPE: Define real-time log filters (No events: header)
$dns.metadata.event_type = "NETWORK_DNS"
$dns.principal.asset.ip = $host 

match:
  // 2. MATCH: Group by the entity key to match metric baseline dimensions
  $host

outcome:
  // 3. OUTCOME: Dynamic observations over the query window
  $event_count = count_distinct($dns.metadata.id)
  $usage_past_24h = count($dns.metadata.id)

  // 4. OUTCOME: Retrieve 30d pre-computed historical baseline metrics
  $historical_avg = max(metrics.dns_queries_total(
      period: 1d, window: 30d,
      metric: event_count_sum, agg: avg,
      principal.asset.ip: $host
  ))

  $historical_stddev = max(metrics.dns_queries_total(
      period: 1d, window: 30d,
      metric: event_count_sum, agg: stddev,
      principal.asset.ip: $host
  ))

  $historical_max = max(metrics.dns_queries_total(
      period: 1d, window: 30d,
      metric: event_count_sum, agg: max,
      principal.asset.ip: $host
  ))

  $historical_observations = max(metrics.dns_queries_total(
      period: 1d, window: 30d,
      metric: event_count_sum, agg: num_metric_periods,
      principal.asset.ip: $host
  ))

  // 5. OUTCOME: Linear AST Mathematical Calculations
  $historical_cv = $historical_stddev / $historical_avg
  $scaled_stddev = 2 * $historical_stddev
  $historical_threshold = $historical_avg + $scaled_stddev
  $diff = $usage_past_24h - $historical_avg
  $z_score = $diff / $historical_stddev

condition:
  // 6. CONDITION: Filter results based on computed thresholds & zero-division protection
  $dns and 
  $historical_avg > 0 and 
  $historical_stddev > 0 and 
  $usage_past_24h > $historical_threshold and 
  $historical_cv < 0.10 and 
  $historical_observations >= 9 and 
  $event_count >= 50

order:
  // 7. PRESENTATION: Sort anomalies by highest Z-Score
  $z_score desc
```
