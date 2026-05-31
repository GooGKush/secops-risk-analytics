# Google SecOps SIEM UDM Stats Search with Metrics

This reference details how to construct ad-hoc **UDM Stats Searches** that leverage pre-computed behavioral metrics in Google SecOps SIEM. 

While YARA-L *detection rules* run continuously on incoming live telemetry streams, **UDM Stats Searches** are ad-hoc analytics queries executed inside the Search interface or Curated Dashboards to hunt for anomalies over historic blocks.

---

## 1. Crucial Constraints for UDM Stats Search Metrics

To prevent query failures or blank results when joining metrics inside Stats Searches, you **must** adhere strictly to these rules:

1.  **One-Day Search Window Limit:**
    *   *The Rule:* When executing any UDM Stats Search that incorporates metric joins, the search query window **must be specified as exactly one day (24 hours)**. 
    *   *Why:* Daily pre-computed metrics are compiled on a daily boundaries schedule. Querying a larger or smaller time-range causes mathematical alignment errors in the query engine when performing metric correlation.
2.  **No `events:` Wrapper block:**
    *   *The Rule:* Unlike YARA-L rules, UDM Stats Searches do **not** wrap variables inside an `events:` block. The variables are declared globally at the very top of the file before `match:`.
3.  **No timespan inside `match:`:**
    *   *The Rule:* In standard YARA-L rules, the group-by contains an explicit hop window constraint (e.g., `match: $user over 1h`). In a **Stats Search**, you **must omit the `over Xh` block entirely** (e.g., use simply `match: $host`).
    *   *Why:* A Stats Search receives its active timeframe boundaries from the **global search query window picker** inside the SecOps UI, rather than hardcoding a sliding temporal window in the YARA-L syntax.
4.  **Explicit Group-By (`match:`):**
    *   All metric search queries require a matching group-by key (declared in the `match:` block) to tie the real-time log events to the metric baseline dimensions.
5.  **Comments / Tuning Blocks:**
    *   Include tuning notes inside the `condition:` block (e.g., indicating how to modify standard deviation multipliers or coefficient ranges) to assist analysts during active threat hunting.


---

## 2. UDM Stats Search Template (Anomalous DNS Queries Hunt)

This query analyzes ad-hoc DNS connection rates over the past 24 hours, joining each active host to their 30-day pre-computed daily DNS baseline, and outputs only anomalous hosts sorted by relative stability:

```yara
// 1. EVENTS: Define real-time telemetry scope
$dns.metadata.event_type = "NETWORK_DNS"
$dns.network.dns.questions.name = $dns_query
$dns.principal.user.userid = $user
$dns.principal.asset.ip = $host 

match:
  // 2. MATCH: Force group-by parameter on the entity key to prevent Outcome Mismatch
  $host

outcome:
  // 3. OUTCOME: Dynamic observations over the query time window
  $event_count = count_distinct($dns.metadata.id)
  $usage_past_24h = count($dns.metadata.id)

  // 4. OUTCOME: Retrieve 30d pre-computed historical baseline metrics
  $historical_stddev = max(metrics.dns_queries_total(
      period:1d, window:30d,
      metric:event_count_sum, agg:stddev,
      principal.asset.ip:$host
  ))

  $historical_avg = max(metrics.dns_queries_total(
      period:1d, window:30d,
      metric:event_count_sum, agg:avg,
      principal.asset.ip:$host
  ))

  $historical_max = max(metrics.dns_queries_total(
      period:1d, window:30d,
      metric:event_count_sum, agg:max,
      principal.asset.ip:$host
  ))

  $historical_observations = max(metrics.dns_queries_total(
      period:1d, window:30d,
      metric:event_count_sum, agg:sum,
      principal.asset.ip:$host
  ))

  // 5. OUTCOME: Calculate baseline Coefficient of Variation (Relative Variability)
  $historical_coefficient_of_variation = max(
    metrics.dns_queries_total(
      period:1d, window:30d,
      metric:event_count_sum, agg:stddev,
      principal.asset.ip:$host
    ) /
    metrics.dns_queries_total(
      period:1d, window:30d,
      metric:event_count_sum, agg:avg,
      principal.asset.ip:$host
    )
  )

  // 6. OUTCOME: Define baseline confidence and stability thresholds
  $observation_threshold = max(9)             // Active at least 9 of the past 30 days
  $coefficient_of_variation_threshold = max(1/10) // CV < 0.1 models extreme stability

  // 7. OUTCOME: Compute dynamic Standard Deviation trigger threshold (+2 STDDEV)
  $historical_threshold = max(
    metrics.dns_queries_total(
      period:1d, window:30d,
      metric:event_count_sum, agg:avg,
      principal.asset.ip:$host
    ) + 2 * metrics.dns_queries_total(
      period:1d, window:30d,
      metric:event_count_sum, agg:stddev,
      principal.asset.ip:$host
    )
  )

condition:
  // 8. CONDITION: Filter results based on computed thresholds
  $dns and 
  ($usage_past_24h > $historical_threshold) and 
  ($historical_coefficient_of_variation < $coefficient_of_variation_threshold) and 
  ($historical_observations >= $observation_threshold) and 
  $event_count >= 50

order:
  // 9. PRESENTATION: Sort anomalies by highest volatility and lowest relative variance
  $historical_stddev desc, 
  $historical_coefficient_of_variation asc 
```
