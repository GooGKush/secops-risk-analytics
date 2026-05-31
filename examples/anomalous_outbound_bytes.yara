// Copyright 2026 Google LLC
rule AnomalousOutboundBytesZScore {
  meta:
    author      = "SecOps Risk Analytics Skill"
    description = "Detects when a host transmits outbound bytes exceeding 3 standard deviations above its 30-day daily average."
    severity    = "HIGH"

  events:
    // Step 1: Declare event and capture joining placeholders
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $ip = $e.principal.asset.ip

  match:
    // Step 2: Group by the placeholder over a 1-day tumbling window
    $ip by 1d tumbling

  outcome:
    // Step 3: Calculate current actual value
    $actual_bytes_out = sum($e.network.sent_bytes)

    // Step 4: Query pre-computed metrics baseline (Must wrap in outermost aggregator max())
    $avg_bytes_out = max(metrics.network_bytes_outbound(
      period: 1d,
      window: 30d,
      metric: value_sum,
      agg: avg,
      principal.asset.ip: $ip
    ))

    $stddev_bytes_out = max(metrics.network_bytes_outbound(
      period: 1d,
      window: 30d,
      metric: value_sum,
      agg: stddev,
      principal.asset.ip: $ip
    ))

    // Step 5: Track metrics for visibility in detection details
    $deviation_threshold = $avg_bytes_out + (3 * $stddev_bytes_out)

  condition:
    // Step 6: Fire condition based on calculated anomaly outcomes
    $actual_bytes_out > $deviation_threshold
}
