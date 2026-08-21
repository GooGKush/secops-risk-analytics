rule Risk_Auth_ZScore_Surge {
  meta:
    author = "SecOps Risk Analytics"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $user = $e.target.user.userid

  match:
    $user over 24h

  outcome:
    $actual_failed_logins = count($e.metadata.id)
    $historical_avg = max(metrics.auth_attempts_fail(
      period: 1d,
      window: 30d,
      metric: event_count_sum,
      agg: avg,
      target.user.userid: $user
    ))
    $historical_stddev = max(metrics.auth_attempts_fail(
      period: 1d,
      window: 30d,
      metric: event_count_sum,
      agg: stddev,
      target.user.userid: $user
    ))
    $diff = $actual_failed_logins - $historical_avg
    $z_score = $diff / $historical_stddev

  condition:
    $e and $historical_stddev > 0 and $z_score >= 3
}
