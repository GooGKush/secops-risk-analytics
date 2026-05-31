# Production UEBA Best Practices

This document details advanced detection engineering lessons and best practices extracted from Google SecOps production-managed rule sets (such as Linux su failed logins and Windows AD context rules).

---

## 1. The Baseline Floor Rule (Reducing Noise)

### The Problem:
If a user historically has `0` failed logins, and suddenly has `1` failed login today, mathematically the event count exceeds the `max()` historical baseline of `0`. However, firing a critical security alert for $1$ failed login is highly undesirable and floods the SOC with noise.

### The Production Standard:
Always establish a **dynamic floor** in your `condition:` block. The rule should only fire if the baseline metrics exceed a minimum threshold of significance.

```yara
condition:
  $e and 
  ($actual_event_count > $max_historical_count) and 
  // ✓ CORRECT: Exclude low-volume baselines
  $max_historical_count > 10 
```

---

## 2. Multi-Namespace Dimension Rigor

### The Problem:
In massive enterprise environments, hostnames (e.g., `DESKTOP-A`) and user IDs (e.g., `admin`) routinely overlap across different Active Directory forests, cloud VPCs, or separate organizations (namespaces). If you do not isolate the namespace, the pre-computed metric query may aggregate data across completely unrelated business units.

### The Production Standard:
When baseline metrics are joined on hostnames or user IDs, you **must** query and match both standard namespaces and target namespaces in the `match:` group-by and `outcome:` dimensions:

```yara
events:
  $e.metadata.event_type = "USER_LOGIN"
  $hostname = $e.principal.asset.hostname
  $target_ns = $e.target.namespace
  $principal_ns = $e.principal.namespace

match:
  // Group-by includes namespaces
  $hostname, $target_ns, $principal_ns over 24h

outcome:
  $max_failures = max(metrics.auth_attempts_fail(
    period: 1d, window: 30d, metric: event_count_sum, agg: max,
    principal.asset.hostname: $hostname,
    principal.namespace: $principal_ns,
    target.namespace: $target_ns
  ))
```

---

## 3. Unified Security Outcome Formatting

### The Problem:
Incoming raw logs have wide variances in security action terminologies (`BLOCKED`, `ALLOW`, `DENIED`, `SUCCESS`, `PASS`). Storing highly erratic vendor actions in outcome tables makes downstream correlations and curated dashboards brittle.

### The Production Standard:
Always map raw actions to a standardized 4-state outcome array: `attempted`, `failed`, `succeeded`, `succeeded`.

```yara
outcome:
  $tmp1 = max(
    // If action is not block or unknown, mark success (value 2)
    if($e.security_result.action != "BLOCK" and $e.security_result.action != "UNKNOWN_ACTION", 2)
  )
  $tmp2 = max(
    // If action is blocked, mark failed (value 1)
    if($e.security_result.action = "BLOCK", 1)
  )
  
  // Standardizes result to: 
  // 0 (attempted), 1 (failed), 2 (succeeded), 3 (succeeded with partial blocks)
  $standardized_outcome = arrays.index_to_str(
    strings.split("attempted,failed,succeeded,succeeded"), 
    $tmp1 + $tmp2
  )
```
