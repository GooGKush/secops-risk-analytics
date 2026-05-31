# Overview of Risk Analytics for UEBA Category

This document describes the pre-built rule sets in the Risk Analytics for UEBA category, the required data ingestion sources, and best practices for writing rules that leverage entity risk scores.

---

## 1. Rule Set Categories & Behavioral Patterns

The Google SecOps Risk Analytics system groups UEBA patterns into five core buckets. Use these patterns as a baseline when modeling your custom behavioral metric queries:

### A. Authentication
*   **New Login by User to Device:** Identifies when a user authenticates to a device they have never historically used.
*   **Anomalous Authentication Events by User:** Triggers when a single user entity has anomalous authentication activity compared to their historical baseline.
*   **Failed Authentications by Device:** Identifies device entities with a statistical spike in failed authentication attempts.
*   **Failed Authentications by User:** Tracks users with high-volume spikes in failed logins compared to their 30-day baseline.

### B. Network Traffic Analysis
*   **Anomalous Inbound Bytes by Device/User:** Tracks significant data uploads to a single device or user compared to historical usage.
*   **Anomalous Outbound Bytes by Device/User:** Tracks excessive data downloads from a device or user.
*   **Anomalous Total Bytes by Device/User:** Evaluates combined inbound and outbound byte volume for anomalies.
*   **Brute Force then Successful Login:** Multi-event correlation targeting failed authentication spikes followed by a successful login for a single user from a single IP.

### C. Peer Group & Newly Created Users
*   **Anomalous Logins/Actions for a Newly Created User:** Detects immediate anomalous spikes in logins, process executions, or group modifications for a user entity created recently (evaluating creation time from Active Directory context data).

### D. Suspicious Actions
*   **Excessive Account Creation by Device:** Tracks device entities generating multiple user accounts.
*   **Excessive Alerts by User:** Spikes in EDR or AV `BLOCK` actions associated with a user compared to historical peer/user data.

### E. Data Loss Prevention (DLP)
*   **Anomalous Processes with Data Exfiltration Capabilities:** Detects anomalous process executions mapped to malware exfiltration features (e.g., keyloggers, screenshots) using VirusTotal file metadata enrichment.

---

## 2. Required Ingestion & Log Mappings

For UEBA and behavioral rules to fire accurately, specific event sources must be mapped properly to UDM namespaces:

| Security Event Category | Required Log Sources | Critical UDM `metadata.event_type` Mappings |
| :--- | :--- | :--- |
| **Authentication** | `AZURE_AD_AUDIT`, `WINEVTLOG` (Event IDs: 4624, 4625, 4768) | `USER_LOGIN`, `USER_CREATION` |
| **Network Traffic** | EDR (`CS_EDR`, `CB_EDR`), Firewall/Proxy (`FORTINET_FIREWALL`, `ZSCALER_WEBPROXY`) | `NETWORK_CONNECTION` (with `sent_bytes` / `received_bytes`) |
| **Process Executions** | EDR (`CS_EDR`, `SENTINEL_EDR`, `CB_EDR`), Windows System | `PROCESS_LAUNCH` (Event ID 4688), `PROCESS_OPEN`, `PROCESS_MODULE_LOAD` |

---

## 3. Entity Risk Scores & Context Joins

Google SecOps pre-calculates entity risk scores. Joining context and risk scores requires following strict architecture boundaries:

### Indispensable Rules for Risk Score Rules:
1.  **Explicit Risk Window Declared:** You **must** include `graph.risk_score.risk_window_size.seconds` in your events filter. The only supported values are:
    *   `86400` (24 hours)
    *   `604800` (7 days)
    *   *Leaving this out returns inaccurate results or compilation errors.*
2.  **Separate Entity Events Required:** Entity risk score data is stored **separately** from standard entity context data. To use both in a single rule, you must join **three separate events** (Event, Context, Risk Score):

```yara
rule EntityContextAndRiskScoreExample {
  meta:
    description = "Join real-time login with standard asset context AND asset risk score."

  events:
    // 1. Real-time event
    $log_in.metadata.event_type = "USER_LOGIN"
    $log_in.principal.hostname = $host

    // 2. Standard Entity Context Graph (ECG)
    $context.graph.entity.hostname = $host
    $context.graph.metadata.entity_type = "ASSET"

    // 3. Entity Risk Score (Stored Separately)
    $risk_score.graph.entity.hostname = $host
    $risk_score.graph.risk_score.risk_window_size.seconds = 604800 // Enforced window size (7d)

  match:
    $host over 2m

  outcome:
    $entity_risk_score = max($risk_score.graph.risk_score.normalized_risk_score)

  condition:
    $log_in and $context and $risk_score and $entity_risk_score > 100
}
```
