# Pre-Computed Metrics Filter Dimensions Reference

When using Google SecOps metric functions, you can **only** filter them by specific combinations of UDM fields. Any other combination will result in a YARA-L compilation or query error.

Here are the strict dimension combinations grouped by function category.

---

## 1. Authentication Attempts
*   **Functions:** 
    *   `metrics.auth_attempts_total` (all USER_LOGIN events)
    *   `metrics.auth_attempts_success` (USER_LOGIN with ALLOW action)
    *   `metrics.auth_attempts_fail` (USER_LOGIN without ALLOW action)

### Supported Dimension Combinations (Filters):
*   `principal.asset.asset_id`
*   `principal.asset.asset_id`, `target.asset.asset_id`
*   `principal.asset.asset_id`, `target.asset.hostname`
*   `principal.asset.asset_id`, `target.asset.ip`
*   `principal.asset.asset_id`, `target.asset.mac`
*   `principal.asset.asset_id`, `target.asset.product_object_id`
*   `principal.asset.hostname`
*   `principal.asset.hostname`, `target.asset.asset_id`
*   `principal.asset.hostname`, `target.asset.hostname`
*   `principal.asset.hostname`, `target.asset.ip`
*   `principal.asset.hostname`, `target.asset.mac`
*   `principal.asset.hostname`, `target.asset.product_object_id`
*   `principal.asset.ip`
*   `principal.asset.ip`, `target.asset.asset_id`
*   `principal.asset.ip`, `target.asset.hostname`
*   `principal.asset.ip`, `target.asset.ip`
*   `principal.asset.ip`, `target.asset.mac`
*   `principal.asset.ip`, `target.asset.product_object_id`
*   `principal.user.email_addresses`
*   `principal.user.email_addresses`, `target.asset.asset_id`
*   `principal.user.email_addresses`, `target.asset.hostname`
*   `principal.user.email_addresses`, `target.asset.ip`
*   `principal.user.email_addresses`, `target.asset.mac`
*   `principal.user.email_addresses`, `target.asset.product_object_id`
*   `principal.user.userid`
*   `principal.user.userid`, `target.asset.asset_id`
*   `principal.user.userid`, `target.asset.hostname`
*   `principal.user.userid`, `target.asset.ip`
*   `principal.user.userid`, `target.asset.mac`
*   `principal.user.userid`, `target.asset.product_object_id`
*   `target.application`
*   `target.user.userid`, `principal.ip_geo_artifact.location.country_or_region`
*   `target.user.userid`, `principal.ip_geo_artifact.network.organization_name`
*   `target.user.userid`, `target.application`

---

## 2. Network Bytes
*   **Functions:**
    *   `metrics.network_bytes_inbound` (uses `received_bytes` as `value_sum`)
    *   `metrics.network_bytes_outbound` (uses `sent_bytes` as `value_sum`)
    *   `metrics.network_bytes_total` (uses sum of both as `value_sum`)

### Supported Dimension Combinations (Filters):
*   `principal.asset.asset_id`
*   `principal.asset.asset_id`, `principal.ip_geo_artifact.location.country_or_region`
*   `principal.asset.asset_id`, `security_result.category`
*   `principal.asset.asset_id`, `target.ip_geo_artifact.network.organization_name`
*   `principal.asset.hostname`
*   `principal.asset.hostname`, `principal.ip_geo_artifact.location.country_or_region`
*   `principal.asset.hostname`, `security_result.category`
*   `principal.asset.hostname`, `target.ip_geo_artifact.network.organization_name`
*   `principal.asset.ip`
*   `principal.asset.ip`, `principal.ip_geo_artifact.location.country_or_region`
*   `principal.asset.ip`, `security_result.category`
*   `principal.asset.ip`, `target.ip_geo_artifact.network.organization_name`
*   `principal.user.userid`
*   `principal.user.userid`, `principal.ip_geo_artifact.location.country_or_region`
*   `principal.user.userid`, `security_result.category`
*   `principal.user.userid`, `target.ip_geo_artifact.network.organization_name`

---

## 3. DNS Bytes & Queries
*   **Functions:**
    *   `metrics.dns_bytes_outbound` (uses `sent_bytes` as `value_sum` on port 53/3000)
    *   `metrics.dns_queries_total`
    *   `metrics.dns_queries_success` (response code 0)
    *   `metrics.dns_queries_fail` (response code > 0)

### Supported DNS Queries Dimensions:
*   `principal.asset.asset_id`, `network.dns_domain`
*   `principal.asset.hostname`, `network.dns_domain`
*   `principal.asset.ip`, `network.dns_domain`
*   `principal.user.userid`, `network.dns_domain`

### Supported DNS Bytes Dimensions:
*   `principal.asset.asset_id`, `target.ip`
*   `principal.asset.hostname`, `target.ip`
*   `principal.asset.ip`, `target.ip`
*   `principal.user.userid`, `target.ip`

---

## 4. File Executions
*   **Functions:**
    *   `metrics.file_executions_total` (PROCESS_LAUNCH event type)
    *   `metrics.file_executions_success` (with ALLOW action)
    *   `metrics.file_executions_fail` (without ALLOW action)

### Supported Dimension Combinations (Filters):
*   `metadata.event_type`, `principal.process.file.sha256`
*   `metadata.event_type`, `principal.asset.asset_id`, `principal.process.file.sha256`
*   `metadata.event_type`, `principal.asset.hostname`, `principal.process.file.sha256`
*   `metadata.event_type`, `principal.asset.ip`, `principal.process.file.sha256`
*   `metadata.event_type`, `principal.user.userid`, `principal.process.file.sha256`
