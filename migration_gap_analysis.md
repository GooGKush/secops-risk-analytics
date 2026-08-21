# Migration & Gap Analysis: Upgrading `secops-risk-analytics`

This document details the architectural, compiler, and statistical enhancements integrated into `secops-risk-analytics`, aligned strictly to **standard single-stage YARA-L 2.0 detection rules** and UDM Stats Searches.

---

## 📋 Summary of Integrated Upgrades

| Upgrade Area | Legacy `secops-risk-analytics` | Integrated Standard (`secops-risk-analytics`) | Impact & Resolution |
| :--- | :--- | :--- | :--- |
| **1. Rule Construct Scope** | Ambiguous scope. | Strictly enforced **single-stage YARA-L 2.0 rule construct** (`events`, `match`, `outcome`, `condition`, `options`). | **Critical**: Standard detection rules in SecOps only execute single-stage rules. |
| **2. Outcome Math Syntax** | Nested metric expressions inside `max(m1 / m2)`. | Pure **linear AST variable assignments** (`$diff = $a - $b`, `$z = $diff / $c`). | **Critical**: Prevents Malachite AST parser compilation rejection. |
| **3. Outcome Logic Restrictions** | Incomplete documentation on arithmetic syntax. | Explicit guardrails: parentheses `()` in arithmetic and bare `if()` in outcome assignments are forbidden; zero-division checks placed in `condition:`. | **Medium**: Eliminates syntax compile failures. |
| **4. Dual-Anchor Hourly Constraint** | High-level note that hourly requires daily. | Explicit dual-anchor documentation and validation (`period: 1h, window: today` paired with `period: 1d, window: 30d`). | **High**: Resolves `Hourly UEBA metrics can only be used alongside daily UEBA metrics`. |
| **5. Baseline Scope Skew** | No mention of log-type filtering implications. | Two-Tier Ingestion Audit in `references/ueba-anti-patterns.md` preventing Part-to-Whole baseline skew. | **Critical**: Protects statistical data integrity and prevents false negatives. |
| **6. Rule vs Search Grammar** | Mixed `options:` into search contexts. | Strict separation: `options:` is rule-only; ad-hoc searches omit timespan in `match:` and terminate after `condition:` or `order:`. | **High**: Prevents parser `<EOF>` syntax errors. |
| **7. Statistical Models Taxonomy** | Basic Standard Deviation and simple CV. | Multi-model statistical coverage in single-stage rules: Standard Z-Score, Stability CV, Poisson Rarity, and Fano Factor / Dispersion Index. | **High**: Expands behavioral anomaly coverage. |

---

## 🛠️ Completed Integration Checklist for `secops-risk-analytics`

### Phase 1: Compiler & Syntax Rectification
- [x] **Linear AST Outcome Arithmetic**:
  - Updated `references/metrics-baselining.md`, `references/metrics-stats-search.md`, and `SKILL.md` to remove nested aggregator arithmetic.
  - Replaced with intermediate linear outcome bindings:
    ```yara
    $mu = max(metrics.auth_attempts_fail(...))
    $sigma = max(metrics.auth_attempts_fail(...))
    $diff = $observed - $mu
    $z_score = $diff / $sigma
    ```
- [x] **Parentheses & Conditional Guardrail**:
  - Documented prohibitions on parentheses in outcome math and bare `if()` outcome expressions.
  - Placed zero-division protection in `condition: $sigma > 0 and $z_score >= 3.0`.
- [x] **Linter Enhancements**:
  - Enhanced `scripts/validate_metrics_yara.py` to detect nested outcome math, invalid parentheses, and missing hourly dual-anchor pairings.

### Phase 2: Telemetry Ingestion & Data Integrity Guardrails
- [x] **Subset-to-Whole Baseline Skew Advisory**:
  - Added dedicated section in `references/ueba-anti-patterns.md` detailing the Part-to-Whole baseline distortion and Two-Tier Ingestion Audit (Compatibility Check $\rightarrow$ Baseline Scope Check).
- [x] **Hourly Dual-Anchor Syntax Pattern**:
  - Updated `references/metrics-functions.md` with the mandatory dual-anchor specification (`period: 1h, window: today` paired with `period: 1d, window: 30d`).

### Phase 3: Single-Stage Statistical Models Taxonomy
- [x] **Incorporate Single-Stage Stats Models**:
  - Updated `references/metrics-baselining.md` with:
    1. **Standard Z-Score ($Z \ge 3.0$)**: For symmetric parametric volume bursts.
    2. **Coefficient of Variation (CV) Stability Modeling**: For detecting anomalies in predictable entities.
    3. **Fano Factor / Dispersion Index ($F = \sigma^2 / \mu \ge 4.0$)**: For bursty spray and brute-force waves.
    4. **Discrete Poisson Rarity**: For rare, low-frequency event anomalies.
- [x] **Example Templates**:
  - Updated `examples/anomalous_outbound_bytes.yara` to use valid match syntax (`$ip over 24h`) and Linear AST outcome calculations.
