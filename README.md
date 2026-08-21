# Google SecOps Risk Analytics Skill Package

A standardized AI agent skill package designed to guide AI coding assistants (and security developers) through writing mathematical, false-positive-free YARA-L 2.0 detection rules inside Google SecOps SIEM. 

This skill enforces strict stability baselining constraints, parameter fixing patterns, and risk score ECG table-joins to prevent common outcome mismatches and logical detection errors.

---

## Package Structure

This repository is structured to conform strictly with the [Agent Skills Specification](https://agentskills.io):

```
secops-risk-analytics/
├── SKILL.md                # Core orchestrator prompt containing metadata and checklists
├── LICENSE                 # Apache 2.0 License
├── scripts/                # Local executable linting scripts
│   └── validate_metrics_yara.py  # A local python linter that enforces YARA-L metric parameters
├── references/             # In-depth domain documentation pulled on-demand by agents
│   ├── metrics-baselining.md  # Standard Z-Score, CV, Fano Factor, and Linear AST math rules
│   ├── metrics-dimensions.md  # Strict pre-computed dimensions mapping sheet
│   ├── metrics-functions.md   # Syntax, Named Parameters, and First-Seen hybrid logic rules
│   ├── metrics-stats-search.md# Ad-hoc UDM stats search with metrics conventions
│   ├── production-best-practices.md # Baseline floors, multi-namespace rigor, action mapping
│   ├── risk-analytics-ueba.md # Category log source maps and separate ECG event join guidelines
│   └── ueba-anti-patterns.md  # Parameter mismatch, scope alignment, and baseline skew prevention
└── examples/               # Standardized working template rules
    ├── anomalous_outbound_bytes.yara  # Outbound bytes Z-Score baseline rule template
    └── risk_auth_zscore_surge.yara    # Authentication surge Z-Score baseline rule template
```

---

## How to Install & Use in AI Coding Assistants

If you are pair-programming with a coding assistant (e.g., Gemini/Jetski or standard models):

### 1. Local Sandboxed Installation
Simply clone or copy this directory into your assistant's search path (e.g., `~/.gemini/skills/`):
```bash
git clone <this_repo_url> ~/.gemini/skills/secops-risk-analytics
```

### 2. Triggering the Capabilities
Once installed, you can trigger the assistant to query these capabilities by calling it in your request:
> *"Write a metrics YARA-L rule for me using the `secops-risk-analytics` skill to identify anomalous authentication attempts."*

---

## Rule Validation & Linting

* **Default (Detection Rules)**: Validated against the live Google SecOps compiler (`validate_rule` tool).
* **SIEM Search (Stats Searches)**: When authoring ad-hoc UDM stats searches, run the local Python linter:
  ```bash
  python3 scripts/validate_metrics_yara.py path/to/your/rule.yara
  ```

---

## Contributions
Contributions to this skill pack are highly welcome! If you identify other pre-computed metric dimensions or YARA-L constraints, please submit a PR containing:
*   An update to `SKILL.md` detailing the lesson/check.
*   An entry inside `references/` explaining the technical theory.
*   Any necessary assertions added to `scripts/validate_metrics_yara.py`.

---

## License
This project is licensed under the [Apache License 2.0](LICENSE).
```
Copyright 2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
