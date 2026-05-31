#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""
validate_metrics_yara.py
A linter to validate YARA-L 2.0 metrics rules for Google SecOps SIEM.
Enforces constraints to prevent Outcome Mismatches, missing aggregators, 
and data scope failures.
"""

import re
import sys
import argparse

def validate_rule(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    errors = []
    warnings = []

    # Extract blocks
    events_match = re.search(r'\bevents:\s*(.*?)\b(match:|outcome:|condition:|$)', content, re.DOTALL)
    match_match = re.search(r'\bmatch:\s*(.*?)\b(outcome:|condition:|$)', content, re.DOTALL)
    outcome_match = re.search(r'\boutcome:\s*(.*?)\b(condition:|options:|$)', content, re.DOTALL)
    condition_match = re.search(r'\bcondition:\s*(.*?)\b(options:|$)', content, re.DOTALL)

    events_block = events_match.group(1) if events_match else ""
    match_block = match_match.group(1) if match_match else ""
    outcome_block = outcome_match.group(1) if outcome_match else ""
    condition_block = condition_match.group(1) if condition_match else ""

    # Ensure metrics functions only exist in outcome
    all_metrics_calls = re.findall(r'\bmetrics\.\w+\(', content)
    outcome_metrics_calls = re.findall(r'\bmetrics\.\w+\(', outcome_block)

    if len(all_metrics_calls) > len(outcome_metrics_calls):
        errors.append("CRITICAL ERROR: Metric functions (metrics.*) are only valid in the 'outcome:' section.")

    # Parse all outcome metrics parameters
    metrics_patterns = re.findall(
        r'\$\w+\s*=\s*(\w+)?\s*\(\s*metrics\.(\w+)\((.*?)\)\s*\)', outcome_block, re.DOTALL
    )




    for wrapper, func_name, params_str in metrics_patterns:
        # 1. Enforce Outermost Aggregator
        if not wrapper or wrapper.lower() not in ['max', 'min', 'avg', 'sum']:
            errors.append(
                f"CRITICAL ERROR: The metrics call to 'metrics.{func_name}' must be wrapped in an "
                f"outermost aggregator (e.g., max(metrics.{func_name}(...)))."
            )

        # Parse named parameters
        params = {}
        param_matches = re.findall(r'(\b\w+(?:\.\w+)*\b)\s*:\s*([^\s,]+)', params_str)
        for key, val in param_matches:
            params[key] = val.strip()

        # 2. Check Period and Window boundaries
        period = params.get('period')
        window = params.get('window')

        if period == '1d' and window != '30d':
            errors.append(f"CRITICAL ERROR (metrics.{func_name}): Daily metrics (period:1d) must use window:30d.")
        elif period == '1h' and window != 'today':
            errors.append(f"CRITICAL ERROR (metrics.{func_name}): Hourly metrics (period:1h) must use window:today.")

        # 3. Parameter Fixing Check (Outcome Mismatch Shield)
        # Find dynamic variables passed to metrics parameters
        dynamic_vars = []
        for key, val in params.items():
            if key not in ['period', 'window', 'metric', 'agg', 'filter'] and val.startswith('$'):
                dynamic_vars.append(val)

        # Ensure dynamic variables are constant (either in match section or fixed in events)
        for var in dynamic_vars:
            # Strip comments from match block before checking
            match_clean = re.sub(r'//.*$', '', match_block, flags=re.MULTILINE)
            in_match = re.search(re.escape(var) + r'\b', match_clean)
            # Variable must be fixed in events block (e.g. $var = "fixed_value" or "fixed_value" = $var)
            is_fixed_in_events = re.search(
                rf'(?:{re.escape(var)}\s*=\s*["\']\w+["\']|["\']\w+["\']\s*=\s*{re.escape(var)})',
                events_block
            )


            if not in_match and not is_fixed_in_events:
                errors.append(
                    f"CRITICAL ERROR: Dimension variable '{var}' used in metrics.{func_name} is dynamic "
                    f"and NOT fixed. To prevent Outcome Mismatch, place '{var}' in the 'match:' section "
                    f"or fix its value in the 'events:' section (e.g., {var} = \"US\")."
                )

    # 4. Target Risk Score Constraints
    if "graph.risk_score" in content:
        # Must filter by window size
        if "graph.risk_score.risk_window_size.seconds" not in content:
            errors.append(
                "CRITICAL ERROR: Rules using entity risk scores (graph.risk_score) must explicitly "
                "filter by 'graph.risk_score.risk_window_size.seconds' (e.seconds = 86400 or 604800)."
            )
        # Warn if standard context graph uses standard context filters on the same event variable
        graph_vars = re.findall(r'(\$\w+)\.graph\.', content)
        if len(set(graph_vars)) < 2 and ("graph.entity" in content and "graph.risk_score" in content):
            warnings.append(
                "WARNING: ECG Context data and Risk Score data are stored separately. "
                "Ensure you use separate entity event variables (e.g., $context and $risk_score) joined on key."
            )

    # Output Results
    if errors:
        print(f"❌ Linter found {len(errors)} compilation errors in {filepath}:")
        for err in errors:
            print(f"  - {err}")
        for warn in warnings:
            print(f"  - {warn}")
        return False
    else:
        print(f"✓ YARA-L Metrics rule {filepath} parsed successfully. No structural constraints violated.")
        if warnings:
            for warn in warnings:
                print(f"  - {warn}")
        return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecOps YARA-L Metrics Rule Validator")
    parser.add_argument("file", help="Path to the .yl2 / .yara rule file")
    args = parser.parse_args()
    
    success = validate_rule(args.file)
    sys.exit(0 if success else 1)
