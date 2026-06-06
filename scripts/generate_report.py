import json
import os
from datetime import datetime

# -----------------------------
# Fixed evaluation constants
# -----------------------------
TOTAL_FILES_SCANNED = 478
EVALUATED_RELEVANT_FILES = 213

TP = 116
FN = 15
FP = 3
TN = 79

PRECISION = "97.5%"
RECALL = "88.5%"
F1_SCORE = "92.8%"
ACCURACY = "91.5%"

# -----------------------------
# Load enriched results
# enriched_results.json contains only files with detected violations
# -----------------------------
with open("enriched_results.json", "r", encoding="utf-8") as f:
    enriched_results = json.load(f)

os.makedirs("reports", exist_ok=True)

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
report_date = datetime.now().strftime("%B %d, %Y")

# -----------------------------
# Count audit-report statistics
# -----------------------------
files_with_violations = [
    r for r in enriched_results
    if r.get("violation_count", 0) > 0
]

total_detected_files = len(files_with_violations)
total_violations = sum(
    r.get("violation_count", 0)
    for r in files_with_violations
)

severity_counts = {
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0
}

nist_counts = {}
rule_counts = {}

for r in files_with_violations:
    for v in r.get("violations", []):
        severity = v.get("severity", "MEDIUM")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        nist = v.get("nist_control", "UNKNOWN")
        nist_counts[nist] = nist_counts.get(nist, 0) + 1

        rule = v.get("rule", "unknown")
        rule_counts[rule] = rule_counts.get(rule, 0) + 1

# -----------------------------
# Build Markdown report
# -----------------------------
md = f"""# IaC Compliance Audit Report

**Generated:** {report_date}  
**Framework:** NIST SP 800-53 Rev. 5  
**Tool:** Open-Agent Framework (OPA + LLM)  
**Scope:** Terraform Infrastructure Configurations  

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Files Scanned | {TOTAL_FILES_SCANNED} |
| Evaluated Relevant Files | {EVALUATED_RELEVANT_FILES} |
| Files with Detected Violations | {total_detected_files} |
| Total Violations Found | {total_violations} |
| HIGH Severity | {severity_counts.get("HIGH", 0)} |
| MEDIUM Severity | {severity_counts.get("MEDIUM", 0)} |
| LOW Severity | {severity_counts.get("LOW", 0)} |
| True Positives | {TP} |
| False Negatives | {FN} |
| False Positives | {FP} |
| True Negatives | {TN} |
| Precision | {PRECISION} |
| Recall | {RECALL} |
| F1 Score | {F1_SCORE} |
| Accuracy | {ACCURACY} |

> Note: The detailed findings below include only configurations where the OPA policy engine detected at least one violation. Evaluation metrics are computed over the full set of {EVALUATED_RELEVANT_FILES} relevant labeled Terraform configurations.

---

## Violations by NIST Control Family

| NIST Control | Count |
|---|---|
"""

for nist, count in sorted(nist_counts.items(), key=lambda x: -x[1]):
    md += f"| {nist} | {count} |\n"

md += """
---

## Violations by Rule

| Rule | Count |
|---|---|
"""

for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
    md += f"| {rule} | {count} |\n"

md += """
---

## Detailed Findings

"""

for r in files_with_violations:
    fname = r.get("file", "unknown")
    expected_label = r.get("expected_label", "UNKNOWN")
    violation_count = r.get("violation_count", 0)

    md += f"### File: {fname}\n\n"
    md += f"**Violations found:** {violation_count}  \n"
    md += f"**Label:** {expected_label}\n\n"

    for i, v in enumerate(r.get("violations", []), 1):
        rule = v.get("rule", "")
        resource = v.get("resource", "")
        nist = v.get("nist_control", "")
        severity = v.get("severity", "")
        message = v.get("message", "")
        explanation = v.get("explanation", "")
        nist_mapping = v.get("nist_mapping", {})
        remediation = v.get("remediation", "")

        md += f"#### Violation {i}: {rule}\n\n"
        md += "| Field | Value |\n"
        md += "|---|---|\n"
        md += f"| Resource | {resource} |\n"
        md += f"| NIST Control | {nist} |\n"
        md += f"| Severity | {severity} |\n"
        md += f"| Message | {message} |\n\n"

        if explanation:
            md += "**Explanation:**\n"
            md += f"{explanation}\n\n"

        if nist_mapping:
            md += "**NIST SP 800-53 Mapping:**\n"
            md += f"- Control ID: {nist_mapping.get('control_id', nist)}\n"
            md += f"- Control Name: {nist_mapping.get('control_name', '')}\n"
            md += f"- Description: {nist_mapping.get('control_description', '')}\n\n"

        if remediation:
            md += "**Remediation:**\n"
            md += "```hcl\n"
            md += f"{remediation}\n"
            md += "```\n\n"

        md += "---\n\n"

md += f"""
## Compliance Summary

This audit report identified **{total_violations} detected compliance violations** across
**{total_detected_files} Terraform configuration files**. These findings are mapped to
NIST SP 800-53 control families AC (Access Control), SC (System and Communications
Protection), and AU (Audit and Accountability).

The full evaluation scanned **{TOTAL_FILES_SCANNED} Terraform files**, of which
**{EVALUATED_RELEVANT_FILES}** were relevant to the implemented policy scope. The OPA-only
detection layer achieved **{PRECISION} precision**, **{RECALL} recall**, **{F1_SCORE} F1 score**,
and **{ACCURACY} accuracy**.

### OPA-Only Detection Performance

| Metric | Value |
|---|---|
| True Positives | {TP} |
| False Negatives | {FN} |
| False Positives | {FP} |
| True Negatives | {TN} |
| Precision | {PRECISION} |
| Recall | {RECALL} |
| F1 Score | {F1_SCORE} |
| Accuracy | {ACCURACY} |

*Report generated by Open-Agent Framework for IaC Compliance Analysis*  
*Generated: {timestamp}*
"""

# -----------------------------
# Save report
# -----------------------------
report_path = "reports/audit_report.md"

with open(report_path, "w", encoding="utf-8") as f:
    f.write(md)

print("Audit report generated.")
print(f"  Saved to                   : {report_path}")
print(f"  Total files scanned         : {TOTAL_FILES_SCANNED}")
print(f"  Evaluated relevant files    : {EVALUATED_RELEVANT_FILES}")
print(f"  Files with violations       : {total_detected_files}")
print(f"  Total violations            : {total_violations}")
print(f"  Precision                   : {PRECISION}")
print(f"  Recall                      : {RECALL}")
print(f"  F1 Score                    : {F1_SCORE}")
print(f"  Accuracy                    : {ACCURACY}")
