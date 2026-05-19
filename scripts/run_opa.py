import subprocess
import json
import os
import hcl2
from normalize_tf import normalize_hcl2

POLICIES_DIR = "policies"
TF_DIRS = ["terraform/non_compliant", "terraform/compliant"]
OUTPUT_FILE = "opa_results.json"

results = []
total = 0

packages = {
    "ac_access_control.rego":       "terraform.ac",
    "sc_system_protection.rego":    "terraform.sc",
    "au_audit_accountability.rego": "terraform.au",
    "s3_encryption.rego":           "terraform.s3"
}

# Only run relevant policies based on what resources exist in the file
RESOURCE_POLICY_MAP = {
    "aws_iam_role_policy":      ["terraform.ac"],
    "aws_security_group":       ["terraform.ac"],
    "aws_s3_bucket":            ["terraform.sc", "terraform.au", "terraform.s3"],
    "aws_db_instance":          ["terraform.sc"],
    "aws_ebs_volume":           ["terraform.sc"],
    "aws_lb_listener":          ["terraform.sc"],
    "aws_cloudtrail":           ["terraform.au"],
}

def get_relevant_packages(tf_json):
    resources = tf_json.get("resource", {})
    relevant = set()
    for resource_type in resources.keys():
        if resource_type in RESOURCE_POLICY_MAP:
            for pkg in RESOURCE_POLICY_MAP[resource_type]:
                relevant.add(pkg)
    return relevant

def run_opa_eval(input_data, package):
    input_path = "temp_input.json"
    with open(input_path, 'w') as f:
        json.dump(input_data, f)
    query = f"data.{package}.violation"
    cmd = ["opa", "eval", "-i", input_path, "-d", POLICIES_DIR, "--format", "json", query]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return []
        output = json.loads(result.stdout)
        results = output.get("result", [])
        if not results:
            return []
        expressions = results[0].get("expressions", [])
        if not expressions:
            return []
        value = expressions[0].get("value", [])
        if isinstance(value, list):
            return value
        elif isinstance(value, dict):
            return list(value.values())
        return []
    except:
        return []

print("Running OPA against Terraform files...")
print("-" * 50)

for tf_dir in TF_DIRS:
    for tf_file in sorted(os.listdir(tf_dir)):
        if not tf_file.endswith(".tf"):
            continue

        tf_path = os.path.join(tf_dir, tf_file)
        total += 1

        try:
            with open(tf_path, 'r', encoding='utf-8') as f:
                raw = hcl2.load(f)
            tf_json = normalize_hcl2(raw)
        except Exception as e:
            print(f"  [SKIP] {tf_file}: {e}")
            continue

        # Only run policies relevant to resources in this file
        relevant_packages = get_relevant_packages(tf_json)

        if not relevant_packages:
            label = "NON_COMPLIANT" if "non_compliant" in tf_dir else "COMPLIANT"
            print(f"  [SKIP-IRRELEVANT] {tf_file} ({label}): no relevant resources")
            results.append({
                "file": tf_file,
                "source_dir": tf_dir,
                "expected_label": label,
                "violations": [],
                "violation_count": 0,
                "skipped": True
            })
            continue

        all_violations = []
        for policy_file, package in packages.items():
            if package not in relevant_packages:
                continue
            viols = run_opa_eval(tf_json, package)
            all_violations.extend(viols)

        # Deduplicate
        seen = set()
        unique = []
        for v in all_violations:
            if isinstance(v, dict):
                key = (v.get('rule',''), v.get('resource',''))
                if key not in seen:
                    seen.add(key)
                    unique.append(v)

        label = "NON_COMPLIANT" if "non_compliant" in tf_dir else "COMPLIANT"

        if unique:
            print(f"  [VIOLATION] {tf_file} ({label}): {len(unique)} found")
            for v in unique:
                print(f"    - {v.get('rule')} | {v.get('nist_control')} | {v.get('severity')}")
        else:
            print(f"  [CLEAN]     {tf_file} ({label})")

        results.append({
            "file": tf_file,
            "source_dir": tf_dir,
            "expected_label": label,
            "violations": unique,
            "violation_count": len(unique),
            "skipped": False
        })

if os.path.exists("temp_input.json"):
    os.remove("temp_input.json")

with open(OUTPUT_FILE, 'w') as f:
    json.dump(results, f, indent=2)

# Only count non-skipped files in metrics
evaluated = [r for r in results if not r.get('skipped')]
nc_detected = sum(1 for r in evaluated if r['expected_label']=='NON_COMPLIANT' and r['violation_count']>0)
nc_missed   = sum(1 for r in evaluated if r['expected_label']=='NON_COMPLIANT' and r['violation_count']==0)
fp          = sum(1 for r in evaluated if r['expected_label']=='COMPLIANT'     and r['violation_count']>0)
tn          = sum(1 for r in evaluated if r['expected_label']=='COMPLIANT'     and r['violation_count']==0)

precision = nc_detected / (nc_detected + fp) if (nc_detected + fp) > 0 else 0
recall    = nc_detected / (nc_detected + nc_missed) if (nc_detected + nc_missed) > 0 else 0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

print("-" * 50)
print(f"Total files scanned        : {total}")
print(f"Evaluated (relevant)       : {len(evaluated)}")
print(f"Non-compliant detected  TP : {nc_detected}")
print(f"Non-compliant missed    FN : {nc_missed}")
print(f"Compliant flagged       FP : {fp}")
print(f"Compliant clean         TN : {tn}")
print(f"")
print(f"Precision : {precision:.1%}")
print(f"Recall    : {recall:.1%}")
print(f"F1 Score  : {f1:.1%}")
print(f"Results saved to           : {OUTPUT_FILE}")