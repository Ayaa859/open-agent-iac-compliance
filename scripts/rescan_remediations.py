"""
Re-scan every LLM-generated remediation snippet through the project's own OPA pipeline.
Run from the repo root:   python scripts/rescan_remediations.py [--opa path/to/opa]

For each unique violation type in enriched_results.json it checks:
  1. the snippet parses as HCL (python-hcl2),
  2. the ORIGINAL rule no longer fires on the snippet (violation resolved),
  3. NO OTHER rule fires on the snippet (no new violation introduced).
Snippets whose resource type is outside the policy library cannot be evaluated and are reported as such.
Writes rescan_results.csv.  Uses your normalize_tf.normalize_hcl2 and the policies/ folder.
"""
import argparse, csv, io, json, os, subprocess, sys
import hcl2
sys.path.insert(0, os.getcwd())          # also find normalize_tf.py when run from the repo root
sys.path.insert(0, os.path.join(os.getcwd(), "scripts"))
from normalize_tf import normalize_hcl2

ap = argparse.ArgumentParser()
ap.add_argument("--opa", default="opa"); ap.add_argument("--enriched", default="enriched_results.json")
ap.add_argument("--policies", default="policies")
args = ap.parse_args()

PACKAGES = {"terraform.ac", "terraform.sc", "terraform.au", "terraform.s3"}
RESOURCE_POLICY_MAP = {
    "aws_iam_role_policy": ["terraform.ac"], "aws_security_group": ["terraform.ac"],
    "aws_s3_bucket": ["terraform.sc", "terraform.au", "terraform.s3"], "aws_db_instance": ["terraform.sc"],
    "aws_ebs_volume": ["terraform.sc"], "aws_lb_listener": ["terraform.sc"],
    "aws_cloudtrail": ["terraform.au"], "aws_dynamodb_table": ["terraform.sc"]}

def violations_for(tf_json):
    pkgs = {p for t in tf_json.get("resource", {}) for p in RESOURCE_POLICY_MAP.get(t, [])}
    found = []
    for pkg in sorted(pkgs):
        with open("temp_rescan_input.json", "w") as f:
            json.dump(tf_json, f)
        out = subprocess.run([args.opa, "eval", "-i", "temp_rescan_input.json", "-d", args.policies, "--format", "json",
                              f"data.{pkg}.violation"], capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            raise RuntimeError(out.stderr[:300])
        res = json.loads(out.stdout).get("result", [])
        val = res[0]["expressions"][0]["value"] if res else []
        found += [v.get("rule") for v in (val if isinstance(val, list) else list(val.values()))]
    return sorted(set(found)), bool(pkgs)

snippets = {}
for r in json.load(open(args.enriched, encoding="utf-8")):
    for v in r["violations"]:
        snippets.setdefault(v["rule"], (v["nist_control"], v["remediation"]))

rows = []
for rule, (nist, snip) in sorted(snippets.items()):
    try:
        raw = hcl2.load(io.StringIO(snip)); valid = True
    except Exception as e:
        rows.append([rule, nist, False, "", "", "", f"HCL error: {str(e)[:80]}"]); continue
    fired, evaluable = violations_for(normalize_hcl2(raw))
    if not evaluable:
        rows.append([rule, nist, True, "n/a", "n/a", "", "resource type outside the policy library: cannot be evaluated by OPA"]); continue
    original_fixed = rule not in fired
    new = [x for x in fired if x != rule]
    verdict = "PASS" if original_fixed and not new else "FAIL"
    rows.append([rule, nist, True, original_fixed, "; ".join(new), verdict, ""])
if os.path.exists("temp_rescan_input.json"): os.remove("temp_rescan_input.json")

with open("rescan_results.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["rule", "nist", "hcl_valid", "original_violation_resolved", "new_violations", "verdict", "note"]); w.writerows(rows)
for r in rows: print(f"{r[0]:36} valid={r[2]!s:5} resolved={r[3]!s:5} new=[{r[4]}] {r[5]} {r[6]}")
print(f"\nPASS: {sum(r[5]=='PASS' for r in rows)} | FAIL: {sum(r[5]=='FAIL' for r in rows)} | not evaluable: {sum(r[3]=='n/a' for r in rows)} | invalid HCL: {sum(r[2] is False for r in rows)}")