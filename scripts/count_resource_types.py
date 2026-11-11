"""
Count, for the final evaluated set (opa_results.json), how many configurations declare each in-scope resource type.
Each configuration is counted once per type, however many resources of that type it declares.

Run from the repo root, in the environment where hcl2 (python-hcl2 4.3.2) works:
    python scripts/count_resource_types.py
Paste the printed counts and percentages into Table 6.
"""
import json, os, collections
import hcl2

INSCOPE = {"aws_s3_bucket", "aws_security_group", "aws_db_instance", "aws_dynamodb_table",
           "aws_lb_listener", "aws_iam_role_policy", "aws_cloudtrail", "aws_ebs_volume"}

res = [r for r in json.load(open("opa_results.json", encoding="utf-8")) if not r.get("skipped")]
cnt, bad = collections.Counter(), []
for r in res:
    path = os.path.join("terraform", os.path.basename(r["source_dir"]), r["file"])
    try:
        with open(path, encoding="utf-8") as f:
            raw = hcl2.load(f)
    except Exception as e:
        bad.append((r["file"], str(e)[:60]))
        continue
    types = {t for item in raw.get("resource", []) for t in item}
    for t in types & INSCOPE:
        cnt[t] += 1

print(f"{len(res)} evaluated files, {len(res) - len(bad)} parsed")
for t, c in cnt.most_common():
    print(f"{t:22} {c:4} {c / len(res):6.1%}")
if bad:
    print("could not parse:", bad[:10])