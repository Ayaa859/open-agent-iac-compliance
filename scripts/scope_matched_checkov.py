"""
Scope-matched Checkov comparison.  Run from the repo root:
    python scope_matched_checkov.py [--labels ground_truth_v2.csv]

Inputs : checkov_results.json (Checkov 3.3.6 JSON), opa_results.json (evaluated files, OPA predictions,
         and the labels used so far). --labels is an optional CSV with columns file,label[,sample] that overrides the labels.
         Validated-sample run:  python scope_matched_checkov.py --labels human_labels_90.csv --only-labelled --subset random60
Outputs: checkov_scope_mapping.csv   (the frozen check mapping, publish as a supplementary table)
         checkov_scope_results.csv   (metrics for every variant)
Variants: full default | A: all checks on the 8 resource types | B: strict mapping | B2: B + SG ingress-rule resources | C: lenient mapping
Each variant is also compared with OPA by McNemar's exact test (b = only OPA right, c = only Checkov right).
"""
import argparse, collections, csv, json, math, os

IN8 = {"aws_s3_bucket", "aws_db_instance", "aws_ebs_volume", "aws_dynamodb_table",
       "aws_lb_listener", "aws_iam_role_policy", "aws_security_group", "aws_cloudtrail"}
COMPANIONS = {"aws_vpc_security_group_ingress_rule", "aws_security_group_rule",
              "aws_s3_bucket_public_access_block", "aws_iam_policy_document"}
STRICT = {  # Checkov check id -> our check (same security property, same direction)
    "CKV_AWS_145": "S3-ENC", "CKV_AWS_18": "S3-LOG", "CKV_AWS_20": "S3-PUB", "CKV_AWS_16": "RDS-ENC",
    "CKV_AWS_3": "EBS-ENC", "CKV_AWS_2": "LB-TLS", "CKV_AWS_355": "IAM-WILD", "CKV_AWS_63": "IAM-WILD",
    "CKV_AWS_62": "IAM-WILD", "CKV_AWS_260": "SG-OPEN", "CKV_AWS_24": "SG-OPEN", "CKV_AWS_25": "SG-OPEN",
    "CKV_AWS_277": "SG-OPEN", "CKV_AWS_251": "CT-LOG", "CKV_AWS_36": "CT-VALID"}
SG_IDS = {k for k, v in STRICT.items() if v == "SG-OPEN"}
SG_COMP = {"aws_vpc_security_group_ingress_rule", "aws_security_group_rule"}  # Checkov reports open ingress on these rule resources
LENIENT_EXTRA = {  # related or stricter variants, and companion-resource findings
    "CKV2_AWS_6": "S3-PUB", "CKV_AWS_54": "S3-PUB", "CKV_AWS_119": "DDB-ENC", "CKV_AWS_189": "EBS-ENC",
    "CKV_AWS_103": "LB-TLS", "CKV_AWS_67": "CT-GLOBAL", "CKV_AWS_356": "IAM-WILD", "CKV2_AWS_40": "IAM-WILD",
    "CKV_AWS_286": "IAM-WILD", "CKV_AWS_287": "IAM-WILD", "CKV_AWS_288": "IAM-WILD", "CKV_AWS_289": "IAM-WILD",
    "CKV_AWS_290": "IAM-WILD", "CKV_AWS_109": "IAM-WILD", "CKV_AWS_111": "IAM-WILD"}

ap = argparse.ArgumentParser(); ap.add_argument("--labels"); ap.add_argument("--checkov", default="checkov_results.json")
ap.add_argument("--opa")
ap.add_argument("--only-labelled", action="store_true", help="evaluate only the files listed in --labels")
ap.add_argument("--subset", help="with --only-labelled: keep rows whose 'sample' column equals this value (e.g. random60)")
args = ap.parse_args()
opa_path = args.opa or next(p for p in ("opa_results.json", "outputs/opa_results.json") if os.path.exists(p))

def load_json(p):
    for enc in ("utf-16", "utf-8-sig"):
        try:
            return json.load(open(p, encoding=enc))
        except (UnicodeError, json.JSONDecodeError):
            pass
    raise SystemExit(f"cannot read {p}")

reps = load_json(args.checkov)
reps = reps if isinstance(reps, list) else [reps]
tf = next(r for r in reps if r.get("check_type") == "terraform")     # the secrets scan is NOT an IaC check
failed = tf["results"]["failed_checks"]
bn = lambda c: os.path.basename(c["file_path"].replace("\\", "/"))
rtype = lambda c: c["resource"].split(".")[0]

opa = [r for r in load_json(opa_path) if not r.get("skipped")]
labels = {r["file"]: r["expected_label"] for r in opa}
csv_rows = list(csv.DictReader(open(args.labels, encoding="utf-8-sig"))) if args.labels else []
labels.update({r["file"]: r["label"] for r in csv_rows})
files = [r["file"] for r in opa]
if args.only_labelled:
    keep = {r["file"] for r in csv_rows if not args.subset or r.get("sample") == args.subset}
    files = [f for f in files if f in keep]
opa_pred = {r["file"]: ("NON_COMPLIANT" if r["violation_count"] > 0 else "COMPLIANT") for r in opa}

def flagged(ids, types):
    return {bn(c) for c in failed if (ids is None or c["check_id"] in ids) and (types is None or rtype(c) in types)}

variants = {
    "full default (all checks)": flagged(None, None),
    "A: all checks, 8 resource types": flagged(None, IN8),
    "B: strict mapping": flagged(set(STRICT), IN8),
    "B2: strict + SG ingress-rule resources": flagged(set(STRICT), IN8) | flagged(SG_IDS, SG_COMP),
    "C: lenient mapping": flagged(set(STRICT) | set(LENIENT_EXTRA), IN8 | COMPANIONS)}

def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h

def mcnemar_exact(b, c):
    n = b + c
    if n == 0: return 1.0
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n)

def score(pred):
    tp = sum(labels[f] == "NON_COMPLIANT" and pred[f] == "NON_COMPLIANT" for f in files)
    fn = sum(labels[f] == "NON_COMPLIANT" and pred[f] == "COMPLIANT" for f in files)
    fp = sum(labels[f] == "COMPLIANT" and pred[f] == "NON_COMPLIANT" for f in files)
    tn = sum(labels[f] == "COMPLIANT" and pred[f] == "COMPLIANT" for f in files)
    p = tp / (tp + fp) if tp + fp else 0; r = tp / (tp + fn) if tp + fn else 0
    return tp, fn, fp, tn, p, r, (2 * p * r / (p + r) if p + r else 0)

rows = []
def report(name, pred, vs_opa=True):
    tp, fn, fp, tn, p, r, f1 = score(pred)
    pl, ph = wilson(tp, tp + fp); rl, rh = wilson(tp, tp + fn)
    b = sum(opa_pred[f] == labels[f] and pred[f] != labels[f] for f in files)
    c = sum(opa_pred[f] != labels[f] and pred[f] == labels[f] for f in files)
    rows.append([name, tp, fn, fp, tn, f"{p:.1%}", f"[{pl:.1%}, {ph:.1%}]", f"{r:.1%}", f"[{rl:.1%}, {rh:.1%}]", f"{f1:.1%}",
                 b if vs_opa else "", c if vs_opa else "", f"{mcnemar_exact(b, c):.4g}" if vs_opa else ""])
    print(f"{name:34} TP={tp:3} FN={fn:3} FP={fp:3} TN={tn:3}  P={p:6.1%} R={r:6.1%} F1={f1:6.1%}"
          + (f"  | vs OPA: b={b} c={c} p={mcnemar_exact(b, c):.4g}" if vs_opa else ""))

print(f"{len(files)} evaluated files, {sum(v == 'NON_COMPLIANT' for f, v in labels.items() if f in set(files))} NON_COMPLIANT\n")
report("OPA framework", opa_pred, vs_opa=False)
for name, fl in variants.items():
    report("Checkov, " + name, {f: "NON_COMPLIANT" if f in fl else "COMPLIANT" for f in files})

with open("checkov_scope_results.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["system", "TP", "FN", "FP", "TN", "precision", "precision_CI", "recall", "recall_CI", "F1", "b_only_OPA_right", "c_only_Checkov_right", "McNemar_exact_p"]); w.writerows(rows)
names = {c["check_id"]: c["check_name"] for c in failed}
with open("checkov_scope_mapping.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["checkov_check_id", "checkov_check_name", "our_check", "tier", "resource_types_counted"])
    for k, v in STRICT.items():
        w.writerow([k, names.get(k, ""), v, "strict+lenient", "the 8 in-scope types" + ("; B2 also counts ingress-rule resources" if k in SG_IDS else "")])
    for k, v in LENIENT_EXTRA.items(): w.writerow([k, names.get(k, ""), v, "lenient only", "8 types + companion resources"])
print("\nWrote checkov_scope_results.csv and checkov_scope_mapping.csv")
