"""
Compare the LLM-only baseline with the hybrid framework (OPA), and with scope-matched Checkov, on the human-validated files.
    python scripts/analyze_llm_only.py [--subset random60] [--runs-file llm_only_runs.jsonl]
Needs: human_labels_90_with_rules.csv, llm_only_runs.jsonl, opa_results.json, checkov_results.json
Writes llm_only_results.csv
"""
import argparse, collections, csv, itertools, json, math, os

ap = argparse.ArgumentParser()
ap.add_argument("--labels", default="human_labels_90_with_rules.csv"); ap.add_argument("--runs-file", default="llm_only_runs.jsonl")
ap.add_argument("--subset", default="random60"); ap.add_argument("--opa", default="opa_results.json"); ap.add_argument("--checkov", default="checkov_results.json")
args = ap.parse_args()

VALID = {"S3-ENC","S3-LOG","S3-PUB","RDS-ENC","EBS-ENC","DDB-ENC","LB-TLS","IAM-WILD","SG-OPEN","CT-LOG","CT-GLOBAL","CT-VALID"}
EXPECT = {"S3-ENC":"SC-28","RDS-ENC":"SC-28","EBS-ENC":"SC-28","DDB-ENC":"SC-28","LB-TLS":"SC-8","IAM-WILD":"AC-6","SG-OPEN":"AC-3",
          "S3-PUB":"AC-3","CT-LOG":"AU-2","CT-GLOBAL":"AU-2","CT-VALID":"AU-9","S3-LOG":"AU-12"}
OPA2CHECK = {"s3_missing_encryption":"S3-ENC","s3_logging_disabled":"S3-LOG","s3_public_access_not_blocked":"S3-PUB","rds_encryption_disabled":"RDS-ENC",
 "ebs_missing_encryption":"EBS-ENC","ebs_encryption_disabled":"EBS-ENC","dynamodb_encryption_disabled":"DDB-ENC","lb_not_using_https":"LB-TLS","lb_protocol_missing":"LB-TLS",
 "wildcard_iam_policy":"IAM-WILD","unrestricted_ingress_specific_port":"SG-OPEN","unrestricted_ingress_all_protocols":"SG-OPEN","cloudtrail_logging_disabled":"CT-LOG",
 "cloudtrail_not_global":"CT-GLOBAL","cloudtrail_no_log_validation":"CT-VALID","cloudtrail_validation_field_missing":"CT-VALID"}

def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0)
    p = k / n; d = 1 + z*z/n; c = (p + z*z/(2*n))/d; h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))/d
    return c - h, c + h
def mcnemar(b, c):
    n = b + c
    return 1.0 if n == 0 else min(1.0, 2*sum(math.comb(n, i) for i in range(min(b, c)+1))/2**n)
def prf(tp, fp, fn):
    p = tp/(tp+fp) if tp+fp else 0.0; r = tp/(tp+fn) if tp+fn else 0.0
    return p, r, (2*p*r/(p+r) if p+r else 0.0)

L = [r for r in csv.DictReader(open(args.labels, encoding="utf-8-sig")) if args.subset == "all" or r["sample"] == args.subset]
files = [r["file"] for r in L]; lab = {r["file"]: r["label"] for r in L}
HAS_RULES = "rules" in L[0]          # rule-level metrics need human_labels_90_with_rules.csv
hrules = {r["file"]: set(x for x in r.get("rules", "").split(";") if x) for r in L}
opa = {r["file"]: r for r in json.load(open(args.opa, encoding="utf-8")) if not r.get("skipped")}
opa_flag = {f: opa[f]["violation_count"] > 0 for f in files}
opa_rules = {f: {OPA2CHECK[v["rule"]] for v in opa[f]["violations"] if v.get("rule") in OPA2CHECK} for f in files}

def load_checkov():
    for enc in ("utf-16", "utf-8-sig"):
        try: return json.load(open(args.checkov, encoding=enc))
        except (UnicodeError, json.JSONDecodeError): pass
    raise SystemExit("cannot read checkov file")
cz = load_checkov(); cz = cz if isinstance(cz, list) else [cz]
tf = next(r for r in cz if r.get("check_type") == "terraform")["results"]["failed_checks"]
IN8 = {"aws_s3_bucket","aws_db_instance","aws_ebs_volume","aws_dynamodb_table","aws_lb_listener","aws_iam_role_policy","aws_security_group","aws_cloudtrail"}
STRICT = {"CKV_AWS_145","CKV_AWS_18","CKV_AWS_20","CKV_AWS_16","CKV_AWS_3","CKV_AWS_2","CKV_AWS_355","CKV_AWS_63","CKV_AWS_62","CKV_AWS_260","CKV_AWS_24","CKV_AWS_25","CKV_AWS_277","CKV_AWS_251","CKV_AWS_36"}
SGI = {"CKV_AWS_260","CKV_AWS_24","CKV_AWS_25","CKV_AWS_277"}; SGC = {"aws_vpc_security_group_ingress_rule","aws_security_group_rule"}
bn = lambda c: os.path.basename(c["file_path"].replace("\\", "/")); rt = lambda c: c["resource"].split(".")[0]
ck_flag = {f: False for f in files}
for c in tf:
    if c["check_id"] in STRICT and (rt(c) in IN8 or (c["check_id"] in SGI and rt(c) in SGC)) and bn(c) in ck_flag: ck_flag[bn(c)] = True

runs = collections.defaultdict(dict)       # (prompt, run) -> file -> record
for line in open(args.runs_file, encoding="utf-8"):
    j = json.loads(line); runs[(j["prompt"], j["run"])][j["file"]] = j

def metrics(pred):
    tp = sum(lab[f] == "NON_COMPLIANT" and pred[f] for f in files); fn = sum(lab[f] == "NON_COMPLIANT" and not pred[f] for f in files)
    fp = sum(lab[f] == "COMPLIANT" and pred[f] for f in files); tn = sum(lab[f] == "COMPLIANT" and not pred[f] for f in files)
    p, r, f1 = prf(tp, fp, fn); return tp, fn, fp, tn, p, r, f1
def show(name, pred, extra=""):
    tp, fn, fp, tn, p, r, f1 = metrics(pred); pl, ph = wilson(tp, tp+fp); rl, rh = wilson(tp, tp+fn)
    print(f"{name:34} TP={tp:2} FN={fn:2} FP={fp:2} TN={tn:2}  P={p:5.1%} [{pl:.0%},{ph:.0%}]  R={r:5.1%} [{rl:.0%},{rh:.0%}]  F1={f1:5.1%} {extra}")
    return [name, tp, fn, fp, tn, f"{p:.3f}", f"{r:.3f}", f"{f1:.3f}"]

print(f"{len(files)} files ({args.subset}), {sum(v == 'NON_COMPLIANT' for v in lab.values())} NON_COMPLIANT\n")
out = [["system", "TP", "FN", "FP", "TN", "precision", "recall", "F1"]]
out.append(show("Hybrid (OPA rules)", opa_flag)); out.append(show("Checkov B2 (scope-matched)", ck_flag))
for pname in ("p1", "p2"):
    keys = sorted(k for k in runs if k[0] == pname)
    if not keys: continue
    pr, parse_fail, rule_sets = {}, 0, {}
    for k in keys:
        rec = runs[k]; pred = {}; rs = {}
        for f in files:
            r = rec.get(f)
            if r is None or not r["ok"]: parse_fail += 1; pred[f] = False; rs[f] = set(); continue
            v = r["violations"] or []
            if pname == "p1":
                good = [x for x in v if isinstance(x, dict) and x.get("check") in VALID]
                rs[f] = {x["check"] for x in good}; pred[f] = bool(good)
            else:
                pred[f] = bool(v); rs[f] = set()
        pr[k] = pred; rule_sets[k] = rs
    print(f"--- LLM only, prompt {pname} ({len(keys)} runs) ---")
    for k in keys: out.append(show(f"LLM-only {pname} run {k[1]}", pr[k]))
    maj = {f: sum(pr[k][f] for k in keys) * 2 > len(keys) for f in files}
    out.append(show(f"LLM-only {pname} majority vote", maj))
    b = sum(opa_flag[f] == (lab[f] == "NON_COMPLIANT") and maj[f] != (lab[f] == "NON_COMPLIANT") for f in files)
    c = sum(opa_flag[f] != (lab[f] == "NON_COMPLIANT") and maj[f] == (lab[f] == "NON_COMPLIANT") for f in files)
    print(f"   McNemar, hybrid vs LLM-only {pname} (majority): b={b} (only hybrid right) c={c} (only LLM right) p={mcnemar(b, c):.3g}")
    unan = sum(len({pr[k][f] for k in keys}) == 1 for f in files)
    print(f"   consistency: identical verdict across all runs on {unan}/{len(files)} files ({unan/len(files):.0%}); parse failures: {parse_fail}/{len(files)*len(keys)} calls")
    if pname == "p1":
        jac = []
        for f in files:
            for a, b2 in itertools.combinations(keys, 2):
                u = rule_sets[a][f] | rule_sets[b2][f]; jac.append(1.0 if not u else len(rule_sets[a][f] & rule_sets[b2][f]) / len(u))
        print(f"   mean pairwise Jaccard of reported check sets across runs: {sum(jac)/len(jac):.2f}")
        ok = tot = tpok = tptot = 0
        for k in keys:
            for f in files:
                r = runs[k].get(f)
                if not r or not r["ok"]: continue
                for x in r["violations"] or []:
                    if isinstance(x, dict) and x.get("check") in VALID:
                        tot += 1; good = str(x.get("nist_control", "")).strip().upper() == EXPECT[x["check"]]; ok += good
                        if HAS_RULES and x["check"] in hrules[f]: tptot += 1; tpok += good
        print(f"   NIST mapping chosen by the model: {ok}/{tot} correct overall ({ok/max(tot,1):.0%})" + (f"; {tpok}/{tptot} on true findings ({tpok/max(tptot,1):.0%})" if HAS_RULES else "") + "   [hybrid: 100% by construction, lookup table]")
        def rule_pr(sets):
            tp = sum(len(sets[f] & hrules[f]) for f in files); fp = sum(len(sets[f] - hrules[f]) for f in files); fn = sum(len(hrules[f] - sets[f]) for f in files); return prf(tp, fp, fn)
        if HAS_RULES:
            po, ro, fo = rule_pr(opa_rules); print(f"   RULE-LEVEL vs human rules: hybrid P={po:.0%} R={ro:.0%} F1={fo:.0%}")
            for k in keys: pp, rr, ff = rule_pr(rule_sets[k]); print(f"                             LLM-only run {k[1]}: P={pp:.0%} R={rr:.0%} F1={ff:.0%}")
        else:
            print("   (rule-level metrics skipped: pass --labels human_labels_90_with_rules.csv to include them)")
    print()
calls = sum(len(v) for v in runs.values())
print(f"API calls: LLM-only {calls}; hybrid pipeline: 16 enrichment calls in total (one per violation type), detection by OPA with 0 calls")
with open("llm_only_results.csv", "w", newline="", encoding="utf-8") as f: csv.writer(f).writerows(out)
print("Wrote llm_only_results.csv")