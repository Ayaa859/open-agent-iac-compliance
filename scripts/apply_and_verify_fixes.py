"""
Apply each LLM-generated remediation INSIDE a real violating Terraform file, then verify it three ways:
  1. terraform validate   (does the fixed file still validate? compared with the unmodified file)
  2. the project's own OPA rules   (is the original violation gone? is a new one introduced?)
  3. Checkov (a second, independent scanner)   (same two questions, using the mapped checks)

Run from the repo root:
    python scripts/apply_and_verify_fixes.py [--per-rule 2] [--opa opa] [--no-terraform]
Needs: opa_results.json, enriched_results.json, the terraform/ folders, policies/, normalize_tf.py,
       checkov (pip install checkov==3.3.6) and, for step 1, the terraform CLI on PATH (init downloads providers).
Writes fix_verification.csv and the modified files in fix_verification_files/.
"""
import argparse, csv, io, json, os, re, shutil, subprocess, sys, tempfile
import hcl2
sys.path.insert(0, os.getcwd()); sys.path.insert(0, os.path.join(os.getcwd(), "scripts"))
from normalize_tf import normalize_hcl2

ap = argparse.ArgumentParser()
ap.add_argument("--per-rule", type=int, default=2); ap.add_argument("--opa", default="opa")
ap.add_argument("--policies", default="policies"); ap.add_argument("--checkov", default="checkov"); ap.add_argument("--checkov-python", help="python.exe of a separate Checkov environment (runs python -m checkov.main); more robust on Windows"); ap.add_argument("--no-terraform", action="store_true"); ap.add_argument("--resume", action="store_true", help="skip violation types already in fix_verification.csv and append to it"); ap.add_argument("--no-checkov", action="store_true", help="skip the Checkov scan (Checkov columns show n/a)")
ap.add_argument("--opa-results", default="opa_results.json"); ap.add_argument("--enriched", default="enriched_results.json")
ap.add_argument("--tf-dir", default="terraform"); ap.add_argument("--out", default="fix_verification_files")
args = ap.parse_args()
sys.stdout.reconfigure(line_buffering=True)      # show progress immediately

RULE2TYPE = {"s3_missing_encryption": "aws_s3_bucket", "s3_logging_disabled": "aws_s3_bucket", "s3_public_access_not_blocked": "aws_s3_bucket",
 "rds_encryption_disabled": "aws_db_instance", "ebs_missing_encryption": "aws_ebs_volume", "ebs_encryption_disabled": "aws_ebs_volume",
 "dynamodb_encryption_disabled": "aws_dynamodb_table", "lb_not_using_https": "aws_lb_listener", "lb_protocol_missing": "aws_lb_listener",
 "wildcard_iam_policy": "aws_iam_role_policy", "unrestricted_ingress_specific_port": "aws_security_group",
 "unrestricted_ingress_all_protocols": "aws_security_group", "cloudtrail_logging_disabled": "aws_cloudtrail", "cloudtrail_not_global": "aws_cloudtrail",
 "cloudtrail_no_log_validation": "aws_cloudtrail", "cloudtrail_validation_field_missing": "aws_cloudtrail"}
RULE2CK = {"s3_missing_encryption": ["CKV_AWS_145"], "s3_logging_disabled": ["CKV_AWS_18"], "s3_public_access_not_blocked": ["CKV_AWS_20"],
 "rds_encryption_disabled": ["CKV_AWS_16"], "ebs_missing_encryption": ["CKV_AWS_3"], "ebs_encryption_disabled": ["CKV_AWS_3"],
 "dynamodb_encryption_disabled": [], "lb_not_using_https": ["CKV_AWS_2"], "lb_protocol_missing": ["CKV_AWS_2"],
 "wildcard_iam_policy": ["CKV_AWS_355", "CKV_AWS_63", "CKV_AWS_62"], "unrestricted_ingress_specific_port": ["CKV_AWS_260", "CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_277"],
 "unrestricted_ingress_all_protocols": ["CKV_AWS_260", "CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_277"], "cloudtrail_logging_disabled": ["CKV_AWS_251"],
 "cloudtrail_not_global": [], "cloudtrail_no_log_validation": ["CKV_AWS_36"], "cloudtrail_validation_field_missing": ["CKV_AWS_36"]}
MAPPED = {i for v in RULE2CK.values() for i in v} | {"CKV2_AWS_6", "CKV_AWS_67", "CKV_AWS_103"}
PKGS = {"aws_iam_role_policy": ["terraform.ac"], "aws_security_group": ["terraform.ac"], "aws_s3_bucket": ["terraform.sc", "terraform.au", "terraform.s3"],
        "aws_db_instance": ["terraform.sc"], "aws_ebs_volume": ["terraform.sc"], "aws_lb_listener": ["terraform.sc"],
        "aws_cloudtrail": ["terraform.au"], "aws_dynamodb_table": ["terraform.sc"]}

def find_block(text, rtype, rname):
    m = re.search(r'(?m)^[ \t]*resource\s+"%s"\s+"%s"\s*\{' % (re.escape(rtype), re.escape(rname)), text)
    if not m: return None
    i, depth, n = m.end(), 1, len(text)
    while i < n and depth > 0:
        c = text[i]
        h = re.match(r'<<-?\s*([A-Za-z_][A-Za-z0-9_]*)', text[i:i + 80]) if text.startswith("<<", i) else None
        if h:
            ident, j = h.group(1), text.find("\n", i) + 1
            while j < n:
                k = text.find("\n", j); k = n if k == -1 else k
                if text[j:k].strip() == ident: i = k; break
                j = k + 1
        elif c == "#" or text.startswith("//", i): i = text.find("\n", i); i = n if i == -1 else i
        elif text.startswith("/*", i): i = text.find("*/", i); i = n if i == -1 else i + 1
        elif c == '"':
            i += 1
            while i < n and text[i] != '"': i += 2 if text[i] == "\\" else 1
        elif c == "{": depth += 1
        elif c == "}": depth -= 1
        i += 1
    return (m.start(), i) if depth == 0 else None

def opa_pairs(text):
    raw = hcl2.load(io.StringIO(text)); tfj = normalize_hcl2(raw); found = set()
    pkgs = {p for t in tfj.get("resource", {}) for p in PKGS.get(t, [])}
    for pkg in sorted(pkgs):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f: json.dump(tfj, f); fn = f.name
        out = subprocess.run([args.opa, "eval", "-i", fn, "-d", args.policies, "--format", "json", f"data.{pkg}.violation"], capture_output=True, text=True, timeout=60)
        os.remove(fn)
        if out.returncode: raise RuntimeError(out.stderr[:200])
        res = json.loads(out.stdout).get("result", [])
        val = res[0]["expressions"][0]["value"] if res else []
        found |= {(v.get("rule"), v.get("resource")) for v in (val if isinstance(val, list) else val.values())}
    return found

def checkov_pairs(text):
    if args.no_checkov: return None
    d = tempfile.mkdtemp(); p = os.path.join(d, "main.tf"); open(p, "w", encoding="utf-8").write(text)
    cmd = [args.checkov_python, "-m", "checkov.main"] if args.checkov_python else [args.checkov]
    try:
        out = subprocess.run(cmd + ["-f", p, "--framework", "terraform", "--compact", "--quiet", "--skip-download", "-o", "json"], capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        shutil.rmtree(d, ignore_errors=True); print("[Checkov timed out: n/a]", end=" "); return None
    shutil.rmtree(d, ignore_errors=True)
    s = out.stdout; s = s[min([x for x in (s.find("{"), s.find("[")) if x >= 0], default=0):]
    try: j = json.loads(s)
    except Exception: return None
    j = j if isinstance(j, list) else [j]
    return {(c["check_id"], c["resource"]) for r in j for c in r.get("results", {}).get("failed_checks", []) if c["check_id"] in MAPPED}

PLUGIN_CACHE = os.path.join(tempfile.gettempdir(), "tf_plugin_cache"); os.makedirs(PLUGIN_CACHE, exist_ok=True)
def cached_aws_version():
    base = os.path.join(PLUGIN_CACHE, "registry.terraform.io", "hashicorp", "aws")
    vs = [v for v in os.listdir(base) if re.match(r"\d+\.\d+\.\d+$", v)] if os.path.isdir(base) else []
    return sorted(vs, key=lambda v: tuple(int(x) for x in v.split(".")))[-1] if vs else None

def tf_validate(text):
    # IaC-Eval files say required_version = "~> 1.9.8", which refuses newer Terraform; relax it (identically for the original and the fixed file)
    text = re.sub(r'(?m)^[ \t]*required_version[ \t]*=[ \t]*"[^"]*"[ \t]*$', "", text)
    pin = cached_aws_version()          # one provider version for every file, so nothing is downloaded again
    if pin:
        if "required_providers" not in text:
            text = 'terraform {\n  required_providers {\n    aws = {\n      source  = "hashicorp/aws"\n      version = "%s"\n    }\n  }\n}\n' % pin + text
        else:
            text = re.sub(r'(source\s*=\s*"hashicorp/aws"[^}]*?)version\s*=\s*"[^"]*"', lambda m: m.group(1) + 'version = "%s"' % pin, text, flags=re.S)
    d = tempfile.mkdtemp(); open(os.path.join(d, "main.tf"), "w", encoding="utf-8").write(text)
    env = dict(os.environ, TF_PLUGIN_CACHE_DIR=PLUGIN_CACHE, TF_IN_AUTOMATION="1")
    i = subprocess.run(["terraform", "init", "-backend=false", "-input=false", "-no-color"], cwd=d, capture_output=True, text=True, env=env, timeout=600)
    if i.returncode: shutil.rmtree(d, ignore_errors=True); return None, "init failed: " + i.stderr.strip().splitlines()[-1][:120] if i.stderr.strip() else "init failed"
    v = subprocess.run(["terraform", "validate", "-json", "-no-color"], cwd=d, capture_output=True, text=True, env=env, timeout=300)
    shutil.rmtree(d, ignore_errors=True)
    try: j = json.loads(v.stdout)
    except Exception: return None, "validate gave no JSON"
    errs = "; ".join(x.get("summary", "") + (" (" + x.get("detail", "").split("\n")[0][:70] + ")" if x.get("detail") else "") for x in j.get("diagnostics", []) if x.get("severity") == "error")
    return bool(j.get("valid")), errs[:260]

HAVE_TF = (not args.no_terraform) and shutil.which("terraform") is not None
if not args.no_terraform and not HAVE_TF: print("terraform CLI not found: skipping step 1 (use --no-terraform to silence this)")
if HAVE_TF:
    print("Preparing Terraform: the first run downloads the AWS provider (about 1-3 minutes, no output until it finishes)...")
    ok_, err_ = tf_validate('provider "aws" {\n  region = "us-east-1"\n}\n')
    print("  Terraform ready." if ok_ is not None else f"  WARNING: Terraform could not initialise ({err_}); validation results will show n/a.")
snips = {}
for r in json.load(open(args.enriched, encoding="utf-8")):
    for v in r["violations"]: snips.setdefault(v["rule"], v["remediation"])
cands = {}
for r in json.load(open(args.opa_results, encoding="utf-8")):
    if r.get("skipped"): continue
    for v in r["violations"]:
        p = os.path.join(args.tf_dir, os.path.basename(r.get("source_dir", "")), r["file"])
        if os.path.exists(p): cands.setdefault(v["rule"], []).append((os.path.getsize(p), p, r["file"], v["resource"]))
os.makedirs(args.out, exist_ok=True)
rows = []
CSV_HEAD = ["rule", "file", "resource", "terraform_status", "terraform_error", "opa_original_resolved", "opa_new_violations", "checkov_original_resolved", "checkov_new_findings", "verdict"]
done_rules = set()
if args.resume and os.path.exists("fix_verification.csv"):
    old = list(csv.reader(open("fix_verification.csv", encoding="utf-8")))[1:]
    rows = [r for r in old if r]; done_rules = {r[0] for r in rows}
    print(f"Resuming: {len(done_rules)} violation types already done: {sorted(done_rules)}")
else:
    with open("fix_verification.csv", "w", newline="", encoding="utf-8") as f: csv.writer(f).writerow(CSV_HEAD)
def save_row(row):
    with open("fix_verification.csv", "a", newline="", encoding="utf-8") as f: csv.writer(f).writerow(row)

def process(rule, path, fname, rname, text, blk, vb, eb):
    snip = re.sub(r'(resource\s+"[^"]+"\s+)"[^"]+"', lambda m: m.group(1) + '"%s"' % rname, snips[rule], count=1)
    fixed = text[:blk[0]] + snip + text[blk[1]:]
    open(os.path.join(args.out, f"{rule}__{fname}"), "w", encoding="utf-8").write(fixed)
    try: before, after = opa_pairs(text), opa_pairs(fixed)
    except Exception as e: print("  skipped (HCL/OPA error):", fname, str(e)[:60]); return False
    print(f"... {rule} / {fname}: scanning original and fixed file", end=" ")
    opa_ok = (rule, rname) not in after; opa_new = sorted({r for r, _ in (after - before)})
    cb, ca = checkov_pairs(text), checkov_pairs(fixed)
    mapped = RULE2CK[rule]
    ck_ok = "n/a" if not mapped or cb is None or ca is None else not any(i in mapped and n.split(".")[-1] == rname for i, n in ca)   # Checkov names resources "type.name"
    ck_new = sorted({i for i, _ in (ca - cb)}) if cb is not None and ca is not None else []
    tf_status, tf_err = "not_run", ""
    if HAVE_TF:
        if vb is not True: tf_status, tf_err = "baseline_invalid", eb or ""
        else:
            va, ea = tf_validate(fixed)
            tf_status, tf_err = ("ok", "") if va is True else (("fail", ea) if va is False else ("inconclusive", ea))
    hard_fail = (not opa_ok) or bool(opa_new) or ck_ok is False or bool(ck_new) or tf_status == "fail"
    verdict = "FAILS" if hard_fail else "WORKS"
    rows.append([rule, fname, rname, tf_status, tf_err, opa_ok, ";".join(opa_new), ck_ok, ";".join(ck_new), verdict]); save_row(rows[-1])
    print(f"\n{rule:36} {fname:30} terraform={tf_status:16} opa_resolved={opa_ok} opa_new={opa_new} ck_resolved={ck_ok} ck_new={ck_new} => {verdict}")
    return True

for rule in sorted(snips):
    if rule in done_rules: continue
    rtype = RULE2TYPE[rule]; done = 0; fallback = None; tried = 0
    for size, path, fname, rname in sorted(set(cands.get(rule, []))):
        if done >= args.per_rule or tried >= 8: break
        text = open(path, encoding="utf-8").read(); blk = find_block(text, rtype, rname)
        if not blk: continue
        vb, eb = (tf_validate(text) if HAVE_TF else (None, ""))
        if HAVE_TF and vb is not True:                      # the unmodified file must validate for the comparison to mean anything
            tried += 1
            if fallback is None: fallback = (path, fname, rname, text, blk, vb, eb)
            print(f"  {fname}: the original does not validate ({(eb or 'no result')[:60]}); trying another file")
            continue
        try:
            if process(rule, path, fname, rname, text, blk, vb, eb): done += 1
        except Exception as e: print(f"\n  error on {fname}: {str(e)[:100]}; moving on")
    if done == 0 and fallback:
        try: process(rule, *fallback)
        except Exception as e: print(f"\n  error on fallback {fallback[1]}: {str(e)[:100]}; moving on")

print(f"\n{len(rows)} fixes applied; WORKS: {sum(r[-1] == 'WORKS' for r in rows)}; FAILS: {sum(r[-1] == 'FAILS' for r in rows)}   -> fix_verification.csv")
print("terraform_status: ok = fixed file validates; fail = validates before the fix but not after; baseline_invalid = the original file did not validate either; inconclusive = init/validate could not run")