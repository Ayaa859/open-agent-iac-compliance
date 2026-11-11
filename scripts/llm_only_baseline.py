"""
LLM-only baseline: the SAME model as the hybrid pipeline (Llama 3.3 70B on Cloudflare Workers AI, temperature 0.1)
reads each Terraform file directly, with NO policy engine.  Run from the repo root:

    set CF_ACCOUNT_ID and CF_API_TOKEN as environment variables first (never write them in the code), then
    python scripts/llm_only_baseline.py --subset random60 --runs 3

Prompts:  p1 = the 12 checks are listed (same rules as the framework, no control IDs: the model must choose them)
          p2 = open prompt: "find AC / SC / AU violations" with no rule list
Output :  llm_only_runs.jsonl  (one line per call; the script resumes if interrupted)
Use --dry-run to test the pipeline without any network call.
"""
import argparse, csv, glob, json, os, random, sys, time

CHECKS = {
 "S3-ENC": "S3 bucket without server-side encryption configured",
 "S3-LOG": "S3 bucket without access logging",
 "S3-PUB": "S3 bucket exposed publicly (public-read ACL, or public access not blocked)",
 "RDS-ENC": "RDS instance (aws_db_instance) without storage encryption",
 "EBS-ENC": "EBS volume without encryption",
 "DDB-ENC": "DynamoDB table with server-side encryption disabled",
 "LB-TLS": "load balancer listener not using HTTPS/TLS",
 "IAM-WILD": "IAM role policy granting wildcard (*) permissions",
 "SG-OPEN": "security group allowing ingress from 0.0.0.0/0",
 "CT-LOG": "CloudTrail logging disabled",
 "CT-GLOBAL": "CloudTrail not logging global service events",
 "CT-VALID": "CloudTrail log file validation disabled"}
SYSTEM = "You are a cloud security expert specializing in NIST SP 800-53 compliance. Always respond with valid JSON only, no markdown, no extra text."
TYPES = "aws_s3_bucket, aws_db_instance, aws_ebs_volume, aws_dynamodb_table, aws_lb_listener, aws_iam_role_policy, aws_security_group, aws_cloudtrail"

def prompt_p1(code):
    checks = "\n".join(f"- {k}: {v}" for k, v in CHECKS.items())
    return f"""Review the Terraform configuration below. Only consider resources of these types: {TYPES}.
Report every violation of the following checks:
{checks}

For each violation give the check id, the resource name, the NIST SP 800-53 Rev. 5 control id that applies (you must choose it), and a one-sentence explanation.
If there are no violations, return an empty list.
Respond ONLY with JSON: {{"violations": [{{"check": "S3-ENC", "resource": "name", "nist_control": "SC-28", "explanation": "..."}}]}}

Terraform configuration:
{code}"""

def prompt_p2(code):
    return f"""Review the Terraform configuration below for compliance violations against the NIST SP 800-53 Rev. 5 control families AC (Access Control), SC (System and Communications Protection) and AU (Audit and Accountability). Only consider resources of these types: {TYPES}.
For each violation give the resource name, a short description, the NIST control id, and a one-sentence explanation.
If there are no violations, return an empty list.
Respond ONLY with JSON: {{"violations": [{{"resource": "name", "description": "...", "nist_control": "SC-28", "explanation": "..."}}]}}

Terraform configuration:
{code}"""

def parse_json(raw):                      # same tolerant parser as the hybrid pipeline
    if not raw: return None
    clean = raw.strip()
    if "```" in clean:
        for part in clean.split("```"):
            if part.startswith("json"): clean = part[4:].strip(); break
            elif "{" in part: clean = part.strip(); break
    s, e = clean.find("{"), clean.rfind("}") + 1
    if s != -1 and e > s: clean = clean[s:e]
    try: return json.loads(clean)
    except Exception: return None

LAST_ERROR = ""

def call_llm(code_prompt, retries=4):
    global LAST_ERROR
    import requests
    acc, tok = os.environ.get("CF_ACCOUNT_ID"), os.environ.get("CF_API_TOKEN")
    if not acc or not tok: sys.exit("Set the CF_ACCOUNT_ID and CF_API_TOKEN environment variables first.")
    url = f"https://api.cloudflare.com/client/v4/accounts/{acc}/ai/run/@cf/meta/llama-3.3-70b-instruct-fp8-fast"
    payload = {"messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": code_prompt}],
               "max_tokens": 1024, "temperature": 0.1}
    for attempt in range(retries):
        try:
            r = requests.post(url, headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}, json=payload, timeout=60)
            if r.status_code == 429:
                LAST_ERROR = "429 " + r.text[:150]; print(f"  rate limit / quota (429), waiting {20 * (attempt + 1)}s: {r.text[:120]}"); time.sleep(20 * (attempt + 1)); continue
            if r.status_code != 200: LAST_ERROR = f"HTTP {r.status_code}: {r.text[:150]}"; print(f"  HTTP {r.status_code}: {r.text[:150]}"); return None
            resp = r.json().get("result", {}).get("response", "")
            return json.dumps(resp) if isinstance(resp, dict) else str(resp).strip()
        except Exception as ex:
            LAST_ERROR = str(ex)[:150]; print(f"  error: {ex}"); time.sleep(10)
    return None

def fake_llm(code_prompt):                # --dry-run only: crude stand-in so the pipeline can be tested offline
    v = []
    if "aws_s3_bucket" in code_prompt and "server_side_encryption" not in code_prompt: v.append({"check": "S3-ENC", "resource": "b", "nist_control": random.choice(["SC-28", "SC-28", "SC-8"]), "explanation": "x", "description": "x"})
    if "0.0.0.0/0" in code_prompt: v.append({"check": "SG-OPEN", "resource": "sg", "nist_control": "AC-3", "explanation": "x", "description": "x"})
    return json.dumps({"violations": v})

ap = argparse.ArgumentParser()
ap.add_argument("--labels", default="human_labels_90_with_rules.csv"); ap.add_argument("--subset", default="random60", help="random60, fresh30 or all")
ap.add_argument("--runs", type=int, default=3); ap.add_argument("--prompts", default="p1,p2")
ap.add_argument("--terraform-dir", default="terraform"); ap.add_argument("--out", default="llm_only_runs.jsonl")
ap.add_argument("--sleep", type=float, default=1.0); ap.add_argument("--dry-run", action="store_true")
args = ap.parse_args()

rows = [r for r in csv.DictReader(open(args.labels, encoding="utf-8-sig")) if args.subset == "all" or r["sample"] == args.subset]
done = set()
if os.path.exists(args.out):
    for line in open(args.out, encoding="utf-8"):
        j = json.loads(line)
        if j["ok"]: done.add((j["file"], j["prompt"], j["run"]))
total = len(rows) * len(args.prompts.split(",")) * args.runs
print(f"{len(rows)} files x {args.prompts} x {args.runs} runs = {total} calls ({len(done)} already done)")
n = 0
with open(args.out, "a", encoding="utf-8") as out:
    for run in range(1, args.runs + 1):
        for pname in args.prompts.split(","):
            for r in rows:
                n += 1
                if (r["file"], pname, run) in done: continue
                path = next(iter(glob.glob(os.path.join(args.terraform_dir, "*", r["file"]))), None)
                if not path: print("  missing file:", r["file"]); continue
                code = open(path, encoding="utf-8").read()
                p = prompt_p1(code) if pname == "p1" else prompt_p2(code)
                rec = {"file": r["file"], "prompt": pname, "run": run, "ok": False, "attempts": 0, "raw": "", "violations": None, "error": ""}
                for attempt in range(1, 3):                       # one retry if the output cannot be parsed
                    rec["attempts"] = attempt
                    raw = fake_llm(p) if args.dry_run else call_llm(p)
                    rec["raw"] = raw or ""
                    if not raw: rec["error"] = LAST_ERROR
                    parsed = parse_json(raw)
                    if parsed is not None and isinstance(parsed.get("violations"), list):
                        rec["violations"] = parsed["violations"]; rec["ok"] = True; break
                out.write(json.dumps(rec) + "\n"); out.flush()
                print(f"[{n}/{total}] {pname} run{run} {r['file']}: {'ok' if rec['ok'] else 'PARSE FAILURE'}")
                if not args.dry_run: time.sleep(args.sleep)
print("Done. Results in", args.out)