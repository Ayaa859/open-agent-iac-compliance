import json
import os
import time
import requests

# Configure Cloudflare Workers AI
CF_ACCOUNT_ID = os.environ["CF_ACCOUNT_ID"]  
CF_API_TOKEN = os.environ["CF_API_TOKEN"]

CF_URL = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/ai/run/@cf/meta/llama-3.3-70b-instruct-fp8-fast"

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}

# Official NIST SP 800-53 Rev. 5 control names and descriptions,
# hardcoded from the authoritative catalog so the enrichment layer
# never has to rely on LLM recall for this factual lookup.
NIST_CATALOG = {
    "SC-28": {
        "control_name": "Protection of Information at Rest",
        "control_description": "The organization protects the confidentiality and integrity of information at rest."
    },
    "SC-8": {
        "control_name": "Transmission Confidentiality and Integrity",
        "control_description": "The information system protects the confidentiality and integrity of transmitted information."
    },
    "AC-6": {
        "control_name": "Least Privilege",
        "control_description": "The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks."
    },
    "AC-3": {
        "control_name": "Access Enforcement",
        "control_description": "The information system enforces approved authorizations for logical access to information and system resources."
    },
    "AU-2": {
        "control_name": "Event Logging",
        "control_description": "The organization identifies the types of events that the system is capable of logging."
    },
    "AU-9": {
        "control_name": "Protection of Audit Information",
        "control_description": "The information system protects audit information and audit logging tools from unauthorized access, modification, and deletion."
    },
    "AU-12": {
        "control_name": "Audit Record Generation",
        "control_description": "The information system provides audit record generation capability for the auditable events defined by the organization."
    },
}

def call_llm(prompt, retries=3):
    payload = {
        "messages": [
            {"role": "system", "content": "You are a cloud security expert specializing in NIST SP 800-53 compliance. Always respond with valid JSON only, no markdown, no extra text."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 1024,
        "temperature": 0.1
    }
    for attempt in range(retries):
        try:
            response = requests.post(CF_URL, headers=HEADERS, json=payload, timeout=30)
            if response.status_code == 429:
                wait = 20 * (attempt + 1)
                print(f"  Rate limit, waiting {wait}s...")
                time.sleep(wait)
                continue
            if response.status_code != 200:
                print(f"  HTTP error {response.status_code}: {response.text[:200]}")
                return None
            data = response.json()
            result = data.get("result", {})
            response_data = result.get("response", "")
            if isinstance(response_data, dict):
                return json.dumps(response_data)
            elif isinstance(response_data, str):
                return response_data.strip()
            return str(response_data).strip()
        except Exception as e:
            print(f"  Error: {e}")
            time.sleep(10)
    return None

def parse_json(raw):
    if not raw:
        return None
    clean = raw.strip()
    if "```" in clean:
        parts = clean.split("```")
        for part in parts:
            if part.startswith("json"):
                clean = part[4:].strip()
                break
            elif "{" in part:
                clean = part.strip()
                break
    start = clean.find("{")
    end   = clean.rfind("}") + 1
    if start != -1 and end > start:
        clean = clean[start:end]
    try:
        return json.loads(clean)
    except:
        return None

# Load OPA results
with open("opa_results.json") as f:
    opa_results = json.load(f)

files_with_violations = [
    r for r in opa_results
    if r["violation_count"] > 0 and not r.get("skipped")
]

print(f"Files with violations : {len(files_with_violations)}")
print(f"Total violations      : {sum(r['violation_count'] for r in files_with_violations)}")

# Collect unique rule types
unique_rules = {}
for r in files_with_violations:
    for v in r["violations"]:
        key = (v.get("rule",""), v.get("nist_control",""))
        if key not in unique_rules:
            unique_rules[key] = {
                "rule":         v.get("rule",""),
                "nist_control": v.get("nist_control",""),
                "severity":     v.get("severity",""),
                "message":      v.get("message","")
            }

print(f"Unique violation types: {len(unique_rules)}")
print("-" * 50)

# Enrich each unique rule once
enrichment_cache = {}

for key, vinfo in unique_rules.items():
    rule     = vinfo["rule"]
    nist     = vinfo["nist_control"]
    severity = vinfo["severity"]
    message  = vinfo["message"]

    prompt = f"""A Policy-as-Code engine detected this violation in a Terraform configuration:

Rule: {rule}
NIST Control: {nist}
Severity: {severity}
Message: {message}

Respond ONLY with this JSON object:
{{
  "explanation": "2-3 sentence plain English explanation of why this is a security risk",
  "nist_mapping": {{
    "control_id": "{nist}",
    "control_name": "the official NIST SP 800-53 control name",
    "control_description": "one sentence description of what this control requires"
  }},
  "remediation": "a complete, corrected Terraform resource block"
}}

STRICT REQUIREMENTS for the "remediation" field:
- It must contain ONLY valid HashiCorp Configuration Language (HCL) syntax, exactly as it would appear in a real .tf file.
- Do NOT include markdown code fences (no ```), backticks, or any explanatory prose or sentences.
- Do NOT use semicolons to separate arguments; each argument goes on its own line.
- Write the FULL resource block (resource "type" "name" {{ ... }}), not just the single changed argument or a description of the change.
- Example of correct format for this field: "resource \\"aws_s3_bucket\\" \\"example\\" {{\\n  bucket = \\"my-bucket\\"\\n}}"

Return only the JSON, no markdown, no extra text."""

    print(f"  Processing: {rule} | {nist}")
    raw = call_llm(prompt)
    parsed = parse_json(raw)

    if parsed:
        # Override the LLM's control_id/control_name/control_description
        # with the authoritative NIST catalog entry, keyed on the control
        # identifier already known from the Rego policy library (not LLM-guessed).
        catalog_entry = NIST_CATALOG.get(nist, {})
        parsed["nist_mapping"] = {
            "control_id": nist,
            "control_name": catalog_entry.get("control_name", parsed.get("nist_mapping", {}).get("control_name", "")),
            "control_description": catalog_entry.get("control_description", parsed.get("nist_mapping", {}).get("control_description", ""))
        }
        enrichment_cache[key] = parsed
        print(f"  Done: {rule} | {nist}")
    else:
        catalog_entry = NIST_CATALOG.get(nist, {})
        enrichment_cache[key] = {
            "explanation": message,
            "nist_mapping": {
                "control_id": nist,
                "control_name": catalog_entry.get("control_name", "See NIST SP 800-53"),
                "control_description": catalog_entry.get("control_description", message)
            },
            "remediation": "Review AWS security best practices"
        }
        print(f"  Fallback used: {rule} | {nist}")

    time.sleep(1)

# Apply cache to all violations
print(f"\nApplying enrichment to all violations...")

enriched_results = []
for r in files_with_violations:
    enriched_violations = []
    for v in r["violations"]:
        key = (v.get("rule",""), v.get("nist_control",""))
        cached = enrichment_cache.get(key, {})
        enriched_violations.append({
            **v,
            "explanation":  cached.get("explanation", ""),
            "nist_mapping": cached.get("nist_mapping", {}),
            "remediation":  cached.get("remediation", "")
        })
    enriched_results.append({
        **r,
        "violations": enriched_violations
    })

with open("enriched_results.json", "w") as f:
    json.dump(enriched_results, f, indent=2)

total_enriched = sum(r['violation_count'] for r in enriched_results)
successful = sum(1 for v in enrichment_cache.values()
                 if v.get("nist_mapping", {}).get("control_name") not in ("See NIST SP 800-53", ""))

print("-" * 50)
print(f"Done.")
print(f"  Unique rules enriched     : {len(unique_rules)}")
print(f"  Successfully via LLM      : {successful}")
print(f"  Total violations enriched : {total_enriched}")
print(f"  Saved to                  : enriched_results.json")
