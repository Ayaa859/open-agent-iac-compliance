import json
import os
import csv
import re

# Matches the content of each "ingress { ... }" block. This assumes ingress
# blocks are flat (from_port, to_port, protocol, cidr_blocks, description)
# with no nested sub-blocks, which holds for the AC-3 patterns this mirrors.
INGRESS_BLOCK_RE = re.compile(r'ingress\s*\{([^}]*)\}', re.IGNORECASE | re.DOTALL)

def has_unrestricted_ingress(tf_code):
    """
    Heuristic counterpart to the unrestricted_ingress_specific_port and
    unrestricted_ingress_all_protocols Rego rules in ac_access_control.rego.
    Checks only inside ingress { } blocks so an open egress rule (very common
    and not a violation) is never mistaken for an open inbound rule.
    """
    for block in INGRESS_BLOCK_RE.findall(tf_code):
        if '0.0.0.0/0' in block:
            return True
    return False

# NIST 800-53 control mapping rules based on resource type
def get_nist_controls(resource, tf_code):
    controls = []
    code = tf_code.lower()

    # AC - Access Control
    if any(x in code for x in ['iam', 'role', 'policy', 'permission', 'assume_role']):
        controls.append('AC-6')
    if 'public' in code and ('true' in code or 'enabled' in code):
        controls.append('AC-3')
    if 'security_group' in resource.lower() and has_unrestricted_ingress(tf_code):
        controls.append('AC-3')

    # SC - System & Communications Protection
    if 'encrypt' not in code and any(x in resource for x in ['s3', 'rds', 'ebs']):
        controls.append('SC-28')
    # DynamoDB defaults to encrypted; only an explicit disable is a violation.
    if 'dynamodb' in resource and 'server_side_encryption' in code \
            and ('enabled = false' in code or 'enabled=false' in code):
        controls.append('SC-28')
    if 'ssl' not in code and 'tls' not in code and any(x in resource for x in ['lb', 'alb', 'elb']):
        controls.append('SC-8')

    # AU - Audit & Accountability
    if any(x in resource for x in ['cloudtrail', 'cloudwatch', 'log']):
        controls.append('AU-2')
    if 'logging' not in code and any(x in resource for x in ['s3', 'lb', 'alb']):
        controls.append('AU-12')

    return controls if controls else ['NONE']

# Create output folders
os.makedirs("terraform/compliant", exist_ok=True)
os.makedirs("terraform/non_compliant", exist_ok=True)

annotations = []
skipped = 0

for i in range(458):
    path = f"iac_dataset/scenario_{i:03d}.json"
    if not os.path.exists(path):
        skipped += 1
        continue

    with open(path) as f:
        entry = json.load(f)

    resource   = entry.get('Resource', 'unknown')
    tf_code    = entry.get('Reference output', '')
    intent     = entry.get('Intent', '')
    difficulty = entry.get('Difficulty', '')

    if not tf_code or len(tf_code) < 20:
        skipped += 1
        continue

    # Detect likely violations
    code_lower = tf_code.lower()
    violations = []

    if 'encrypted' not in code_lower and any(x in resource.lower() for x in ['s3','rds','ebs']):
        violations.append('missing_encryption')
    # DynamoDB is encrypted by default (AWS-owned key) even when the
    # server_side_encryption block is absent, so absence of the keyword
    # does NOT indicate non-compliance here. Only an explicit disable does,
    # matching the dynamodb_encryption_disabled Rego rule.
    if 'dynamodb' in resource.lower() and 'server_side_encryption' in code_lower \
            and ('enabled = false' in code_lower or 'enabled=false' in code_lower):
        violations.append('dynamodb_encryption_disabled')
    if 'logging' not in code_lower and any(x in resource.lower() for x in ['s3','lb','alb','trail']):
        violations.append('missing_logging')
    if any(x in code_lower for x in ['"*"', "'*'", '= "*"']):
        violations.append('wildcard_permission')
    if 'public_access' not in code_lower and 's3' in resource.lower():
        violations.append('public_access_not_blocked')
    # AC-3: mirrors unrestricted_ingress_specific_port / unrestricted_ingress_all_protocols.
    # Checked inside ingress { } blocks only, so an open egress rule (common
    # and not itself a violation) doesn't get mistaken for an open inbound rule.
    if 'security_group' in resource.lower() and has_unrestricted_ingress(tf_code):
        violations.append('unrestricted_ingress')

    is_compliant = len(violations) == 0
    nist_controls = get_nist_controls(resource, tf_code)

    # Save .tf file
    label = "compliant" if is_compliant else "non_compliant"
    tf_filename = f"terraform/{label}/scenario_{i:03d}.tf"
    with open(tf_filename, 'w') as f:
        f.write(tf_code)

    annotations.append({
        'scenario_id': f"scenario_{i:03d}",
        'resource': resource,
        'difficulty': difficulty,
        'compliant': is_compliant,
        'violations': ', '.join(violations) if violations else 'none',
        'nist_controls': ', '.join(nist_controls),
        'intent': (intent or '')[:100]
    })

# Save annotation CSV
with open('dataset_annotations.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=annotations[0].keys())
    writer.writeheader()
    writer.writerows(annotations)

compliant_count = sum(1 for a in annotations if a['compliant'])
non_compliant_count = sum(1 for a in annotations if not a['compliant'])

print(f" Done!")
print(f"   Total processed : {len(annotations)}")
print(f"   Compliant       : {compliant_count}")
print(f"   Non-compliant   : {non_compliant_count}")
print(f"   Skipped         : {skipped}")
print(f"   Saved to        : terraform/ and dataset_annotations.csv")
