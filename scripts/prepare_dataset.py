import json
import os
import csv

# NIST 800-53 control mapping rules based on resource type
def get_nist_controls(resource, tf_code):
    controls = []
    code = tf_code.lower()

    # AC - Access Control
    if any(x in code for x in ['iam', 'role', 'policy', 'permission', 'assume_role']):
        controls.append('AC-6')
    if 'public' in code and ('true' in code or 'enabled' in code):
        controls.append('AC-3')

    # SC - System & Communications Protection
    if 'encrypt' not in code and any(x in resource for x in ['s3', 'rds', 'ebs', 'dynamodb']):
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

    if 'encrypted' not in code_lower and any(x in resource.lower() for x in ['s3','rds','ebs','dynamodb']):
        violations.append('missing_encryption')
    if 'logging' not in code_lower and any(x in resource.lower() for x in ['s3','lb','alb','trail']):
        violations.append('missing_logging')
    if any(x in code_lower for x in ['"*"', "'*'", '= "*"']):
        violations.append('wildcard_permission')
    if 'public_access' not in code_lower and 's3' in resource.lower():
        violations.append('public_access_not_blocked')

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
