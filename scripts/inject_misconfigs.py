import os
import shutil
import json
import csv

# We take IaC-Eval .tf files as BASE (realistic Terraform)
# Then inject known misconfigurations to create labeled ground truth
# This is standard practice - same approach as Toprani & Madisetti [13]

os.makedirs("terraform/non_compliant", exist_ok=True)
os.makedirs("terraform/compliant", exist_ok=True)

ground_truth = []

# ── COMPLIANT FILES (use IaC-Eval originals as-is) ──────────────────
compliant_templates = [
    ("scenario_009.tf", "aws_s3_bucket"),
    ("scenario_010.tf", "aws_s3_bucket"),
    ("scenario_011.tf", "aws_db_instance"),
    ("scenario_034.tf", "aws_cloudtrail"),
    ("scenario_060.tf", "aws_iam_role"),
    ("scenario_062.tf", "aws_s3_bucket"),
]

for fname, resource in compliant_templates:
    src = f"terraform/compliant/{fname}"
    if os.path.exists(src):
        ground_truth.append({
            "file": fname,
            "label": "COMPLIANT",
            "injected_violation": "none",
            "nist_control": "none",
            "resource": resource
        })

# ── NON-COMPLIANT FILES (crafted with known misconfigs) ──────────────

non_compliant = [

    # SC-28: S3 bucket with no encryption block
    ("nc_s3_no_encryption.tf", """
resource "aws_s3_bucket" "example" {
  bucket = "my-insecure-bucket"
  acl    = "private"
}
""", "aws_s3_bucket", "SC-28", "s3_missing_encryption"),

    # SC-28: RDS with encryption disabled
    ("nc_rds_no_encryption.tf", """
resource "aws_db_instance" "example" {
  identifier        = "mydb"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "password123"
  storage_encrypted = false
}
""", "aws_db_instance", "SC-28", "rds_missing_encryption"),

    # SC-28: EBS volume not encrypted
    ("nc_ebs_no_encryption.tf", """
resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}
""", "aws_ebs_volume", "SC-28", "ebs_missing_encryption"),

    # AC-3: S3 bucket with no public access block
    ("nc_s3_public_access.tf", """
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
""", "aws_s3_bucket", "AC-3", "s3_public_access_not_blocked"),

    # AC-6: IAM policy with wildcard permissions
    ("nc_iam_wildcard.tf", """
resource "aws_iam_role_policy" "admin_policy" {
  name = "admin-policy"
  role = aws_iam_role.example.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
""", "aws_iam_role_policy", "AC-6", "wildcard_iam_policy"),

    # AC-3: Security group with open ingress
    ("nc_sg_open_ingress.tf", """
resource "aws_security_group" "open_sg" {
  name        = "open-security-group"
  description = "Allows all inbound traffic"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""", "aws_security_group", "AC-3", "unrestricted_ingress"),

    # AU-2: CloudTrail logging disabled
    ("nc_cloudtrail_no_logging.tf", """
resource "aws_cloudtrail" "example" {
  name                          = "my-trail"
  s3_bucket_name                = "my-bucket"
  enable_logging                = false
  include_global_service_events = false
  enable_log_file_validation    = false
}
""", "aws_cloudtrail", "AU-2", "cloudtrail_logging_disabled"),

    # AU-12: S3 bucket with no logging block
    ("nc_s3_no_logging.tf", """
resource "aws_s3_bucket" "nolog_bucket" {
  bucket = "bucket-without-logging"
  acl    = "private"
}
""", "aws_s3_bucket", "AU-12", "s3_logging_disabled"),

    # AU-9: CloudTrail no log file validation
    ("nc_cloudtrail_no_validation.tf", """
resource "aws_cloudtrail" "example" {
  name                          = "my-trail"
  s3_bucket_name                = "my-bucket"
  enable_logging                = true
  include_global_service_events = true
  enable_log_file_validation    = false
}
""", "aws_cloudtrail", "AU-9", "cloudtrail_no_log_validation"),

    # SC-8: Load balancer not using HTTPS
    ("nc_lb_no_https.tf", """
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.example.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }
}
""", "aws_lb_listener", "SC-8", "lb_not_using_https"),

    # Multiple violations: S3 no encryption + no logging
    ("nc_s3_multiple_violations.tf", """
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "totally-insecure-bucket"
  acl    = "public-read"
}
resource "aws_iam_role_policy" "bad_policy" {
  name = "bad-policy"
  role = "some-role"
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
}
""", "aws_s3_bucket", "SC-28,AC-3,AC-6,AU-12", "multiple_violations"),

    # SC-28: RDS with no encryption specified at all
    ("nc_rds_no_encryption_2.tf", """
resource "aws_db_instance" "unencrypted" {
  identifier        = "prod-db"
  engine            = "postgres"
  instance_class    = "db.t3.small"
  allocated_storage = 100
  username          = "dbadmin"
  password          = "supersecret"
}
""", "aws_db_instance", "SC-28", "rds_missing_encryption"),

    # AC-3: Another open security group (SSH open to world)
    ("nc_sg_ssh_open.tf", """
resource "aws_security_group" "ssh_open" {
  name = "ssh-open"
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""", "aws_security_group", "AC-3", "unrestricted_ingress"),

    # AU-2 + AU-9: CloudTrail misconfigured
    ("nc_cloudtrail_misconfigured.tf", """
resource "aws_cloudtrail" "bad_trail" {
  name                          = "bad-trail"
  s3_bucket_name                = "trail-bucket"
  enable_logging                = false
  include_global_service_events = false
  enable_log_file_validation    = false
}
""", "aws_cloudtrail", "AU-2,AU-9", "cloudtrail_logging_disabled"),

    # SC-28: EBS not encrypted (no field at all)
    ("nc_ebs_no_field.tf", """
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-west-2a"
  size              = 100
}
""", "aws_ebs_volume", "SC-28", "ebs_missing_encryption"),
]

# Write non-compliant files
for fname, tf_content, resource, nist, rule in non_compliant:
    fpath = f"terraform/non_compliant/{fname}"
    with open(fpath, 'w') as f:
        f.write(tf_content.strip())
    ground_truth.append({
        "file": fname,
        "label": "NON_COMPLIANT",
        "injected_violation": rule,
        "nist_control": nist,
        "resource": resource
    })
    print(f"  Created: {fname} [{nist}]")

# Add compliant counterparts
compliant_tf_files = [
    ("c_s3_encrypted.tf", """
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
  acl    = "private"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_logging" "secure_bucket" {
  bucket        = aws_s3_bucket.secure_bucket.id
  target_bucket = aws_s3_bucket.secure_bucket.id
  target_prefix = "log/"
}
""", "aws_s3_bucket", "none", "none"),

    ("c_rds_encrypted.tf", """
resource "aws_db_instance" "secure_db" {
  identifier        = "secure-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "securepassword"
  storage_encrypted = true
}
""", "aws_db_instance", "none", "none"),

    ("c_cloudtrail_full.tf", """
resource "aws_cloudtrail" "secure_trail" {
  name                          = "secure-trail"
  s3_bucket_name                = "trail-bucket"
  enable_logging                = true
  include_global_service_events = true
  enable_log_file_validation    = true
}
""", "aws_cloudtrail", "none", "none"),

    ("c_sg_restricted.tf", """
resource "aws_security_group" "restricted_sg" {
  name = "restricted-sg"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
""", "aws_security_group", "none", "none"),

    ("c_ebs_encrypted.tf", """
resource "aws_ebs_volume" "secure_volume" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}
""", "aws_ebs_volume", "none", "none"),
]

for fname, tf_content, resource, nist, rule in compliant_tf_files:
    fpath = f"terraform/compliant/{fname}"
    with open(fpath, 'w') as f:
        f.write(tf_content.strip())
    ground_truth.append({
        "file": fname,
        "label": "COMPLIANT",
        "injected_violation": rule,
        "nist_control": nist,
        "resource": resource
    })
    print(f"  Created: {fname} [COMPLIANT]")

# Save ground truth CSV
with open("ground_truth.csv", 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=ground_truth[0].keys())
    writer.writeheader()
    writer.writerows(ground_truth)

nc = sum(1 for g in ground_truth if g['label'] == 'NON_COMPLIANT')
c  = sum(1 for g in ground_truth if g['label'] == 'COMPLIANT')
print(f"\nGround truth saved to ground_truth.csv")
print(f"  Non-compliant : {nc}")
print(f"  Compliant     : {c}")
print(f"  Total         : {len(ground_truth)}")