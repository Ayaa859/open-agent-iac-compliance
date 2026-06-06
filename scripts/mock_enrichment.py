import json
import os

# Expert-quality enrichment for all 11 violation types
# Based on NIST SP 800-53 Rev 5 official documentation

ENRICHMENT_LIBRARY = {
    "s3_missing_encryption": {
        "explanation": "S3 buckets without server-side encryption store data in plaintext, exposing sensitive information to unauthorized access if the bucket is compromised or misconfigured. Encryption at rest ensures that even if storage media is physically accessed, data remains unreadable without the encryption key. This is a critical requirement for any bucket storing sensitive, personal, or regulated data.",
        "nist_mapping": {
            "control_id": "SC-28",
            "control_name": "Protection of Information at Rest",
            "control_description": "The information system protects the confidentiality and integrity of information at rest."
        },
        "remediation": """resource "aws_s3_bucket" "example" {
  bucket = "my-secure-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}"""
    },

    "rds_encryption_disabled": {
        "explanation": "RDS instances with storage encryption disabled store database files, backups, and snapshots in plaintext on disk. If the underlying storage is accessed by an unauthorized party, all data including credentials and sensitive records would be fully exposed. Enabling encryption at rest is a fundamental database security control required by most regulatory frameworks.",
        "nist_mapping": {
            "control_id": "SC-28",
            "control_name": "Protection of Information at Rest",
            "control_description": "The information system protects the confidentiality and integrity of information at rest."
        },
        "remediation": """resource "aws_db_instance" "example" {
  identifier        = "mydb"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "securepassword"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}"""
    },

    "rds_missing_encryption": {
        "explanation": "RDS instances without an explicit encryption setting may default to unencrypted storage depending on the instance type and region. Failing to specify storage_encrypted leaves the security posture of the database undefined and potentially non-compliant. Explicitly setting encryption ensures consistent enforcement regardless of default behaviors.",
        "nist_mapping": {
            "control_id": "SC-28",
            "control_name": "Protection of Information at Rest",
            "control_description": "The information system protects the confidentiality and integrity of information at rest."
        },
        "remediation": """resource "aws_db_instance" "example" {
  identifier        = "mydb"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "securepassword"
  storage_encrypted = true
}"""
    },

    "ebs_encryption_disabled": {
        "explanation": "EBS volumes with encryption explicitly disabled store all data including operating system files, application data, and swap space in plaintext. An attacker who gains access to the underlying hardware or a detached snapshot can read all volume data without restriction. EBS encryption is a zero-performance-impact control that should be enabled on all production volumes.",
        "nist_mapping": {
            "control_id": "SC-28",
            "control_name": "Protection of Information at Rest",
            "control_description": "The information system protects the confidentiality and integrity of information at rest."
        },
        "remediation": """resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}"""
    },

    "ebs_missing_encryption": {
        "explanation": "EBS volumes without an explicit encryption setting rely on the account-level default encryption configuration, which may not be enabled. Omitting the encrypted attribute creates ambiguity in the security posture of the volume and may result in unencrypted storage in environments where account-level defaults have not been configured. Explicit specification is required for audit traceability.",
        "nist_mapping": {
            "control_id": "SC-28",
            "control_name": "Protection of Information at Rest",
            "control_description": "The information system protects the confidentiality and integrity of information at rest."
        },
        "remediation": """resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}"""
    },

    "lb_not_using_https": {
        "explanation": "Load balancer listeners configured with HTTP transmit all traffic including authentication tokens, session cookies, and user data in plaintext over the network. This exposes communications to interception through man-in-the-middle attacks. All public-facing load balancers must use HTTPS with a valid TLS certificate to ensure confidentiality and integrity of data in transit.",
        "nist_mapping": {
            "control_id": "SC-8",
            "control_name": "Transmission Confidentiality and Integrity",
            "control_description": "The information system implements cryptographic mechanisms to prevent unauthorized disclosure of information during transmission."
        },
        "remediation": """resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.example.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }
}"""
    },

    "wildcard_iam_policy": {
        "explanation": "IAM policies granting wildcard Action and Resource permissions effectively give the attached principal full administrative access to all AWS services and resources. This violates the principle of least privilege, creating an enormous blast radius if the credentials are compromised. Every IAM policy should grant only the minimum permissions required for the specific task the principal needs to perform.",
        "nist_mapping": {
            "control_id": "AC-6",
            "control_name": "Least Privilege",
            "control_description": "The organization employs the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned tasks."
        },
        "remediation": """resource "aws_iam_role_policy" "example" {
  name = "least-privilege-policy"
  role = aws_iam_role.example.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "s3:GetObject",
        "s3:PutObject"
      ]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}"""
    },

    "unrestricted_ingress": {
        "explanation": "Security groups permitting inbound traffic from 0.0.0.0/0 on all ports expose the associated resources to the entire internet with no network-level access restriction. This creates an unrestricted attack surface for port scanning, brute force attacks, and exploitation of any vulnerable services running on the instance. Ingress rules should always restrict source addresses to known, trusted CIDR ranges.",
        "nist_mapping": {
            "control_id": "AC-3",
            "control_name": "Access Enforcement",
            "control_description": "The information system enforces approved authorizations for logical access to information and system resources."
        },
        "remediation": """resource "aws_security_group" "example" {
  name        = "restricted-sg"
  description = "Allows only necessary inbound traffic"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "HTTPS from internal network only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}"""
    },

    "unrestricted_ingress_all_protocols": {
        "explanation": "Security groups using protocol -1 permit all traffic types including ICMP, UDP, and TCP from any source address. This completely eliminates network-level access control for the associated resources, exposing them to all forms of network-based attacks. Protocol and port restrictions are a fundamental defense-in-depth control that must be applied to all security groups.",
        "nist_mapping": {
            "control_id": "AC-3",
            "control_name": "Access Enforcement",
            "control_description": "The information system enforces approved authorizations for logical access to information and system resources."
        },
        "remediation": """resource "aws_security_group" "example" {
  name = "restricted-sg"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}"""
    },

    "cloudtrail_logging_disabled": {
        "explanation": "CloudTrail trails with logging disabled stop recording API activity across the AWS account, creating blind spots in audit coverage. Security incidents, unauthorized access, and configuration changes occurring during logging outages cannot be investigated or attributed. Continuous CloudTrail logging is a foundational requirement for incident response and forensic investigation capabilities.",
        "nist_mapping": {
            "control_id": "AU-2",
            "control_name": "Event Logging",
            "control_description": "The organization determines that the information system is capable of auditing defined auditable events."
        },
        "remediation": """resource "aws_cloudtrail" "example" {
  name                          = "secure-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  enable_logging                = true
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}"""
    },

    "cloudtrail_not_global": {
        "explanation": "CloudTrail trails not configured to log global service events miss API activity for services such as IAM, STS, and CloudFront, which operate globally rather than in a specific region. IAM events in particular are critical for detecting privilege escalation and unauthorized credential usage. Enabling global service event logging ensures complete audit coverage across all AWS service categories.",
        "nist_mapping": {
            "control_id": "AU-2",
            "control_name": "Event Logging",
            "control_description": "The organization determines that the information system is capable of auditing defined auditable events."
        },
        "remediation": """resource "aws_cloudtrail" "example" {
  name                          = "secure-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  enable_logging                = true
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}"""
    },

    "cloudtrail_no_log_validation": {
        "explanation": "CloudTrail log file validation uses cryptographic hashing to detect whether log files have been modified, deleted, or forged after delivery to S3. Without validation enabled, an attacker who gains write access to the log bucket can tamper with audit records to conceal malicious activity. Log file integrity validation is essential for maintaining the trustworthiness of audit evidence.",
        "nist_mapping": {
            "control_id": "AU-9",
            "control_name": "Protection of Audit Information",
            "control_description": "The information system protects audit information and audit tools from unauthorized access, modification, and deletion."
        },
        "remediation": """resource "aws_cloudtrail" "example" {
  name                          = "secure-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  enable_logging                = true
  include_global_service_events = true
  enable_log_file_validation    = true
}"""
    },

    "s3_logging_disabled": {
        "explanation": "S3 buckets without access logging do not record requests made against the bucket, preventing detection of unauthorized access attempts, data exfiltration, or misconfigured permissions. Access logs provide an audit trail of all GET, PUT, and DELETE operations that is essential for security investigations and compliance reporting. Logging should be enabled on all buckets storing sensitive or regulated data.",
        "nist_mapping": {
            "control_id": "AU-12",
            "control_name": "Audit Record Generation",
            "control_description": "The information system generates audit records for the events defined in AU-2 with the content defined in AU-3."
        },
        "remediation": """resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.example.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}"""
    },

    "s3_public_access_not_blocked": {
        "explanation": "S3 buckets with public-read ACL but without a public access block configuration can expose all stored objects to anonymous internet access. Even if the bucket was intentionally made public, the absence of an explicit public access block allows future policy changes or misconfiguration to inadvertently expose sensitive data. The public access block provides a safety mechanism that prevents accidental public exposure.",
        "nist_mapping": {
            "control_id": "AC-3",
            "control_name": "Access Enforcement",
            "control_description": "The information system enforces approved authorizations for logical access to information and system resources."
        },
        "remediation": """resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}"""
    }
}

# Load OPA results
with open("opa_results.json") as f:
    opa_results = json.load(f)

files_with_violations = [
    r for r in opa_results
    if r["violation_count"] > 0 and not r.get("skipped")
]

print(f"Files with violations: {len(files_with_violations)}")
print(f"Total violations: {sum(r['violation_count'] for r in files_with_violations)}")
print(f"Enrichment library covers: {len(ENRICHMENT_LIBRARY)} violation types")
print("-" * 50)

enriched_results = []
enriched_count = 0
not_found = set()

for r in files_with_violations:
    enriched_violations = []
    for v in r["violations"]:
        rule = v.get("rule", "")
        nist = v.get("nist_control", "")

        if rule in ENRICHMENT_LIBRARY:
            cached = ENRICHMENT_LIBRARY[rule]
            enriched_count += 1
            print(f"   {r['file']} | {rule} | {nist}")
        else:
            cached = {
                "explanation": v.get("message", ""),
                "nist_mapping": {
                    "control_id": nist,
                    "control_name": "See NIST SP 800-53",
                    "control_description": v.get("message", "")
                },
                "remediation": "Review AWS security best practices"
            }
            not_found.add(rule)

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

total = sum(r['violation_count'] for r in enriched_results)

print("-" * 50)
print(f" Done!")
print(f"   Total violations enriched : {enriched_count}")
print(f"   Total violations          : {total}")
print(f"   Saved to                  : enriched_results.json")
if not_found:
    print(f"   Rules not in library      : {not_found}")
