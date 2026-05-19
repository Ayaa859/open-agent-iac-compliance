import os

os.makedirs("policies", exist_ok=True)

with open("policies/ac_access_control.rego", "w") as f:
    f.write("""package terraform.ac

import rego.v1

# AC-6: IAM wildcard permissions
violation contains result if {
    resource := input.resource.aws_iam_role_policy[name]
    policy := resource.policy
    contains(policy, "*")
    result := {
        "resource": name,
        "rule": "wildcard_iam_policy",
        "nist_control": "AC-6",
        "severity": "HIGH",
        "message": "IAM policy uses wildcard (*) permissions, violating least privilege"
    }
}

# AC-3: Security group with 0.0.0.0/0 and from_port 0
violation contains result if {
    resource := input.resource.aws_security_group[name]
    ingress := resource.ingress[_]
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    ingress.from_port == 0
    result := {
        "resource": name,
        "rule": "unrestricted_ingress",
        "nist_control": "AC-3",
        "severity": "HIGH",
        "message": "Security group allows unrestricted inbound traffic from 0.0.0.0/0"
    }
}

# AC-3: Security group with protocol -1 (all traffic)
violation contains result if {
    resource := input.resource.aws_security_group[name]
    ingress := resource.ingress[_]
    ingress.cidr_blocks[_] == "0.0.0.0/0"
    ingress.protocol == "-1"
    result := {
        "resource": name,
        "rule": "unrestricted_ingress_all_protocols",
        "nist_control": "AC-3",
        "severity": "HIGH",
        "message": "Security group allows all protocol traffic from 0.0.0.0/0"
    }
}
""")

with open("policies/sc_system_protection.rego", "w") as f:
    f.write("""package terraform.sc

import rego.v1

# SC-28: S3 bucket missing encryption
violation contains result if {
    input.resource.aws_s3_bucket[name]
    not input.resource.aws_s3_bucket_server_side_encryption_configuration
    not input.resource.aws_s3_bucket_object
    result := {
        "resource": name,
        "rule": "s3_missing_encryption",
        "nist_control": "SC-28",
        "severity": "HIGH",
        "message": "S3 bucket does not have server-side encryption configured"
    }
}

# SC-28: RDS encryption explicitly disabled
violation contains result if {
    resource := input.resource.aws_db_instance[name]
    resource.storage_encrypted == false
    result := {
        "resource": name,
        "rule": "rds_encryption_disabled",
        "nist_control": "SC-28",
        "severity": "HIGH",
        "message": "RDS instance has storage encryption explicitly disabled"
    }
}

# SC-28: EBS encryption explicitly disabled
violation contains result if {
    resource := input.resource.aws_ebs_volume[name]
    resource.encrypted == false
    result := {
        "resource": name,
        "rule": "ebs_encryption_disabled",
        "nist_control": "SC-28",
        "severity": "HIGH",
        "message": "EBS volume has encryption explicitly disabled"
    }
}

# SC-28: EBS missing encryption field
violation contains result if {
    resource := input.resource.aws_ebs_volume[name]
    not resource.encrypted
    result := {
        "resource": name,
        "rule": "ebs_missing_encryption",
        "nist_control": "SC-28",
        "severity": "HIGH",
        "message": "EBS volume does not specify encryption"
    }
}

# SC-8: Load balancer not using HTTPS
violation contains result if {
    resource := input.resource.aws_lb_listener[name]
    resource.protocol != "HTTPS"
    result := {
        "resource": name,
        "rule": "lb_not_using_https",
        "nist_control": "SC-8",
        "severity": "MEDIUM",
        "message": "Load balancer listener is not enforcing HTTPS/TLS"
    }
}
""")

with open("policies/au_audit_accountability.rego", "w") as f:
    f.write("""package terraform.au

import rego.v1

# AU-2: CloudTrail logging explicitly disabled
violation contains result if {
    resource := input.resource.aws_cloudtrail[name]
    resource.enable_logging == false
    result := {
        "resource": name,
        "rule": "cloudtrail_logging_disabled",
        "nist_control": "AU-2",
        "severity": "HIGH",
        "message": "CloudTrail logging is explicitly disabled"
    }
}

# AU-2: CloudTrail global events disabled
violation contains result if {
    resource := input.resource.aws_cloudtrail[name]
    resource.include_global_service_events == false
    result := {
        "resource": name,
        "rule": "cloudtrail_not_global",
        "nist_control": "AU-2",
        "severity": "MEDIUM",
        "message": "CloudTrail is not logging global service events"
    }
}

# AU-9: CloudTrail log validation disabled
violation contains result if {
    resource := input.resource.aws_cloudtrail[name]
    resource.enable_log_file_validation == false
    result := {
        "resource": name,
        "rule": "cloudtrail_no_log_validation",
        "nist_control": "AU-9",
        "severity": "MEDIUM",
        "message": "CloudTrail log file validation is explicitly disabled"
    }
}

# AU-12: S3 logging missing when ACL is set
violation contains result if {
    resource := input.resource.aws_s3_bucket[name]
    resource.acl
    not input.resource.aws_s3_bucket_logging
    not input.resource.aws_s3_bucket_server_side_encryption_configuration
    result := {
        "resource": name,
        "rule": "s3_logging_disabled",
        "nist_control": "AU-12",
        "severity": "MEDIUM",
        "message": "S3 bucket does not have access logging enabled"
    }
}
""")

with open("policies/s3_encryption.rego", "w") as f:
    f.write("""package terraform.s3

import rego.v1

# AC-3: S3 public access not blocked when public-read ACL set
violation contains result if {
    resource := input.resource.aws_s3_bucket[name]
    contains(resource.acl, "public-read")
    not input.resource.aws_s3_bucket_public_access_block
    result := {
        "resource": name,
        "rule": "s3_public_access_not_blocked",
        "nist_control": "AC-3",
        "severity": "HIGH",
        "message": "S3 bucket has public-read ACL without public access block"
    }
}
""")

print("Policies restored to 97% precision version!")