# IaC Compliance Audit Report

**Generated:** November 08, 2026
**Framework:** NIST SP 800-53 Rev. 5
**Tool:** Open-Agent Framework (OPA + LLM)
**Scope:** Terraform Infrastructure Configurations

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Files Scanned | 128 |
| Files with Violations | 128 |
| Total Violations Found | 157 |
| HIGH Severity | 123 |
| MEDIUM Severity | 34 |
| LOW Severity | 0 |

---

## Violations by NIST Control Family

| NIST Control | Count |
|---|---|
| SC-28 | 101 |
| SC-8 | 23 |
| AC-6 | 11 |
| AC-3 | 9 |
| AU-9 | 6 |
| AU-2 | 4 |
| AU-12 | 3 |

---

## Violations by Rule

| Rule | Count |
|---|---|
| s3_missing_encryption | 96 |
| lb_not_using_https | 21 |
| wildcard_iam_policy | 11 |
| unrestricted_ingress_specific_port | 7 |
| cloudtrail_validation_field_missing | 3 |
| cloudtrail_no_log_validation | 3 |
| s3_logging_disabled | 3 |
| cloudtrail_not_global | 2 |
| cloudtrail_logging_disabled | 2 |
| ebs_missing_encryption | 2 |
| lb_protocol_missing | 2 |
| dynamodb_encryption_disabled | 1 |
| ebs_encryption_disabled | 1 |
| rds_encryption_disabled | 1 |
| s3_public_access_not_blocked | 1 |
| unrestricted_ingress_all_protocols | 1 |

---

## Detailed Findings

### File: nc_cloudtrail_misconfigured.tf

**Violations found:** 4
**Label:** NON_COMPLIANT

#### Violation 1: cloudtrail_validation_field_missing

| Field | Value |
|---|---|
| Resource | bad_trail |
| NIST Control | AU-9 |
| Severity | MEDIUM |
| Message | CloudTrail does not specify enable_log_file_validation |

**Explanation:**
This is a security risk because without log file validation, it is difficult to ensure the integrity and authenticity of the logs collected by CloudTrail. An attacker could potentially tamper with or alter log files, making it challenging to detect and respond to security incidents. Enabling log file validation helps to ensure that logs are accurate and trustworthy.

**NIST SP 800-53 Mapping:**
- Control ID: AU-9
- Control Name: Protection of Audit Information
- Description: The information system protects audit information and audit logging tools from unauthorized access, modification, and deletion.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
```

---

#### Violation 2: cloudtrail_not_global

| Field | Value |
|---|---|
| Resource | bad_trail |
| NIST Control | AU-2 |
| Severity | MEDIUM |
| Message | CloudTrail is not logging global service events |

**Explanation:**
This is a security risk because it allows unauthorized access to AWS services without being detected, which can lead to security breaches and data theft. Global service events provide visibility into management operations that can impact the security of the AWS account. Without logging these events, it is difficult to detect and respond to potential security incidents.

**NIST SP 800-53 Mapping:**
- Control ID: AU-2
- Control Name: Event Logging
- Description: The organization identifies the types of events that the system is capable of logging.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
}
```

---

#### Violation 3: cloudtrail_no_log_validation

| Field | Value |
|---|---|
| Resource | bad_trail |
| NIST Control | AU-9 |
| Severity | MEDIUM |
| Message | CloudTrail log file validation is explicitly disabled |

**Explanation:**
Disabling CloudTrail log file validation is a security risk because it allows unauthorized modifications to log files, which can be used to cover up malicious activities. This can lead to undetected security breaches and compromised data. Enabling log file validation ensures the integrity and authenticity of log data.

**NIST SP 800-53 Mapping:**
- Control ID: AU-9
- Control Name: Protection of Audit Information
- Description: The information system protects audit information and audit logging tools from unauthorized access, modification, and deletion.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
```

---

#### Violation 4: cloudtrail_logging_disabled

| Field | Value |
|---|---|
| Resource | bad_trail |
| NIST Control | AU-2 |
| Severity | HIGH |
| Message | CloudTrail logging is explicitly disabled |

**Explanation:**
Disabling CloudTrail logging poses a significant security risk as it prevents the collection and storage of audit logs, making it difficult to detect and respond to security incidents. This lack of visibility can allow malicious activities to go undetected, compromising the security and integrity of the cloud environment. By disabling logging, organizations may not be able to investigate security incidents or comply with regulatory requirements.

**NIST SP 800-53 Mapping:**
- Control ID: AU-2
- Control Name: Event Logging
- Description: The organization identifies the types of events that the system is capable of logging.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  is_organization_trail         = false
}
```

---

### File: nc_cloudtrail_no_logging.tf

**Violations found:** 4
**Label:** NON_COMPLIANT

#### Violation 1: cloudtrail_validation_field_missing

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-9 |
| Severity | MEDIUM |
| Message | CloudTrail does not specify enable_log_file_validation |

**Explanation:**
This is a security risk because without log file validation, it is difficult to ensure the integrity and authenticity of the logs collected by CloudTrail. An attacker could potentially tamper with or alter log files, making it challenging to detect and respond to security incidents. Enabling log file validation helps to ensure that logs are accurate and trustworthy.

**NIST SP 800-53 Mapping:**
- Control ID: AU-9
- Control Name: Protection of Audit Information
- Description: The information system protects audit information and audit logging tools from unauthorized access, modification, and deletion.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
```

---

#### Violation 2: cloudtrail_not_global

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-2 |
| Severity | MEDIUM |
| Message | CloudTrail is not logging global service events |

**Explanation:**
This is a security risk because it allows unauthorized access to AWS services without being detected, which can lead to security breaches and data theft. Global service events provide visibility into management operations that can impact the security of the AWS account. Without logging these events, it is difficult to detect and respond to potential security incidents.

**NIST SP 800-53 Mapping:**
- Control ID: AU-2
- Control Name: Event Logging
- Description: The organization identifies the types of events that the system is capable of logging.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
}
```

---

#### Violation 3: cloudtrail_no_log_validation

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-9 |
| Severity | MEDIUM |
| Message | CloudTrail log file validation is explicitly disabled |

**Explanation:**
Disabling CloudTrail log file validation is a security risk because it allows unauthorized modifications to log files, which can be used to cover up malicious activities. This can lead to undetected security breaches and compromised data. Enabling log file validation ensures the integrity and authenticity of log data.

**NIST SP 800-53 Mapping:**
- Control ID: AU-9
- Control Name: Protection of Audit Information
- Description: The information system protects audit information and audit logging tools from unauthorized access, modification, and deletion.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
```

---

#### Violation 4: cloudtrail_logging_disabled

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-2 |
| Severity | HIGH |
| Message | CloudTrail logging is explicitly disabled |

**Explanation:**
Disabling CloudTrail logging poses a significant security risk as it prevents the collection and storage of audit logs, making it difficult to detect and respond to security incidents. This lack of visibility can allow malicious activities to go undetected, compromising the security and integrity of the cloud environment. By disabling logging, organizations may not be able to investigate security incidents or comply with regulatory requirements.

**NIST SP 800-53 Mapping:**
- Control ID: AU-2
- Control Name: Event Logging
- Description: The organization identifies the types of events that the system is capable of logging.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  is_organization_trail         = false
}
```

---

### File: nc_cloudtrail_no_validation.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: cloudtrail_validation_field_missing

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-9 |
| Severity | MEDIUM |
| Message | CloudTrail does not specify enable_log_file_validation |

**Explanation:**
This is a security risk because without log file validation, it is difficult to ensure the integrity and authenticity of the logs collected by CloudTrail. An attacker could potentially tamper with or alter log files, making it challenging to detect and respond to security incidents. Enabling log file validation helps to ensure that logs are accurate and trustworthy.

**NIST SP 800-53 Mapping:**
- Control ID: AU-9
- Control Name: Protection of Audit Information
- Description: The information system protects audit information and audit logging tools from unauthorized access, modification, and deletion.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
```

---

#### Violation 2: cloudtrail_no_log_validation

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-9 |
| Severity | MEDIUM |
| Message | CloudTrail log file validation is explicitly disabled |

**Explanation:**
Disabling CloudTrail log file validation is a security risk because it allows unauthorized modifications to log files, which can be used to cover up malicious activities. This can lead to undetected security breaches and compromised data. Enabling log file validation ensures the integrity and authenticity of log data.

**NIST SP 800-53 Mapping:**
- Control ID: AU-9
- Control Name: Protection of Audit Information
- Description: The information system protects audit information and audit logging tools from unauthorized access, modification, and deletion.

**Remediation:**
```hcl
resource "aws_cloudtrail" "example" {
  name                          = "example-trail"
  s3_bucket_name                = "example-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
```

---

### File: nc_dynamodb_no_encryption.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: dynamodb_encryption_disabled

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | DynamoDB table has server-side encryption explicitly disabled |

**Explanation:**
This is a security risk because server-side encryption is a critical security control that protects data at rest from unauthorized access. Without encryption, sensitive data stored in the DynamoDB table is vulnerable to exploitation by malicious actors. Enabling server-side encryption ensures that data is encrypted and protected from unauthorized access.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_dynamodb_table" "example" {
  name           = "example-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  attribute {
    name = "id"
    type = "S"
  }
  server_side_encryption {
    enabled = true
  }
}
```

---

### File: nc_ebs_no_encryption.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: ebs_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | EBS volume does not specify encryption |

**Explanation:**
This is a security risk because unencrypted EBS volumes can expose sensitive data to unauthorized access, potentially leading to data breaches or other security incidents. Encryption is essential to protect data at rest, and omitting it can have severe consequences. By not specifying encryption, the EBS volume is vulnerable to data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_ebs_volume" "example" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = true
  kms_key_id        = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
}
```

---

#### Violation 2: ebs_encryption_disabled

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | EBS volume has encryption explicitly disabled |

**Explanation:**
This is a security risk because unencrypted EBS volumes can expose sensitive data to unauthorized access, potentially leading to data breaches or other security incidents. Encryption is a critical security control that protects data at rest. By enabling encryption, organizations can ensure the confidentiality and integrity of their data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_ebs_volume" "example" {
  availability_zone = "us-west-2a"
  size              = 30
  encrypted         = true
  type              = "gp3"
}
```

---

### File: nc_ebs_no_field.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: ebs_missing_encryption

| Field | Value |
|---|---|
| Resource | unencrypted |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | EBS volume does not specify encryption |

**Explanation:**
This is a security risk because unencrypted EBS volumes can expose sensitive data to unauthorized access, potentially leading to data breaches or other security incidents. Encryption is essential to protect data at rest, and omitting it can have severe consequences. By not specifying encryption, the EBS volume is vulnerable to data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_ebs_volume" "example" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = true
  kms_key_id        = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
}
```

---

### File: nc_iam_wildcard.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | admin_policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

### File: nc_lb_no_https.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | http_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: nc_rds_no_encryption.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: rds_encryption_disabled

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | RDS instance has storage encryption explicitly disabled |

**Explanation:**
This is a security risk because it allows unauthorized access to sensitive data stored in the RDS instance. Without encryption, an attacker who gains access to the instance can easily read and exploit the data. This violates the principle of protecting sensitive information at rest.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_db_instance" "example" {
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "13.4"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "myuser"
  password             = "mypassword"
  parameter_group_name = "default.postgres13"
  skip_final_snapshot  = true
  storage_encrypted    = true
  vpc_security_group_ids = ["sg-12345678"]
}
```

---

### File: nc_s3_no_encryption.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_logging_disabled

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-12 |
| Severity | MEDIUM |
| Message | S3 bucket does not have access logging enabled |

**Explanation:**
This is a security risk because without access logging enabled, it is difficult to track and monitor access to the S3 bucket, making it challenging to detect and respond to potential security incidents. This lack of visibility can lead to undetected data breaches or unauthorized access. Enabling access logging is essential for maintaining the security and integrity of the data stored in the S3 bucket.

**NIST SP 800-53 Mapping:**
- Control ID: AU-12
- Control Name: Audit Record Generation
- Description: The information system provides audit record generation capability for the auditable events defined by the organization.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "private"
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "my-log-bucket"
    target_prefix = "logs/"
  }
}
```

---

### File: nc_s3_no_logging.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | nolog_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_logging_disabled

| Field | Value |
|---|---|
| Resource | nolog_bucket |
| NIST Control | AU-12 |
| Severity | MEDIUM |
| Message | S3 bucket does not have access logging enabled |

**Explanation:**
This is a security risk because without access logging enabled, it is difficult to track and monitor access to the S3 bucket, making it challenging to detect and respond to potential security incidents. This lack of visibility can lead to undetected data breaches or unauthorized access. Enabling access logging is essential for maintaining the security and integrity of the data stored in the S3 bucket.

**NIST SP 800-53 Mapping:**
- Control ID: AU-12
- Control Name: Audit Record Generation
- Description: The information system provides audit record generation capability for the auditable events defined by the organization.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "private"
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "my-log-bucket"
    target_prefix = "logs/"
  }
}
```

---

### File: nc_s3_public_access.tf

**Violations found:** 3
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | public_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_logging_disabled

| Field | Value |
|---|---|
| Resource | public_bucket |
| NIST Control | AU-12 |
| Severity | MEDIUM |
| Message | S3 bucket does not have access logging enabled |

**Explanation:**
This is a security risk because without access logging enabled, it is difficult to track and monitor access to the S3 bucket, making it challenging to detect and respond to potential security incidents. This lack of visibility can lead to undetected data breaches or unauthorized access. Enabling access logging is essential for maintaining the security and integrity of the data stored in the S3 bucket.

**NIST SP 800-53 Mapping:**
- Control ID: AU-12
- Control Name: Audit Record Generation
- Description: The information system provides audit record generation capability for the auditable events defined by the organization.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "private"
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "my-log-bucket"
    target_prefix = "logs/"
  }
}
```

---

#### Violation 3: s3_public_access_not_blocked

| Field | Value |
|---|---|
| Resource | public_bucket |
| NIST Control | AC-3 |
| Severity | HIGH |
| Message | S3 bucket has public-read ACL without public access block |

**Explanation:**
This is a security risk because it allows unauthorized access to sensitive data stored in the S3 bucket. Anyone with the bucket's URL can read the data, potentially leading to data breaches or leaks. This violates the principle of least privilege and can have severe consequences.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Enforcement
- Description: The information system enforces approved authorizations for logical access to information and system resources.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl = "private"
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  public_access_block {
    block_public_acls = true
    block_public_policy = true
    ignore_public_acls = true
    restrict_public_buckets = true
  }
}
```

---

### File: nc_sg_ssh_open.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: unrestricted_ingress_all_protocols

| Field | Value |
|---|---|
| Resource | ssh_open |
| NIST Control | AC-3 |
| Severity | HIGH |
| Message | Security group allows all protocol traffic from 0.0.0.0/0 |

**Explanation:**
Allowing all protocol traffic from any IP address is a significant security risk because it exposes the resource to potential attacks from any source on the internet. This could lead to unauthorized access, data breaches, or other malicious activities. It is essential to restrict ingress traffic to only necessary protocols and sources.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Enforcement
- Description: The information system enforces approved authorizations for logical access to information and system resources.

**Remediation:**
```hcl
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "example security group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
```

---

### File: scenario_009.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | sample_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_010.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | sampleapril26426 |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_011.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | sample_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_036.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | apriltwentyeight |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_037.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | apriltwentynine |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_039.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | apriltwentyninth |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | apriltwentyninth2 |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_040.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | aprilthirthieth |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_041.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | aprilthirthyfirst |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | aprilthirthyfirst2 |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_059.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | decemberthirtysecond |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_060.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | januarysecond |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_061.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | januarythird |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_062.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | januaryseventh |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_063.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | januaryfifth |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_064.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | januarysixth |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_065.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_066.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | januaryeleventh |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_067.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | firehose-opensearch |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_070.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | januarysixteenth |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_074.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

### File: scenario_075.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

### File: scenario_076.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

### File: scenario_077.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

### File: scenario_104.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | a |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_107.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | sample |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_109.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | platform_infra |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_110.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | a |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_111.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_112.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_113.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | a |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_114.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | a |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_115.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | cg-data-from-web |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | cg-data-s3-bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_116.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | my_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_117.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_118.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_120.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_121.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | log_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_123.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_204.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_205.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_212.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_213.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_214.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | log_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_267.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_268.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example-bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_269.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | mybucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_270.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_271.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | analytics |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_272.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_273.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | inventory |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | test |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_274.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | inventory |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | test |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_275.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_276.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_278.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_279.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_280.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_282.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_283.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_284.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_285.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_286.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_287.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_288.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_289.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_290.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_291.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_292.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | log_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_293.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | log_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_294.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | artifact_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_295.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | artifact_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_296.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | artifact_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_297.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | artifact_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_298.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | artifact_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_299.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | artifact_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_300.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | artifact_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_301.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | artifact_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_302.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | lambda_policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | caas |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_303.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | lambda_policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | caas |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_304.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | lambda_policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | caas |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_305.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | lambda_policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | caas |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_316.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | video_content |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_317.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | video_content |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_318.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | video_content |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_319.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | website_content |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_320.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | lb-listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_321.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | lb-listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_322.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | lb-listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_323.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | lb-listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_343.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: unrestricted_ingress_specific_port

| Field | Value |
|---|---|
| Resource | main |
| NIST Control | AC-3 |
| Severity | HIGH |
| Message | Security group allows unrestricted inbound on a specific port from 0.0.0.0/0 |

**Explanation:**
This is a security risk because it allows anyone from any IP address to access the specific port, potentially leading to unauthorized access or malicious activity. Unrestricted ingress can expose the system to various attacks, including denial-of-service and exploitation of vulnerabilities. It is essential to restrict access to only necessary IP addresses or ranges.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Enforcement
- Description: The information system enforces approved authorizations for logical access to information and system resources.

**Remediation:**
```hcl
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "example security group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
```

---

### File: scenario_344.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: unrestricted_ingress_specific_port

| Field | Value |
|---|---|
| Resource | main |
| NIST Control | AC-3 |
| Severity | HIGH |
| Message | Security group allows unrestricted inbound on a specific port from 0.0.0.0/0 |

**Explanation:**
This is a security risk because it allows anyone from any IP address to access the specific port, potentially leading to unauthorized access or malicious activity. Unrestricted ingress can expose the system to various attacks, including denial-of-service and exploitation of vulnerabilities. It is essential to restrict access to only necessary IP addresses or ranges.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Enforcement
- Description: The information system enforces approved authorizations for logical access to information and system resources.

**Remediation:**
```hcl
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "example security group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
```

---

### File: scenario_345.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: unrestricted_ingress_specific_port

| Field | Value |
|---|---|
| Resource | main |
| NIST Control | AC-3 |
| Severity | HIGH |
| Message | Security group allows unrestricted inbound on a specific port from 0.0.0.0/0 |

**Explanation:**
This is a security risk because it allows anyone from any IP address to access the specific port, potentially leading to unauthorized access or malicious activity. Unrestricted ingress can expose the system to various attacks, including denial-of-service and exploitation of vulnerabilities. It is essential to restrict access to only necessary IP addresses or ranges.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Enforcement
- Description: The information system enforces approved authorizations for logical access to information and system resources.

**Remediation:**
```hcl
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "example security group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
```

---

### File: scenario_388.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_protocol_missing

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener does not specify a protocol |

**Explanation:**
Not specifying a protocol for a load balancer listener is a security risk because it can lead to unintended exposure of services to unauthorized access, potentially allowing attackers to exploit vulnerabilities in unsupported protocols. This lack of specificity can also make it difficult to enforce security policies and monitor traffic. By not defining a protocol, the load balancer may default to a protocol that is not intended, increasing the attack surface.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port = 443
  protocol = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
  certificate_arn = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_389.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_390.tf

**Violations found:** 2
**Label:** NON_COMPLIANT

#### Violation 1: unrestricted_ingress_specific_port

| Field | Value |
|---|---|
| Resource | web-server |
| NIST Control | AC-3 |
| Severity | HIGH |
| Message | Security group allows unrestricted inbound on a specific port from 0.0.0.0/0 |

**Explanation:**
This is a security risk because it allows anyone from any IP address to access the specific port, potentially leading to unauthorized access or malicious activity. Unrestricted ingress can expose the system to various attacks, including denial-of-service and exploitation of vulnerabilities. It is essential to restrict access to only necessary IP addresses or ranges.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Enforcement
- Description: The information system enforces approved authorizations for logical access to information and system resources.

**Remediation:**
```hcl
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "example security group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
```

---

#### Violation 2: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_391.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_392.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_393.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_394.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_395.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_396.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_397.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_398.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_399.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_400.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_protocol_missing

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener does not specify a protocol |

**Explanation:**
Not specifying a protocol for a load balancer listener is a security risk because it can lead to unintended exposure of services to unauthorized access, potentially allowing attackers to exploit vulnerabilities in unsupported protocols. This lack of specificity can also make it difficult to enforce security policies and monitor traffic. By not defining a protocol, the load balancer may default to a protocol that is not intended, increasing the attack surface.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port = 443
  protocol = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
  certificate_arn = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_401.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_402.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_403.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_404.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_405.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: lb_not_using_https

| Field | Value |
|---|---|
| Resource | my_listener |
| NIST Control | SC-8 |
| Severity | MEDIUM |
| Message | Load balancer listener is not enforcing HTTPS/TLS |

**Explanation:**
This is a security risk because it allows data to be transmitted in plaintext, making it vulnerable to eavesdropping and tampering. Using HTTPS/TLS encryption ensures that data remains confidential and integrity is maintained. This vulnerability can be exploited by malicious actors to intercept sensitive information.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The information system protects the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
resource "aws_lb_listener" "example" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:region:account-id:certificate/certificate-id"
}
```

---

### File: scenario_437.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: unrestricted_ingress_specific_port

| Field | Value |
|---|---|
| Resource | allow-db-access |
| NIST Control | AC-3 |
| Severity | HIGH |
| Message | Security group allows unrestricted inbound on a specific port from 0.0.0.0/0 |

**Explanation:**
This is a security risk because it allows anyone from any IP address to access the specific port, potentially leading to unauthorized access or malicious activity. Unrestricted ingress can expose the system to various attacks, including denial-of-service and exploitation of vulnerabilities. It is essential to restrict access to only necessary IP addresses or ranges.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Enforcement
- Description: The information system enforces approved authorizations for logical access to information and system resources.

**Remediation:**
```hcl
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "example security group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
```

---

### File: scenario_438.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: unrestricted_ingress_specific_port

| Field | Value |
|---|---|
| Resource | allow-db-access |
| NIST Control | AC-3 |
| Severity | HIGH |
| Message | Security group allows unrestricted inbound on a specific port from 0.0.0.0/0 |

**Explanation:**
This is a security risk because it allows anyone from any IP address to access the specific port, potentially leading to unauthorized access or malicious activity. Unrestricted ingress can expose the system to various attacks, including denial-of-service and exploitation of vulnerabilities. It is essential to restrict access to only necessary IP addresses or ranges.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Enforcement
- Description: The information system enforces approved authorizations for logical access to information and system resources.

**Remediation:**
```hcl
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "example security group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
```

---

### File: scenario_439.tf

**Violations found:** 1
**Label:** NON_COMPLIANT

#### Violation 1: unrestricted_ingress_specific_port

| Field | Value |
|---|---|
| Resource | allow-db-access |
| NIST Control | AC-3 |
| Severity | HIGH |
| Message | Security group allows unrestricted inbound on a specific port from 0.0.0.0/0 |

**Explanation:**
This is a security risk because it allows anyone from any IP address to access the specific port, potentially leading to unauthorized access or malicious activity. Unrestricted ingress can expose the system to various attacks, including denial-of-service and exploitation of vulnerabilities. It is essential to restrict access to only necessary IP addresses or ranges.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Enforcement
- Description: The information system enforces approved authorizations for logical access to information and system resources.

**Remediation:**
```hcl
resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "example security group"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
```

---

### File: scenario_012.tf

**Violations found:** 1
**Label:** COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | sample_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_013.tf

**Violations found:** 2
**Label:** COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | eu_sample_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

#### Violation 2: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | us_west_sample_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_014.tf

**Violations found:** 1
**Label:** COMPLIANT

#### Violation 1: s3_missing_encryption

| Field | Value |
|---|---|
| Resource | sample_bucket |
| NIST Control | SC-28 |
| Severity | HIGH |
| Message | S3 bucket does not have server-side encryption configured |

**Explanation:**
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Server-side encryption ensures that data is encrypted at rest, making it more difficult for attackers to access sensitive information. This vulnerability could be exploited by malicious actors to steal or modify sensitive data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects the confidentiality and integrity of information at rest.

**Remediation:**
```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

---

### File: scenario_153.tf

**Violations found:** 1
**Label:** COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | dynamodb_lambda_policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, violating the principle of least privilege. This can lead to unauthorized access and potentially allow an attacker to exploit these permissions. It is essential to restrict permissions to only those necessary for the intended functionality.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.

**Remediation:**
```hcl
resource "aws_iam_policy" "example" {
  name        = "example-policy"
  description = "Example policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---


## Compliance Summary

This audit identified **157 compliance violations** across
**128 Terraform configuration files**, mapped to
NIST SP 800-53 control families AC (Access Control), SC (System and
Communications Protection), and AU (Audit and Accountability).

### OPA-Only Detection Performance

| Metric | Value |
|---|---|
| Precision | 97.5% |
| Recall | 87.8% |
| F1 Score | 92.4% |

*Report generated by Open-Agent Framework for IaC Compliance Analysis*
*Generated: 2026-11-08 13:29*
