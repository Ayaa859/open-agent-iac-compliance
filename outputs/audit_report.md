# IaC Compliance Audit Report

**Generated:** June 06, 2026  
**Framework:** NIST SP 800-53 Rev. 5  
**Tool:** Open-Agent Framework (OPA + LLM)  
**Scope:** Terraform Infrastructure Configurations  

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Files Scanned | 478 |
| Evaluated Relevant Files | 213 |
| Files with Detected Violations | 119 |
| Total Violations Found | 144 |
| HIGH Severity | 115 |
| MEDIUM Severity | 29 |
| LOW Severity | 0 |
| True Positives | 116 |
| False Negatives | 15 |
| False Positives | 3 |
| True Negatives | 79 |
| Precision | 97.5% |
| Recall | 88.5% |
| F1 Score | 92.8% |
| Accuracy | 91.5% |

> Note: The detailed findings below include only configurations where the OPA policy engine detected at least one violation. Evaluation metrics are computed over the full set of 213 relevant labeled Terraform configurations.

---

## Violations by NIST Control Family

| NIST Control | Count |
|---|---|
| SC-28 | 101 |
| SC-8 | 21 |
| AC-6 | 11 |
| AU-2 | 4 |
| AU-9 | 3 |
| AU-12 | 3 |
| AC-3 | 1 |

---

## Violations by Rule

| Rule | Count |
|---|---|
| s3_missing_encryption | 96 |
| lb_not_using_https | 21 |
| wildcard_iam_policy | 11 |
| cloudtrail_no_log_validation | 3 |
| s3_logging_disabled | 3 |
| cloudtrail_not_global | 2 |
| cloudtrail_logging_disabled | 2 |
| ebs_missing_encryption | 2 |
| rds_encryption_disabled | 2 |
| ebs_encryption_disabled | 1 |
| s3_public_access_not_blocked | 1 |

---

## Detailed Findings

### File: nc_cloudtrail_misconfigured.tf

**Violations found:** 3  
**Label:** NON_COMPLIANT

#### Violation 1: cloudtrail_not_global

| Field | Value |
|---|---|
| Resource | bad_trail |
| NIST Control | AU-2 |
| Severity | MEDIUM |
| Message | CloudTrail is not logging global service events |

**Explanation:**
Not logging global service events in CloudTrail poses a security risk as it may allow unauthorized or malicious activities to go undetected, potentially leading to security breaches or compliance issues. Global service events provide visibility into management operations that can impact the security and integrity of cloud resources. Without this logging, it becomes challenging to track and investigate security incidents.

**NIST SP 800-53 Mapping:**
- Control ID: AU-2
- Control Name: Audit Events
- Description: The information system generates audit records containing information that can be used to reconstruct the following: the security-relevant event, the outcome of the event, the identity of the subject causing the event, and the identity of the object affected by the event.

**Remediation:**
```hcl
terraform { required_version = ">= 0.14.0" } provider "aws" { region = "us-west-2" } resource "aws_cloudtrail" "example" { name                          = "example-trail" s3_bucket_name               = aws_s3_bucket.example.id s3_key_prefix                = "/log" include_global_service_events = true }
```

---

#### Violation 2: cloudtrail_no_log_validation

| Field | Value |
|---|---|
| Resource | bad_trail |
| NIST Control | AU-9 |
| Severity | MEDIUM |
| Message | CloudTrail log file validation is explicitly disabled |

**Explanation:**
Disabling CloudTrail log file validation is a security risk because it allows unauthorized modifications to log files, which can be used to cover up malicious activities. This can lead to undetected security breaches and compromised data. By disabling validation, an attacker can tamper with log files without being detected.

**NIST SP 800-53 Mapping:**
- Control ID: AU-9
- Control Name: Audit and Accountability: Audit Log Receipt, Alert, and Storage Protection
- Description: The information system protects audit information and audit logs in accordance with organization-defined policies and procedures.

**Remediation:**
```hcl
Enable log file validation by setting `enable_log_file_validation` to `true` in the CloudTrail configuration, for example: `enable_log_file_validation = true`
```

---

#### Violation 3: cloudtrail_logging_disabled

| Field | Value |
|---|---|
| Resource | bad_trail |
| NIST Control | AU-2 |
| Severity | HIGH |
| Message | CloudTrail logging is explicitly disabled |

**Explanation:**
Disabling CloudTrail logging poses a significant security risk as it prevents the collection and storage of audit logs, making it challenging to detect and respond to security incidents. Without these logs, it is difficult to track changes to resources, identify potential security threats, and conduct forensic analysis. This lack of visibility can lead to undetected security breaches and non-compliance with regulatory requirements.

**NIST SP 800-53 Mapping:**
- Control ID: AU-2
- Control Name: Audit Events
- Description: The organization must generate audit records for all auditable events and provide the capability to generate audit records for all auditable events.

**Remediation:**
```hcl
Enable CloudTrail logging by setting `is_logging` to `true` and configuring the `s3_bucket_name` and `s3_key_prefix` properties, for example: `resource "aws_cloudtrail" "example" { is_logging = true, s3_bucket_name = "example-bucket", s3_key_prefix = "example-prefix" }`
```

---

### File: nc_cloudtrail_no_logging.tf

**Violations found:** 3  
**Label:** NON_COMPLIANT

#### Violation 1: cloudtrail_not_global

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-2 |
| Severity | MEDIUM |
| Message | CloudTrail is not logging global service events |

**Explanation:**
Not logging global service events in CloudTrail poses a security risk as it may allow unauthorized or malicious activities to go undetected, potentially leading to security breaches or compliance issues. Global service events provide visibility into management operations that can impact the security and integrity of cloud resources. Without this logging, it becomes challenging to track and investigate security incidents.

**NIST SP 800-53 Mapping:**
- Control ID: AU-2
- Control Name: Audit Events
- Description: The information system generates audit records containing information that can be used to reconstruct the following: the security-relevant event, the outcome of the event, the identity of the subject causing the event, and the identity of the object affected by the event.

**Remediation:**
```hcl
terraform { required_version = ">= 0.14.0" } provider "aws" { region = "us-west-2" } resource "aws_cloudtrail" "example" { name                          = "example-trail" s3_bucket_name               = aws_s3_bucket.example.id s3_key_prefix                = "/log" include_global_service_events = true }
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
Disabling CloudTrail log file validation is a security risk because it allows unauthorized modifications to log files, which can be used to cover up malicious activities. This can lead to undetected security breaches and compromised data. By disabling validation, an attacker can tamper with log files without being detected.

**NIST SP 800-53 Mapping:**
- Control ID: AU-9
- Control Name: Audit and Accountability: Audit Log Receipt, Alert, and Storage Protection
- Description: The information system protects audit information and audit logs in accordance with organization-defined policies and procedures.

**Remediation:**
```hcl
Enable log file validation by setting `enable_log_file_validation` to `true` in the CloudTrail configuration, for example: `enable_log_file_validation = true`
```

---

#### Violation 3: cloudtrail_logging_disabled

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-2 |
| Severity | HIGH |
| Message | CloudTrail logging is explicitly disabled |

**Explanation:**
Disabling CloudTrail logging poses a significant security risk as it prevents the collection and storage of audit logs, making it challenging to detect and respond to security incidents. Without these logs, it is difficult to track changes to resources, identify potential security threats, and conduct forensic analysis. This lack of visibility can lead to undetected security breaches and non-compliance with regulatory requirements.

**NIST SP 800-53 Mapping:**
- Control ID: AU-2
- Control Name: Audit Events
- Description: The organization must generate audit records for all auditable events and provide the capability to generate audit records for all auditable events.

**Remediation:**
```hcl
Enable CloudTrail logging by setting `is_logging` to `true` and configuring the `s3_bucket_name` and `s3_key_prefix` properties, for example: `resource "aws_cloudtrail" "example" { is_logging = true, s3_bucket_name = "example-bucket", s3_key_prefix = "example-prefix" }`
```

---

### File: nc_cloudtrail_no_validation.tf

**Violations found:** 1  
**Label:** NON_COMPLIANT

#### Violation 1: cloudtrail_no_log_validation

| Field | Value |
|---|---|
| Resource | example |
| NIST Control | AU-9 |
| Severity | MEDIUM |
| Message | CloudTrail log file validation is explicitly disabled |

**Explanation:**
Disabling CloudTrail log file validation is a security risk because it allows unauthorized modifications to log files, which can be used to cover up malicious activities. This can lead to undetected security breaches and compromised data. By disabling validation, an attacker can tamper with log files without being detected.

**NIST SP 800-53 Mapping:**
- Control ID: AU-9
- Control Name: Audit and Accountability: Audit Log Receipt, Alert, and Storage Protection
- Description: The information system protects audit information and audit logs in accordance with organization-defined policies and procedures.

**Remediation:**
```hcl
Enable log file validation by setting `enable_log_file_validation` to `true` in the CloudTrail configuration, for example: `enable_log_file_validation = true`
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
This is a security risk because unencrypted EBS volumes can expose sensitive data to unauthorized access, potentially leading to data breaches or other security incidents. Encryption is essential to protect data at rest, and omitting it can compromise the confidentiality and integrity of the data. By not specifying encryption, the EBS volume is vulnerable to unauthorized access.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest through the use of cryptographic mechanisms to prevent unauthorized disclosure and modification.

**Remediation:**
```hcl
Add the `encrypted` attribute to the EBS volume resource and set it to `true`, for example: `resource "aws_ebs_volume" "example" { encrypted = true }`
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
This is a security risk because unencrypted EBS volumes can expose sensitive data to unauthorized access, potentially leading to data breaches or other security incidents. Encryption is essential to protect data at rest, and disabling it intentionally or unintentionally can have severe consequences. By encrypting EBS volumes, organizations can ensure the confidentiality and integrity of their data.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
Add the 'encrypted' argument to the 'aws_ebs_volume' resource and set it to 'true', for example: 'resource "aws_ebs_volume" "example" { encrypted = true }'
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
This is a security risk because unencrypted EBS volumes can expose sensitive data to unauthorized access, potentially leading to data breaches or other security incidents. Encryption is essential to protect data at rest, and omitting it can compromise the confidentiality and integrity of the data. By not specifying encryption, the EBS volume is vulnerable to unauthorized access.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest through the use of cryptographic mechanisms to prevent unauthorized disclosure and modification.

**Remediation:**
```hcl
Add the `encrypted` attribute to the EBS volume resource and set it to `true`, for example: `resource "aws_ebs_volume" "example" { encrypted = true }`
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because unencrypted RDS instances can expose sensitive data to unauthorized access, potentially leading to data breaches and compliance issues. Encryption is essential to protect data at rest, and disabling it intentionally or unintentionally can have severe consequences. By not encrypting the RDS instance, the organization is vulnerable to data theft and tampering.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization must protect the confidentiality and integrity of information at rest, which includes encrypting sensitive data stored in databases.

**Remediation:**
```hcl
storage_encrypted = true
```

---

### File: nc_rds_no_encryption_2.tf

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
This is a security risk because unencrypted RDS instances can expose sensitive data to unauthorized access, potentially leading to data breaches and compliance issues. Encryption is essential to protect data at rest, and disabling it intentionally or unintentionally can have severe consequences. By not encrypting the RDS instance, the organization is vulnerable to data theft and tampering.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization must protect the confidentiality and integrity of information at rest, which includes encrypting sensitive data stored in databases.

**Remediation:**
```hcl
storage_encrypted = true
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
Disabling access logging for an S3 bucket poses a security risk as it makes it difficult to track and monitor access to sensitive data, making it challenging to detect and respond to potential security incidents. Without logging, it is hard to determine who accessed the data, when, and from where. This lack of visibility can lead to undetected data breaches and unauthorized access.

**NIST SP 800-53 Mapping:**
- Control ID: AU-12
- Control Name: Audit Generation
- Description: The information system generates audit records to the extent needed to enable the auditing of events that have a security relevance.

**Remediation:**
```hcl
Add the following Terraform code snippet to enable access logging for the S3 bucket: `logging { target_bucket = "your-target-bucket-name" target_prefix = "your-target-prefix/" }`
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
Disabling access logging for an S3 bucket poses a security risk as it makes it difficult to track and monitor access to sensitive data, making it challenging to detect and respond to potential security incidents. Without logging, it is hard to determine who accessed the data, when, and from where. This lack of visibility can lead to undetected data breaches and unauthorized access.

**NIST SP 800-53 Mapping:**
- Control ID: AU-12
- Control Name: Audit Generation
- Description: The information system generates audit records to the extent needed to enable the auditing of events that have a security relevance.

**Remediation:**
```hcl
Add the following Terraform code snippet to enable access logging for the S3 bucket: `logging { target_bucket = "your-target-bucket-name" target_prefix = "your-target-prefix/" }`
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
Disabling access logging for an S3 bucket poses a security risk as it makes it difficult to track and monitor access to sensitive data, making it challenging to detect and respond to potential security incidents. Without logging, it is hard to determine who accessed the data, when, and from where. This lack of visibility can lead to undetected data breaches and unauthorized access.

**NIST SP 800-53 Mapping:**
- Control ID: AU-12
- Control Name: Audit Generation
- Description: The information system generates audit records to the extent needed to enable the auditing of events that have a security relevance.

**Remediation:**
```hcl
Add the following Terraform code snippet to enable access logging for the S3 bucket: `logging { target_bucket = "your-target-bucket-name" target_prefix = "your-target-prefix/" }`
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
This is a security risk because an S3 bucket with public-read ACL and without public access block allows anyone on the internet to access the bucket's contents, potentially exposing sensitive data. This could lead to unauthorized data breaches or other malicious activities. By not blocking public access, the bucket's data is vulnerable to unauthorized access.

**NIST SP 800-53 Mapping:**
- Control ID: AC-3
- Control Name: Access Control for Remote Access Sessions
- Description: This control requires that access to system resources be controlled based on user identity, authentication, and authorization.

**Remediation:**
```hcl
aws_s3_bucket_public_access_block.example: { bucket = aws_s3_bucket.example.id, block_public_acls   = true, block_public_policy = true, ignore_public_acls  = true, restrict_public_buckets = true }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
```

---

### File: scenario_153.tf

**Violations found:** 1  
**Label:** NON_COMPLIANT

#### Violation 1: wildcard_iam_policy

| Field | Value |
|---|---|
| Resource | dynamodb_lambda_policy |
| NIST Control | AC-6 |
| Severity | HIGH |
| Message | IAM policy uses wildcard (*) permissions, violating least privilege |

**Explanation:**
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
Using wildcard (*) permissions in an IAM policy is a security risk because it grants excessive access to resources, potentially allowing unauthorized actions. This violates the principle of least privilege, which requires that users and services have only the necessary permissions to perform their tasks. As a result, an attacker who gains access to an account with wildcard permissions could exploit these broad permissions to cause harm.

**NIST SP 800-53 Mapping:**
- Control ID: AC-6
- Control Name: Least Privilege
- Description: The organization must ensure that all users and services are granted only the necessary privileges to perform their assigned tasks.

**Remediation:**
```hcl
Replace the wildcard (*) with explicit permissions, for example: `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "*" } ] }) }` becomes `resource "aws_iam_policy" "example" { policy = jsonencode({ Version = "2012-10-17", Statement = [ { Effect = "Allow", Action = [ "ec2:DescribeInstances", "ec2:DescribeImages" ], Resource = "arn:aws:ec2:region:account-id:instance/*" } ] }) }`
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
```

---

### File: scenario_390.tf

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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because it allows sensitive data to be transmitted in plaintext, making it vulnerable to eavesdropping and interception by unauthorized parties. Using HTTPS/TLS encryption ensures that data remains confidential and tamper-proof during transmission. By not enforcing HTTPS/TLS, the load balancer listener is exposing the application and its users to potential security threats.

**NIST SP 800-53 Mapping:**
- Control ID: SC-8
- Control Name: Transmission Confidentiality and Integrity
- Description: The organization must protect the confidentiality and integrity of transmitted information.

**Remediation:**
```hcl
listener { protocol = "HTTPS"; port        = "443"; ssl_policy      = "ELBSecurityPolicy-2016-08"; certificate_arn = "arn:aws:acm:REGION:ACCOUNT_ID:certificate/CERTIFICATE_ID" }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
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
This is a security risk because without server-side encryption, data stored in the S3 bucket is not protected from unauthorized access, which could lead to data breaches and other security incidents. Sensitive data, such as personal identifiable information or confidential business data, is particularly vulnerable. Encrypting data at rest is a critical security control to prevent data exposure.

**NIST SP 800-53 Mapping:**
- Control ID: SC-28
- Control Name: Protection of Information at Rest
- Description: The organization protects information at rest in accordance with the classification of the information.

**Remediation:**
```hcl
aws_s3_bucket.example: server_side_encryption_configuration { rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } } }
```

---


## Compliance Summary

This audit report identified **144 detected compliance violations** across
**119 Terraform configuration files**. These findings are mapped to
NIST SP 800-53 control families AC (Access Control), SC (System and Communications
Protection), and AU (Audit and Accountability).

The full evaluation scanned **478 Terraform files**, of which
**213** were relevant to the implemented policy scope. The OPA-only
detection layer achieved **97.5% precision**, **88.5% recall**, **92.8% F1 score**,
and **91.5% accuracy**.

### OPA-Only Detection Performance

| Metric | Value |
|---|---|
| True Positives | 116 |
| False Negatives | 15 |
| False Positives | 3 |
| True Negatives | 79 |
| Precision | 97.5% |
| Recall | 88.5% |
| F1 Score | 92.8% |
| Accuracy | 91.5% |

*Report generated by Open-Agent Framework for IaC Compliance Analysis*  
*Generated: 2026-06-06 18:48*
