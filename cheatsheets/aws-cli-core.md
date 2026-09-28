# AWS CLI Core Services & Security Reference Guide

## 1. Universal Command Anatomy
Every AWS CLI command adheres to a uniform structure:
```bash
aws <service> <operation> [--parameter <value>] [--profile <name>] [--region <id>] [--output json|table|text]
Action Verb Conventionslist-: Returns resource identifiers and basic collections without deep configuration details.get-: Retrieves the detailed configuration or document of a specific entity.describe-: Infrastructure-oriented inspection (EC2, VPC, RDS).create-: Provisions a brand-new resource.set- / update-: Modifies an existing state or reassigns active attributes.delete-: Permanently removes a resource.2. STS (Security Token Service) — Identity & Context VerificationMandatory starting point for credential validation and environment situational awareness.OperationSyntax ExamplePurposeget-caller-identityaws sts get-caller-identityReturns the Account ID, ARN, and UserId of the active session.get-session-tokenaws sts get-session-tokenGenerates temporary session credentials (useful for MFA flows).assume-roleaws sts assume-role --role-arn <ARN> --role-session-name <NAME>Assumes a target IAM role; yields an Access Key, Secret Key, and Session Token.3. IAM (Identity & Access Management) — Auditing & PrivEsc VectorsEntity DiscoveryBash# Users
aws iam list-users
aws iam get-user --user-name <USER>

# Groups
aws iam list-groups
aws iam list-groups-for-user --user-name <USER>

# Roles and Instance Profiles
aws iam list-roles
aws iam get-role --role-name <ROLE>
aws iam list-instance-profiles
Policy Enumeration (Attached vs. Inline)Bash# Customer Managed & AWS Managed Policies
aws iam list-attached-user-policies --user-name <USER>
aws iam list-attached-role-policies --role-name <ROLE>
aws iam get-policy --policy-arn <ARN>

# Inline Policies (Embedded inside identities)
aws iam list-user-policies --user-name <USER>
aws iam get-user-policy --user-name <USER> --policy-name <POLICY>
aws iam list-role-policies --role-name <ROLE>
aws iam get-role-policy --role-name <ROLE> --policy-name <POLICY>
Policy Versioning (Rollback Vector)Bash# List available historical versions
aws iam list-policy-versions --policy-arn <ARN>

# Inspect statement JSON for a specific version
aws iam get-policy-version --policy-arn <ARN> --version-id <VERSION>

# Exploitation: Switch default to an insecure legacy version
aws iam set-default-policy-version --policy-arn <ARN> --version-id <VERSION>

# Hardening / Cleanup: Delete an obsolete policy version
aws iam delete-policy-version --policy-arn <ARN> --version-id <VERSION>
4. S3 (Simple Storage Service) — Data Exposure & EnumerationOperationSyntax ExamplePurposelsaws s3 lsLists all buckets present in the target AWS account.ls (recursive)aws s3 ls s3://<BUCKET>/ --recursiveIterates and lists all keys/objects inside a bucket.cpaws s3 cp <LOCAL_FILE> s3://<BUCKET>/<PATH>Uploads local files (or downloads if path order is inverted).syncaws s3 sync s3://<BUCKET> ./lootPerforms recursive bulk synchronization of entire bucket contents.get-bucket-policyaws s3api get-bucket-policy --bucket <NAME>Reads the resource-based access policy.get-bucket-aclaws s3api get-bucket-acl --bucket <NAME>Verifies anonymous/public access (AllUsers, AuthenticatedUsers).5. EC2 & VPC — Compute & Network Boundary EnumerationCompute & Virtual MachinesBash# List instances with state, public/private IP, and IAM role association
aws ec2 describe-instances \
  --query "Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress,PrivateIpAddress,IamInstanceProfile.Arn]" \
  --output table

# Verify IAM instance profile mappings
aws ec2 describe-iam-instance-profile-associations
Perimeter Defense & Network Access ControlsBash# List Security Groups and ingress rules
aws ec2 describe-security-groups \
  --query "SecurityGroups[*].[GroupId,GroupName,IpPermissions]"
6. Lambda — Serverless & Execution HijackingBash# List deployed Lambda functions
aws lambda list-functions

# Retrieve function configuration, environment variables, and pre-signed code URL
aws lambda get-function --function-name <FUNCTION_NAME>

# Inspect resource-based policy (invocation permissions)
aws lambda get-policy --function-name <FUNCTION_NAME>
7. Secrets Management & Parameter StoreAWS Secrets ManagerBash# List secret names and metadata
aws secretsmanager list-secrets

# Retrieve plain-text secret payload
aws secretsmanager get-secret-value --secret-id <SECRET_NAME_OR_ARN>
SSM Parameter StoreBash# Enumerate parameters
aws ssm describe-parameters

# Retrieve decrypted SecureString parameter
aws ssm get-parameter --name <PARAM_NAME> --with-decryption
8. Output Filtering with JMESPath (--query)Avoid terminal information overload by extracting exact JSON keys directly at the CLI level:Bash# Extract only usernames
aws iam list-users --query "Users[*].UserName" --output text

# Extract attached policy ARNs for a target user
aws iam list-attached-user-policies --user-name <USER> --query "AttachedPolicies[*].PolicyArn" --output text

# Filter running EC2 instance IDs
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[*].Instances[*].InstanceId" \
  --output text
9. CLI Shell Autocompletion Setup (WSL / Bash)Enable tab-completion globally for all AWS CLI services and arguments:Bashecho "complete -C '/usr/local/bin/aws_completer' aws" >> ~/.bashrc
source ~/.bashrc
