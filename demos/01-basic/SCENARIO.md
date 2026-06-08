# Demo 01 - Basic Terraform misconfiguration scan

This demo scans a small, intentionally insecure Terraform module so you can see
TFSCAN flag real-world IaC misconfigurations.

## Input

`insecure_main.tf` defines a handful of AWS resources with common mistakes:

- An S3 bucket with a `public-read` ACL and no default encryption.
- A security group that exposes SSH (port 22) to `0.0.0.0/0`.
- An RDS instance that is publicly accessible and unencrypted.
- An unencrypted EBS volume.
- An IAM policy granting wildcard (`*`) permissions.

## Run it

```sh
# Human-readable table (default)
python -m tfscan scan demos/01-basic/insecure_main.tf

# Machine-readable JSON for CI pipelines
python -m tfscan scan demos/01-basic/insecure_main.tf --format json

# Shareable self-contained HTML report
python -m tfscan scan demos/01-basic/insecure_main.tf --format html -o report.html
```

## Expected result

TFSCAN reports multiple CRITICAL/HIGH findings (S3 public ACL, SSH open to the
world, public + unencrypted RDS, unencrypted EBS, wildcard IAM policy) and exits
with a non-zero status code so the scan can gate a CI pipeline.

Exit codes:

- `0` - no findings
- `1` - findings present (gate should fail the build)
- `2` - scan/parse error
