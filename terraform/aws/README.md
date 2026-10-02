# AWS CSD traffic generator

This independent Terraform root deploys a public-subnet browser worker for authorized Client-Side Defense demonstrations against exactly `https://client-side-defense.f5-sales-demo.com`. It does not replace or share state with the Azure deployment in `terraform/`.

## Architecture and boundaries

The stack creates one VPC (`10.44.0.0/16`), one subnet with an Internet Gateway route, an EC2
worker with automatic public addressing disabled, and one Elastic IP attached directly to the worker
ENI. There is no NAT Gateway or private worker subnet. The VPC default security group has no ingress
or egress, and an encrypted CloudWatch log group receives all VPC flow records through a scoped
service role.

SSH is enabled only for Ubuntu public-key authentication. The worker security group permits exactly
TCP/22 from `operator_ssh_cidr`, which must be a canonical IPv4 `/32`; no password or root login is
allowed. Terraform creates an EC2 key pair from either an existing public-key file or public-key
text. It never reads, generates, or stores the private key. Systems Manager remains the recovery
path. IMDSv2, KMS-encrypted gp3 storage, detailed monitoring, API termination protection, SSM
endpoints, and encrypted evidence/log storage remain required.

Run evidence is written beneath `runs/<run-id>/<scenario>/`. Status metadata records the repository, source commit, Chrome and Node versions, AMI, instance, region, deployment-manifest version, and deployment-manifest SHA-256.

Do not place credentials, session tokens, private keys, customer data, or unsanitized browser artifacts in source, variables, Terraform state, logs, screenshots, or receipts.
Evidence files remain immutable after `SHA256SUMS` is written. Their embedded upload state stays
`pending`; successful remote finalization is represented only by `upload-commit.json`, uploaded last
after every object, manifest, and checksum succeeds. Every upload records user metadata
`sha256=<local-digest>` and sends no SSE override, relying on the versioned bucket's default
customer-managed KMS key. Failed or interrupted uploads leave `.finalization-failed.json` and can be
resumed without browser execution:

```bash
sudo -u tgen env RUNTIME_ENV=/etc/traffic-generator/runtime.env \
  /bin/bash /opt/traffic-generator/source/suites/csd-violations/run.sh \
  --retry-upload /opt/traffic-generator/runtime/results/<run-id>/<scenario>
```

Retry validates the frozen local checksum set and uses `s3api head-object` for every exact S3 key.
A 404 is uploadable; denied or other errors fail closed. Existing keys are skipped only when their
case-normalized `Metadata.sha256` exactly matches the local digest; missing or mismatched metadata
fails rather than overwriting. This applies to zero-byte objects and the final commit. A partial or
already committed retry therefore uploads only missing objects and keeps `upload-commit.json` last.

The evidence bucket enables EventBridge notifications and S3 server access logging. Access logs land in
a dedicated same-region, private, versioned SSE-S3 bucket with bounded lifecycle retention and EventBridge
notifications. AWS requires S3-managed encryption for a server-access-log destination; the resource-local
Checkov KMS exemption documents that service constraint. This terminal sink deliberately does not log
itself or replicate because either configuration would recurse or create another regional sink.

Evidence replicates to a private, versioned destination in the exact guarded `us-east-2` region using a
dedicated replica-region customer-managed KMS key. The replica emits EventBridge notifications and writes
server access records to a second private, versioned SSE-S3 terminal sink in `us-east-2`; that sink also
emits EventBridge notifications but neither logs itself nor replicates. The replication role receives only
source version reads, source-key decrypt, destination replication, and destination-key encrypt/data-key
permissions. Cross-region storage, replication transfer, two KMS keys, CloudWatch Logs ingestion/storage,
VPC flow logs, and both access-log sinks add ongoing AWS cost.

## 1. Discover and pin inputs

Authenticate with AWS profile `280469140135_Users`, then perform live discovery for account `280469140135` in `us-east-1`. Select an available x86_64 Canonical Ubuntu 24.04 EBS-backed HVM AMI, Availability Zone, and instance type appropriate for Chrome plus Xvfb. Do not copy an AMI or instance type from this repository or another account.

Resolve the exact source commit and these versioned artifacts with their SHA-256 digests: AWS CLI v2
Linux x86_64 archive, Amazon CloudWatch agent Ubuntu amd64 package, Node.js archive, Chrome for
Testing archive, and compatible exact `playwright-core` version. Also resolve the reviewed
deployment-manifest version and digest. Every runtime archive or package URL must contain its declared
exact version; `latest` URLs are rejected.

From the GitHub jumpbox, determine its current public IPv4 immediately before each plan and apply and express it as an exact `/32`. The current observed example is `142.127.218.190/32`; it is evidence for the example only and must be revalidated because ISP addressing can change. Terraform intentionally performs no external IP discovery.

Use an existing public key, for example `~/.ssh/id_ed25519.pub` in the operator account. Set `ssh_public_key_path` for interactive use, or `ssh_public_key` for automation, but never both. Do not commit public-key material, and never provide a private key.

Copy `terraform.tfvars.example` to an untracked `terraform.tfvars` and replace every placeholder.

## 2. Initialize and validate

The backend remains separate from Azure: S3 bucket `terraform-tfstate-xc`, key `f5-sales-demo/traffic-generator-aws.tfstate`, region `us-east-1`, native lock file, encryption enabled.

```bash
set -euo pipefail
export AWS_PROFILE=280469140135_Users
export AWS_REGION=us-east-1

terraform -chdir=terraform/aws init
terraform -chdir=terraform/aws fmt -check -recursive
terraform -chdir=terraform/aws validate
terraform -chdir=terraform/aws test
checkov -d terraform/aws
```

Credentials come from the named AWS profile. Do not put credentials in Terraform files.

## 3. Create and review a saved plan

Revalidate the jumpbox public IPv4 first, update `operator_ssh_cidr` if it changed, then create a private plan directory and inspect the saved plan:

```bash
set -euo pipefail
export AWS_PROFILE=280469140135_Users
export AWS_REGION=us-east-1

install -d -m 700 terraform/aws/.plans
terraform -chdir=terraform/aws plan -out=.plans/traffic-generator-aws.tfplan
terraform -chdir=terraform/aws show .plans/traffic-generator-aws.tfplan
shasum -a 256 terraform/aws/.plans/traffic-generator-aws.tfplan
```

Review the account/profile/primary/replication region guards, exact SSH `/32`, public-key source,
public subnet and IGW route, direct EIP-to-ENI attachment, default-SG deny rules, VPC flow logs,
endpoint placement, IAM scope, KMS policies, evidence EventBridge notification, access-log sink,
cross-region replication, immutable runtime pins, manifest provenance, and termination protection.
Obtain explicit approval for that exact saved plan before applying it. Do not apply a regenerated or
unreviewed plan.

## 4. Apply and connect

After approval of the reviewed SHA-256 digest, apply only that exact saved plan:

```bash
set -euo pipefail
export AWS_PROFILE=280469140135_Users
export AWS_REGION=us-east-1

terraform -chdir=terraform/aws apply .plans/traffic-generator-aws.tfplan
terraform -chdir=terraform/aws output -raw ssh_command
```

The `ssh_command` output is executable when `ssh_public_key_path` was used. When key text was supplied directly, use the corresponding private key outside Terraform:

```bash
ssh ubuntu@"$(terraform -chdir=terraform/aws output -raw public_ip)"
```

With `continuous_enabled = true` (the default), Terraform-driven cloud-init hydration starts recurring CSD traffic after verified source installation and bounded runtime health. **No manual start is needed.** SSM remains available for recovery and deliberate allowlisted scenario execution after pausing/draining recurrence:

```bash
INSTANCE_ID="$(terraform -chdir=terraform/aws output -raw instance_id)"
DOCUMENT_NAME="$(terraform -chdir=terraform/aws output -raw ssm_document_name)"
aws --profile 280469140135_Users --region us-east-1 ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "$DOCUMENT_NAME" \
  --parameters 'Scenario=["login-credential-skimmer"]'
```

## 5. Verify runtime and evidence

Cloud-init rewrites regional `ec2.archive.ubuntu.com`, archive, and security Ubuntu package sources to
HTTPS before `apt-get update`. It installs AWS CLI v2 and the Amazon CloudWatch agent only from exact
versioned archives/packages after strict SHA-256 verification. A failed download, checksum, package
install, or version check stops bootstrap. npm always runs as the unprivileged `tgen` user with
`/opt/node/bin` first in `PATH`.

Source installation is transactional and retry-safe. Bootstrap fetches the pinned commit into
`/opt/traffic-generator/source.tmp` with at most four attempts, verifies both the exact Git commit and
the SHA-256 of canonical `suites/csd-violations/scenarios.mjs` against
`DEPLOYMENT_MANIFEST_SHA256`, removes the Git remote, and only then atomically renames the checkout to
`/opt/traffic-generator/source`. An interrupted staging directory is discarded on retry. On a rerun, an
existing source tree is retained only when both immutable identities still match; otherwise root rebuilds
it from clean staging. Root ownership and read-only modes are applied after verification, so `tgen` can
execute the reviewed suite but cannot alter source or provenance. A failed fetch or digest mismatch exhausts
the bounded attempts and stops cloud-init without publishing an unverified checkout.

For unattended hydration, `source_commit` must be the exact published, reviewed merge SHA containing
`continuous.mjs` and the compatible `run.sh`/`run.mjs` changes. Derive the scenario-manifest SHA-256
from `suites/csd-violations/scenarios.mjs` at that same commit and retain the reviewed manifest version.
Do not use a moving branch, an old one-shot source pin, a guessed future SHA, or uncommitted source
embedded in user data. Source reuse also requires the dispatcher to be present. The example keeps
symbolic source/digest inputs until publication; existing provider constraints and lock versions remain unchanged.

The CloudWatch agent persistently forwards four distinct local logs to the encrypted runtime log group:
`/var/log/cloud-init-output.log`, worker health, Xvfb, and the canonical scenario wrapper output. Its own
logs are deliberately excluded to avoid recursion. The worker IAM policy permits scoped CloudWatch Logs
writes, while the log group uses the customer-managed KMS key through its regional CloudWatch Logs
service principal.

Cloud-init enables Ubuntu public-key SSH, disables password/root login, installs Chrome's setuid sandbox
with root ownership and mode `4755`, then proves Chrome starts as the unprivileged `tgen` user without
`--no-sandbox`. The first-boot health service verifies only runtime identity, dependencies, Xvfb, the
sandbox, and a headed Chrome navigation to local `about:blank`; it does not execute any CSD scenario or
prove application reachability or detection.

Inspect `/opt/traffic-generator/status.json` and confirm the runtime provenance fields match the reviewed
plan. Validate SSM registration, SSH from the current jumpbox `/32`, both browser services, all four
CloudWatch log streams, and local evidence beneath
`/opt/traffic-generator/runtime/results/<run-id>/<scenario>/`. Confirm that each receipt `objectKey` and
screenshot `objectKey` names the exact uploaded object beneath `runs/<run-id>/<scenario>/`, with the
scenario segment appearing once. A successful browser run does not itself prove an F5 Distributed Cloud
Client-Side Defense detection; verify that separately through the approved API or console workflow.

## Unattended recurrence, status, and control

The root-owned `csd-continuous.service` invokes pinned Node with `continuous.mjs tick`. Each timer
firing executes at most one existing scenario, or one due frozen-upload retry without starting Chrome.
The dispatcher imports the canonical 11-name order from `scenarios.mjs`, advances through terminal
decisions, then wraps. `completedCycles` counts decisions, not eleven successful detections or uploads.
This is separate from the newer generic catalog scheduler, which excludes CSD; do not configure both
as alternative owners of CSD traffic.

Bootstrap stops recurrence before installation, verifies the source and dispatcher, starts Xvfb and
bounded health, requires `ready`, then enables/starts `csd-continuous.timer` only when enabled.
`continuous_enabled` is a Terraform boolean defaulting to `true`, exposed as an output and rendered
once as `CONTINUOUS_ENABLED=1` or `0` in `/etc/traffic-generator/runtime.env`. Disabled hydration
still installs and validates the dispatcher and units, but stops/disables recurrence. Do not hand-edit
the Terraform-owned environment as a permanent configuration change. User-data changes retain the
worker replacement behavior; review the saved plan and protection-disable procedure before deployment.

The enabled timer survives reboot without rerunning cloud-init: first tick after 30 seconds, subsequent
tick 15 seconds after the service becomes inactive, with 1-second accuracy and no missed-tick replay.
The service waits for network-online and headed health; health waits for Xvfb. Recurrence includes
cleanup, backoff, contention, and reboot gaps: it is not zero-downtime or uninterrupted traffic.

Read sanitized scheduling status on the worker:

```bash
sudo /opt/node/bin/node \
  /opt/traffic-generator/source/suites/csd-violations/continuous.mjs status
systemctl is-enabled csd-continuous.timer
systemctl is-active csd-continuous.timer csd-continuous.service
```

An inactive oneshot between ticks is normal. Status exposes cursor, attempted/browser-passed/committed/
failed/timeout/interrupted counters, completed cycles, current run/scenario, heartbeat, retry schedule,
last outcome, and bounded pending uploads; it does not expose raw infrastructure identities, credentials,
or error bodies. Root atomically persists private state under
`/opt/traffic-generator/runtime/continuous/state.json`. A fatal blocked state survives reboot: diagnose
and correct the cause rather than deleting state or treating a restart as recovery.

For temporary operator maintenance or manual SSM traffic, inhibit the timer first and allow the current
service to drain (up to its 1,100-second start budget). Verify the service is inactive and the shared
lock is free before proceeding. If it cannot drain, stop the service deliberately and verify interrupted
run cleanup and pending evidence before continuing:

```bash
sudo systemctl stop csd-continuous.timer
systemctl is-active csd-continuous.service
sudo flock -n /run/lock/csd-traffic-generator.lock /usr/bin/true
# Only if cancellation is required instead of draining:
sudo systemctl stop csd-continuous.service
```

Temporary `stop` does not survive reboot. For maintenance spanning reboot, disable the timer as an
explicit temporary operational override (`sudo systemctl disable --now csd-continuous.timer`), or deploy
the reviewed Terraform setting `continuous_enabled = false`; record the override and reconcile it.
Only after maintenance is complete, health is ready, no manual run holds the lock, and the reviewed
configuration enables recurrence, resume with `sudo systemctl enable --now csd-continuous.timer`.
Do not call `tick` as an operator start command or delete the shared lock. `run.sh` alone owns the
nonblocking lock for normal and upload-retry execution; reboot tmpfiles recreates it as root:tgen `0660`.

**Page Tamper UAT requires explicit pause and drain for the entire quiet, baseline, canary, and recovery
window.** There is no automatic reservation integration with the CSD controller. This timer schedules
only the existing 11 browser scenarios, never a Page Tamper baseline/canary/header matrix.

### Failure bounds and evidence retention

Scenario execution is bounded to 900 seconds, finalization to 120 seconds, and owned-child cleanup to
30 seconds. The systemd service has a 1,100-second start timeout, 45-second stop timeout, and cgroup
containment; health has 120/30-second start/stop bounds. These do not depend on SSM command timeouts.
Transient work has at most three total attempts with 30/60/120-second backoff steps capped at 300
seconds. Exhaustion records failure and advances; lock contention consumes neither cursor nor retries.
Fatal configuration, provenance, target, integrity, or authentication failures block further launches.

At most 32 pending upload records are retained, with at most three total retry attempts per frozen
upload and a 120-second retry deadline. A tick retries at most one due upload and does not run a browser
in the same tick. Exhausted retries remain visible; queue/disk limits block new browser work rather
than deleting pending evidence. `execution-result.json` (schema version 1) lives under the run root,
outside the frozen scenario directory, and separates browser exit, upload exit/commit, outcome, failure
category, and signal. Missing or inconsistent results are failures, not inferred successes.

Only completed committed run directories are eligible for oldest-first pruning after seven days or
when total local detail exceeds 5 GiB. New work is rejected below 1 GiB free space; pending evidence
has a 2 GiB subcap. Active and pending evidence is never silently pruned. Log rotation is daily or at
10 MiB, retaining seven compressed rotations with delayed compression and copytruncate. Investigate
a disk block and preserve required evidence before authorized cleanup; never remove live run paths
or frozen pending evidence to make status green.

Verify fresh hydration with committed, hash-validated evidence for all eleven names over two cycles,
monotonic counters, bounded disk usage, no owned-child leaks, and controlled reboot recurrence. A ready
probe, active timer, successful browser run, or upload commit does **not** guarantee CSD detection.
These are acceptance checks for later approved deployment, not claims that this source change has
already been applied or validated on a live worker.

## 6. Drift and recovery

After runtime verification, run the drift check with the same explicit AWS identity; exit `0` means no changes, `2` requires review, and `1` is an error:

```bash
set -euo pipefail
export AWS_PROFILE=280469140135_Users
export AWS_REGION=us-east-1
terraform -chdir=terraform/aws plan -detailed-exitcode
```

Resume failed applies from the same backend state after diagnosing EIP quota, route/IGW state, instance availability, source-CIDR drift, key-file availability, SSM registration, endpoint reachability, archive checksums, cloud-init, or KMS/IAM denial. Do not replace resources manually or create parallel configuration.

After retrieving `upload-commit.json` from the exact run/scenario prefix, validate its
`status: committed`, exact `objectKey`, and recorded digests for `upload-manifest.json` and `SHA256SUMS`.
Validate the complete checksum set before tenant correlation from the authenticated operator context,
not from the AWS worker. Follow the structured `xcsh_api` workflow in `docs/en/07-integrate.mdx`: read
`detected_domains`, convert receipt `startedAt`/`completedAt` values to epoch seconds, and query `scripts`
and `formFields` with snake_case `start_time`/`end_time`. Compare exact receipt-derived reviewed hosts only
for `detected_domains` and `scripts`. Record `formFields` only as an optional aggregate count and
`OBSERVED` or `PENDING` classification for the receipt window, without attribution to specific generated
field identifiers. Correlation never changes the browser receipt or scenario result, and the worker
contains no tenant token or raw HTTP API client.

## Worker replacement recovery

A bootstrap failure does not authorize replacement while API termination protection is enabled. Recovery requires two independently saved, reviewed, and approved plans; do not change the variable default or combine the changes.

1. Create a saved plan with only `-var='termination_protection_enabled=false'`. It must show an in-place update of `aws_instance.worker.disable_api_termination` from `true` to `false`, no worker replacement, and no unrelated changes. Inspect it and record its SHA-256. Obtain explicit approval for that exact digest, apply only that plan, and verify the output is `false`.
2. Correct the reviewed bootstrap input or source. Create a new saved replacement plan with `-var='termination_protection_enabled=true'` and the approved replacement trigger, such as `-replace=aws_instance.worker`. It must restore `disable_api_termination = true` on the new worker.
3. Inspect the replacement plan and record its different SHA-256. Obtain separate explicit approval for that exact digest, then apply only that plan.
4. Verify the replacement reports `ready`, termination protection is restored, and runtime, Systems Manager, SSH, logging, and evidence checks pass. Apply success alone is not recovery proof.

Never disable protection and request replacement in the same plan. Never leave the replacement worker unprotected.

## Guarded destroy

`termination_protection_enabled` defaults to `true`. The versioned evidence, replica, primary access-log,
and replica access-log buckets all use `force_destroy = false`; Terraform cannot delete any of them while
current objects, noncurrent versions, or delete markers remain. Preserve required evidence and logs first.
After explicit approval for the exact four output buckets, use the authenticated procedure in
[Teardown](../../docs/en/08-teardown.mdx): take a complete auto-paginated inventory of versions and delete
markers in each owning region, delete no more than 1,000 identifiers per request, then re-list and repeat
within the documented safety bound because deletion or concurrent writes can leave or create delete markers.
Before planning destroy, independently verify all four buckets have zero current objects, versions, and
delete markers. Reaching the pass bound or finding remaining inventory fails closed and requires investigation
plus new approval; it never authorizes automatic purging or `force_destroy = true`.

Create the private `.plans` directory before saving plans. Pass
`-var='termination_protection_enabled=false'` as untracked CLI input rather than editing `main.tf`.
Inspect each saved plan, record its SHA-256, and obtain explicit approval for that exact digest
before applying it. Apply the approved disablement plan exactly, verify the output is `false`, then
repeat the review, digest, and separate approval process for the destroy plan.
