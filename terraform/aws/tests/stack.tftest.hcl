mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "280469140135"
      arn        = "arn:aws:iam::280469140135:user/terraform-test"
      user_id    = "AIDATEST"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }

  mock_data "aws_ami" {
    defaults = {
      id                  = "ami-0123456789abcdef0"
      architecture        = "x86_64"
      root_device_type    = "ebs"
      state               = "available"
      virtualization_type = "hvm"
    }
  }

  mock_data "aws_ec2_instance_type" {
    defaults = { supported_architectures = ["x86_64"] }
  }

  mock_resource "aws_eip" {
    defaults = { public_ip = "203.0.113.10" }
  }

  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::280469140135:role/mock-role" }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:280469140135:log-group:mock" }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::mock-source-bucket"
      id  = "mock-source-bucket"
    }
  }
}

mock_provider "aws" {
  alias = "replica"

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::mock-replica-bucket"
      id  = "mock-replica-bucket"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:us-east-2:280469140135:key/00000000-0000-0000-0000-000000000000"
      key_id = "00000000-0000-0000-0000-000000000000"
    }
  }
}

override_data {
  target = data.aws_iam_policy_document.replica_kms
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

override_data {
  target = data.aws_iam_policy_document.replica_access_logs
  values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
}

variables {
  availability_zone               = "us-east-1a"
  ami_id                          = "ami-0123456789abcdef0"
  instance_type                   = "m7i.large"
  operator_ssh_cidr               = "142.127.218.190/32"
  ssh_public_key                  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestPublicKeyMaterialOnly operator@test"
  source_commit                   = "0123456789abcdef0123456789abcdef01234567"
  aws_cli_version                 = "2.31.21"
  aws_cli_archive_url             = "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.31.21.zip"
  aws_cli_archive_sha256          = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  cloudwatch_agent_version        = "1.300057.0b252"
  cloudwatch_agent_package_url    = "https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/1.300057.0b252/amazon-cloudwatch-agent.deb"
  cloudwatch_agent_package_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  node_archive_url                = "https://nodejs.org/dist/v22.20.0/node-v22.20.0-linux-x64.tar.xz"
  node_archive_sha256             = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  chrome_archive_url              = "https://storage.googleapis.com/chrome-for-testing-public/140.0.7339.207/linux64/chrome-linux64.zip"
  chrome_archive_sha256           = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  playwright_core_version         = "1.55.0"
  deployment_manifest_version     = "1.0.0"
  deployment_manifest_sha256      = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
}

run "reject_wrong_account" {
  command = plan
  variables { aws_account_id = "111111111111" }
  expect_failures = [var.aws_account_id]
}

run "reject_wrong_profile" {
  command = plan
  variables { aws_profile = "default" }
  expect_failures = [var.aws_profile]
}

run "reject_wrong_region" {
  command = plan
  variables { aws_region = "us-west-2" }
  expect_failures = [var.aws_region]
}

run "reject_non_host_ssh_cidr" {
  command = plan
  variables { operator_ssh_cidr = "142.127.218.0/24" }
  expect_failures = [var.operator_ssh_cidr]
}

run "reject_noncanonical_ssh_cidr" {
  command = plan
  variables { operator_ssh_cidr = "142.127.218.190/32" }

  assert {
    condition     = length(one(aws_security_group.worker.ingress).cidr_blocks) == 1 && contains(one(aws_security_group.worker.ingress).cidr_blocks, "142.127.218.190/32")
    error_message = "The exact current operator /32 must be the sole SSH source."
  }
}

run "accept_rsa_operator_key" {
  command = plan
  variables { ssh_public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCTestPublicKeyMaterialOnly operator@test" }

  assert {
    condition     = startswith(aws_key_pair.operator.public_key, "ssh-rsa ")
    error_message = "The Terraform-managed EC2 key pair must accept EC2-supported RSA public keys."
  }
}

run "reject_ecdsa_operator_key" {
  command = plan
  variables { ssh_public_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAITestPublicKeyMaterialOnly operator@test" }
  expect_failures = [check.operator_public_key]
}

run "reject_security_key_operator_key" {
  command = plan
  variables { ssh_public_key = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tITestPublicKeyMaterialOnly operator@test" }
  expect_failures = [check.operator_public_key]
}


run "reject_unpinned_source_commit" {
  command = plan
  variables { source_commit = "main" }
  expect_failures = [var.source_commit]
}

run "reject_unpinned_aws_cli_archive" {
  command = plan
  variables { aws_cli_archive_url = "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" }
  expect_failures = [var.aws_cli_archive_url]
}

run "reject_mismatched_aws_cli_version" {
  command = plan
  variables { aws_cli_version = "2.31.20" }
  expect_failures = [check.pinned_runtime_artifact_urls]
}

run "reject_unpinned_cloudwatch_agent" {
  command = plan
  variables { cloudwatch_agent_package_url = "https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb" }
  expect_failures = [var.cloudwatch_agent_package_url]
}


run "reject_unpinned_node_archive" {
  command = plan
  variables { node_archive_url = "https://nodejs.org/download/latest/node.tar.xz" }
  expect_failures = [var.node_archive_url]
}

run "reject_unpinned_chrome_archive" {
  command = plan
  variables { chrome_archive_url = "https://storage.googleapis.com/chrome-for-testing-public/latest/linux64/chrome-linux64.zip" }
  expect_failures = [var.chrome_archive_url]
}

run "reject_graviton_instance_type" {
  command = plan
  variables { instance_type = "m7g.large" }
  expect_failures = [var.instance_type]
}


run "verify_public_worker_and_storage" {
  command = apply

  assert {
    condition     = aws_instance.worker.ami == data.aws_ami.worker.id && one(aws_instance.worker.primary_network_interface).network_interface_id == aws_network_interface.worker.id && aws_network_interface.worker.subnet_id == aws_subnet.public.id
    error_message = "The validated Ubuntu worker must launch with the pre-associated public-subnet network interface."
  }

  assert {
    condition     = aws_instance.worker.iam_instance_profile == aws_iam_instance_profile.worker.name && aws_instance.worker.key_name == aws_key_pair.operator.key_name
    error_message = "The worker must attach the exact IAM instance profile and operator EC2 key pair independently of its primary ENI."
  }

  assert {
    condition     = aws_eip.worker.network_interface == aws_network_interface.worker.id
    error_message = "The stable Elastic IP must attach directly to the primary ENI before instance launch and cloud-init."
  }

  assert {
    condition     = length(aws_security_group.worker.ingress) == 1 && one(aws_security_group.worker.ingress).protocol == "tcp" && one(aws_security_group.worker.ingress).from_port == 22 && one(aws_security_group.worker.ingress).to_port == 22 && length(one(aws_security_group.worker.ingress).cidr_blocks) == 1 && contains(one(aws_security_group.worker.ingress).cidr_blocks, var.operator_ssh_cidr) && !contains(one(aws_security_group.worker.ingress).cidr_blocks, "0.0.0.0/0")
    error_message = "The worker must expose only TCP/22 to the exact operator /32, never broad ingress."
  }

  assert {
    condition     = startswith(aws_key_pair.operator.public_key, "ssh-ed25519 ") && !strcontains(aws_key_pair.operator.public_key, "PRIVATE KEY")
    error_message = "The Terraform-managed EC2 key pair must contain public key material only."
  }

  assert {
    condition     = aws_subnet.public.map_public_ip_on_launch == false && one(aws_route_table.public.route).cidr_block == "0.0.0.0/0" && one(aws_route_table.public.route).gateway_id == aws_internet_gateway.this.id
    error_message = "The public subnet must route through the IGW without automatic public IP assignment."
  }

  assert {
    condition     = toset(keys(aws_vpc_endpoint.interface)) == toset(["logs", "ssm", "ssmmessages"]) && aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway" && contains(aws_vpc_endpoint.s3.route_table_ids, aws_route_table.public.id)
    error_message = "SSM recovery and S3 endpoints must remain attached to the public worker network."
  }

  assert {
    condition     = aws_instance.worker.metadata_options[0].http_tokens == "required" && aws_instance.worker.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "The worker must require IMDSv2 with a hop limit of one."
  }

  assert {
    condition     = aws_instance.worker.root_block_device[0].encrypted && aws_instance.worker.root_block_device[0].volume_type == "gp3" && aws_instance.worker.root_block_device[0].kms_key_id == aws_kms_key.runtime.arn
    error_message = "The worker root volume must be KMS-encrypted gp3."
  }

  assert {
    condition     = aws_instance.worker.disable_api_termination && aws_instance.worker.monitoring && aws_instance.worker.ebs_optimized
    error_message = "The worker must retain termination protection, detailed monitoring, and EBS optimization."
  }

  assert {
    condition     = aws_s3_bucket.evidence.force_destroy == false && aws_s3_bucket_versioning.evidence.versioning_configuration[0].status == "Enabled" && aws_cloudwatch_log_group.runtime.kms_key_id == aws_kms_key.runtime.arn
    error_message = "Evidence storage and runtime logs must retain their destruction and KMS safeguards."
  }

  assert {
    condition     = length(aws_default_security_group.this.ingress) == 0 && length(aws_default_security_group.this.egress) == 0
    error_message = "The VPC default security group must deny all ingress and egress."
  }

  assert {
    condition     = aws_flow_log.vpc.vpc_id == aws_vpc.this.id && aws_flow_log.vpc.traffic_type == "ALL" && aws_flow_log.vpc.log_destination == aws_cloudwatch_log_group.vpc_flow.arn
    error_message = "The VPC must send all flow records to the encrypted flow-log group."
  }

  assert {
    condition     = aws_s3_bucket_notification.evidence.eventbridge && aws_s3_bucket_notification.access_logs.eventbridge && aws_s3_bucket_logging.evidence.target_bucket == aws_s3_bucket.access_logs.id
    error_message = "The evidence and access-log buckets must enable EventBridge notifications, and evidence must use dedicated server access logging."
  }

  assert {
    condition = (
      aws_s3_bucket.evidence_replica.force_destroy == false &&
      aws_s3_bucket_versioning.evidence_replica.versioning_configuration[0].status == "Enabled" &&
      one(aws_s3_bucket_server_side_encryption_configuration.evidence_replica.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms" &&
      one(aws_s3_bucket_server_side_encryption_configuration.evidence_replica.rule).apply_server_side_encryption_by_default[0].kms_master_key_id == aws_kms_key.evidence_replica.arn &&
      one(aws_s3_bucket_replication_configuration.evidence.rule).destination[0].bucket == aws_s3_bucket.evidence_replica.arn &&
      one(aws_s3_bucket_replication_configuration.evidence.rule).destination[0].encryption_configuration[0].replica_kms_key_id == aws_kms_key.evidence_replica.arn
    )
    error_message = "Evidence must replicate with the replica-region KMS key to the protected, versioned cross-region destination bucket."
  }

  assert {
    condition = (
      aws_s3_bucket_notification.evidence_replica.eventbridge &&
      aws_s3_bucket_logging.evidence_replica.target_bucket == aws_s3_bucket.replica_access_logs.id &&
      aws_s3_bucket_notification.replica_access_logs.eventbridge &&
      aws_s3_bucket.replica_access_logs.force_destroy == false &&
      one(aws_s3_bucket_server_side_encryption_configuration.replica_access_logs.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"
    )
    error_message = "Replica storage must publish EventBridge events and log to a retained, SSE-S3 terminal sink that also publishes EventBridge events."
  }
}

run "verify_separately_approved_teardown_toggle" {
  command = plan
  variables { termination_protection_enabled = false }

  assert {
    condition     = aws_instance.worker.disable_api_termination == false
    error_message = "An explicitly reviewed teardown plan must be able to disable API termination protection."
  }
}

run "verify_scoped_execution_contract" {
  command = apply

  assert {
    condition     = aws_iam_role_policy_attachment.ssm.role == aws_iam_role.worker.name && endswith(aws_iam_role_policy_attachment.ssm.policy_arn, "/AmazonSSMManagedInstanceCore")
    error_message = "The worker role must retain standard SSM managed-instance recovery."
  }

  assert {
    condition     = strcontains(aws_instance.worker.user_data, var.source_commit) && strcontains(aws_instance.worker.user_data, var.deployment_manifest_sha256) && strcontains(aws_instance.worker.user_data, "chrome_sandbox") && !strcontains(aws_instance.worker.user_data, "--no-sandbox") && strcontains(aws_instance.worker.user_data, "PasswordAuthentication no")
    error_message = "Bootstrap must record provenance, verify the Chrome sandbox, omit sandbox bypasses, and disable SSH passwords."
  }

  assert {
    condition     = strcontains(aws_instance.worker.user_data, "package_update: false") && strcontains(aws_instance.worker.user_data, "ec2.archive.ubuntu.com/ubuntu/") && strcontains(aws_instance.worker.user_data, "https://\\1.ubuntu.com/ubuntu/") && strcontains(aws_instance.worker.user_data, "apt-get update") && strcontains(aws_instance.worker.user_data, "apt-get install -y --no-install-recommends") && !strcontains(aws_instance.worker.user_data, "awscli ca-certificates")
    error_message = "Bootstrap must rewrite regional, archive, and security Ubuntu APT sources to HTTPS before installing packages without the distro AWS CLI."
  }

  assert {
    condition     = length(regexall("(?m)^  - - /bin/bash\\s*$", aws_instance.worker.user_data)) == 8 && length(regexall("(?m)^    - -c\\s*$", aws_instance.worker.user_data)) == 8 && !strcontains(aws_instance.worker.user_data, "runcmd:\n  - |")
    error_message = "Every multiline cloud-init runcmd entry must invoke Bash explicitly so pipefail and Bash syntax are interpreted by Bash."
  }

  assert {
    condition     = strcontains(file("${path.module}/main.tf"), "actions   = [\"kms:Decrypt\", \"kms:Encrypt\", \"kms:GenerateDataKey\"]") && strcontains(file("${path.module}/main.tf"), "resources = [aws_kms_key.runtime.arn]")
    error_message = "The worker must have decrypt, encrypt, and data-key permissions scoped to the runtime KMS key."
  }

  assert {
    condition     = strcontains(file("${path.module}/main.tf"), "sid       = \"ReadRunEvidence\"") && strcontains(file("${path.module}/main.tf"), "actions   = [\"s3:GetObject\"]") && length(regexall("resources = \\[\"\\$\\{aws_s3_bucket\\.evidence\\.arn\\}/runs/\\*\"\\]", file("${path.module}/main.tf"))) >= 2
    error_message = "The worker must read evidence only from the evidence bucket runs prefix."
  }

  assert {
    condition     = strcontains(aws_instance.worker.user_data, var.aws_cli_archive_url) && strcontains(aws_instance.worker.user_data, var.aws_cli_archive_sha256) && strcontains(aws_instance.worker.user_data, "aws --version") && strcontains(aws_instance.worker.user_data, var.cloudwatch_agent_package_url) && strcontains(aws_instance.worker.user_data, var.cloudwatch_agent_package_sha256) && strcontains(aws_instance.worker.user_data, "amazon-cloudwatch-agent-ctl")
    error_message = "Bootstrap must checksum and install the exact pinned AWS CLI v2 and CloudWatch agent artifacts."
  }

  assert {
    condition     = strcontains(aws_instance.worker.user_data, "sudo -u tgen env PATH=/opt/node/bin:") && length(regexall("/opt/node/bin/npm", aws_instance.worker.user_data)) == 2
    error_message = "Every npm invocation must run as tgen with the pinned Node path explicitly exported."
  }

  assert {
    condition     = strcontains(aws_instance.worker.user_data, "/var/log/cloud-init-output.log") && strcontains(aws_instance.worker.user_data, "/var/log/csd-worker-health.log") && strcontains(aws_instance.worker.user_data, "/var/log/csd-xvfb.log") && strcontains(aws_instance.worker.user_data, "/var/log/csd-scenario.log") && !strcontains(aws_instance.worker.user_data, "/opt/aws/amazon-cloudwatch-agent/logs")
    error_message = "CloudWatch agent must persist bootstrap, health, Xvfb, and scenario logs without collecting its own logs recursively."
  }

  assert {
    condition     = length([for rule in aws_security_group.worker.egress : rule if rule.protocol == "tcp" && rule.from_port == 80 && rule.to_port == 80]) == 0
    error_message = "Worker egress must remain HTTPS-only for package and dependency downloads."
  }

  assert {
    condition = (
      length(regexall("X-aws-ec2-metadata-token-ttl-seconds: 60", aws_instance.worker.user_data)) == 2 &&
      length(regexall("latest/meta-data/instance-id", aws_instance.worker.user_data)) == 2 &&
      length(regexall("export INSTANCE_ID", aws_instance.worker.user_data)) == 2 &&
      strcontains(aws_instance.worker.user_data, "--preserve-env=INSTANCE_ID,RUN_ID,CSD_SCENARIO,DISPLAY") &&
      strcontains(aws_instance.worker.user_data, "--arg instance_id \"$INSTANCE_ID\"") &&
      strcontains(aws_instance.worker.user_data, "IMDSv2 returned an invalid instance ID")
    )
    error_message = "SSM execution and first-boot health must fail closed on IMDSv2 identity while the canonical suite wrapper loads immutable provenance from runtime.env."
  }

  assert {
    condition = (
      strcontains(aws_instance.worker.user_data, "/bin/bash /opt/traffic-generator/source/suites/csd-violations/run.sh") &&
      !strcontains(aws_instance.worker.user_data, "/opt/node/bin/node /opt/traffic-generator/source/suites/csd-violations/run.mjs") &&
      !strcontains(aws_instance.worker.user_data, "stdbuf -oL -eL tee") &&
      strcontains(aws_instance.worker.user_data, "rc=$?") &&
      strcontains(aws_instance.worker.user_data, "exit \"$rc\"")
    )
    error_message = "The SSM entry point must preserve the canonical run.sh exit and must not duplicate browser, logging, checksum, or upload orchestration."
  }

  assert {
    condition = (
      strcontains(aws_instance.worker.user_data, "headless: false") &&
      strcontains(aws_instance.worker.user_data, "page.goto(\"about:blank\")") &&
      !strcontains(aws_instance.worker.user_data, "AWS headed Chrome captures") &&
      !strcontains(aws_instance.worker.user_data, "--test-name-pattern") &&
      !strcontains(aws_instance.worker.user_data, "CSD_AWS_ALLOW_VERIFYING_STATUS")
    )
    error_message = "Boot health must use a local headed about:blank Chrome/Xvfb smoke and never execute scenario integration or capture production evidence."
  }

  assert {
    condition = (
      strcontains(aws_instance.worker.user_data, "tmp=/opt/traffic-generator/source.tmp") &&
      strcontains(aws_instance.worker.user_data, "for attempt in 1 2 3 4") &&
      strcontains(aws_instance.worker.user_data, "git -C \"$tmp\" fetch --quiet --depth=1 origin \"$commit\"") &&
      strcontains(aws_instance.worker.user_data, "valid \"$dst\"") &&
      strcontains(aws_instance.worker.user_data, "sha256sum \"$1/$manifest\"") &&
      strcontains(aws_instance.worker.user_data, "= \"$digest\"") &&
      strcontains(aws_instance.worker.user_data, "mv \"$tmp\" \"$dst\"") &&
      !strcontains(aws_instance.worker.user_data, "git -C /opt/traffic-generator/source remote add")
    )
    error_message = "Source installation must retry into clean staging, verify the exact commit and canonical scenario-manifest digest, reuse only a matching checkout, and rename atomically."
  }



  assert {
    condition     = strcontains(aws_instance.worker.user_data, "chown -R root:root \"$dst\"") && strcontains(aws_instance.worker.user_data, "find \"$dst\" -type d -exec chmod 0555") && strcontains(aws_instance.worker.user_data, "find \"$dst\" -type f -exec chmod 0444")
    error_message = "Installed source must be root-owned and read-only so tgen can execute but cannot mutate it."
  }

  assert {
    condition     = strcontains(aws_instance.worker.user_data, "export RUN_ID=\"$run_id\"") && strcontains(aws_instance.worker.user_data, "export CSD_SCENARIO=\"$scenario\"") && strcontains(aws_instance.worker.user_data, "/opt/traffic-generator/source/suites/csd-violations/run.sh") && !strcontains(aws_instance.worker.user_data, "/opt/traffic-generator/results") && !strcontains(aws_instance.worker.user_data, "$scenario/$scenario")
    error_message = "The worker must provide one run/scenario identity to canonical run.sh, which owns the matching local evidence and S3 prefix."
  }

  assert {
    condition     = output.instance_id == aws_instance.worker.id && output.public_ip == aws_eip.worker.public_ip && strcontains(output.ssh_command, "ubuntu@${aws_eip.worker.public_ip}") && output.ssm_document_name == aws_ssm_document.run_scenario.name && output.evidence_bucket_name == aws_s3_bucket.evidence.id
    error_message = "Operational outputs must expose public SSH and SSM recovery coordinates without private key material."
  }

  assert {
    condition     = output.target_url == "https://client-side-defense.f5-sales-demo.com" && output.source_commit == var.source_commit && output.deployment_manifest_sha256 == var.deployment_manifest_sha256 && output.termination_protection_enabled
    error_message = "Outputs must preserve target, immutable provenance, and termination protection."
  }
}
