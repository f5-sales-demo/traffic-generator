data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_ami" "worker" {
  owners = ["099720109477"]

  filter {
    name   = "image-id"
    values = [var.ami_id]
  }

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_ec2_instance_type" "worker" {
  instance_type = var.instance_type
}

data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_109:KMS key policies require Resource "*"; administration is restricted to this account root principal.
  #checkov:skip=CKV_AWS_111:KMS key policies require Resource "*"; service use is constrained by source account or encryption context.
  #checkov:skip=CKV_AWS_356:AWS KMS does not support key ARNs in a key policy Resource element; "*" means this key only.
  statement {
    sid    = "AccountAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogsEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/f5-sales-demo/${var.name_prefix}*"]
    }
  }

  statement {
    sid    = "S3Encryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

locals {
  common_tags = merge({
    Application = "traffic-generator"
    Component   = "client-side-defense"
    ManagedBy   = "terraform"
    Repository  = "f5-sales-demo/traffic-generator"
  }, var.tags)

  operator_public_key = trimspace(var.ssh_public_key_path != null ? file(pathexpand(var.ssh_public_key_path)) : coalesce(var.ssh_public_key, ""))

  scenario_names = [
    "login-credential-skimmer",
    "registration-harvester",
    "payment-overlay-card-skimmer",
    "obfuscated-loader",
    "multi-cdn-injection",
    "tag-manager-hijack",
    "multi-channel-exfiltration",
    "high-volume-domain-exfiltration",
    "form-overlay",
    "keylogger-simulation",
    "maximum-detection",
  ]
}

check "operator_public_key" {
  assert {
    condition     = (var.ssh_public_key_path == null) != (var.ssh_public_key == null) && can(regex("^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/]+={0,3}(?: .*)?$", local.operator_public_key))
    error_message = "Set exactly one of ssh_public_key_path or ssh_public_key to one EC2-supported ssh-ed25519 or ssh-rsa public key; private key material and other key types are not accepted."
  }
}

check "deployment_identity" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
    error_message = "Refusing to deploy outside AWS account ${var.aws_account_id}."
  }
}

resource "aws_kms_key" "runtime" {
  description             = "Encrypts ${var.name_prefix} evidence, logs, and volumes"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "runtime" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.runtime.key_id
}

resource "aws_vpc" "this" {
  cidr_block           = "10.44.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  ingress = []
  egress  = []

  tags = { Name = "${var.name_prefix}-default-deny" }
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/f5-sales-demo/${var.name_prefix}/vpc-flow"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.runtime.arn
}

data "aws_iam_policy_document" "flow_logs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.name_prefix}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume_role.json
}

data "aws_iam_policy_document" "flow_logs" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.vpc_flow.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "${var.name_prefix}-vpc-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}

resource "aws_flow_log" "vpc" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.this.id
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  availability_zone       = var.availability_zone
  cidr_block              = "10.44.0.0/24"
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name_prefix}-public-egress" }
}


resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "${var.name_prefix}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}


resource "aws_security_group" "worker" {
  name        = "${var.name_prefix}-worker"
  description = "Source-restricted SSH and required worker egress"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "SSH from the current operator jumpbox public IPv4"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.operator_ssh_cidr]
  }

  egress {
    description = "HTTPS egress for target, AWS APIs, and immutable dependencies"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS over UDP"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS over TCP"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-worker" }
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name_prefix}-endpoints"
  description = "TLS from the worker to AWS service endpoints"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "HTTPS from worker"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.worker.id]
  }

  tags = { Name = "${var.name_prefix}-endpoints" }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(["ssm", "ssmmessages", "logs"])

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.public.id]
  security_group_ids  = [aws_security_group.endpoints.id]

  tags = { Name = "${var.name_prefix}-${each.value}" }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id]
  tags              = { Name = "${var.name_prefix}-s3" }
}

resource "aws_s3_bucket" "evidence" {
  bucket_prefix = "${var.name_prefix}-evidence-"
  force_destroy = false
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.runtime.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  #checkov:skip=CKV_AWS_300:Lifecycle aborts incomplete multipart uploads after seven days; scanner does not recognize the provider v6 nested block.
  rule {
    id     = "expire-run-evidence"
    status = "Enabled"

    filter {
      prefix = "runs/"
    }

    expiration {
      days = var.evidence_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.bucket.json
}

resource "aws_cloudwatch_log_group" "runtime" {
  name              = "/f5-sales-demo/${var.name_prefix}/runtime"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.runtime.arn
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "worker" {
  name               = "${var.name_prefix}-worker"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.worker.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "worker" {
  statement {
    sid       = "WriteRunEvidence"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["${aws_s3_bucket.evidence.arn}/runs/*"]
  }
  statement {
    sid       = "ReadRunEvidence"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/runs/*"]
  }

  statement {
    sid       = "ListRunEvidencePrefix"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["runs/*"]
    }
  }
  statement {
    sid       = "UseRuntimeKey"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.runtime.arn]
  }
  statement {
    sid       = "WriteRuntimeLogs"
    actions   = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime.arn}:*"]
  }
}

resource "aws_iam_role_policy" "worker" {
  name   = "${var.name_prefix}-evidence-logs"
  role   = aws_iam_role.worker.id
  policy = data.aws_iam_policy_document.worker.json
}

resource "aws_iam_instance_profile" "worker" {
  name = "${var.name_prefix}-worker"
  role = aws_iam_role.worker.name
}

resource "aws_key_pair" "operator" {
  key_name   = "${var.name_prefix}-operator"
  public_key = local.operator_public_key
}

resource "aws_network_interface" "worker" {
  subnet_id       = aws_subnet.public.id
  security_groups = [aws_security_group.worker.id]
  tags            = { Name = "${var.name_prefix}-worker" }
}

resource "aws_eip" "worker" {
  domain            = "vpc"
  network_interface = aws_network_interface.worker.id
  tags              = { Name = "${var.name_prefix}-worker" }

  depends_on = [aws_internet_gateway.this]
}


resource "aws_instance" "worker" {
  ami                  = data.aws_ami.worker.id
  instance_type        = var.instance_type
  availability_zone    = var.availability_zone
  iam_instance_profile = aws_iam_instance_profile.worker.name
  key_name             = aws_key_pair.operator.key_name
  primary_network_interface {
    network_interface_id = aws_network_interface.worker.id
  }
  ebs_optimized                        = true
  monitoring                           = true
  disable_api_termination              = var.termination_protection_enabled
  instance_initiated_shutdown_behavior = "stop"
  user_data_replace_on_change          = true
  user_data = templatefile("${path.module}/cloud-init.tftpl", {
    aws_region                      = var.aws_region
    ami_id                          = var.ami_id
    evidence_bucket                 = aws_s3_bucket.evidence.id
    log_group_name                  = aws_cloudwatch_log_group.runtime.name
    source_commit                   = var.source_commit
    source_repository_url           = var.source_repository_url
    aws_cli_version                 = var.aws_cli_version
    aws_cli_archive_url             = var.aws_cli_archive_url
    aws_cli_archive_sha256          = var.aws_cli_archive_sha256
    cloudwatch_agent_version        = var.cloudwatch_agent_version
    cloudwatch_agent_package_url    = var.cloudwatch_agent_package_url
    cloudwatch_agent_package_sha256 = var.cloudwatch_agent_package_sha256
    node_archive_url                = var.node_archive_url
    node_archive_sha256             = var.node_archive_sha256
    chrome_archive_url              = var.chrome_archive_url
    chrome_archive_sha256           = var.chrome_archive_sha256
    playwright_core_version         = var.playwright_core_version
    deployment_manifest_version     = var.deployment_manifest_version
    deployment_manifest_sha256      = var.deployment_manifest_sha256
    target_url                      = var.target_url
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    encrypted             = true
    kms_key_id            = aws_kms_key.runtime.arn
    volume_type           = "gp3"
    volume_size           = var.root_volume_size_gib
    iops                  = var.root_volume_iops
    throughput            = var.root_volume_throughput
    delete_on_termination = true
  }

  tags = { Name = "${var.name_prefix}-worker" }


  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.aws_account_id && var.aws_region == "us-east-1" && var.aws_profile == "280469140135_Users"
      error_message = "Account, profile, and region must match the reviewed deployment boundary."
    }
    precondition {
      condition     = contains(data.aws_ec2_instance_type.worker.supported_architectures, "x86_64") && !contains(data.aws_ec2_instance_type.worker.supported_architectures, "arm64")
      error_message = "instance_type must support x86_64 and must not be a Graviton/arm64 instance type."
    }
    precondition {
      condition     = var.target_url == "https://client-side-defense.f5-sales-demo.com"
      error_message = "Target must be the exact authorized CSD demo origin."
    }
  }

  depends_on = [
    aws_eip.worker,
    aws_route_table_association.public,
    aws_vpc_endpoint.interface,
    aws_vpc_endpoint.s3,
    aws_s3_bucket_policy.evidence,
  ]
}


data "aws_iam_policy_document" "replica_kms" {
  provider = aws.replica

  #checkov:skip=CKV_AWS_109:KMS key policies require Resource "*"; administration is restricted to this account root principal.
  #checkov:skip=CKV_AWS_111:KMS key policies require Resource "*"; use is delegated through scoped IAM policy on the replication role.
  #checkov:skip=CKV_AWS_356:AWS KMS does not support key ARNs in a key policy Resource element; "*" means this key only.
  statement {
    sid    = "AccountAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "evidence_replica" {
  provider                = aws.replica
  description             = "Encrypts ${var.name_prefix} cross-region evidence replicas"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.replica_kms.json
}

resource "aws_kms_alias" "evidence_replica" {
  provider      = aws.replica
  name          = "alias/${var.name_prefix}-evidence-replica"
  target_key_id = aws_kms_key.evidence_replica.key_id
}

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:This bucket is the terminal S3 access-log destination; enabling self-logging would recurse indefinitely.
  #checkov:skip=CKV_AWS_144:Access logs are operational telemetry with bounded retention; replicating the sink would duplicate log-delivery objects and cost.
  #checkov:skip=CKV_AWS_145:Amazon S3 server access-log destination buckets require SSE-S3 default encryption; SSE-KMS can produce log objects the bucket owner cannot read.
  bucket_prefix = "${var.name_prefix}-access-logs-"
  force_destroy = false
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  #checkov:skip=CKV_AWS_300:Lifecycle aborts incomplete multipart uploads after seven days; scanner does not recognize the provider v6 nested block.
  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.access_logs]
}

data "aws_iam_policy_document" "access_logs" {
  statement {
    sid    = "S3ServerAccessLogsPolicy"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs.arn}/evidence-access/*"]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.evidence.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = data.aws_iam_policy_document.access_logs.json
}

resource "aws_s3_bucket_logging" "evidence" {
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "evidence-access/"

  depends_on = [aws_s3_bucket_policy.access_logs]
}

resource "aws_s3_bucket_notification" "evidence" {
  bucket      = aws_s3_bucket.evidence.id
  eventbridge = true
}

resource "aws_s3_bucket_notification" "access_logs" {
  bucket      = aws_s3_bucket.access_logs.id
  eventbridge = true
}

resource "aws_s3_bucket" "evidence_replica" {
  provider      = aws.replica
  bucket_prefix = "${var.name_prefix}-replica-"
  force_destroy = false
}

resource "aws_s3_bucket_ownership_controls" "evidence_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.evidence_replica.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "evidence_replica" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.evidence_replica.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.evidence_replica.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.evidence_replica.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.evidence_replica.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_notification" "evidence_replica" {
  provider    = aws.replica
  bucket      = aws_s3_bucket.evidence_replica.id
  eventbridge = true
}

resource "aws_s3_bucket" "replica_access_logs" {
  provider = aws.replica
  #checkov:skip=CKV_AWS_18:This bucket is the terminal cross-region S3 access-log destination; enabling self-logging would recurse indefinitely.
  #checkov:skip=CKV_AWS_144:Replica access logs are terminal operational telemetry with bounded retention; replicating this sink would create another regional sink.
  #checkov:skip=CKV_AWS_145:Amazon S3 server access-log destination buckets require SSE-S3 default encryption; SSE-KMS can produce log objects the bucket owner cannot read.
  bucket_prefix = "${var.name_prefix}-replica-logs-"
  force_destroy = false
}

resource "aws_s3_bucket_ownership_controls" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "replica_access_logs" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.replica_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id
  #checkov:skip=CKV_AWS_300:Lifecycle aborts incomplete multipart uploads after seven days; scanner does not recognize the provider v6 nested block.
  rule {
    id     = "expire-replica-access-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.replica_access_logs]
}

data "aws_iam_policy_document" "replica_access_logs" {
  provider = aws.replica

  statement {
    sid    = "S3ServerAccessLogsPolicy"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.replica_access_logs.arn}/replica-access/*"]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.evidence_replica.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.replica_access_logs.arn, "${aws_s3_bucket.replica_access_logs.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id
  policy   = data.aws_iam_policy_document.replica_access_logs.json
}

resource "aws_s3_bucket_logging" "evidence_replica" {
  provider      = aws.replica
  bucket        = aws_s3_bucket.evidence_replica.id
  target_bucket = aws_s3_bucket.replica_access_logs.id
  target_prefix = "replica-access/"

  depends_on = [aws_s3_bucket_policy.replica_access_logs]
}

resource "aws_s3_bucket_notification" "replica_access_logs" {
  provider    = aws.replica
  bucket      = aws_s3_bucket.replica_access_logs.id
  eventbridge = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.evidence_replica.id
  #checkov:skip=CKV_AWS_300:Lifecycle aborts incomplete multipart uploads after seven days; scanner does not recognize the provider v6 nested block.
  rule {
    id     = "expire-replicated-evidence"
    status = "Enabled"
    filter {}

    expiration {
      days = var.evidence_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence_replica]
}

data "aws_iam_policy_document" "replication_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replication" {
  name               = "${var.name_prefix}-evidence-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume_role.json
}

data "aws_iam_policy_document" "replication" {
  statement {
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.evidence.arn]
  }

  statement {
    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging",
    ]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
  }

  statement {
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
    ]
    resources = ["${aws_s3_bucket.evidence_replica.arn}/*"]
  }

  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.runtime.arn]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${aws_s3_bucket.evidence.arn}/*"]
    }
  }

  statement {
    actions   = ["kms:Encrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.evidence_replica.arn]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${aws_s3_bucket.evidence_replica.arn}/*"]
    }
  }
}

resource "aws_iam_role_policy" "replication" {
  name   = "${var.name_prefix}-evidence-replication"
  role   = aws_iam_role.replication.id
  policy = data.aws_iam_policy_document.replication.json
}

resource "aws_s3_bucket_replication_configuration" "evidence" {
  depends_on = [
    aws_iam_role_policy.replication,
    aws_s3_bucket_versioning.evidence,
    aws_s3_bucket_versioning.evidence_replica,
  ]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "replicate-all-evidence"
    status = "Enabled"

    filter {}

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.evidence_replica.arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.evidence_replica.arn
      }
    }
  }
}



resource "aws_ssm_document" "run_scenario" {
  name            = "${var.name_prefix}-run-scenario"
  document_type   = "Command"
  document_format = "YAML"

  content = yamlencode({
    schemaVersion = "2.2"
    description   = "Run one allowlisted CSD browser scenario without shell interpolation"
    parameters = {
      Scenario = {
        type              = "String"
        description       = "Canonical CSD scenario name"
        allowedValues     = local.scenario_names
        interpolationType = "ENV_VAR"
      }
    }
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "RunCsdScenario"
      inputs = {
        timeoutSeconds = "1800"
        runCommand = [
          "/usr/local/bin/csd-run \"$SSM_Scenario\"",
        ]
      }
    }]
  })
}
