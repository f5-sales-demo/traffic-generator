variable "aws_account_id" {
  description = "Expected AWS account ID; plans fail closed for any other account."
  type        = string
  default     = "280469140135"

  validation {
    condition     = var.aws_account_id == "280469140135"
    error_message = "aws_account_id must be 280469140135."
  }
}

variable "aws_profile" {
  description = "Required AWS shared configuration profile."
  type        = string
  default     = "280469140135_Users"

  validation {
    condition     = var.aws_profile == "280469140135_Users"
    error_message = "aws_profile must be 280469140135_Users."
  }
}

variable "aws_region" {
  description = "AWS region for the independent CSD traffic-generator deployment."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "aws_region must be us-east-1."
  }
}

variable "replication_region" {
  description = "Exact secondary AWS region for evidence replication."
  type        = string
  default     = "us-east-2"

  validation {
    condition     = var.replication_region == "us-east-2"
    error_message = "replication_region must be us-east-2."
  }
}

variable "availability_zone" {
  description = "Availability Zone selected by the reviewed live instance-offering discovery."
  type        = string

  validation {
    condition     = startswith(var.availability_zone, "us-east-1")
    error_message = "availability_zone must be in us-east-1."
  }
}

variable "ami_id" {
  description = "Exact reviewed Ubuntu 24.04 LTS AMI ID from live discovery."
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.ami_id))
    error_message = "ami_id must be an explicit AMI ID."
  }
}

variable "instance_type" {
  description = "Exact reviewed x86_64 instance type from live discovery, sized for Chrome and Xvfb."
  type        = string

  validation {
    condition     = can(regex("^(m|c|r)(5|6|7|8)(a|i|id|in|d|n|dn|ad|zn)?\\.(large|xlarge|2xlarge|4xlarge)$", var.instance_type))
    error_message = "instance_type must be a reviewed current-generation x86_64 M, C, or R family size; Graviton g-family variants are prohibited."
  }
}

variable "operator_ssh_cidr" {
  description = "Current operator jumpbox public IPv4 address as an exact /32; revalidate immediately before every plan or apply."
  type        = string

  validation {
    condition     = can(cidrhost(var.operator_ssh_cidr, 0)) && can(regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/32$", var.operator_ssh_cidr)) && "${cidrhost(var.operator_ssh_cidr, 0)}/32" == var.operator_ssh_cidr
    error_message = "operator_ssh_cidr must be one canonical IPv4 host CIDR ending in /32."
  }
}

variable "ssh_public_key_path" {
  description = "Optional path to an existing operator SSH public key. Exactly one of this or ssh_public_key must be set."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.ssh_public_key_path == null || (length(trimspace(var.ssh_public_key_path)) > 0 && fileexists(pathexpand(var.ssh_public_key_path)))
    error_message = "ssh_public_key_path must be null or identify an existing public key file."
  }
}

variable "ssh_public_key" {
  description = "Optional operator SSH public key text for automation. Exactly one of this or ssh_public_key_path must be set; never supply private key material."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true

  validation {
    condition     = var.ssh_public_key == null || !strcontains(var.ssh_public_key, "PRIVATE KEY")
    error_message = "ssh_public_key must contain public key text, never private key material."
  }
}

variable "source_commit" {
  description = "Exact traffic-generator repository commit deployed to the worker."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.source_commit))
    error_message = "source_commit must be a 40-character lowercase Git commit SHA."
  }
}

variable "source_repository_url" {
  description = "Immutable-source repository URL."
  type        = string
  default     = "https://github.com/f5-sales-demo/traffic-generator.git"

  validation {
    condition     = var.source_repository_url == "https://github.com/f5-sales-demo/traffic-generator.git"
    error_message = "source_repository_url must be the canonical traffic-generator repository."
  }
}

variable "aws_cli_version" {
  description = "Exact AWS CLI v2 version installed on the Linux x86_64 worker."
  type        = string

  validation {
    condition     = can(regex("^2\\.[0-9]+\\.[0-9]+$", var.aws_cli_version))
    error_message = "aws_cli_version must be an exact AWS CLI v2 semantic version."
  }
}

variable "aws_cli_archive_url" {
  description = "Pinned HTTPS URL for the exact AWS CLI v2 Linux x86_64 archive."
  type        = string

  validation {
    condition     = can(regex("^https://awscli\\.amazonaws\\.com/awscli-exe-linux-x86_64-2\\.[0-9]+\\.[0-9]+\\.zip$", var.aws_cli_archive_url))
    error_message = "aws_cli_archive_url must pin a versioned AWS CLI v2 Linux x86_64 archive."
  }
}

variable "aws_cli_archive_sha256" {
  description = "SHA-256 checksum for aws_cli_archive_url."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.aws_cli_archive_sha256))
    error_message = "aws_cli_archive_sha256 must be a lowercase SHA-256 digest."
  }
}

variable "cloudwatch_agent_version" {
  description = "Exact Amazon CloudWatch agent package version installed on the worker."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+[0-9A-Za-z.+~-]*$", var.cloudwatch_agent_version))
    error_message = "cloudwatch_agent_version must be an exact package version."
  }
}

variable "cloudwatch_agent_package_url" {
  description = "Official AWS Ubuntu amd64 Amazon CloudWatch agent package URL. Exact package version and SHA-256 are verified separately."
  type        = string

  validation {
    condition     = var.cloudwatch_agent_package_url == "https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb"
    error_message = "cloudwatch_agent_package_url must use the official AWS Ubuntu amd64 package URL."
  }
}

variable "cloudwatch_agent_package_sha256" {
  description = "SHA-256 checksum for cloudwatch_agent_package_url."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.cloudwatch_agent_package_sha256))
    error_message = "cloudwatch_agent_package_sha256 must be a lowercase SHA-256 digest."
  }
}

check "pinned_runtime_artifact_urls" {
  assert {
    condition = (
      var.aws_cli_archive_url == "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-${var.aws_cli_version}.zip" &&
      var.cloudwatch_agent_package_url == "https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb"
    )
    error_message = "AWS CLI URL must contain its exact version and CloudWatch Agent must use the official package URL."
  }
}

variable "node_archive_url" {
  description = "Pinned HTTPS URL for the reviewed Node.js 22 Linux x64 archive."
  type        = string

  validation {
    condition     = can(regex("^https://nodejs\\.org/dist/v22\\.[0-9]+\\.[0-9]+/node-v22\\.[0-9]+\\.[0-9]+-linux-x64\\.tar\\.xz$", var.node_archive_url))
    error_message = "node_archive_url must pin a Node.js 22 Linux x64 release archive."
  }
}

variable "node_archive_sha256" {
  description = "SHA-256 checksum for node_archive_url."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.node_archive_sha256))
    error_message = "node_archive_sha256 must be a lowercase SHA-256 digest."
  }
}

variable "chrome_archive_url" {
  description = "Pinned HTTPS URL for a reviewed Chrome for Testing Linux x64 archive."
  type        = string

  validation {
    condition     = can(regex("^https://storage\\.googleapis\\.com/chrome-for-testing-public/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/linux64/chrome-linux64\\.zip$", var.chrome_archive_url))
    error_message = "chrome_archive_url must pin a versioned Chrome for Testing Linux x64 archive."
  }
}

variable "chrome_archive_sha256" {
  description = "SHA-256 checksum for chrome_archive_url."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.chrome_archive_sha256))
    error_message = "chrome_archive_sha256 must be a lowercase SHA-256 digest."
  }
}

variable "playwright_core_version" {
  description = "Exact playwright-core version installed for the browser suite."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.playwright_core_version))
    error_message = "playwright_core_version must be an exact semantic version."
  }
}

variable "deployment_manifest_version" {
  description = "Version identifier for the reviewed deployment manifest represented by this configuration."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.deployment_manifest_version))
    error_message = "deployment_manifest_version must be an exact semantic version."
  }
}

variable "deployment_manifest_sha256" {
  description = "SHA-256 digest of the reviewed deployment manifest used to establish runtime provenance."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.deployment_manifest_sha256))
    error_message = "deployment_manifest_sha256 must be a lowercase SHA-256 digest."
  }
}

variable "termination_protection_enabled" {
  description = "API termination-protection state. Keep true for deployment and operation; set false only in a separately approved teardown plan."
  type        = bool
  default     = true
}


variable "target_url" {
  description = "Exact authorized CSD demo target."
  type        = string
  default     = "https://client-side-defense.f5-sales-demo.com"

  validation {
    condition     = var.target_url == "https://client-side-defense.f5-sales-demo.com"
    error_message = "target_url must be the exact authorized CSD demo origin."
  }
}

variable "name_prefix" {
  description = "Stable prefix for AWS resource names."
  type        = string
  default     = "csd-traffic-generator"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,31}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-33 lowercase alphanumeric or hyphen characters."
  }
}

variable "root_volume_size_gib" {
  description = "Encrypted gp3 root volume size."
  type        = number
  default     = 40

  validation {
    condition     = var.root_volume_size_gib >= 30 && var.root_volume_size_gib <= 200
    error_message = "root_volume_size_gib must be between 30 and 200 GiB."
  }
}

variable "root_volume_iops" {
  description = "Encrypted gp3 root volume IOPS."
  type        = number
  default     = 3000

  validation {
    condition     = var.root_volume_iops >= 3000 && var.root_volume_iops <= 16000
    error_message = "root_volume_iops must be between 3000 and 16000."
  }
}

variable "root_volume_throughput" {
  description = "Encrypted gp3 root volume throughput in MiB/s."
  type        = number
  default     = 125

  validation {
    condition     = var.root_volume_throughput >= 125 && var.root_volume_throughput <= 1000
    error_message = "root_volume_throughput must be between 125 and 1000 MiB/s."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention."
  type        = number
  default     = 365

  validation {
    condition     = contains([365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must retain runtime logs for at least one year using a supported CloudWatch Logs value."
  }
}

variable "evidence_retention_days" {
  description = "Days before current evidence objects expire."
  type        = number
  default     = 30

  validation {
    condition     = var.evidence_retention_days >= 1 && var.evidence_retention_days <= 365
    error_message = "evidence_retention_days must be between 1 and 365."
  }
}

variable "tags" {
  description = "Additional non-sensitive tags."
  type        = map(string)
  default     = {}
}
