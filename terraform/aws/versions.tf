terraform {
  required_version = ">= 1.14.0, < 2.0.0"

  backend "s3" {
    bucket       = "terraform-tfstate-xc"
    key          = "f5-sales-demo/traffic-generator-aws.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0, < 7.0.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = local.common_tags
  }
}


provider "aws" {
  alias   = "replica"
  region  = var.replication_region
  profile = var.aws_profile

  default_tags {
    tags = local.common_tags
  }
}
