terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # REQUIRED: Configure via partial backend config before first init:
  #   terraform init -backend-config=backend.hcl
  #
  # Create backend.hcl with:
  #   bucket         = "canopy-tfstate-123456789012"
  #   key            = "control-plane/terraform.tfstate"
  #   region         = "ap-northeast-1"
  #   dynamodb_table = "canopy-tflock"
  #   encrypt        = true
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "canopy"
      Component = "control-plane"
      ManagedBy = "terraform"
    }
  }
}
