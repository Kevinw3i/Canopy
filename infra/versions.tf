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
  # Copy backend.hcl.example to backend.hcl and fill in your account-specific values.
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project
      Component = "control-plane"
      ManagedBy = "terraform"
    }
  }
}
