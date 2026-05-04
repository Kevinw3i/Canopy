# ── General ──────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "ap-northeast-1"
}

variable "project" {
  description = "Project name used in resource naming"
  type        = string
  default     = "canopy"
}

# ── Networking ──────────────────────────────────────────

variable "create_vpc" {
  description = "Whether Terraform should create a dedicated VPC for Canopy. If false, vpc_id/public_subnet_ids/private_subnet_ids must point to existing networking."
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  description = "CIDR block for the Terraform-managed VPC when create_vpc = true."
  type        = string
  default     = "10.200.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDR blocks for the Terraform-managed VPC. Must span at least two AZs."
  type        = list(string)
  default     = ["10.200.0.0/24", "10.200.1.0/24"]

  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "public_subnet_cidrs must contain at least two CIDR blocks."
  }
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDR blocks for the Terraform-managed VPC. Must span at least two AZs."
  type        = list(string)
  default     = ["10.200.10.0/24", "10.200.11.0/24"]

  validation {
    condition     = length(var.private_subnet_cidrs) >= 2
    error_message = "private_subnet_cidrs must contain at least two CIDR blocks."
  }
}

variable "single_nat_gateway" {
  description = "Use one NAT Gateway for all private subnets when create_vpc = true. Set false for one NAT per private subnet/AZ."
  type        = bool
  default     = true
}

variable "vpc_id" {
  description = "VPC ID where resources are deployed"
  type        = string
  default     = ""
}

variable "public_subnet_ids" {
  description = "Public subnets for the ALB (at least 2 AZs)"
  type        = list(string)
  default     = []
}

variable "private_subnet_ids" {
  description = "Private subnets for ECS tasks (at least 2 AZs)"
  type        = list(string)
  default     = []
}

# ── ECS ─────────────────────────────────────────────────

variable "cpu" {
  description = "Fargate task CPU units"
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate task memory (MiB)"
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Number of ECS tasks"
  type        = number
  default     = 2
}

variable "create_service" {
  description = "Whether to create the ECS service. Set to false on first deploy to create ECR first, push image, then re-apply with true."
  type        = bool
  default     = true
}

variable "cpu_architecture" {
  description = "Fargate CPU architecture (X86_64 or ARM64). Must match the Docker image."
  type        = string
  default     = "X86_64"
}

variable "image_tag" {
  description = "Docker image tag to deploy (must be a versioned tag, e.g. v1.0.0 or a git SHA). Can be empty when create_service = false."
  type        = string
  default     = ""

  validation {
    condition     = var.image_tag != "latest"
    error_message = "Using 'latest' is not allowed. Specify an explicit version tag or git SHA for deterministic deployments."
  }
}

# ── ALB Exposure ────────────────────────────────────────

variable "alb_internal" {
  description = "Whether the ALB should be internal (not internet-facing). Defaults to true for safety."
  type        = bool
  default     = true
}

variable "alb_allowed_cidrs" {
  description = "CIDR blocks allowed to reach the ALB on 443. Required for both internal and public modes."
  type        = list(string)

  validation {
    condition     = length(var.alb_allowed_cidrs) > 0
    error_message = "alb_allowed_cidrs must contain at least one CIDR block (e.g. your VPC CIDR for internal, or office IPs for public)."
  }
}

# ── TLS / DNS ───────────────────────────────────────────

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for HTTPS listener"
  type        = string
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID (optional, set to empty string to skip DNS record)"
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "FQDN for the control-plane (e.g. canopy.example.com)"
  type        = string
  default     = ""
}

# ── Secrets ─────────────────────────────────────────────

variable "jwt_secret_arn" {
  description = "Secrets Manager ARN for the JWT signing secret. Create the secret out-of-band to avoid exposing it in Terraform state."
  type        = string
}

variable "jwt_secret_version_id" {
  description = "Secrets Manager version ID for the JWT secret. Pin this during rolling deployments to ensure all tasks use the same key. Leave empty to use AWSCURRENT."
  type        = string
  default     = ""
}

variable "secrets_kms_key_arns" {
  description = "KMS key ARNs used to encrypt Secrets Manager secrets (jwt_secret, oidc_client_secret). Leave empty if using AWS-managed keys."
  type        = list(string)
  default     = []
}

# ── Application config ──────────────────────────────────

variable "oidc_issuer_url" {
  description = "OIDC provider issuer URL"
  type        = string
}

variable "oidc_client_id" {
  description = "OIDC client ID"
  type        = string
}

variable "oidc_client_secret_arn" {
  description = "Secrets Manager ARN for the OIDC client secret (for confidential clients). Leave empty for public clients."
  type        = string
  default     = ""
}

variable "oidc_client_secret_version_id" {
  description = "Secrets Manager version ID for the OIDC client secret. Required when oidc_client_secret_arn is set, for the same version-pinning reason as jwt_secret_version_id."
  type        = string
  default     = ""
}

variable "generate_config" {
  description = "Generate config.toml from env vars at startup. Must be true for ECS deployments to ensure all Terraform-managed settings are applied."
  type        = bool
  default     = true

  validation {
    condition     = var.generate_config == true
    error_message = "generate_config must be true for ECS deployments. Mounted config mode is not supported as it can silently ignore Terraform-supplied settings."
  }
}

variable "entitlements_file" {
  description = "Path to the entitlements TOML file inside the container (baked via --build-arg or mounted)"
  type        = string
  default     = "/etc/canopy/entitlements.toml"
}

variable "jwt_expiry_seconds" {
  description = "Internal JWT expiry"
  type        = number
  default     = 3600
}

variable "aws_session_duration_seconds" {
  description = "STS AssumeRole session duration"
  type        = number
  default     = 3600
}

variable "cors_allowed_origins" {
  description = "CORS allowed origins list"
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 90
}

# ── Cross-account access ────────────────────────────────

variable "enable_direct_access" {
  description = "Allow the control-plane to directly access EC2/CloudWatch/STS in the deployment account (role_arn = \"direct\" in entitlements). Defaults to false for least-privilege."
  type        = bool
  default     = false
}

variable "force_new_deployment" {
  description = "Force a full task replacement instead of rolling update. Set to true when changing entitlements to avoid mixed auth versions behind the ALB."
  type        = bool
  default     = false
}

variable "sts_external_id" {
  description = "STS ExternalId used in cross-account AssumeRole calls. Must match the target account's trust policy."
  type        = string
  default     = "canopy"
}

variable "assumable_role_arns" {
  description = "IAM role ARNs that the control-plane task role is allowed to assume (cross-account)"
  type        = list(string)
  default     = []
}
