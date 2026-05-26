# ── General ──────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "ap-northeast-1"

  validation {
    condition     = can(regex("^[a-z]{2,5}(-[a-z0-9]+)+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region identifier such as ap-northeast-1."
  }
}

variable "project" {
  description = "Project name used in resource naming"
  type        = string
  default     = "canopy"

  validation {
    condition = (
      length(var.project) >= 1 &&
      length(var.project) <= 28 &&
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.project))
    )
    error_message = "project must be 1-28 characters, use only lowercase letters, numbers, and hyphens, and not start or end with a hyphen."
  }
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

  validation {
    condition = (
      can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", var.vpc_cidr)) &&
      try(cidrsubnet(var.vpc_cidr, 0, 0) == var.vpc_cidr, false)
    )
    error_message = "vpc_cidr must be a valid canonical IPv4 CIDR block."
  }
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDR blocks for the Terraform-managed VPC. Must span at least two AZs."
  type        = list(string)
  default     = ["10.200.0.0/24", "10.200.1.0/24"]

  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "public_subnet_cidrs must contain at least two CIDR blocks."
  }

  validation {
    condition = alltrue([
      for cidr in var.public_subnet_cidrs :
      (
        can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", cidr)) &&
        try(cidrsubnet(cidr, 0, 0) == cidr, false)
      )
    ])
    error_message = "public_subnet_cidrs must contain only valid canonical IPv4 CIDR blocks."
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

  validation {
    condition = alltrue([
      for cidr in var.private_subnet_cidrs :
      (
        can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", cidr)) &&
        try(cidrsubnet(cidr, 0, 0) == cidr, false)
      )
    ])
    error_message = "private_subnet_cidrs must contain only valid canonical IPv4 CIDR blocks."
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

  validation {
    condition     = var.vpc_id == "" || can(regex("^vpc-[0-9a-f]{8}([0-9a-f]{9})?$", var.vpc_id))
    error_message = "vpc_id must be empty or a valid VPC ID."
  }
}

variable "public_subnet_ids" {
  description = "Public subnets for the ALB (at least 2 AZs)"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.public_subnet_ids :
      can(regex("^subnet-[0-9a-f]{8}([0-9a-f]{9})?$", id))
    ])
    error_message = "public_subnet_ids must contain only valid subnet IDs."
  }
}

variable "private_subnet_ids" {
  description = "Private subnets for ECS tasks (at least 2 AZs)"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.private_subnet_ids :
      can(regex("^subnet-[0-9a-f]{8}([0-9a-f]{9})?$", id))
    ])
    error_message = "private_subnet_ids must contain only valid subnet IDs."
  }
}

# ── ECS ─────────────────────────────────────────────────

variable "cpu" {
  description = "Fargate task CPU units"
  type        = number
  default     = 512

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096, 8192, 16384], var.cpu)
    error_message = "cpu must be a valid Fargate task CPU value: 256, 512, 1024, 2048, 4096, 8192, or 16384."
  }
}

variable "memory" {
  description = "Fargate task memory (MiB)"
  type        = number
  default     = 1024

  validation {
    condition = contains(concat(
      [512, 1024, 2048, 3072],
      [for memory in range(4096, 30721, 1024) : memory],
      [for memory in range(32768, 61441, 4096) : memory],
      [for memory in range(65536, 122881, 8192) : memory],
    ), var.memory)
    error_message = "memory must be a valid Fargate task memory value in MiB."
  }
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

  validation {
    condition     = contains(["X86_64", "ARM64"], var.cpu_architecture)
    error_message = "cpu_architecture must be either X86_64 or ARM64."
  }
}

variable "image_tag" {
  description = "Docker image tag to deploy (must be a versioned tag, e.g. v1.0.0 or a git SHA). Can be empty when create_service = false."
  type        = string
  default     = ""

  validation {
    condition     = var.image_tag == "" || can(regex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$", var.image_tag))
    error_message = "image_tag must be empty or a valid Docker image tag."
  }

  validation {
    condition     = lower(var.image_tag) != "latest"
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

  validation {
    condition = alltrue([
      for cidr in var.alb_allowed_cidrs :
      (
        can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", cidr)) &&
        try(cidrsubnet(cidr, 0, 0) == cidr, false)
      )
    ])
    error_message = "alb_allowed_cidrs must contain only valid canonical IPv4 CIDR blocks."
  }
}

# ── TLS / DNS ───────────────────────────────────────────

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for HTTPS listener"
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-zA-Z-]*:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-fA-F-]{36}$", var.acm_certificate_arn))
    error_message = "acm_certificate_arn must be a concrete ACM certificate ARN."
  }
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone ID (optional, set to empty string to skip DNS record)"
  type        = string
  default     = ""

  validation {
    condition     = var.route53_zone_id == "" || can(regex("^Z[A-Z0-9]+$", var.route53_zone_id))
    error_message = "route53_zone_id must be empty or a Route 53 hosted zone ID such as Z0123456789ABCDEFGHIJ."
  }
}

variable "domain_name" {
  description = "FQDN for the control-plane (e.g. canopy.example.com)"
  type        = string
  default     = ""

  validation {
    condition     = var.domain_name == "" || can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\\.?$", var.domain_name))
    error_message = "domain_name must be empty or a valid DNS name such as canopy.example.com."
  }
}

# ── Secrets ─────────────────────────────────────────────

variable "jwt_secret_arn" {
  description = "Secrets Manager ARN for the JWT signing secret. Create the secret out-of-band to avoid exposing it in Terraform state."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-zA-Z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.jwt_secret_arn))
    error_message = "jwt_secret_arn must be a concrete Secrets Manager secret ARN."
  }
}

variable "jwt_secret_version_id" {
  description = "Secrets Manager version ID for the JWT secret. Required when create_service = true so rolling deployments pin every task to the same key."
  type        = string
  default     = ""

  validation {
    condition     = var.jwt_secret_version_id == "" || can(regex("^[A-Za-z0-9-]{32,64}$", var.jwt_secret_version_id))
    error_message = "jwt_secret_version_id must be empty or a Secrets Manager version ID."
  }
}

variable "secrets_kms_key_arns" {
  description = "KMS key ARNs used to encrypt Secrets Manager secrets (jwt_secret, oidc_client_secret). Leave empty if using AWS-managed keys."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.secrets_kms_key_arns :
      can(regex("^arn:aws[a-zA-Z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$", arn))
    ])
    error_message = "secrets_kms_key_arns must contain only concrete KMS key ARNs."
  }
}

# ── Application config ──────────────────────────────────

variable "oidc_issuer_url" {
  description = "OIDC provider issuer URL"
  type        = string

  validation {
    condition     = can(regex("^https://[^[:space:]?#]+$", var.oidc_issuer_url))
    error_message = "oidc_issuer_url must be an HTTPS issuer URL without whitespace, query, or fragment."
  }
}

variable "oidc_client_id" {
  description = "OIDC client ID"
  type        = string

  validation {
    condition     = length(trimspace(var.oidc_client_id)) > 0 && length(regexall("[[:space:]]", var.oidc_client_id)) == 0
    error_message = "oidc_client_id must be non-empty and contain no whitespace."
  }
}

variable "oidc_client_secret_arn" {
  description = "Secrets Manager ARN for the OIDC client secret (for confidential clients). Leave empty for public clients."
  type        = string
  default     = ""

  validation {
    condition     = var.oidc_client_secret_arn == "" || can(regex("^arn:aws[a-zA-Z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.oidc_client_secret_arn))
    error_message = "oidc_client_secret_arn must be empty or a concrete Secrets Manager secret ARN."
  }
}

variable "oidc_client_secret_version_id" {
  description = "Secrets Manager version ID for the OIDC client secret. Required when oidc_client_secret_arn is set, for the same version-pinning reason as jwt_secret_version_id."
  type        = string
  default     = ""

  validation {
    condition     = var.oidc_client_secret_version_id == "" || can(regex("^[A-Za-z0-9-]{32,64}$", var.oidc_client_secret_version_id))
    error_message = "oidc_client_secret_version_id must be empty or a Secrets Manager version ID."
  }
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
  description = "Path to the entitlements TOML file inside the container. Production images bake this file via BuildKit secret."
  type        = string
  default     = "/etc/canopy/entitlements.toml"
}

variable "jwt_expiry_seconds" {
  description = "Internal JWT expiry"
  type        = number
  default     = 3600

  validation {
    condition     = var.jwt_expiry_seconds > 0 && var.jwt_expiry_seconds == floor(var.jwt_expiry_seconds)
    error_message = "jwt_expiry_seconds must be a positive whole number."
  }
}

variable "aws_session_duration_seconds" {
  description = "STS AssumeRole session duration"
  type        = number
  default     = 3600

  validation {
    condition     = var.aws_session_duration_seconds >= 900 && var.aws_session_duration_seconds <= 43200 && var.aws_session_duration_seconds == floor(var.aws_session_duration_seconds)
    error_message = "aws_session_duration_seconds must be a whole number between 900 and 43200 seconds."
  }
}

variable "cors_allowed_origins" {
  description = "CORS allowed origins list"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for origin in var.cors_allowed_origins :
      can(regex("^https?://([A-Za-z0-9.-]+|\\[[0-9A-Fa-f:.]+\\])(:[0-9]{1,5})?$", origin))
    ])
    error_message = "cors_allowed_origins must contain origins only, such as https://canopy.example.com or http://localhost:9876."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days"
  type        = number
  default     = 90

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096,
      1827, 2192, 2557, 2922, 3288, 3653
    ], var.log_retention_days)
    error_message = "log_retention_days must be a CloudWatch Logs supported retention value."
  }
}

# ── Cross-account access ────────────────────────────────

variable "enable_direct_access" {
  description = "Allow the control-plane to directly access EC2, ECS task inventory, CloudWatch Logs, and STS in the deployment account (role_arn = \"direct\" in entitlements). Defaults to false for least-privilege. ECS Exec still requires an assumable role."
  type        = bool
  default     = false
}

variable "force_new_deployment" {
  description = "Trigger a new ECS deployment using the current task definition. This does not guarantee zero overlap between old and new tasks; reduce desired_count to 1 for entitlement rollouts that must avoid mixed rules."
  type        = bool
  default     = false
}

variable "sts_external_id" {
  description = "STS ExternalId used in cross-account AssumeRole calls. Must match the target account's trust policy."
  type        = string
  default     = "canopy"

  validation {
    condition = (
      length(var.sts_external_id) >= 2 &&
      length(var.sts_external_id) <= 1224 &&
      can(regex("^[A-Za-z0-9_+=,.@:/-]+$", var.sts_external_id))
    )
    error_message = "sts_external_id must be 2-1224 characters and may contain only alphanumeric characters plus _+=,.@:/-."
  }
}

variable "assumable_role_arns" {
  description = "IAM role ARNs that the control-plane task role is allowed to assume (cross-account)"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.assumable_role_arns :
      can(regex("^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", arn))
    ])
    error_message = "assumable_role_arns must contain concrete IAM role ARNs without wildcards."
  }
}
