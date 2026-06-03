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

  validation {
    condition     = var.desired_count >= 0 && var.desired_count == floor(var.desired_count)
    error_message = "desired_count must be a non-negative whole number."
  }
}

variable "mcp_session_store" {
  description = "MCP session state backend. Use dynamodb for ECS services with desired_count > 1; memory is only safe for local/dev or single-task deployments."
  type        = string
  default     = "dynamodb"

  validation {
    condition     = contains(["memory", "dynamodb"], var.mcp_session_store)
    error_message = "mcp_session_store must be either memory or dynamodb."
  }
}

variable "mcp_session_table_name" {
  description = "Optional DynamoDB table name for MCP session state. Defaults to <project>-mcp-sessions when mcp_session_store = dynamodb."
  type        = string
  default     = ""

  validation {
    condition = (
      var.mcp_session_table_name == "" ||
      (
        length(var.mcp_session_table_name) >= 3 &&
        length(var.mcp_session_table_name) <= 255 &&
        can(regex("^[A-Za-z0-9_.-]+$", var.mcp_session_table_name))
      )
    )
    error_message = "mcp_session_table_name must be empty or a valid DynamoDB table name."
  }
}

variable "mcp_ec2_diagnostic_command_store" {
  description = "MCP EC2 diagnostic command record backend. Use dynamodb for production so command ownership and completion state survive task restarts."
  type        = string
  default     = "dynamodb"

  validation {
    condition     = contains(["memory", "dynamodb"], var.mcp_ec2_diagnostic_command_store)
    error_message = "mcp_ec2_diagnostic_command_store must be either memory or dynamodb."
  }
}

variable "mcp_ec2_diagnostic_command_table_name" {
  description = "Optional DynamoDB table name for MCP EC2 diagnostic command records. Defaults to <project>-mcp-ec2-diagnostic-commands when mcp_ec2_diagnostic_command_store = dynamodb."
  type        = string
  default     = ""

  validation {
    condition = (
      var.mcp_ec2_diagnostic_command_table_name == "" ||
      (
        length(var.mcp_ec2_diagnostic_command_table_name) >= 3 &&
        length(var.mcp_ec2_diagnostic_command_table_name) <= 255 &&
        can(regex("^[A-Za-z0-9_.-]+$", var.mcp_ec2_diagnostic_command_table_name))
      )
    )
    error_message = "mcp_ec2_diagnostic_command_table_name must be empty or a valid DynamoDB table name."
  }
}

variable "mcp_ec2_diagnostic_ssm_document_name" {
  description = "Pinned SSM document name for MCP EC2 diagnostics dispatch. Leave empty to keep dispatch disabled."
  type        = string
  default     = ""

  validation {
    condition     = var.mcp_ec2_diagnostic_ssm_document_name == "" || var.mcp_ec2_diagnostic_ssm_document_name == "Canopy-Ec2Diagnostics"
    error_message = "mcp_ec2_diagnostic_ssm_document_name must be empty or Canopy-Ec2Diagnostics."
  }
}

variable "mcp_ec2_diagnostic_ssm_document_version" {
  description = "Pinned numeric SSM document version for MCP EC2 diagnostics dispatch. Leave empty to keep dispatch disabled."
  type        = string
  default     = ""

  validation {
    condition     = var.mcp_ec2_diagnostic_ssm_document_version == "" || can(regex("^[1-9][0-9]*$", var.mcp_ec2_diagnostic_ssm_document_version))
    error_message = "mcp_ec2_diagnostic_ssm_document_version must be empty or a positive numeric document version."
  }
}

variable "mcp_ec2_diagnostic_helper_version" {
  description = "Expected canopy-ec2-diagnostics helper contract version. Leave empty to use the control-plane default."
  type        = string
  default     = ""

  validation {
    condition     = var.mcp_ec2_diagnostic_helper_version == "" || var.mcp_ec2_diagnostic_helper_version == "2026-06-04.1"
    error_message = "mcp_ec2_diagnostic_helper_version must be empty or 2026-06-04.1."
  }
}

variable "mcp_ec2_diagnostic_command_spec_key_secret_id" {
  description = "Optional Secrets Manager ARN for the MCP EC2 diagnostics command-spec encryption key. Required when SSM dispatch is enabled."
  type        = string
  default     = ""

  validation {
    condition     = var.mcp_ec2_diagnostic_command_spec_key_secret_id == "" || can(regex("^arn:aws[a-zA-Z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", var.mcp_ec2_diagnostic_command_spec_key_secret_id))
    error_message = "mcp_ec2_diagnostic_command_spec_key_secret_id must be empty or a concrete Secrets Manager secret ARN."
  }
}

variable "mcp_ec2_diagnostic_command_spec_key_secret_version_id" {
  description = "Secrets Manager version ID for the MCP EC2 diagnostics command-spec key. Required when mcp_ec2_diagnostic_command_spec_key_secret_id is set."
  type        = string
  default     = ""

  validation {
    condition     = var.mcp_ec2_diagnostic_command_spec_key_secret_version_id == "" || can(regex("^[A-Za-z0-9-]{32,64}$", var.mcp_ec2_diagnostic_command_spec_key_secret_version_id))
    error_message = "mcp_ec2_diagnostic_command_spec_key_secret_version_id must be empty or a Secrets Manager version ID."
  }
}

variable "allow_multi_task_memory_mcp_session_store" {
  description = "Explicit unsafe override for desired_count > 1 with memory MCP sessions. Intended only for emergency debugging; production should keep this false."
  type        = bool
  default     = false
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

variable "allow_public_alb_world_cidr" {
  description = "Explicitly allow 0.0.0.0/0 on a public ALB. Defaults to false; prefer office or VPN CIDRs."
  type        = bool
  default     = false
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
  description = "KMS key ARNs used to encrypt Secrets Manager secrets (jwt_secret, oidc_client_secret, database secrets). Leave empty if using AWS-managed keys."
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

variable "database_secret_arns" {
  description = "Secrets Manager ARNs for MCP database credentials. Secrets must contain JSON with username and password. Create them out-of-band to avoid exposing passwords in Terraform state."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.database_secret_arns :
      can(regex("^arn:aws[a-zA-Z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$", arn))
    ])
    error_message = "database_secret_arns must contain only concrete Secrets Manager secret ARNs."
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

  validation {
    condition = (
      can(regex("^/[A-Za-z0-9._/-]+$", var.entitlements_file)) &&
      !contains(split("/", var.entitlements_file), "..")
    )
    error_message = "entitlements_file must be an absolute container path without parent directory segments."
  }
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

variable "database_connections_toml" {
  description = "Optional TOML snippet appended to generated config.toml for [database_connections.*]. Do not include passwords; use secret_arn fields only."
  type        = string
  default     = ""
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

variable "audit_export_cloudwatch_log_group_name" {
  description = "Optional CloudWatch Logs log group name for direct audit event export. Leave empty to disable."
  type        = string
  default     = ""

  validation {
    condition     = var.audit_export_cloudwatch_log_group_name == "" || (length(var.audit_export_cloudwatch_log_group_name) <= 512 && can(regex("^[A-Za-z0-9_./#-]+$", var.audit_export_cloudwatch_log_group_name)))
    error_message = "audit_export_cloudwatch_log_group_name must be empty or a valid CloudWatch Logs log group name."
  }
}

variable "audit_export_cloudwatch_log_stream_name" {
  description = "CloudWatch Logs stream name used when audit_export_cloudwatch_log_group_name is set."
  type        = string
  default     = "canopy-audit"

  validation {
    condition     = length(var.audit_export_cloudwatch_log_stream_name) >= 1 && length(var.audit_export_cloudwatch_log_stream_name) <= 512 && can(regex("^[^:*]*$", var.audit_export_cloudwatch_log_stream_name))
    error_message = "audit_export_cloudwatch_log_stream_name must be 1-512 characters and cannot contain ':' or '*'."
  }
}

variable "audit_export_s3_bucket" {
  description = "Optional S3 bucket name for direct audit event export. Leave empty to disable."
  type        = string
  default     = ""

  validation {
    condition     = var.audit_export_s3_bucket == "" || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.audit_export_s3_bucket))
    error_message = "audit_export_s3_bucket must be empty or a valid DNS-style S3 bucket name."
  }
}

variable "audit_export_s3_prefix" {
  description = "S3 key prefix for direct audit event export."
  type        = string
  default     = "canopy/audit/"
}

variable "audit_export_queue_size" {
  description = "In-memory queue size for remote audit export sinks."
  type        = number
  default     = 1024

  validation {
    condition     = var.audit_export_queue_size >= 1 && var.audit_export_queue_size <= 100000 && var.audit_export_queue_size == floor(var.audit_export_queue_size)
    error_message = "audit_export_queue_size must be a whole number between 1 and 100000."
  }
}

# ── Cross-account access ────────────────────────────────

variable "enable_direct_access" {
  description = "Allow the control-plane to directly access EC2, SSM managed-instance inventory, ECS task inventory, CloudWatch Logs, and STS in the deployment account (role_arn = \"direct\" in entitlements). Defaults to false for least-privilege. ECS Exec still requires an assumable role."
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

variable "assumable_role_arn_patterns" {
  description = "IAM role ARN patterns used for AWS Organizations account discovery, for example arn:aws:iam::*:role/CanopyRole. Only a wildcard account-id segment is allowed."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.assumable_role_arn_patterns :
      can(regex("^arn:aws[a-zA-Z-]*:iam::\\*:role/[A-Za-z0-9+=,.@_/-]+$", arn))
    ])
    error_message = "assumable_role_arn_patterns must use a wildcard account-id segment only, for example arn:aws:iam::*:role/CanopyRole."
  }
}
