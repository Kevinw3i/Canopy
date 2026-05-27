# ── Task Execution Role ──────────────────────────────────
# Used by ECS to pull images from ECR and read secrets.

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "task_execution" {
  name = "${var.project}-task-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_execution_base" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "task_execution_secrets" {
  name = "secrets-access"
  role = aws_iam_role.task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = compact([
          data.aws_secretsmanager_secret.jwt_secret.arn,
          var.oidc_client_secret_arn != "" ? var.oidc_client_secret_arn : "",
        ])
      }],
      length(var.secrets_kms_key_arns) > 0 ? [{
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secrets_kms_key_arns
      }] : []
    )
  })
}

# ── Task Role ────────────────────────────────────────────
# Used by the control-plane process to call AWS APIs.

resource "aws_iam_role" "task" {
  name = "${var.project}-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "task_permissions" {
  name = "${var.project}-permissions"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # Cross-account AssumeRole (only if role ARNs provided)
      length(var.assumable_role_arns) > 0 ? [{
        Sid      = "AssumeTargetRoles"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole", "sts:TagSession"]
        Resource = var.assumable_role_arns
      }] : [],

      # Cross-account AssumeRole patterns for AWS Organizations account discovery.
      length(var.assumable_role_arn_patterns) > 0 ? [{
        Sid      = "AssumeDiscoveredTargetRoles"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole", "sts:TagSession"]
        Resource = var.assumable_role_arn_patterns
      }] : [],

      # SimulatePrincipalPolicy for cross-account role selection (always when roles configured)
      length(var.assumable_role_arns) > 0 ? [{
        Sid      = "SimulatePolicy"
        Effect   = "Allow"
        Action   = ["iam:SimulatePrincipalPolicy"]
        Resource = var.assumable_role_arns
      }] : [],

      # SimulatePrincipalPolicy for discovered role patterns.
      length(var.assumable_role_arn_patterns) > 0 ? [{
        Sid      = "SimulateDiscoveredPolicy"
        Effect   = "Allow"
        Action   = ["iam:SimulatePrincipalPolicy"]
        Resource = var.assumable_role_arn_patterns
      }] : [],

      # Organizations account discovery is only needed when role patterns are configured.
      length(var.assumable_role_arn_patterns) > 0 ? [{
        Sid      = "OrganizationsAccountDiscovery"
        Effect   = "Allow"
        Action   = ["organizations:ListAccounts"]
        Resource = "*"
      }] : [],

      # Direct AWS access in deployment account (opt-in via enable_direct_access)
      var.enable_direct_access ? [{
        Sid    = "DirectAccess"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ssm:DescribeInstanceInformation",
          "ecs:DescribeClusters",
          "ecs:DescribeTasks",
          "ecs:ListClusters",
          "ecs:ListTasks",
          "logs:DescribeLogGroups",
          "logs:FilterLogEvents",
          "logs:StartQuery",
          "logs:GetQueryResults",
          "logs:StartLiveTail",
        ]
        Resource = "*"
      }] : [],

      # Optional direct audit event export to CloudWatch Logs.
      var.audit_export_cloudwatch_log_group_name != "" ? [{
        Sid    = "AuditCloudWatchLogsExport"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogStreams",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = [
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${var.audit_export_cloudwatch_log_group_name}",
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${var.audit_export_cloudwatch_log_group_name}:*",
        ]
      }] : [],

      # Optional direct audit event export to S3.
      var.audit_export_s3_bucket != "" ? [{
        Sid    = "AuditS3Export"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = format(
          "arn:aws:s3:::%s/%s",
          var.audit_export_s3_bucket,
          trim(var.audit_export_s3_prefix, "/") != "" ? format("%s/*", trim(var.audit_export_s3_prefix, "/")) : "*"
        )
      }] : [],

      # STS GetCallerIdentity is always needed for preflight health check
      [{
        Sid      = "StsIdentity"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      }],

      # MCP database credentials. Passwords stay in Secrets Manager; config only stores ARNs.
      length(var.database_secret_arns) > 0 ? [{
        Sid      = "DatabaseSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = var.database_secret_arns
      }] : [],

      length(var.database_secret_arns) > 0 && length(var.secrets_kms_key_arns) > 0 ? [{
        Sid      = "DatabaseSecretsKmsDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secrets_kms_key_arns
      }] : []
    )
  })
}
