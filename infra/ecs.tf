# ── Cluster ──────────────────────────────────────────────

resource "aws_ecs_cluster" "main" {
  name = var.project

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ── Task Definition ─────────────────────────────────────

resource "aws_ecs_task_definition" "control_plane" {
  count  = var.create_service ? 1 : 0
  family = "${var.project}-control-plane"

  lifecycle {
    precondition {
      condition     = var.image_tag != ""
      error_message = "image_tag is required when create_service = true."
    }
    precondition {
      condition     = var.jwt_secret_version_id != ""
      error_message = "jwt_secret_version_id is required for deterministic JWT key pinning across all tasks."
    }
    precondition {
      condition     = var.oidc_client_secret_arn == "" || var.oidc_client_secret_version_id != ""
      error_message = "oidc_client_secret_version_id is required when oidc_client_secret_arn is set."
    }
  }
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  container_definitions = jsonencode([{
    name      = "control-plane"
    image     = "${aws_ecr_repository.control_plane.repository_url}:${var.image_tag}"
    essential = true

    portMappings = [{
      containerPort = 8443
      protocol      = "tcp"
    }]

    environment = [
      { name = "RUST_LOG", value = "control_plane=info,tower_http=info" },
      { name = "GENERATE_CONFIG", value = var.generate_config ? "1" : "0" },
      { name = "OIDC_ISSUER_URL", value = var.oidc_issuer_url },
      { name = "OIDC_CLIENT_ID", value = var.oidc_client_id },
      { name = "JWT_EXPIRY_SECONDS", value = tostring(var.jwt_expiry_seconds) },
      { name = "AWS_DEFAULT_REGION", value = var.aws_region },
      { name = "AWS_SESSION_DURATION_SECONDS", value = tostring(var.aws_session_duration_seconds) },
      { name = "ENTITLEMENTS_FILE", value = var.entitlements_file },
      { name = "CORS_ALLOWED_ORIGINS", value = join(",", var.cors_allowed_origins) },
      { name = "STS_EXTERNAL_ID", value = var.sts_external_id },
    ]

    # Inject secrets via ECS-native secrets injection (uses execution role).
    secrets = concat(
      [{ name = "JWT_SECRET", valueFrom = var.jwt_secret_version_id != "" ? "${data.aws_secretsmanager_secret.jwt_secret.arn}:::${var.jwt_secret_version_id}" : data.aws_secretsmanager_secret.jwt_secret.arn }],
      var.oidc_client_secret_arn != "" ? [
        { name = "OIDC_CLIENT_SECRET", valueFrom = var.oidc_client_secret_version_id != "" ? "${var.oidc_client_secret_arn}:::${var.oidc_client_secret_version_id}" : var.oidc_client_secret_arn }
      ] : []
    )

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.control_plane.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "curl -f http://localhost:8443/health || exit 1"]
      interval    = 15
      timeout     = 5
      retries     = 5
      startPeriod = 180
    }

    stopTimeout = 30
  }])
}

# ── Service ─────────────────────────────────────────────

resource "aws_ecs_service" "control_plane" {
  count           = var.create_service ? 1 : 0
  name            = "control-plane"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.control_plane[0].arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = local.network_private_subnet_ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.control_plane.arn
    container_name   = "control-plane"
    container_port   = 8443
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  force_new_deployment = var.force_new_deployment

  health_check_grace_period_seconds  = 180
  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  depends_on = [aws_lb_listener.https]
}
