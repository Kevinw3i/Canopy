mock_provider "aws" {}

variables {
  create_service = false
  create_vpc     = false

  vpc_id             = "vpc-00000000000000000"
  public_subnet_ids  = ["subnet-00000000000000001", "subnet-00000000000000002"]
  private_subnet_ids = ["subnet-00000000000000003", "subnet-00000000000000004"]

  alb_allowed_cidrs = ["10.0.0.0/16"]

  acm_certificate_arn = "arn:aws:acm:ap-northeast-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
  jwt_secret_arn      = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy/jwt-secret-XXXXXX"
  route53_zone_id     = ""
  domain_name         = ""

  oidc_issuer_url = "https://accounts.google.com"
  oidc_client_id  = "test-client-id"
}

run "accepts_zero_desired_count" {
  command = plan

  variables {
    desired_count = 0
  }
}

run "rejects_negative_desired_count" {
  command = plan

  variables {
    desired_count = -1
  }

  expect_failures = [
    var.desired_count,
  ]
}

run "rejects_fractional_desired_count" {
  command = plan

  variables {
    desired_count = 1.5
  }

  expect_failures = [
    var.desired_count,
  ]
}

run "rejects_unsupported_fargate_cpu" {
  command = plan

  variables {
    cpu = 128
  }

  expect_failures = [
    var.cpu,
  ]
}

run "rejects_unsupported_fargate_memory" {
  command = plan

  variables {
    memory = 1536
  }

  expect_failures = [
    var.memory,
  ]
}

run "rejects_invalid_cpu_architecture" {
  command = plan

  variables {
    cpu_architecture = "x86_64"
  }

  expect_failures = [
    var.cpu_architecture,
  ]
}

run "rejects_invalid_image_tag_format" {
  command = plan

  variables {
    image_tag = "-bad"
  }

  expect_failures = [
    var.image_tag,
  ]
}

run "rejects_latest_image_tag" {
  command = plan

  variables {
    image_tag = "latest"
  }

  expect_failures = [
    var.image_tag,
  ]
}

run "rejects_service_without_image_tag" {
  command = plan

  variables {
    create_service        = true
    image_tag             = ""
    jwt_secret_version_id = "00000000-0000-0000-0000-000000000000"
  }

  expect_failures = [
    aws_ecs_task_definition.control_plane,
  ]
}

run "accepts_service_launch_inputs" {
  command = plan

  variables {
    create_service        = true
    image_tag             = "cp-v0.1.0"
    jwt_secret_version_id = "00000000-0000-0000-0000-000000000000"
  }
}

run "rejects_disabled_generate_config" {
  command = plan

  variables {
    generate_config = false
  }

  expect_failures = [
    var.generate_config,
  ]
}

run "rejects_non_positive_jwt_expiry_seconds" {
  command = plan

  variables {
    jwt_expiry_seconds = 0
  }

  expect_failures = [
    var.jwt_expiry_seconds,
  ]
}

run "rejects_short_aws_session_duration_seconds" {
  command = plan

  variables {
    aws_session_duration_seconds = 899
  }

  expect_failures = [
    var.aws_session_duration_seconds,
  ]
}

run "rejects_cors_origin_with_path" {
  command = plan

  variables {
    cors_allowed_origins = ["https://canopy.example.com/callback"]
  }

  expect_failures = [
    var.cors_allowed_origins,
  ]
}

run "rejects_sts_external_id_with_space" {
  command = plan

  variables {
    sts_external_id = "bad external id"
  }

  expect_failures = [
    var.sts_external_id,
  ]
}

run "rejects_unsupported_log_retention_days" {
  command = plan

  variables {
    log_retention_days = 2
  }

  expect_failures = [
    var.log_retention_days,
  ]
}

run "rejects_invalid_assumable_role_arn" {
  command = plan

  variables {
    assumable_role_arns = ["arn:aws:iam::123456789012:policy/Canopy"]
  }

  expect_failures = [
    var.assumable_role_arns,
  ]
}

run "accepts_organization_assumable_role_pattern" {
  command = plan

  variables {
    assumable_role_arn_patterns = ["arn:aws:iam::*:role/CanopyRole"]
  }
}

run "rejects_invalid_organization_assumable_role_pattern" {
  command = plan

  variables {
    assumable_role_arn_patterns = ["arn:aws:iam::123456789012:role/Canopy*"]
  }

  expect_failures = [
    var.assumable_role_arn_patterns,
  ]
}

run "rejects_invalid_jwt_secret_arn" {
  command = plan

  variables {
    jwt_secret_arn = "arn:aws:ssm:ap-northeast-1:123456789012:parameter/canopy/jwt-secret"
  }

  expect_failures = [
    var.jwt_secret_arn,
  ]
}

run "rejects_invalid_jwt_secret_version_id" {
  command = plan

  variables {
    jwt_secret_version_id = "short"
  }

  expect_failures = [
    var.jwt_secret_version_id,
  ]
}

run "rejects_invalid_secrets_kms_key_arn" {
  command = plan

  variables {
    secrets_kms_key_arns = ["arn:aws:kms:ap-northeast-1:123456789012:alias/canopy"]
  }

  expect_failures = [
    var.secrets_kms_key_arns,
  ]
}

run "rejects_non_https_oidc_issuer_url" {
  command = plan

  variables {
    oidc_issuer_url = "http://accounts.google.com"
  }

  expect_failures = [
    var.oidc_issuer_url,
  ]
}

run "rejects_oidc_client_id_with_whitespace" {
  command = plan

  variables {
    oidc_client_id = "test client id"
  }

  expect_failures = [
    var.oidc_client_id,
  ]
}

run "rejects_invalid_oidc_client_secret_arn" {
  command = plan

  variables {
    oidc_client_secret_arn = "arn:aws:ssm:ap-northeast-1:123456789012:parameter/canopy/oidc-client-secret"
  }

  expect_failures = [
    var.oidc_client_secret_arn,
  ]
}

run "rejects_invalid_oidc_client_secret_version_id" {
  command = plan

  variables {
    oidc_client_secret_version_id = "short"
  }

  expect_failures = [
    var.oidc_client_secret_version_id,
  ]
}

run "rejects_service_without_jwt_secret_version_id" {
  command = plan

  variables {
    create_service        = true
    image_tag             = "cp-v0.1.0"
    jwt_secret_version_id = ""
  }

  expect_failures = [
    aws_ecs_task_definition.control_plane,
  ]
}

run "rejects_oidc_secret_without_version_id" {
  command = plan

  variables {
    create_service         = true
    image_tag              = "cp-v0.1.0"
    jwt_secret_version_id  = "00000000-0000-0000-0000-000000000000"
    oidc_client_secret_arn = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy/oidc-client-secret-XXXXXX"
  }

  expect_failures = [
    aws_ecs_task_definition.control_plane,
  ]
}

run "rejects_oidc_version_without_secret_arn" {
  command = plan

  variables {
    create_service                = true
    image_tag                     = "cp-v0.1.0"
    jwt_secret_version_id         = "00000000-0000-0000-0000-000000000000"
    oidc_client_secret_arn        = ""
    oidc_client_secret_version_id = "00000000-0000-0000-0000-000000000000"
  }

  expect_failures = [
    aws_ecs_task_definition.control_plane,
  ]
}

run "rejects_invalid_fargate_cpu_memory_pair" {
  command = plan

  variables {
    create_service        = true
    image_tag             = "cp-v0.1.0"
    jwt_secret_version_id = "00000000-0000-0000-0000-000000000000"
    cpu                   = 256
    memory                = 4096
  }

  expect_failures = [
    aws_ecs_task_definition.control_plane,
  ]
}

run "rejects_relative_entitlements_file" {
  command = plan

  variables {
    entitlements_file = "entitlements.toml"
  }

  expect_failures = [
    var.entitlements_file,
  ]
}

run "rejects_parent_segment_entitlements_file" {
  command = plan

  variables {
    entitlements_file = "/etc/canopy/../entitlements.toml"
  }

  expect_failures = [
    var.entitlements_file,
  ]
}
