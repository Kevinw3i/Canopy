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
