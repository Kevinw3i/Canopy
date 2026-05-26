mock_provider "aws" {}

variables {
  create_service = false
  create_vpc     = false

  vpc_id             = "vpc-00000000000000000"
  public_subnet_ids  = ["subnet-00000000000000001", "subnet-00000000000000002"]
  private_subnet_ids = ["subnet-00000000000000003", "subnet-00000000000000004"]

  acm_certificate_arn = "arn:aws:acm:ap-northeast-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
  jwt_secret_arn      = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:canopy/jwt-secret-XXXXXX"
  route53_zone_id     = ""
  domain_name         = ""

  alb_internal                = true
  alb_allowed_cidrs           = ["10.0.0.0/16"]
  allow_public_alb_world_cidr = false

  oidc_issuer_url = "https://accounts.google.com"
  oidc_client_id  = "test-client-id"
}

run "public_alb_rejects_world_cidr_without_opt_in" {
  command = plan

  variables {
    alb_internal                    = false
    alb_allowed_cidrs               = ["0.0.0.0/0"]
    allow_public_alb_world_cidr     = false
  }

  expect_failures = [
    aws_security_group.alb,
  ]
}

run "public_alb_accepts_world_cidr_with_opt_in" {
  command = plan

  variables {
    alb_internal                = false
    alb_allowed_cidrs           = ["0.0.0.0/0"]
    allow_public_alb_world_cidr = true
  }
}

run "public_alb_accepts_scoped_cidr_without_opt_in" {
  command = plan

  variables {
    alb_internal                = false
    alb_allowed_cidrs           = ["203.0.113.0/24"]
    allow_public_alb_world_cidr = false
  }
}

run "rejects_invalid_vpc_id" {
  command = plan

  variables {
    vpc_id = "vpc-nothex"
  }

  expect_failures = [
    var.vpc_id,
  ]
}

run "rejects_invalid_public_subnet_id" {
  command = plan

  variables {
    public_subnet_ids = ["subnet-00000000000000001", "subnet-nothex"]
  }

  expect_failures = [
    var.public_subnet_ids,
  ]
}

run "rejects_invalid_private_subnet_id" {
  command = plan

  variables {
    private_subnet_ids = ["subnet-00000000000000003", "subnet-nothex"]
  }

  expect_failures = [
    var.private_subnet_ids,
  ]
}

run "rejects_invalid_alb_allowed_cidr" {
  command = plan

  variables {
    alb_allowed_cidrs = ["999.0.0.0/16"]
  }

  expect_failures = [
    var.alb_allowed_cidrs,
  ]
}

run "rejects_invalid_acm_certificate_arn" {
  command = plan

  variables {
    acm_certificate_arn = "arn:aws:acm:ap-northeast-1:123456789012:certificate/not-a-uuid"
  }

  expect_failures = [
    var.acm_certificate_arn,
  ]
}

run "rejects_invalid_route53_zone_id" {
  command = plan

  variables {
    route53_zone_id = "zone-123"
  }

  expect_failures = [
    var.route53_zone_id,
  ]
}

run "rejects_invalid_domain_name" {
  command = plan

  variables {
    domain_name = "-canopy.example.com"
  }

  expect_failures = [
    var.domain_name,
  ]
}

run "rejects_reused_network_without_vpc_id" {
  command = plan

  variables {
    vpc_id = ""
  }

  expect_failures = [
    aws_security_group.alb,
  ]
}

run "rejects_domain_without_route53_zone" {
  command = plan

  variables {
    domain_name = "canopy.example.com"
  }

  expect_failures = [
    aws_lb.control_plane,
  ]
}

run "rejects_route53_zone_without_domain" {
  command = plan

  variables {
    route53_zone_id = "Z0123456789ABCDEFGHIJ"
  }

  expect_failures = [
    aws_lb.control_plane,
  ]
}

run "rejects_public_alb_without_two_public_subnets" {
  command = plan

  variables {
    alb_internal      = false
    public_subnet_ids = ["subnet-00000000000000001"]
  }

  expect_failures = [
    aws_lb.control_plane,
  ]
}

run "rejects_reused_network_without_two_private_subnets" {
  command = plan

  variables {
    private_subnet_ids = ["subnet-00000000000000003"]
  }

  expect_failures = [
    aws_lb.control_plane,
  ]
}
