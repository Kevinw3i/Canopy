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
