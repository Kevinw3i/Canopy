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
