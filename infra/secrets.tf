# JWT signing secret — provisioned out-of-band and passed by ARN.
# This avoids storing the signing key in Terraform state.
#
# To create the secret:
#   aws secretsmanager create-secret \
#     --name canopy/jwt-secret \
#     --secret-string "$(openssl rand -base64 44)"

data "aws_secretsmanager_secret" "jwt_secret" {
  arn = var.jwt_secret_arn
}
