# JWT signing secret — provisioned out-of-band and passed by ARN.
# This avoids storing the signing key in Terraform state.
#
# To create the secret:
#   AWS_REGION=${AWS_REGION:-ap-northeast-1}
#   aws secretsmanager create-secret \
#     --name canopy/jwt-secret \
#     --secret-string "$(openssl rand -base64 44)" \
#     --region "$AWS_REGION"

data "aws_secretsmanager_secret" "jwt_secret" {
  arn = var.jwt_secret_arn
}
