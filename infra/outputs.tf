output "ecr_repository_url" {
  description = "ECR repository URL for docker push"
  value       = aws_ecr_repository.control_plane.repository_url
}

output "alb_dns_name" {
  description = "ALB DNS name (use for CNAME or Route 53 alias)"
  value       = aws_lb.control_plane.dns_name
}

output "vpc_id" {
  description = "VPC ID used by the control-plane deployment"
  value       = local.network_vpc_id
}

output "public_subnet_ids" {
  description = "Public subnet IDs used by the control-plane deployment"
  value       = local.network_public_subnet_ids
}

output "private_subnet_ids" {
  description = "Private subnet IDs used by the control-plane deployment"
  value       = local.network_private_subnet_ids
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "ECS service name (for update-service commands)"
  value       = var.create_service ? aws_ecs_service.control_plane[0].name : ""
}

output "jwt_secret_arn" {
  description = "Secrets Manager ARN for JWT secret"
  value       = data.aws_secretsmanager_secret.jwt_secret.arn
}

output "log_group_name" {
  description = "CloudWatch log group for container logs"
  value       = aws_cloudwatch_log_group.control_plane.name
}
