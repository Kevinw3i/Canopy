resource "aws_cloudwatch_log_group" "control_plane" {
  name              = "/ecs/${var.project}/control-plane"
  retention_in_days = var.log_retention_days
}
