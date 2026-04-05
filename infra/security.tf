# ── ALB Security Group ───────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "${var.project}-alb-sg"
  description = "ALB for ${var.project} control-plane"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each = { for idx, cidr in var.alb_allowed_cidrs : idx => cidr }

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from ${each.value}"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "alb_to_tasks" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to ECS tasks"
  ip_protocol                  = "tcp"
  from_port                    = 8443
  to_port                      = 8443
  referenced_security_group_id = aws_security_group.tasks.id
}

# ── ECS Tasks Security Group ────────────────────────────

resource "aws_security_group" "tasks" {
  name        = "${var.project}-task-sg"
  description = "ECS tasks for ${var.project} control-plane"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "tasks_from_alb" {
  security_group_id            = aws_security_group.tasks.id
  description                  = "Traffic from ALB only"
  ip_protocol                  = "tcp"
  from_port                    = 8443
  to_port                      = 8443
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "tasks_all_outbound" {
  security_group_id = aws_security_group.tasks.id
  description       = "Outbound (OIDC provider, AWS APIs, NAT)"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
