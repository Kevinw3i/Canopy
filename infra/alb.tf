# ── Application Load Balancer ────────────────────────────

resource "aws_lb" "control_plane" {
  name               = "${var.project}-alb"
  load_balancer_type = "application"
  internal           = var.alb_internal
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.alb_internal ? local.network_private_subnet_ids : local.network_public_subnet_ids
}

# ── Target Group ────────────────────────────────────────

resource "aws_lb_target_group" "control_plane" {
  name        = "${var.project}-tg"
  port        = 8443
  protocol    = "HTTP"
  vpc_id      = local.network_vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    interval            = 15
    timeout             = 3
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200"
  }

  deregistration_delay = 30
}

# ── HTTPS Listener ──────────────────────────────────────

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.control_plane.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.control_plane.arn
  }
}

# ── DNS Record (optional) ───────────────────────────────

resource "aws_route53_record" "control_plane" {
  count   = var.route53_zone_id != "" && var.domain_name != "" ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.control_plane.dns_name
    zone_id                = aws_lb.control_plane.zone_id
    evaluate_target_health = true
  }
}
