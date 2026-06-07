# ── Security Groups ──────────────────────────────────────────────

resource "aws_security_group" "providapt" {
  name_prefix = "providapt-${var.environment}-"
  description = "ProvidAPT security group"
  vpc_id      = local.vpc_id

  tags = merge(var.tags, {
    Name = "providapt-${var.environment}-sg"
  })
}

# SSH access
resource "aws_security_group_rule" "ssh_in" {
  security_group_id = aws_security_group.providapt.id
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidrs
  description       = "SSH access from trusted networks"
}

# ProvidAPT REST API
resource "aws_security_group_rule" "api_rest_in" {
  security_group_id = aws_security_group.providapt.id
  type              = "ingress"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidrs
  description       = "ProvidAPT REST API"
}

# ProvidAPT gRPC API
resource "aws_security_group_rule" "api_grpc_in" {
  security_group_id = aws_security_group.providapt.id
  type              = "ingress"
  from_port         = 50051
  to_port           = 50051
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidrs
  description       = "ProvidAPT gRPC API"
}

# Prometheus metrics
resource "aws_security_group_rule" "prometheus_in" {
  count             = var.enable_monitoring ? 1 : 0
  security_group_id = aws_security_group.providapt.id
  type              = "ingress"
  from_port         = 9090
  to_port           = 9090
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidrs
  description       = "Prometheus metrics"
}

# Grafana dashboard
resource "aws_security_group_rule" "grafana_in" {
  count             = var.enable_monitoring ? 1 : 0
  security_group_id = aws_security_group.providapt.id
  type              = "ingress"
  from_port         = 3000
  to_port           = 3000
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidrs
  description       = "Grafana dashboard"
}

# ICMP for health checks
resource "aws_security_group_rule" "icmp_in" {
  security_group_id = aws_security_group.providapt.id
  type              = "ingress"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = var.allowed_cidrs
  description       = "ICMP ping"
}

# Outbound internet access
resource "aws_security_group_rule" "out_all" {
  security_group_id = aws_security_group.providapt.id
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Outbound internet access"
}
