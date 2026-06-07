# ── Monitoring Stack (Prometheus + Grafana) ────────────────────

resource "aws_instance" "monitoring" {
  count                  = var.enable_monitoring ? 1 : 0
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.small"
  subnet_id              = local.subnet_ids[0]
  key_name               = var.ssh_key_name
  vpc_security_group_ids = [aws_security_group.providapt.id]

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  user_data_base64 = base64encode(templatefile("${path.module}/templates/monitoring-user-data.sh.tpl", {
    providapt_ips = join(" ", aws_instance.providapt[*].private_ip)
  }))

  tags = merge(local.common_tags, {
    Name = "providapt-${var.environment}-monitoring"
  })
}

resource "aws_eip" "monitoring" {
  count    = var.enable_monitoring ? 1 : 0
  domain   = "vpc"
  instance = aws_instance.monitoring[0].id

  tags = merge(local.common_tags, {
    Name = "providapt-${var.environment}-monitoring-eip"
  })
}
