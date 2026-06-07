# ── ProvidAPT Compute Instances ─────────────────────────────────

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu-24.04-lts-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_instance" "providapt" {
  count                  = var.instance_count
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = local.subnet_ids[count.index % length(local.subnet_ids)]
  key_name               = var.ssh_key_name
  vpc_security_group_ids = [aws_security_group.providapt.id]
  iam_instance_profile   = var.enable_backup ? aws_iam_instance_profile.providapt[0].name : null

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_size
    encrypted   = true

    tags = merge(local.common_tags, {
      Name = "providapt-${var.environment}-root-${count.index}"
    })
  }

  user_data_base64 = base64encode(local.user_data)

  tags = merge(local.common_tags, {
    Name = "providapt-${var.environment}-${count.index}"
  })
}

# ── Elastic IPs ─────────────────────────────────────────────────

resource "aws_eip" "providapt" {
  count    = var.instance_count
  domain   = "vpc"
  instance = aws_instance.providapt[count.index].id

  tags = merge(local.common_tags, {
    Name = "providapt-${var.environment}-eip-${count.index}"
  })
}

# ── DNS records ─────────────────────────────────────────────────

resource "aws_route53_record" "providapt_api" {
  count   = var.domain_name != "" ? 1 : 0
  zone_id = data.aws_route53_zone.providapt[0].zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = 300
  records = aws_eip.providapt[*].public_ip
}

data "aws_route53_zone" "providapt" {
  count  = var.domain_name != "" ? 1 : 0
  name   = var.domain_name
  private_zone = false
}
