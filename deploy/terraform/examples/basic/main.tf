# ── Basic ProvidAPT Deployment Example ─────────────────────────
# Deploys a single ProvidAPT instance with monitoring and backup.
#
# Usage:
#   terraform init
#   terraform plan
#   terraform apply
#
# Prerequisites:
#   - AWS credentials configured (env vars, ~/.aws/credentials, or IAM role)
#   - SSH key pair created in the target region

module "providapt" {
  source = "../../"

  environment   = "prod"
  instance_type = "t3.medium"

  # SSH access
  ssh_key_name = "providapt-key"
  allowed_cidrs = [
    "10.0.0.0/8",
    "203.0.113.0/32", # Office public IP
  ]

  # Monitoring
  enable_monitoring = true

  # Backup (30-day retention)
  enable_backup         = true
  backup_retention_days = 30

  # Resource tags
  tags = {
    Project     = "ProvidAPT"
    ManagedBy   = "Terraform"
    Environment = "prod"
  }
}

output "instance_ip" {
  value = module.providapt.instance_ips[0]
}

output "api_endpoint" {
  value = module.providapt.api_endpoint
}
