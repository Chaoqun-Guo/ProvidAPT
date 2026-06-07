# ── High-Availability ProvidAPT Cluster Example ────────────────
# Deploys 3 ProvidAPT instances across 3 availability zones with
# monitoring, backup, and DNS load balancing.
#
# Usage:
#   terraform init
#   terraform plan
#   terraform apply

module "providapt" {
  source = "../../"

  environment   = "prod"
  instance_count = 3
  instance_type = "t3.large"
  data_volume_size = 200

  ssh_key_name = "providapt-key"
  allowed_cidrs = [
    "10.0.0.0/8",
  ]

  enable_monitoring = true
  enable_backup     = true
  backup_retention_days = 90

  # DNS
  domain_name = "providapt.internal.example.com"

  tags = {
    Project     = "ProvidAPT"
    ManagedBy   = "Terraform"
    Environment = "prod"
    HighAvailability = "true"
  }
}

output "cluster_ips" {
  description = "Private IPs of all ProvidAPT instances"
  value       = module.providapt.instance_private_ips
}

output "dns_endpoint" {
  value = "https://providapt.internal.example.com:8080"
}
