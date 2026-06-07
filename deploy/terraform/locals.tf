# ── Local computed values ──────────────────────────────────────

locals {
  vpc_id     = var.vpc_id != "" ? var.vpc_id : aws_vpc.main[0].id
  subnet_ids = length(var.subnet_ids) > 0 ? var.subnet_ids : aws_subnet.main[*].id

  # User-data script to format and mount the data volume
  user_data = templatefile("${path.module}/templates/user-data.sh.tpl", {
    environment       = var.environment
    providapt_version = var.providapt_version
    enable_backup     = var.enable_backup
    backup_bucket     = var.enable_backup ? aws_s3_bucket.backup[0].bucket : ""
    tls_enabled       = var.tls_enabled
  })

  common_tags = merge(var.tags, {
    Environment = var.environment
  })
}
