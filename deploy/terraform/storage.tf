# ── Data volumes for ProvidAPT store ────────────────────────────

resource "aws_ebs_volume" "providapt_data" {
  count             = var.instance_count
  availability_zone = aws_instance.providapt[count.index].availability_zone
  size              = var.data_volume_size
  type              = "gp3"
  encrypted         = true

  tags = merge(var.tags, {
    Name = "providapt-${var.environment}-data-${count.index}"
  })
}

resource "aws_volume_attachment" "providapt_data" {
  count       = var.instance_count
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.providapt_data[count.index].id
  instance_id = aws_instance.providapt[count.index].id

  stop_instance_before_detaching = true
}

# ── Backup bucket ────────────────────────────────────────────────

resource "aws_s3_bucket" "backup" {
  count  = var.enable_backup ? 1 : 0
  bucket = "providapt-${var.environment}-backups-${data.aws_caller_identity.current.account_id}"

  tags = merge(var.tags, {
    Name = "providapt-${var.environment}-backups"
  })
}

resource "aws_s3_bucket_versioning" "backup" {
  count  = var.enable_backup ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backup" {
  count  = var.enable_backup ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id

  rule {
    id     = "expire-old-backups"
    status = "Enabled"

    expiration {
      days = var.backup_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup" {
  count  = var.enable_backup ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "backup" {
  count  = var.enable_backup ? 1 : 0
  bucket = aws_s3_bucket.backup[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── IAM for backup uploads ──────────────────────────────────────

resource "aws_iam_role" "providapt_backup" {
  count = var.enable_backup ? 1 : 0
  name  = "providapt-${var.environment}-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_policy" "backup_upload" {
  count = var.enable_backup ? 1 : 0
  name  = "providapt-${var.environment}-backup-upload"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.backup[0].arn,
          "${aws_s3_bucket.backup[0].arn}/*",
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "backup_upload" {
  count      = var.enable_backup ? 1 : 0
  role       = aws_iam_role.providapt_backup[0].name
  policy_arn = aws_iam_policy.backup_upload[0].arn
}

resource "aws_iam_instance_profile" "providapt" {
  count = var.enable_backup ? 1 : 0
  name  = "providapt-${var.environment}-profile"
  role  = aws_iam_role.providapt_backup[0].name
}

# ── Data source ─────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
