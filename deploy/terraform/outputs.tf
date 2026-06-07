output "instance_ips" {
  description = "Public IP addresses of the ProvidAPT instances"
  value       = aws_instance.providapt[*].public_ip
}

output "instance_private_ips" {
  description = "Private IP addresses of the ProvidAPT instances"
  value       = aws_instance.providapt[*].private_ip
}

output "security_group_id" {
  description = "Security group ID attached to ProvidAPT instances"
  value       = aws_security_group.providapt.id
}

output "api_endpoint" {
  description = "ProvidAPT REST API endpoint"
  value = var.domain_name != "" ? "https://${var.domain_name}:8080" : format(
    "https://%s:8080",
    aws_instance.providapt[0].public_ip,
  )
}

output "grpc_endpoint" {
  description = "ProvidAPT gRPC endpoint"
  value = var.domain_name != "" ? "%s:50051" : format(
    "%s:50051",
    aws_instance.providapt[0].public_ip,
  )
}

output "ssh_command" {
  description = "SSH command template for accessing ProvidAPT instances"
  value       = format("ssh -i %s.pem ubuntu@%%s", var.ssh_key_name)
}

output "monitoring_endpoints" {
  description = "Monitoring service endpoints"
  value = var.enable_monitoring ? {
    prometheus = format("http://%s:9090", aws_instance.providapt[0].public_ip)
    grafana    = format("http://%s:3000", aws_instance.providapt[0].public_ip)
  } : {}
}

output "backup_bucket" {
  description = "S3 bucket for automated store backups"
  value       = var.enable_backup ? aws_s3_bucket.backup[0].bucket : null
}
