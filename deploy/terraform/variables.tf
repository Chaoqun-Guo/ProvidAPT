variable "cloud_provider" {
  description = "Cloud provider. This module currently supports AWS."
  type        = string
  default     = "aws"

  validation {
    condition     = var.cloud_provider == "aws"
    error_message = "cloud_provider must be aws. Use a provider-specific module for GCP, Azure, or OpenStack."
  }
}

variable "region" {
  description = "Cloud region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "instance_count" {
  description = "Number of ProvidAPT instances to deploy"
  type        = number
  default     = 1
}

variable "instance_type" {
  description = "VM instance type / flavor"
  type        = string
  default     = "t3.medium"
}

variable "root_volume_size" {
  description = "Root volume size in GB"
  type        = number
  default     = 40
}

variable "data_volume_size" {
  description = "Persistent data volume size in GB (for /var/log/providapt)"
  type        = number
  default     = 100
}

variable "ssh_key_name" {
  description = "SSH key pair name for VM access"
  type        = string
  default     = "providapt-key"
}

variable "allowed_cidrs" {
  description = "CIDR blocks allowed to access the API and SSH"
  type        = list(string)
  default = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
  ]
}

variable "environment" {
  description = "Deployment environment label (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default = {
    Project     = "ProvidAPT"
    ManagedBy   = "Terraform"
  }
}

variable "enable_monitoring" {
  description = "Deploy Prometheus/Grafana monitoring stack alongside ProvidAPT"
  type        = bool
  default     = true
}

variable "enable_backup" {
  description = "Enable automated backup of the ProvidAPT store"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
}

variable "providapt_version" {
  description = "ProvidAPT release version to deploy"
  type        = string
  default     = "v1.2.2"
}

variable "domain_name" {
  description = "DNS domain name for the ProvidAPT API endpoint"
  type        = string
  default     = ""
}

variable "tls_enabled" {
  description = "Enable TLS for the ProvidAPT gRPC/REST API"
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "Existing VPC ID (leave empty to create a new VPC)"
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "Existing subnet IDs (leave empty to create new subnets)"
  type        = list(string)
  default     = []
}
