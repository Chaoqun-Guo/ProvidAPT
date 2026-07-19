# Provider configuration

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }

    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }

  # Remote state backend (configure per environment)
  # backend "s3" {
  #   bucket  = "providapt-terraform-state"
  #   key     = "providapt/terraform.tfstate"
  #   region  = "us-east-1"
  #   encrypt = true
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}
