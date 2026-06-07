# ── VPC (optional, created only when vpc_id is empty) ──────────

resource "aws_vpc" "main" {
  count                = var.vpc_id != "" ? 0 : 1
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "providapt-${var.environment}-vpc"
  })
}

resource "aws_internet_gateway" "main" {
  count  = var.vpc_id != "" ? 0 : 1
  vpc_id = local.vpc_id

  tags = merge(local.common_tags, {
    Name = "providapt-${var.environment}-igw"
  })
}

resource "aws_subnet" "main" {
  count             = var.vpc_id != "" ? 0 : var.instance_count
  vpc_id            = local.vpc_id
  cidr_block        = cidrsubnet("10.0.0.0/16", 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index % length(data.aws_availability_zones.available.names)]

  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "providapt-${var.environment}-subnet-${count.index}"
  })
}

resource "aws_route_table" "main" {
  count  = var.vpc_id != "" ? 0 : 1
  vpc_id = local.vpc_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }

  tags = merge(local.common_tags, {
    Name = "providapt-${var.environment}-rt"
  })
}

resource "aws_route_table_association" "main" {
  count          = var.vpc_id != "" ? 0 : var.instance_count
  subnet_id      = aws_subnet.main[count.index].id
  route_table_id = aws_route_table.main[0].id
}

data "aws_availability_zones" "available" {
  state = "available"
}
