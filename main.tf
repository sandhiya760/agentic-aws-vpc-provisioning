
# Terraform and AWS provider configuration
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Remote Terraform state in S3
  backend "s3" {
    bucket       = "agentic-vpc-tfstate-960946313156-ap-south-1"
    key          = "aws-vpc-agent/terraform.tfstate"
    region       = "ap-south-1"
    encrypt      = true
    use_lockfile = true
  }
}

# AWS provider
provider "aws" {
  region = "ap-south-1"
}

# Main VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name         = "agentic-vpc"
    Environment  = "development"
    ManagedBy    = "Terraform"
    ApprovalDemo = "manual-approval-test"
  }
}

# Discover available Availability Zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Subnet address ranges
locals {
  availability_zones = slice(
    data.aws_availability_zones.available.names,
    0,
    2
  )

  public_subnet_cidrs = [
    "10.0.1.0/24",
    "10.0.2.0/24"
  ]

  private_subnet_cidrs = [
    "10.0.11.0/24",
    "10.0.12.0/24"
  ]
}

# Two public subnets
resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_subnet_cidrs[count.index]
  availability_zone       = local.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "agentic-public-subnet-${count.index + 1}"
    Environment = "development"
    ManagedBy   = "Terraform"
  }
}

# Two private application subnets
resource "aws_subnet" "private" {
  count = 2

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = local.availability_zones[count.index]

  tags = {
    Name        = "agentic-private-subnet-${count.index + 1}"
    Environment = "development"
    ManagedBy   = "Terraform"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "agentic-igw"
    Environment = "development"
    ManagedBy   = "Terraform"
  }
}

# Public route table with internet route
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name        = "agentic-public-rt"
    Environment = "development"
    ManagedBy   = "Terraform"
  }
}

# Associate public subnets with public route table
resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private route tables (no NAT Gateway)
resource "aws_route_table" "private" {
  count  = 2
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "agentic-private-rt-${count.index + 1}"
    Environment = "development"
    ManagedBy   = "Terraform"
  }
}

# Associate private subnets with private route tables
resource "aws_route_table_association" "private" {
  count = 2

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Application security group: no inbound rules
resource "aws_security_group" "app" {
  name        = "agentic-app-sg"
  description = "Security group for application resources"
  vpc_id      = aws_vpc.main.id

  # Allow outbound IPv4 traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow outbound IPv4 traffic"
  }

  tags = {
    Name        = "agentic-app-sg"
    Environment = "development"
    ManagedBy   = "Terraform"
  }
}

# Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR range of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of private application subnets"
  value       = aws_subnet.private[*].id
}

output "app_security_group_id" {
  description = "ID of the application security group"
  value       = aws_security_group.app.id
}
