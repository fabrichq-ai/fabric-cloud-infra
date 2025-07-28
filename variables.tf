variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
}

variable "project" {
  description = "Tag prefix for all resources"
  type        = string
  default     = "fabric"
}

variable "vpc_cidr" {
  description = "CIDR for the VPC"
  type        = string
  default     = "172.31.0.0/16"
}

variable "public_subnet_cidr_1" {
  description = "CIDR for public subnet"
  type        = string
  default     = "172.31.0.0/20"
}

variable "public_subnet_cidr_2" {
  description = "CIDR for public subnet"
  type        = string
  default     = "172.31.16.0/20"
}

variable "private_app_subnet_cidr" {
  description = "CIDR for private app subnet"
  type        = string
  default     = "172.31.32.0/20"
}

variable "private_db_subnet_cidr_1" {
  description = "CIDR for private db subnet"
  type        = string
  default     = "172.31.48.0/20"
}

variable "private_db_subnet_cidr_2" {
  description = "CIDR for private db subnet"
  type        = string
  default     = "172.31.64.0/20"
}

variable "db_engine" {
  description = "Database engine type (e.g., mysql, postgresql)"
  type        = string
  default     = "mysql"
}

variable "db_engine_version" {
  description = "Database engine version"
  type        = string
  default     = "8.0"
}

variable "db_instance_class" {
  description = "Database instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "db_username" {
  description = "Database admin username"
  type        = string
  default     = "admin"
}

variable "db_password" {
  description = "Database admin password"
  type        = string
  sensitive   = true
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "fabric_db"
}

variable "enable_alb" {
  description = "Enable Application Load Balancer"
  type        = bool
  default     = true
}

variable "ec2_instance_type" {
  description = "Enable Application Load Balancer"
  type        = string
  default     = "t2.xlarge"
}

variable "key_pair_name" {
  type    = string
  default = ""
}

variable "cloudwatch_retention_days" {
  type    = number
  default = 30
}

variable "server_ec2_ami_id" {
  description = "Server EC2 AMI ID"
  type        = string
  default     = "ami-09b0a86a2c84101e1"
}

variable "alb_domains" {
  type        = list(string)
  default     = ["app.fabrichq.ai", "app-api.fabrichq.ai"]
  description = "Primary + SANs for ACM cert"
}

variable "vpn_client_cidr" {
  description = "CIDR block for VPN clients (should not overlap with VPC CIDR)"
  type        = string
  default     = "192.168.100.0/22"  # Supports ~1000 concurrent connections
}