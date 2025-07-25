#############################
# Terraform — AWS VPC STACK #
#############################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

############################
# 1. PROVIDER & VARIABLES  #
############################

provider "aws" {
  region = var.aws_region
}

#######################
# 2. DATA & LOCALS    #
#######################

data "aws_availability_zones" "available" {}

locals {
  az1 = data.aws_availability_zones.available.names[0]
  az2 = data.aws_availability_zones.available.names[1] # for RDS second subnet

  common_tags = {
    Project     = var.project
    Environment = "prod"
    ManagedBy   = "Terraform"
  }

  # Log group names (override as needed)
  cw_log_group_db_postgresql = "/aws/rds/instance/${var.project}-db/postgresql"
  cw_log_group_db_upgrade    = "/aws/rds/instance/${var.project}-db/upgrade"
  cw_log_group_server        = "/${var.project}/server"
  cw_log_group_celery        = "/${var.project}/celery"
  cw_log_group_vpn           = "/aws/clientvpn/${var.project}"
}

#############
# 3.  VPC   #
#############

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(local.common_tags, { Name = "${var.project}-vpc" })
}


resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.common_tags, { Name = "${var.project}-igw" })
}

############################
# 4. SUBNETS & ROUTE TABLES#
############################

# Public subnets (2 AZs)
resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr_1
  availability_zone       = local.az1
  map_public_ip_on_launch = true
  tags                    = merge(local.common_tags, { Name = "${var.project}-public-subnet-1" })
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr_2
  availability_zone       = local.az2
  map_public_ip_on_launch = true
  tags                    = merge(local.common_tags, { Name = "${var.project}-public-subnet-2" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.common_tags, { Name = "${var.project}-public-rt" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_assoc_1" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_assoc_2" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public.id
}

# NAT Gateway (in public subnet AZ1)
resource "aws_eip" "nat-1" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.igw]
  tags       = merge(local.common_tags, { Name = "${var.project}-nat-eip-1" })
}

resource "aws_nat_gateway" "nat-1" {
  allocation_id = aws_eip.nat-1.id
  subnet_id     = aws_subnet.public_1.id
  tags          = merge(local.common_tags, { Name = "${var.project}-nat-gw-1" })
}

# Private APP subnet (single AZ)
resource "aws_subnet" "private_app" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_app_subnet_cidr
  availability_zone = local.az1
  tags              = merge(local.common_tags, { Name = "${var.project}-private-app-subnet" })
}

resource "aws_route_table" "private_app" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.common_tags, { Name = "${var.project}-private-app-rt" })
}

resource "aws_route" "private_app_nat" {
  route_table_id         = aws_route_table.private_app.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat-1.id
}

resource "aws_route_table_association" "private_app_assoc" {
  subnet_id      = aws_subnet.private_app.id
  route_table_id = aws_route_table.private_app.id
}

# Private DB subnets (2 AZs)
resource "aws_subnet" "private_db_1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_db_subnet_cidr_1
  availability_zone = local.az1
  tags              = merge(local.common_tags, { Name = "${var.project}-private-db-subnet-1" })
}

resource "aws_subnet" "private_db_2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_db_subnet_cidr_2
  availability_zone = local.az2
  tags              = merge(local.common_tags, { Name = "${var.project}-private-db-subnet-2" })
}

resource "aws_route_table" "private_db" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.common_tags, { Name = "${var.project}-private-db-rt" })
}

resource "aws_route_table_association" "private_db_assoc_1" {
  subnet_id      = aws_subnet.private_db_1.id
  route_table_id = aws_route_table.private_db.id
}

resource "aws_route_table_association" "private_db_assoc_2" {
  subnet_id      = aws_subnet.private_db_2.id
  route_table_id = aws_route_table.private_db.id
}

############################
# 5. SECURITY GROUPS       #
############################

# ALB SG (public)
resource "aws_security_group" "alb" {
  name        = "${var.project}-alb-sg"
  description = "ALB public SG"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.project}-alb-sg" })
}

# App EC2 SG
resource "aws_security_group" "app" {
  name        = "${var.project}-app-sg"
  description = "App server SG"
  vpc_id      = aws_vpc.main.id

  # Allow ALB->EC2 on HTTP/HTTPS (and your custom app port if any)
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # SSH access from VPN clients
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpn_client_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.project}-app-sg" })
}

# RDS SG (allow from app SG and VPN clients)
resource "aws_security_group" "rds" {
  name        = "${var.project}-rds-sg"
  description = "RDS isolated SG"
  vpc_id      = aws_vpc.main.id

  # Allow from app servers
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  # Allow from VPN clients
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpn_client_cidr]
  }

  tags = merge(local.common_tags, { Name = "${var.project}-rds-sg" })
}

##############################################
# 5A. CLOUDWATCH & IAM (COMMON & RDS MONITOR)#
##############################################

# (NEW) KMS key for RDS encryption & Performance Insights
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS ${var.project}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = merge(local.common_tags, { Name = "${var.project}-rds-kms" })
}

# (NEW) IAM for RDS Enhanced Monitoring
resource "aws_iam_role" "rds_enhanced_monitoring" {
  name = "${var.project}-rds-enhanced-monitoring-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "monitoring.rds.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring_attach" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# (NEW) CloudWatch Log Groups
# You can control retention via var.cloudwatch_retention_days (add in variables.tf)
resource "aws_cloudwatch_log_group" "rds_postgresql" {
  name              = local.cw_log_group_db_postgresql
  retention_in_days = var.cloudwatch_retention_days
  tags              = local.common_tags
}
resource "aws_cloudwatch_log_group" "rds_upgrade" {
  name              = local.cw_log_group_db_upgrade
  retention_in_days = var.cloudwatch_retention_days
  tags              = local.common_tags
}
resource "aws_cloudwatch_log_group" "server" {
  name              = local.cw_log_group_server
  retention_in_days = var.cloudwatch_retention_days
  tags              = local.common_tags
}
resource "aws_cloudwatch_log_group" "celery" {
  name              = local.cw_log_group_celery
  retention_in_days = var.cloudwatch_retention_days
  tags              = local.common_tags
}

# VPN CloudWatch Log Group
resource "aws_cloudwatch_log_group" "vpn" {
  name              = local.cw_log_group_vpn
  retention_in_days = var.cloudwatch_retention_days
  tags              = local.common_tags
}

# VPN CloudWatch Log Stream
resource "aws_cloudwatch_log_stream" "vpn" {
  name           = "${var.project}-vpn-connection-logs"
  log_group_name = aws_cloudwatch_log_group.vpn.name
}

# (NEW) IAM Role for EC2 CloudWatch Agent (common role)
resource "aws_iam_role" "cw_agent" {
  name = "${var.project}-cw-agent-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "cw_agent_attach" {
  role       = aws_iam_role.cw_agent.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "cw_agent" {
  name = "${var.project}-cw-agent-profile"
  role = aws_iam_role.cw_agent.name
}

###################################
# 5B. CLIENT VPN CERTIFICATES     #
###################################

# Generate CA private key
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Generate CA certificate
resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name  = "${var.project}-vpn-ca.local"
    organization = var.project
  }

  dns_names = ["${var.project}-vpn-ca.local"]

  validity_period_hours = 87600 # 10 years
  is_ca_certificate     = true

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "cert_signing",
  ]
}

# Generate server private key
resource "tls_private_key" "server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Generate server certificate
resource "tls_cert_request" "server" {
  private_key_pem = tls_private_key.server.private_key_pem

  subject {
    common_name  = "${var.project}-vpn-server.local"
    organization = var.project
  }

  dns_names = ["${var.project}-vpn-server.local"]
}

resource "tls_locally_signed_cert" "server" {
  cert_request_pem   = tls_cert_request.server.cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 87600 # 10 years

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# Generate client private key
resource "tls_private_key" "client" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Generate client certificate
resource "tls_cert_request" "client" {
  private_key_pem = tls_private_key.client.private_key_pem

  subject {
    common_name  = "${var.project}-vpn-client.local"
    organization = var.project
  }

  dns_names = ["${var.project}-vpn-client.local"]
}

resource "tls_locally_signed_cert" "client" {
  cert_request_pem   = tls_cert_request.client.cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 87600 # 10 years

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "client_auth",
  ]
}

# Upload certificates to ACM
resource "aws_acm_certificate" "server" {
  private_key      = tls_private_key.server.private_key_pem
  certificate_body = tls_locally_signed_cert.server.cert_pem
  certificate_chain = tls_self_signed_cert.ca.cert_pem

  tags = merge(local.common_tags, { Name = "${var.project}-vpn-server-cert" })
}

resource "aws_acm_certificate" "client" {
  private_key      = tls_private_key.client.private_key_pem
  certificate_body = tls_locally_signed_cert.client.cert_pem
  certificate_chain = tls_self_signed_cert.ca.cert_pem

  tags = merge(local.common_tags, { Name = "${var.project}-vpn-client-cert" })
}

###################################
# 5C. CLIENT VPN ENDPOINT         #
###################################

resource "aws_ec2_client_vpn_endpoint" "main" {
  description            = "${var.project} Client VPN"
  server_certificate_arn = aws_acm_certificate.server.arn
  client_cidr_block      = var.vpn_client_cidr
  split_tunnel           = true
  dns_servers            = [cidrhost(var.vpc_cidr, 2)] # VPC DNS resolver

  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = aws_acm_certificate.client.arn
  }

  connection_log_options {
    enabled               = true
    cloudwatch_log_group  = aws_cloudwatch_log_group.vpn.name
    cloudwatch_log_stream = aws_cloudwatch_log_stream.vpn.name
  }

  tags = merge(local.common_tags, { Name = "${var.project}-client-vpn" })
}

# Associate VPN with private app subnet only (simpler approach)
resource "aws_ec2_client_vpn_network_association" "app" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  subnet_id              = aws_subnet.private_app.id
}

# Authorization rules
resource "aws_ec2_client_vpn_authorization_rule" "vpc_access" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  target_network_cidr    = var.vpc_cidr
  authorize_all_groups   = true
  description            = "Access to VPC"
}

resource "aws_ec2_client_vpn_authorization_rule" "internet_access" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  target_network_cidr    = "0.0.0.0/0"
  authorize_all_groups   = true
  description            = "Internet access"
}

# Route for internet access through NAT Gateway
resource "aws_ec2_client_vpn_route" "internet" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  destination_cidr_block = "0.0.0.0/0"
  target_vpc_subnet_id   = aws_subnet.private_app.id
  description            = "Route to internet via NAT"
}

##########################
# 6. COMPUTE – EC2 (NOW) #
##########################

resource "aws_instance" "app" {
  ami                         = var.server_ec2_ami_id
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.private_app.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  key_name                    = var.key_pair_name != "" ? var.key_pair_name : null
  associate_public_ip_address = false
  disable_api_termination     = false
  monitoring                  = true

  # Attach CW agent IAM profile
  iam_instance_profile        = aws_iam_instance_profile.cw_agent.name

  root_block_device {
    volume_size = 120          # 100GB more than default if it was 20GB
    volume_type = "gp3"
    delete_on_termination = true
  }

  tags = merge(local.common_tags, { Name = "${var.project}-app-ec2" })
}

########################
# 7.  LOAD BALANCER    #
########################

resource "aws_acm_certificate" "stage" {
  domain_name               = var.alb_domains[0]
  subject_alternative_names = slice(var.alb_domains, 1, length(var.alb_domains))
  validation_method         = "DNS"
  tags                      = local.common_tags
}

# Output the exact CNAMEs you must create in Namecheap
output "acm_dns_validation_records" {
  description = "Create these CNAME records in Namecheap."
  value = {
    for dvo in aws_acm_certificate.stage.domain_validation_options :
    dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }
}

data "aws_acm_certificate" "stage_issued" {
  domain      = var.alb_domains[0]
  statuses    = ["ISSUED"]
  most_recent = true
  depends_on  = [aws_acm_certificate.stage]
}

resource "aws_lb" "app" {
  count                     = var.enable_alb ? 1 : 1
  name                      = "${var.project}-alb"
  internal                  = false
  load_balancer_type        = "application"
  security_groups           = [aws_security_group.alb.id]
  subnets                   = [aws_subnet.public_1.id, aws_subnet.public_2.id]
  enable_deletion_protection = false
  tags                      = local.common_tags
}

resource "aws_lb_target_group" "app" {
  count       = var.enable_alb ? 1 : 0
  name        = "${var.project}-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"

  health_check {
    path                = "/"
    interval            = 30
    timeout             = 5
    unhealthy_threshold = 2
    healthy_threshold   = 3
  }
  tags = local.common_tags
}

# HTTPS listener
resource "aws_lb_listener" "https" {
  count             = var.enable_alb ? 1 : 0
  load_balancer_arn = aws_lb.app[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = data.aws_acm_certificate.stage_issued.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app[0].arn
  }
}

# Redirect HTTP -> HTTPS
resource "aws_lb_listener" "http_redirect" {
  count             = var.enable_alb ? 1 : 0
  load_balancer_arn = aws_lb.app[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_target_group_attachment" "app" {
  count            = var.enable_alb ? 1 : 0
  target_group_arn = aws_lb_target_group.app[0].arn
  target_id        = aws_instance.app.id
  port             = 80
}

########################
# 8.  DATABASE (RDS)   #
########################

resource "aws_db_subnet_group" "rds" {
  name       = "${var.project}-rds-subnet-group"
  subnet_ids = [aws_subnet.private_db_1.id, aws_subnet.private_db_2.id]
  tags       = local.common_tags
}

resource "aws_db_instance" "main" {
  identifier              = "${var.project}-db"
  engine                  = var.db_engine
  engine_version          = var.db_engine_version
  instance_class          = var.db_instance_class
  db_subnet_group_name    = aws_db_subnet_group.rds.name
  vpc_security_group_ids  = [aws_security_group.rds.id]

  multi_az                = true

  allocated_storage       = 50
  storage_type            = "gp3"

  # Encryption
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds.arn

  username                = var.db_username
  password                = var.db_password
  db_name                 = var.db_name
  publicly_accessible     = false

  # Backups
  backup_retention_period = 7
  backup_window           = "02:00-04:00"
  copy_tags_to_snapshot   = true

  # Maintenance
  maintenance_window      = "Sun:05:00-Sun:06:00"
  deletion_protection     = true
  final_snapshot_identifier = "${var.project}-final-snap"
  skip_final_snapshot       = false

  # Monitoring
  monitoring_interval   = 60
  monitoring_role_arn   = aws_iam_role.rds_enhanced_monitoring.arn

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = aws_kms_key.rds.arn

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = local.common_tags
}

###################
# 9.  OUTPUTS     #
###################

output "alb_dns_name" {
  value       = try(aws_lb.app[0].dns_name, "ALB disabled")
  description = "Point your domain (CNAME) to this."
}

output "ec2_private_ip" {
  value = aws_instance.app.private_ip
}

output "rds_endpoint" {
  value = aws_db_instance.main.endpoint
}

# VPN-related outputs
output "vpn_endpoint_id" {
  value       = aws_ec2_client_vpn_endpoint.main.id
  description = "Client VPN Endpoint ID"
}

output "vpn_endpoint_dns_name" {
  value       = aws_ec2_client_vpn_endpoint.main.dns_name
  description = "Client VPN Endpoint DNS Name"
}

# Save client configuration files
resource "local_file" "client_certificate" {
  content    = tls_locally_signed_cert.client.cert_pem
  filename   = "${path.module}/client.crt"
  depends_on = [tls_locally_signed_cert.client]
}

resource "local_file" "client_private_key" {
  content    = tls_private_key.client.private_key_pem
  filename   = "${path.module}/client.key"
  depends_on = [tls_private_key.client]
}

resource "local_file" "ca_certificate" {
  content    = tls_self_signed_cert.ca.cert_pem
  filename   = "${path.module}/ca.crt"
  depends_on = [tls_self_signed_cert.ca]
}

output "vpn_configuration_download_command" {
  value = "aws ec2 export-client-vpn-client-configuration --client-vpn-endpoint-id ${aws_ec2_client_vpn_endpoint.main.id} --output text > ${var.project}-vpn-config.ovpn"
  description = "Run this command to download the VPN configuration file after deployment"
}