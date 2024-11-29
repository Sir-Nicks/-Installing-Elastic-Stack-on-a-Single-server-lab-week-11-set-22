// AWS Provider Configuration
provider "aws" {
  region = "eu-west-2"
}

// RSA Key Pair of size 4096 bits
resource "tls_private_key" "keypair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

// Create Private Key File
resource "local_file" "private_key" {
  content  = tls_private_key.keypair.private_key_pem
  filename = "elastic.pem"
}

// Creating EC2 KeyPair
resource "aws_key_pair" "keypair" {
  key_name   = "elastic-keypair"
  public_key = tls_private_key.keypair.public_key_openssh
}

// Security Group for Elastic Stack
resource "aws_security_group" "ec2_sg" {
  name        = "elastic"
  description = "Allow inbound traffic for Prometheus and Grafana"

  ingress {
    description = "Elasticsearch port"
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Logstash"
    from_port   = 5043
    to_port     = 5044
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Kibana Port"
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH port"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "elk_server"
  }
}

// Security Group for Nginx
resource "aws_security_group" "nginx_sg" {
  name        = "nginx_sg"
  description = "Allow all Nginx traffic"

  dynamic "ingress" {
    for_each = local.ingress_config_nginx
    content {
      description = ingress.value.description
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

locals {
  ingress_config_nginx = [
    {
      description = "SSH port"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "Nginx port"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

// EC2 Instance for Elastic Stack Server
resource "aws_instance" "prom_graf" {
  ami                    = "ami-0e8d228ad90af673b" // Ubuntu AMI
  instance_type          = "t2.large"
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  key_name               = aws_key_pair.keypair.key_name
  associate_public_ip_address = true

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "elk_server"
  }
}

// EC2 Instance for General Web Server
resource "aws_instance" "ec2_server" {
  ami                    = "ami-0e8d228ad90af673b" // Ubuntu AMI
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.nginx_sg.id]
  key_name               = aws_key_pair.keypair.key_name
  associate_public_ip_address = true

  tags = {
    Name = "nginx_server"
  }
}

// Outputs
output "elk_ip" {
  value = aws_instance.prom_graf.public_ip
}

output "nginx_ip" {
  value = aws_instance.ec2_server.public_ip
}
