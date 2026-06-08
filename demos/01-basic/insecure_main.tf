# Intentionally insecure example module for TFSCAN demo purposes.
# Do NOT deploy this. Every resource here contains a known misconfiguration.

resource "aws_s3_bucket" "data" {
  bucket = "my-app-data-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Allow web + ssh"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}

resource "aws_iam_policy" "admin" {
  name   = "too-broad"
  policy = "{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\" } ] }"
}
