# Zypheron CLI - AWS S3 Binary Distribution
#
# Infrastructure for serving CLI binaries via CloudFront + S3
# URL pattern: https://download.zypheron.net/v1.0.0/zypheron-linux-amd64.tar.gz
#
# Usage:
#   cd infrastructure/aws
#   terraform init
#   terraform plan
#   terraform apply

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment for remote state (recommended for team use)
  # backend "s3" {
  #   bucket = "zypheron-terraform-state"
  #   key    = "aws/download-cdn/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

provider "aws" {
  region = var.aws_region
}

# For ACM certificate (must be us-east-1 for CloudFront)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# ============ Variables ============

variable "aws_region" {
  description = "AWS region for S3 bucket"
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Domain for downloads"
  type        = string
  default     = "download.zypheron.net"
}

variable "hosted_zone_name" {
  description = "Route53 hosted zone name"
  type        = string
  default     = "zypheron.net"
}

variable "bucket_name" {
  description = "S3 bucket name for binary storage"
  type        = string
  default     = "zypheron-cli-releases"
}

# ============ S3 Bucket ============

resource "aws_s3_bucket" "releases" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_versioning" "releases" {
  bucket = aws_s3_bucket.releases.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "releases" {
  bucket = aws_s3_bucket.releases.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id

  rule {
    id     = "cleanup-old-noncurrent-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# ============ CloudFront OAC ============

resource "aws_cloudfront_origin_access_control" "releases" {
  name                              = "${var.bucket_name}-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# S3 bucket policy allowing CloudFront access
resource "aws_s3_bucket_policy" "releases" {
  bucket = aws_s3_bucket.releases.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.releases.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.releases.arn
          }
        }
      }
    ]
  })
}

# ============ ACM Certificate ============

resource "aws_acm_certificate" "releases" {
  provider          = aws.us_east_1
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_route53_zone" "main" {
  name = var.hosted_zone_name
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.releases.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = data.aws_route53_zone.main.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.record]
}

resource "aws_acm_certificate_validation" "releases" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.releases.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# ============ CloudFront Cache Policies ============

resource "aws_cloudfront_cache_policy" "releases_default" {
  name        = "${var.bucket_name}-default-cache"
  comment     = "Default cache policy for release binaries (1 day)"
  min_ttl     = 0
  default_ttl = 86400    # 1 day
  max_ttl     = 2592000  # 30 days

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_cache_policy" "releases_short" {
  name        = "${var.bucket_name}-short-cache"
  comment     = "Short TTL cache for install.sh (5 minutes)"
  min_ttl     = 0
  default_ttl = 300   # 5 minutes
  max_ttl     = 3600  # 1 hour

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_cache_policy" "releases_latest" {
  name        = "${var.bucket_name}-latest-cache"
  comment     = "Minimal TTL cache for latest version pointer (1 minute)"
  min_ttl     = 0
  default_ttl = 60    # 1 minute
  max_ttl     = 300   # 5 minutes

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

# ============ CloudFront Distribution ============

resource "aws_cloudfront_distribution" "releases" {
  origin {
    domain_name              = aws_s3_bucket.releases.bucket_regional_domain_name
    origin_id                = "S3-${var.bucket_name}"
    origin_access_control_id = aws_cloudfront_origin_access_control.releases.id
  }

  enabled         = true
  is_ipv6_enabled = true
  comment         = "Zypheron CLI binary distribution"

  aliases = [var.domain_name]

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${var.bucket_name}"
    viewer_protocol_policy = "redirect-to-https"
    cache_policy_id        = aws_cloudfront_cache_policy.releases_default.id
    compress               = true
  }

  # Cache install.sh with shorter TTL so updates propagate quickly
  ordered_cache_behavior {
    path_pattern           = "/install.sh"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${var.bucket_name}"
    viewer_protocol_policy = "redirect-to-https"
    cache_policy_id        = aws_cloudfront_cache_policy.releases_short.id
    compress               = true
  }

  # Latest version pointer - short TTL
  ordered_cache_behavior {
    path_pattern           = "/latest/*"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-${var.bucket_name}"
    viewer_protocol_policy = "redirect-to-https"
    cache_policy_id        = aws_cloudfront_cache_policy.releases_latest.id
    compress               = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.releases.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# ============ Route53 Record ============

resource "aws_route53_record" "download" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.releases.domain_name
    zone_id                = aws_cloudfront_distribution.releases.hosted_zone_id
    evaluate_target_health = false
  }
}

# ============ Outputs ============

output "s3_bucket_name" {
  value = aws_s3_bucket.releases.id
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.releases.id
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.releases.domain_name
}

output "download_url" {
  value = "https://${var.domain_name}"
}
