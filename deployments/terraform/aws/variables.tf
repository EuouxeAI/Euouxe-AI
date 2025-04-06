# Euouxe AI - Enterprise Infrastructure Variables
# Supports AWS, Azure, GCP with security hardening and compliance

# ========================
# Global Configuration
# ========================
variable "environment" {
  type        = string
  description = "Deployment environment (prod/stage/dev)"
  default     = "prod"
  validation {
    condition     = contains(["prod", "stage", "dev"], var.environment)
    error_message = "Valid values: prod, stage, dev"
  }
}

variable "cost_center" {
  type        = string
  description = "Financial tracking code for resource tagging"
}

variable "compliance_framework" {
  type        = string
  description = "Security compliance requirements (gdpr/hipaa/pci)"
  default     = "gdpr"
}

# ========================
# Multi-Cloud Configuration 
# ========================
variable "cloud_provider" {
  type        = string
  description = "Primary cloud provider (aws/azure/gcp)"
  default     = "aws"
}

variable "aws_config" {
  type = object({
    region          = string
    vpc_cidr        = string
    azs             = list(string)
    instance_type   = string
    rds_engine      = string
  })
  default = {
    region        = "us-west-2"
    vpc_cidr      = "10.0.0.0/16"
    azs           = ["us-west-2a", "us-west-2b"]
    instance_type = "m6i.large"
    rds_engine    = "postgres13"
  }
}

variable "gcp_config" {
  type = object({
    project_id     = string
    region         = string
    network_name   = string
    machine_type   = string
  })
  default = null
}

# ========================
# Security & Compliance
# ========================
variable "encryption_config" {
  type = object({
    enabled         = bool
    kms_key_arn     = string
    disk_encryption = string
  })
  default = {
    enabled         = true
    kms_key_arn     = "alias/brim-prod-key"
    disk_encryption = "AES-256-XTS"
  }
}

variable "network_hardening" {
  type = object({
    allowed_ingress_cidr = list(string)
    enable_flow_logs     = bool
    waf_ruleset_arn      = string
  })
  default = {
    allowed_ingress_cidr = ["10.0.0.0/8"]
    enable_flow_logs     = true
    waf_ruleset_arn      = "arn:aws:wafv2:us-west-2:123456789012:global/rulegroup/prod-rules"
  }
}

# ========================
# Monitoring & Logging
# ========================
variable "monitoring_config" {
  type = object({
    prometheus_endpoint = string
    grafana_integration = bool
    cloudwatch_retention = number
    log_export_bucket   = string
  })
  default = {
    prometheus_endpoint = "internal-prometheus.brim.net:9090"
    grafana_integration = true
    cloudwatch_retention = 365
    log_export_bucket   = "brim-logs-prod"
  }
}

variable "alert_thresholds" {
  type = object({
    cpu_utilization    = number
    memory_threshold   = number
    disk_space         = number
    http_error_rate    = number
  })
  default = {
    cpu_utilization  = 80
    memory_threshold = 85
    disk_space       = 90
    http_error_rate  = 5
  }
}

# ========================
# Auto-Scaling & HA
# ========================
variable "autoscaling_config" {
  type = object({
    min_size     = number
    max_size     = number
    desired      = number
    metric_type  = string
    cooldown     = number
  })
  default = {
    min_size    = 3
    max_size    = 10
    desired     = 4
    metric_type = "CPUUtilization"
    cooldown    = 300
  }
}

variable "ha_zones" {
  type        = list(string)
  description = "Availability Zones for HA deployment"
  default     = ["us-west-2a", "us-west-2b", "us-west-2c"]
}

# ========================
# Container Orchestration
# ========================
variable "eks_config" {
  type = object({
    cluster_version = string
    node_group = object({
      instance_types = list(string)
      capacity_type  = string
    })
    fargate_profiles = map(list(string))
  })
  default = {
    cluster_version = "1.27"
    node_group = {
      instance_types = ["m5.large", "m5.xlarge"]
      capacity_type  = "SPOT"
    }
    fargate_profiles = {
      monitoring = ["prometheus", "grafana"]
    }
  }
}

# ========================
# Database Configuration
# ========================
variable "rds_config" {
  type = object({
    instance_class    = string
    allocated_storage = number
    multi_az          = bool
    backup_retention = number
    parameter_group   = string
  })
  default = {
    instance_class    = "db.m5.large"
    allocated_storage = 500
    multi_az          = true
    backup_retention  = 35
    parameter_group   = "default.postgres13"
  }
}

# ========================
# Secrets Management
# ========================
variable "vault_config" {
  type = object({
    address       = string
    token         = string
    secrets_path  = string
    tls_skip_verify = bool
  })
  sensitive = true
  default = {
    address       = "https://vault.prod.brim.net:8200"
    token         = "hvs.prod_xyz"
    secrets_path  = "secret/data/brim/prod"
    tls_skip_verify = false
  }
}
