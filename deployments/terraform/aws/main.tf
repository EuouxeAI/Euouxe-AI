module "brim_eks_cluster" {
  source = "./modules/eks-cluster"

  cluster_name    = "brim-prod"
  vpc_id         = aws_vpc.main.id
  node_capacity  = 10
  instance_types = ["m5.large", "m5.xlarge"]
  enable_ssm     = true
}

module "brim_rds" {
  source = "./modules/rds-postgresql"

  db_name          = "brim_core"
  master_username  = var.db_admin_user
  master_password  = var.db_admin_pass
  storage_encrypted = true
  kms_key_id       = aws_kms_key.rds.arn
  security_groups  = [aws_security_group.rds.id]
}

resource "aws_elasticache_redis" "brim_redis" {
  cluster_id           = "brim-redis"
  node_type            = "cache.m5.large"
  num_cache_nodes      = 3
  engine_version       = "7.0"
  parameter_group_name = "default.redis7"
  security_group_ids   = [aws_security_group.redis.id]
  at_rest_encryption   = true
  transit_encryption   = true
}
