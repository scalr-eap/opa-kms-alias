package terraform

import input.tfplan as tfplan
import input.tfrun as tfrun

allowed_kms_keys = [
  "pg-kms-key"
]

contains(arr, elem) {
  arr[_] = elem
}

# Config for S3 buckets
s3_buckets_cnf[r] {
    r := tfplan.configuration.root_module.resources[_]
    r.type == "aws_s3_bucket"
}

deny[reason] {
  r := s3_buckets_cnf[_]
  s := r.expressions.server_side_encryption_configuration[_]
  kms_key := s.rule.apply_server_side_encryption_by_default[_].kms_master_key_id.references[_]
  not startswith(kms_key, "data.aws_kms_key.")
  reason := "KMS Master key ID not derived from data source!"
}