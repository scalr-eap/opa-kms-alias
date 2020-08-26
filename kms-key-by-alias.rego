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

the_key(expr) = cv {
  cv := expr.references[_]
} else = ds {
  ds := expr.constant_value
}

deny[reason] {
  kms_key := the_key(s3_buckets_cnf[_].expressions.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("KMS Master key ID '%s' not derived from data source!",[kms_key])
}