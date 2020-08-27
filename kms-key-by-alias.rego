# Validate that the KMS key name(alias) is in the allowed list
#
# To enforce this the policy must check that all uses of KMS keys a referenced from a data source and the data source itself uses and allowed key name.

# KMS is used in many AWS services. This policy will attempt to deal with all cases

# AWS CloudTrail
# Amazon DynamoDB
# Amazon Elastic Block Store (Amazon EBS) : DONE
# Amazon Elastic Transcoder
# Amazon EMR
# Amazon Redshift
# Amazon Relational Database Service (Amazon RDS)
# AWS Secrets Manager
# Amazon Simple Email Service (Amazon SES)
# Amazon Simple Storage Service (Amazon S3) : DONE
# AWS Systems Manager Parameter Store
# Amazon WorkMail
# Amazon WorkSpaces

package terraform

import input.tfplan as tfplan
import input.tfrun as tfrun

allowed_kms_keys = [
  "pg-kms-keyx"
]

contains(arr, elem) {
  arr[_] = elem
}

# Configuration may be specified in one of 3 ways
# - Constant value, i.e. a quoted string "the_value"
# - A variable in the references[] specifying a value
# - An actual reference e.g. data.foo.bar
#
# This extracts the relevant value, i.e. the constant value, the value of the variable or the reference
eval_expression(plan, expr) = constant_value {
    constant_value := expr.constant_value
} else = var_value {
    ref = expr.references[0]
    startswith(ref, "var.")
    var_name := replace(ref, "var.", "")
    var_value := plan.variables[var_name].value
} else = reference {
    reference = expr.references[_]
}

#--------------------

# Tests that the key_id used in the data source is in the allowed list.
deny[reason] {
  walk(tfplan.configuration.root_module, [path, value])
  value.mode == "data"
  value.type == "aws_kms_key"
  key_alias := eval_expression(tfplan, value.expressions.key_id)
  key_name := trim_prefix(key_alias, "alias/")
  not contains(allowed_kms_keys, key_name)
  reason := sprintf("%s.%s :: KMS key name '%s' not in permitted list",[value.type,value.name, key_alias])
}

#---------------
# S3 Buckets
# Tests for a replication configuration rule referencing a KMS key. This MUST be a data source.
deny[reason] {
  walk(tfplan.configuration.root_module, [path, value])
  value.mode == "managed"
  value.type == "aws_s3_bucket"
  kms_key := eval_expression(tfplan, value.expressions.replication_configuration[_].rules[_].destination[_].replica_kms_key_id)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("%s.%s :: replication KMS Master key ID '%s' not derived from data source!",[value.type,value.name,kms_key])
}

# Tests for a server side encryption rule referencing a KMS key. This MUST be a data source.
deny[reason] {
  walk(tfplan.configuration.root_module, [path, value])
  value.mode == "managed"
  value.type == "aws_s3_bucket"
  kms_key := eval_expression(tfplan, value.expressions.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("%s.%s :: server_side_encryption KMS Master key ID '%s' not derived from data source!",[value.type,value.name,kms_key])
}

#---------------
# EBS

types = [
  "aws_ebs_volume",
  "aws_ebs_default_kms_key",
  "aws_db_instance"
]

attributes = [
  "kms_key_id",
  "key_arn",
  "performance_insights_kms_key_id"
]

deny[reason] {
  walk(tfplan.configuration.root_module, [path, value])
  attr := attributes[_]
  type := types[_]
  value.mode == "managed"
  value.type == type
  obj := json.filter(value.expressions,[attr])
  walk(obj, [opath, ovalue])
  kms_key := eval_expression(tfplan, ovalue)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("%s.%s :: %s '%s' not derived from data source!",[value.type,value.name,attr,kms_key])
}