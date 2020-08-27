# Validate that the KMS key name(alias) is in the allowed list
#
# To enforce this the policy must check that all uses of KMS keys a referenced from a data source and the data source itself uses and allowed key name.

# KMS is used in many AWS services. This policy will attempt to deal with all cases

# AWS CloudTrail : DONE
# AWS Cloudwatch : DONE
# Amazon DynamoDB : DONE
# Amazon Elastic Block Store (Amazon EBS) : DONE
# Amazon Elastic Transcoder : DONE
# Amazon EMR : DONE
# Amazon Redshift : DONE
# Amazon Relational Database Service (Amazon RDS) : DONE
# AWS Secrets Manager : DONE
# Amazon Simple Email Service (Amazon SES) : DONE
# Amazon Simple Storage Service (Amazon S3) : DONE
# AWS Systems Manager Parameter Store : DONE


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
  tfrun.is_destroy == false
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
  tfrun.is_destroy == false
  walk(tfplan.configuration.root_module, [path, value])
  value.mode == "managed"
  value.type == "aws_s3_bucket"
  kms_key := eval_expression(tfplan, value.expressions.replication_configuration[_].rules[_].destination[_].replica_kms_key_id)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("%s.%s :: replication KMS Master key ID '%s' not derived from data source!",[value.type,value.name,kms_key])
}

# Tests for a server side encryption rule referencing a KMS key. This MUST be a data source.
deny[reason] {
  tfrun.is_destroy == false
  walk(tfplan.configuration.root_module, [path, value])
  value.mode == "managed"
  value.type == "aws_s3_bucket"
  kms_key := eval_expression(tfplan, value.expressions.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("%s.%s :: server_side_encryption KMS Master key ID '%s' not derived from data source!",[value.type,value.name,kms_key])
}

#---------------
# GENERAL
# Search for attributes in the list and check they are referencing data sources

attributes = [
  "aws_ebs_volume:kms_key_id",
  "aws_ebs_default_kms_key:key_arn",
  "aws_db_instance:kms_key_id",
  "aws_db_instance:performance_insights_kms_key_id",
  "aws_rds_cluster:kms_key_id",
  "aws_rds_cluster_instance:performance_insights_kms_key_id",
  "aws_cloudtrail:kms_key_id",
  "aws_cloudwatch_log_group:kms_key_id",
  "aws_dynamodb_table:kms_key_arn",
  "aws_elastictranscoder_pipeline:aws_kms_key_arn",
  "aws_redshift_cluster:kms_key_id",
  "aws_redshift_snapshot_copy_grant:kms_key_id",
  "aws_secretsmanager_secret:kms_key_id",
  "aws_ssm_parameter:key_id"
]

deny[reason] {
  tfrun.is_destroy == false
  walk(tfplan.configuration.root_module, [path, value])
  attr := attributes[_]
  attr_s := split(attr,":")
  value.mode == "managed"
  value.type == attr_s[0]
  obj := json.filter(value.expressions,[attr_s[1]])
  walk(obj, [opath, ovalue])
  kms_key := eval_expression(tfplan, ovalue)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("%s.%s :: %s '%s' not derived from data source!",[value.type,value.name,attr_s[1],kms_key])
}

#---------
# EMR

# Extract ARN from the JSON config. This may be a UUID or alias/name arn.

deny[reason] {
  tfrun.is_destroy == false
  walk(tfplan.configuration.root_module, [path, value])
  value.mode == "managed"
  value.type == "aws_emr_security_configuration"
  config := eval_expression(tfplan, value.expressions.configuration)
  arn := regex.find_n("arn:aws:kms:[a-z0-9-:/_]*", config, 1)
  arn_bits := split(arn[0],":")
  id := arn_bits[count(arn_bits)-1]
  key_name := trim_prefix(id, "alias/")
  not contains(allowed_kms_keys, key_name)
  reason := sprintf("%s.%s :: configuration disc encryption key '%s' not from permitted list",[value.type,value.name,key_name])
}

#-----
# SES

# Tests for a S3 encryption referencing a KMS key. This MUST be a data source.
deny[reason] {
  tfrun.is_destroy == false
  walk(tfplan.configuration.root_module, [path, value])
  value.mode == "managed"
  value.type == "aws_ses_receipt_rule"
  kms_key := eval_expression(tfplan, value.expressions.s3_action.kms_key_arn)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("%s.%s :: s3_action KMS Master key ID '%s' not derived from data source!",[value.type,value.name,kms_key])
}

#------
# SSM

# Tests for a S3 encryption referencing a KMS key. This MUST be a data source.
deny[reason] {
  tfrun.is_destroy == false
  walk(tfplan.configuration.root_module, [path, value])
  value.mode == "managed"
  value.type == "aws_ssm_resource_data_sync"
  kms_key := eval_expression(tfplan, value.expressions.s3_destination.kms_key_arn)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("%s.%s :: s3_action KMS Master key ID '%s' not derived from data source!",[value.type,value.name,kms_key])
}

