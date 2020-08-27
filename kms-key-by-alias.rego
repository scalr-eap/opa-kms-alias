# Validate that the KMS key name(alias) is in the allowed list
#
# To enforce this the policy must check that all uses of KMS keys a referenced from a data source and the data source itself uses and allowed key name.

package terraform

import input.tfplan as tfplan
import input.tfrun as tfrun

allowed_kms_keys = [
  "pg-kms-keyx"
]

contains(arr, elem) {
  arr[_] = elem
}

# Extract configuration block for given type and mode
config_type(plan, type, mode) = config {
  config := plan.configuration.root_module.resources[0]
  config.type == type
  config.mode == mode
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

# Tests for a server side encryption rule referencing a KMS key. This MUST be a data source.

deny[reason] {
  walk(tfplan.configuration.root_module, [path, value])
  "managed" == value.mode
  "aws_s3_bucket" == value.type
  kms_key := eval_expression(tfplan, value.expressions.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id)
  not startswith(kms_key, "data.aws_kms_key.")
  reason := sprintf("KMS Master key ID '%s' not derived from data source!",[kms_key])
}

#deny[reason] {
#  config := config_type(tfplan,"aws_s3_bucket","managed")
#  kms_key := eval_expression(tfplan, config.expressions.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id)
#  not startswith(kms_key, "data.aws_kms_key.")
#  reason := sprintf("KMS Master key ID '%s' not derived from data source!",[kms_key])
#}

# Tests that the key_id used in the data source is in the allowed list.
deny[reason] {
  walk(tfplan.configuration.root_module, [path, value])
  "data" == value.mode
  "aws_kms_key" == value.type
  key_alias := eval_expression(tfplan, value.expressions.key_id)
  key_name := trim_prefix(key_alias, "alias/")
  not contains(allowed_kms_keys, key_name)
  reason := sprintf("KMS Master key ID '%s' not not in permitted list",[key_alias])
}