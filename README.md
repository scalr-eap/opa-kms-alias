# AWS KMS Policies

# kms-key-by-alias

Purpose is to ensure that only KMS keys from a defined list are used. List is specified by name not ARN.

In KMS the name is actually an alias in the format "alias/name".

All AWS resources that use KMS require an ARN or ID and wont take a name in the simple "alias/name" format. So to enforce valid names the policy does two things.

1. Ensures that all kms key arguments use a data sources (data.aws_kms_key) to reference the ARN.
2. The alias/name used in any data.aws_kms_key is in the allowed list.

