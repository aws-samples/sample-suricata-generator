"""
MRG AWS modules.

Contains Network Firewall client, Lambda deployer, IAM role management,
and SNS topic/subscription management.

All modules accept an AWSSessionManager instance from the main application
for boto3 client creation, ensuring consistent credential and profile usage.
"""

# Network Firewall client
from src.mrg.aws.network_firewall import (
    NetworkFirewallError,
    RuleGroupNotFoundError,
    RuleGroupCapacityError,
    UpdateTokenMismatchError,
    is_compatible_managed_rule_group,
    list_managed_rule_groups,
    list_user_rule_groups,
    describe_rule_group,
    create_rule_group,
    update_rule_group,
    delete_rule_group,
    create_backup_rule_group,
    tag_resource,
    rule_group_exists,
    validate_rule_group_name,
)

# Lambda deployer
from src.mrg.aws.lambda_deployer import (
    LambdaDeployerError,
    LambdaNotFoundError,
    EnvironmentVariableLimitError,
    get_function_name,
    create_lambda_package,
    wait_for_function_active,
    create_lambda_function,
    update_lambda_function_code,
    update_lambda_environment,
    get_lambda_configs,
    add_or_update_config,
    remove_config,
    get_lambda_function,
    delete_lambda_function,
    invoke_lambda_function,
    estimate_config_size,
    lambda_function_exists,
)

# IAM role management
from src.mrg.aws.iam import (
    IAMError,
    RoleNotFoundError,
    create_lambda_role,
    get_lambda_role,
    delete_lambda_role,
    get_role_name,
    get_policy_name,
    get_lambda_policy_document,
)

# SNS topic and subscription management
from src.mrg.aws.sns import (
    SNSError,
    TopicNotFoundError,
    get_managed_threat_signatures_topic_arn,
    create_notification_topic,
    subscribe_lambda_to_managed_topic,
    add_lambda_sns_permission,
    subscribe_email_to_notification_topic,
    publish_notification,
    get_notification_topic,
    list_topic_subscriptions,
    unsubscribe,
    delete_notification_topic,
    get_notification_topic_name,
)
