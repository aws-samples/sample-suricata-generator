"""
IAM Role and Policy Management for Managed Rule Group Generator

Manages the IAM role and policy used by the Lambda function.
Creates a least-privilege policy that allows the Lambda to:
- Read managed rule groups (DescribeRuleGroup on aws-managed)
- Manage user rule groups (Create/Update/Delete/Describe on account)
- List rule groups
- Publish to the notification SNS topic
- Write CloudWatch logs

All AWS calls go through AWSSessionManager.get_client() for profile support.
"""

import json
import logging
import time
from typing import Dict, List, Optional

from src.aws.aws_session_manager import AWSSessionManager

logger = logging.getLogger(__name__)

# Resource naming conventions
LAMBDA_ROLE_NAME_TEMPLATE = 'ManagedRuleGenerator-LambdaRole-{region}'
LAMBDA_POLICY_NAME_TEMPLATE = 'ManagedRuleGenerator-LambdaPolicy-{region}'

# Lambda assume role trust policy
LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}


def _build_lambda_policy(region: str, account_id: str) -> Dict:
    """Build the least-privilege IAM policy for the Lambda function.

    Per Section 11 of the feature spec, the policy grants:
    - DescribeRuleGroup on aws-managed ThreatSignatures* rule groups
    - Full management of user rule groups (Create/Update/Delete/Describe/Tag)
    - ListRuleGroups (resource: *)
    - SNS Publish to ManagedRuleGenerator-Notifications topic
    - CloudWatch Logs for the Lambda function

    Args:
        region: AWS region for resource ARNs.
        account_id: AWS account ID for resource ARNs.

    Returns:
        IAM policy document as a dict.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DescribeRuleGroups",
                "Effect": "Allow",
                "Action": [
                    "network-firewall:DescribeRuleGroup"
                ],
                "Resource": "*"
            },
            {
                "Sid": "ManageUserRuleGroups",
                "Effect": "Allow",
                "Action": [
                    "network-firewall:UpdateRuleGroup",
                    "network-firewall:CreateRuleGroup",
                    "network-firewall:DeleteRuleGroup",
                    "network-firewall:TagResource"
                ],
                "Resource": "arn:aws:network-firewall:{}:{}:stateful-rulegroup/*".format(
                    region, account_id
                )
            },
            {
                "Sid": "ListRuleGroups",
                "Effect": "Allow",
                "Action": [
                    "network-firewall:ListRuleGroups"
                ],
                "Resource": "*"
            },
            {
                "Sid": "PublishNotifications",
                "Effect": "Allow",
                "Action": [
                    "sns:Publish"
                ],
                "Resource": "arn:aws:sns:{}:{}:ManagedRuleGenerator-Notifications".format(
                    region, account_id
                )
            },
            {
                "Sid": "CloudWatchLogs",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:{}:{}:log-group:/aws/lambda/ManagedRuleGenerator-*".format(
                    region, account_id
                )
            }
        ]
    }


class IAMError(Exception):
    """Base exception for IAM operations."""
    pass


class RoleNotFoundError(IAMError):
    """Raised when an IAM role is not found."""
    pass


def get_role_name(region: str) -> str:
    """Get the standard IAM role name for a region.

    Args:
        region: AWS region.

    Returns:
        IAM role name string.
    """
    return LAMBDA_ROLE_NAME_TEMPLATE.format(region=region)


def get_policy_name(region: str) -> str:
    """Get the standard IAM policy name for a region.

    Args:
        region: AWS region.

    Returns:
        IAM policy name string.
    """
    return LAMBDA_POLICY_NAME_TEMPLATE.format(region=region)


def create_lambda_role(session_manager: AWSSessionManager,
                       region: str,
                       account_id: Optional[str] = None) -> Dict:
    """Create the IAM role for the Lambda function.

    Creates the role with the Lambda trust policy and attaches
    the least-privilege inline policy.

    If the role already exists, returns the existing role's details.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region (used for naming and policy ARNs).
        account_id: AWS account ID. If None, will be fetched via STS.

    Returns:
        Dict with keys:
        - 'RoleName': The role name
        - 'RoleArn': The role ARN
        - 'Created': True if newly created, False if already existed

    Raises:
        IAMError: If role creation fails.
    """
    # IAM is a global service, no region needed for client
    iam_client = session_manager.get_client('iam')

    role_name = get_role_name(region)
    policy_name = get_policy_name(region)

    if account_id is None:
        sts_client = session_manager.get_client('sts')
        account_id = sts_client.get_caller_identity()['Account']
    # account_id is guaranteed to be str at this point
    assert isinstance(account_id, str)

    # Check if role already exists
    try:
        response = iam_client.get_role(RoleName=role_name)
        role_arn = response['Role']['Arn']
        logger.info("IAM role already exists: %s", role_name)

        # Update the inline policy to ensure it's current
        _put_role_policy(iam_client, role_name, policy_name, region, account_id)

        return {
            'RoleName': role_name,
            'RoleArn': role_arn,
            'Created': False,
        }
    except iam_client.exceptions.NoSuchEntityException:
        pass  # Role doesn't exist, create it
    except Exception as e:
        error_msg = "Failed to check IAM role '{}': {}".format(role_name, str(e))
        logger.error(error_msg)
        raise IAMError(error_msg) from e

    # Create the role
    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(LAMBDA_TRUST_POLICY),
            Description='Lambda execution role for Managed Rule Group Generator ({})'.format(region),
            Tags=[
                {'Key': 'ManagedRuleGenerator', 'Value': 'lambda-role'},
                {'Key': 'Region', 'Value': region},
            ],
        )
        role_arn = response['Role']['Arn']
        logger.info("Created IAM role: %s (ARN: %s)", role_name, role_arn)

        # Attach inline policy
        _put_role_policy(iam_client, role_name, policy_name, region, account_id)

        # Wait briefly for IAM propagation (IAM is eventually consistent)
        # The Lambda creation may fail if we try to use the role immediately
        logger.info("Waiting for IAM role propagation...")
        time.sleep(10)

        return {
            'RoleName': role_name,
            'RoleArn': role_arn,
            'Created': True,
        }

    except Exception as e:
        error_msg = "Failed to create IAM role '{}': {}".format(role_name, str(e))
        logger.error(error_msg)
        raise IAMError(error_msg) from e


def _put_role_policy(iam_client, role_name: str, policy_name: str,
                     region: str, account_id: str) -> None:
    """Attach or update the inline policy on the Lambda role.

    Args:
        iam_client: boto3 IAM client.
        role_name: Name of the IAM role.
        policy_name: Name for the inline policy.
        region: AWS region.
        account_id: AWS account ID.

    Raises:
        IAMError: If the policy attachment fails.
    """
    try:
        policy_doc = _build_lambda_policy(region, account_id)
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_doc),
        )
        logger.info("Attached inline policy '%s' to role '%s'", policy_name, role_name)
    except Exception as e:
        error_msg = "Failed to attach policy '{}' to role '{}': {}".format(
            policy_name, role_name, str(e)
        )
        logger.error(error_msg)
        raise IAMError(error_msg) from e


def get_lambda_role(session_manager: AWSSessionManager,
                    region: str) -> Optional[Dict]:
    """Get the existing Lambda role for a region, if it exists.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.

    Returns:
        Dict with 'RoleName' and 'RoleArn' if the role exists, None otherwise.
    """
    iam_client = session_manager.get_client('iam')
    role_name = get_role_name(region)

    try:
        response = iam_client.get_role(RoleName=role_name)
        return {
            'RoleName': response['Role']['RoleName'],
            'RoleArn': response['Role']['Arn'],
        }
    except iam_client.exceptions.NoSuchEntityException:
        return None
    except Exception as e:
        logger.warning("Failed to get IAM role '%s': %s", role_name, str(e))
        return None


def delete_lambda_role(session_manager: AWSSessionManager,
                       region: str) -> bool:
    """Delete the Lambda role and its inline policies.

    Removes all inline policies from the role first, then deletes the role.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.

    Returns:
        True if deleted successfully, False if the role didn't exist.

    Raises:
        IAMError: If deletion fails for reasons other than the role not existing.
    """
    iam_client = session_manager.get_client('iam')
    role_name = get_role_name(region)

    try:
        # List and remove all inline policies first
        try:
            policy_response = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in policy_response.get('PolicyNames', []):
                iam_client.delete_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name,
                )
                logger.info("Deleted inline policy '%s' from role '%s'", policy_name, role_name)
        except iam_client.exceptions.NoSuchEntityException:
            logger.info("IAM role '%s' does not exist, nothing to delete", role_name)
            return False

        # List and detach all managed policies
        try:
            attached_response = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_response.get('AttachedPolicies', []):
                iam_client.detach_role_policy(
                    RoleName=role_name,
                    PolicyArn=policy['PolicyArn'],
                )
                logger.info("Detached managed policy '%s' from role '%s'",
                            policy['PolicyArn'], role_name)
        except Exception:
            pass  # Non-critical if no managed policies

        # Delete the role
        iam_client.delete_role(RoleName=role_name)
        logger.info("Deleted IAM role: %s", role_name)
        return True

    except iam_client.exceptions.NoSuchEntityException:
        logger.info("IAM role '%s' does not exist, nothing to delete", role_name)
        return False
    except Exception as e:
        error_msg = "Failed to delete IAM role '{}': {}".format(role_name, str(e))
        logger.error(error_msg)
        raise IAMError(error_msg) from e


def get_lambda_policy_document(region: str, account_id: str) -> str:
    """Get the Lambda policy document as a formatted JSON string.

    Useful for display in the Help > AWS Setup Guide.

    Args:
        region: AWS region.
        account_id: AWS account ID.

    Returns:
        JSON string of the policy document.
    """
    policy = _build_lambda_policy(region, account_id)
    return json.dumps(policy, indent=2)
