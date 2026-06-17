"""
SNS Topic and Subscription Management for Managed Rule Group Generator

Manages:
- Subscription to the AWS-Managed-Threat-Signatures SNS topic (triggers Lambda)
- Creation of the ManagedRuleGenerator-Notifications topic (user alerts)
- Email subscriptions for change notifications

All AWS calls go through AWSSessionManager.get_client() for profile support.
"""

import logging
from typing import Dict, List, Optional

from src.aws.aws_session_manager import AWSSessionManager

logger = logging.getLogger(__name__)

# The AWS-managed SNS topic for threat signature updates (per-region)
# The topic is owned by different AWS accounts in each region.
MANAGED_THREAT_SIGNATURES_TOPIC_NAME = 'AWS-Managed-Threat-Signatures'

# Known region -> AWS account ID mapping for the managed topic
# These are the AWS-owned accounts that publish threat signature updates.
_MANAGED_TOPIC_ACCOUNT_IDS = {
    'us-east-1': '121169385865',
    'us-east-2': '298017169073',
    'us-west-1': '944178319330',
    'us-west-2': '191285106958',
    'ca-central-1': '257121193784',
    'eu-central-1': '570904534863',
    'eu-west-1': '415366098628',
    'eu-west-2': '601262743723',
    'eu-west-3': '855336276712',
    'eu-north-1': '164068535668',
    'sa-east-1': '496739210437',
    'ap-northeast-1': '171877676388',
    'ap-northeast-2': '798480584765',
    'ap-northeast-3': '262935724646',
    'ap-southeast-1': '556625892612',
    'ap-southeast-2': '412650407292',
    'ap-south-1': '429188163907',
}

# User notification topic name
NOTIFICATION_TOPIC_NAME = 'ManagedRuleGenerator-Notifications'


class SNSError(Exception):
    """Base exception for SNS operations."""
    pass


class TopicNotFoundError(SNSError):
    """Raised when an SNS topic is not found."""
    pass


def get_managed_threat_signatures_topic_arn(region: str,
                                            session_manager: Optional[AWSSessionManager] = None) -> Optional[str]:
    """Get the ARN of the AWS-Managed-Threat-Signatures SNS topic for a region.

    The topic is owned by different AWS accounts in each region. This function
    uses a known mapping for common regions and falls back to SNS API discovery
    for unknown regions.

    Args:
        region: AWS region.
        session_manager: Optional AWSSessionManager for API-based discovery
                        when the region is not in the known mapping.

    Returns:
        Topic ARN string, or None if the topic cannot be determined.
    """
    # Check known mapping first
    account_id = _MANAGED_TOPIC_ACCOUNT_IDS.get(region)
    if account_id:
        return 'arn:aws:sns:{}:{}:{}'.format(region, account_id, MANAGED_THREAT_SIGNATURES_TOPIC_NAME)

    # For unknown regions, try API-based discovery
    if session_manager:
        discovered = _discover_managed_topic_arn(session_manager, region)
        if discovered:
            return discovered

    logger.warning("No managed threat signatures topic mapping for region '%s'. "
                   "SNS auto-sync subscription will be skipped.", region)
    return None


def _discover_managed_topic_arn(session_manager: AWSSessionManager, region: str) -> Optional[str]:
    """Try to discover the managed threat signatures topic ARN via API.

    Lists all SNS subscriptions in the account and looks for one targeting
    a topic named AWS-Managed-Threat-Signatures.

    Args:
        session_manager: AWSSessionManager instance.
        region: AWS region.

    Returns:
        Topic ARN string if found, None otherwise.
    """
    try:
        client = session_manager.get_client('sns', region_name=region)
        paginator = client.get_paginator('list_subscriptions')
        for page in paginator.paginate():
            for sub in page.get('Subscriptions', []):
                topic_arn = sub.get('TopicArn', '')
                if topic_arn.endswith(':' + MANAGED_THREAT_SIGNATURES_TOPIC_NAME):
                    logger.info("Discovered managed topic ARN via subscriptions: %s", topic_arn)
                    return topic_arn
    except Exception as e:
        logger.debug("Could not discover managed topic via subscriptions: %s", str(e))

    return None


def get_notification_topic_name() -> str:
    """Get the standard notification topic name.

    Returns:
        Topic name string.
    """
    return NOTIFICATION_TOPIC_NAME


def create_notification_topic(session_manager: AWSSessionManager,
                              region: str) -> Dict:
    """Create the notification SNS topic for user change alerts.

    Creates the ManagedRuleGenerator-Notifications topic if it doesn't
    already exist. SNS CreateTopic is idempotent — if the topic already
    exists, it returns the existing topic's ARN.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.

    Returns:
        Dict with keys:
        - 'TopicArn': The topic ARN
        - 'TopicName': The topic name

    Raises:
        SNSError: If topic creation fails.
    """
    client = session_manager.get_client('sns', region_name=region)

    try:
        response = client.create_topic(
            Name=NOTIFICATION_TOPIC_NAME,
            Tags=[
                {'Key': 'ManagedRuleGenerator', 'Value': 'notification-topic'},
            ],
        )

        topic_arn = response.get('TopicArn', '')

        logger.info("Created/confirmed notification topic: %s (ARN: %s)",
                     NOTIFICATION_TOPIC_NAME, topic_arn)

        return {
            'TopicArn': topic_arn,
            'TopicName': NOTIFICATION_TOPIC_NAME,
        }

    except Exception as e:
        error_msg = "Failed to create notification topic in {}: {}".format(region, str(e))
        logger.error(error_msg)
        raise SNSError(error_msg) from e


def subscribe_lambda_to_managed_topic(session_manager: AWSSessionManager,
                                      region: str,
                                      lambda_function_arn: str) -> Dict:
    """Subscribe the Lambda function to the AWS-Managed-Threat-Signatures topic.

    This subscription triggers the Lambda whenever AWS updates a managed
    threat signature rule group.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        lambda_function_arn: ARN of the Lambda function to subscribe.

    Returns:
        Dict with keys:
        - 'SubscriptionArn': The subscription ARN
        - 'TopicArn': The managed topic ARN

    Raises:
        SNSError: If subscription fails.
    """
    client = session_manager.get_client('sns', region_name=region)
    topic_arn = get_managed_threat_signatures_topic_arn(region, session_manager)
    if not topic_arn:
        raise SNSError(
            "Cannot subscribe to managed topic: no topic ARN mapping for region '{}'. "
            "You can manually subscribe the Lambda to the AWS-Managed-Threat-Signatures "
            "topic using the AWS console.".format(region)
        )

    try:
        response = client.subscribe(
            TopicArn=topic_arn,
            Protocol='lambda',
            Endpoint=lambda_function_arn,
        )

        subscription_arn = response.get('SubscriptionArn', '')

        logger.info("Subscribed Lambda %s to managed topic %s (Subscription: %s)",
                     lambda_function_arn, topic_arn, subscription_arn)

        return {
            'SubscriptionArn': subscription_arn,
            'TopicArn': topic_arn,
        }

    except Exception as e:
        error_msg = "Failed to subscribe Lambda to managed topic in {}: {}".format(
            region, str(e)
        )
        logger.error(error_msg)
        raise SNSError(error_msg) from e


def add_lambda_sns_permission(session_manager: AWSSessionManager,
                              region: str,
                              lambda_function_arn: str) -> bool:
    """Add permission for SNS to invoke the Lambda function.

    This is required for the SNS subscription to work. The Lambda resource
    policy must allow the SNS topic to invoke the function.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        lambda_function_arn: ARN of the Lambda function.

    Returns:
        True if permission was added successfully.

    Raises:
        SNSError: If adding the permission fails.
    """
    lambda_client = session_manager.get_client('lambda', region_name=region)
    topic_arn = get_managed_threat_signatures_topic_arn(region, session_manager)
    if not topic_arn:
        logger.warning("No managed topic ARN for region '%s', skipping permission.", region)
        return True

    try:
        lambda_client.add_permission(
            FunctionName=lambda_function_arn,
            StatementId='AllowSNSInvoke-ManagedThreatSignatures',
            Action='lambda:InvokeFunction',
            Principal='sns.amazonaws.com',
            SourceArn=topic_arn,
        )
        logger.info("Added SNS invoke permission to Lambda: %s", lambda_function_arn)
        return True

    except Exception as e:
        error_str = str(e)
        # Permission may already exist
        if 'ResourceConflictException' in error_str or 'already exists' in error_str:
            logger.info("SNS invoke permission already exists on Lambda: %s",
                        lambda_function_arn)
            return True
        error_msg = "Failed to add SNS permission to Lambda: {}".format(error_str)
        logger.error(error_msg)
        raise SNSError(error_msg) from e


def subscribe_email_to_notification_topic(session_manager: AWSSessionManager,
                                          region: str,
                                          topic_arn: str,
                                          email: str) -> Dict:
    """Subscribe an email address to the notification topic.

    The email address will receive a confirmation email from AWS.
    The subscription is pending until the user confirms it.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        topic_arn: ARN of the notification topic.
        email: Email address to subscribe.

    Returns:
        Dict with keys:
        - 'SubscriptionArn': The subscription ARN (may be 'pending confirmation')
        - 'Email': The subscribed email address

    Raises:
        SNSError: If subscription fails.
    """
    client = session_manager.get_client('sns', region_name=region)

    try:
        response = client.subscribe(
            TopicArn=topic_arn,
            Protocol='email',
            Endpoint=email,
        )

        subscription_arn = response.get('SubscriptionArn', 'pending confirmation')

        logger.info("Subscribed email %s to notification topic (Subscription: %s)",
                     email, subscription_arn)

        return {
            'SubscriptionArn': subscription_arn,
            'Email': email,
        }

    except Exception as e:
        error_msg = "Failed to subscribe email '{}' to topic: {}".format(email, str(e))
        logger.error(error_msg)
        raise SNSError(error_msg) from e


def publish_notification(session_manager: AWSSessionManager,
                         region: str,
                         topic_arn: str,
                         subject: str,
                         message: str) -> Dict:
    """Publish a notification message to the SNS topic.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        topic_arn: ARN of the notification topic.
        subject: Email subject line (max 100 chars).
        message: Notification message body.

    Returns:
        Dict with 'MessageId'.

    Raises:
        SNSError: If publishing fails.
    """
    client = session_manager.get_client('sns', region_name=region)

    try:
        # SNS subject is limited to 100 characters
        if len(subject) > 100:
            subject = subject[:97] + '...'

        response = client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message,
        )

        message_id = response.get('MessageId', '')
        logger.info("Published notification to %s (MessageId: %s)", topic_arn, message_id)

        return {
            'MessageId': message_id,
        }

    except Exception as e:
        error_msg = "Failed to publish notification to {}: {}".format(topic_arn, str(e))
        logger.error(error_msg)
        raise SNSError(error_msg) from e


def get_notification_topic(session_manager: AWSSessionManager,
                           region: str) -> Optional[Dict]:
    """Find the existing notification topic in a region, if it exists.

    Searches for a topic named ManagedRuleGenerator-Notifications.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.

    Returns:
        Dict with 'TopicArn' and 'TopicName' if found, None otherwise.
    """
    client = session_manager.get_client('sns', region_name=region)

    try:
        # List topics and find ours by name
        paginator = client.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page.get('Topics', []):
                arn = topic.get('TopicArn', '')
                # Topic ARN format: arn:aws:sns:region:account:name
                if arn.endswith(':' + NOTIFICATION_TOPIC_NAME):
                    return {
                        'TopicArn': arn,
                        'TopicName': NOTIFICATION_TOPIC_NAME,
                    }

        return None

    except Exception as e:
        logger.warning("Failed to find notification topic in %s: %s", region, str(e))
        return None


def list_topic_subscriptions(session_manager: AWSSessionManager,
                             region: str,
                             topic_arn: str) -> List[Dict]:
    """List all subscriptions for a given SNS topic.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        topic_arn: ARN of the topic.

    Returns:
        List of dicts with keys: 'SubscriptionArn', 'Protocol', 'Endpoint'.

    Raises:
        SNSError: If listing fails.
    """
    client = session_manager.get_client('sns', region_name=region)

    try:
        subscriptions = []
        paginator = client.get_paginator('list_subscriptions_by_topic')
        for page in paginator.paginate(TopicArn=topic_arn):
            for sub in page.get('Subscriptions', []):
                subscriptions.append({
                    'SubscriptionArn': sub.get('SubscriptionArn', ''),
                    'Protocol': sub.get('Protocol', ''),
                    'Endpoint': sub.get('Endpoint', ''),
                })

        return subscriptions

    except Exception as e:
        error_msg = "Failed to list subscriptions for {}: {}".format(topic_arn, str(e))
        # AuthorizationError on cross-account topics (e.g., AWS-Managed-Threat-Signatures)
        # is expected — we can't list subscriptions on topics we don't own.
        if 'AuthorizationError' in str(e) or 'not authorized' in str(e):
            logger.debug(error_msg)
        else:
            logger.error(error_msg)
        raise SNSError(error_msg) from e


def unsubscribe(session_manager: AWSSessionManager,
                region: str,
                subscription_arn: str) -> bool:
    """Unsubscribe from an SNS topic.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        subscription_arn: ARN of the subscription to remove.

    Returns:
        True if unsubscribed successfully.

    Raises:
        SNSError: If unsubscribing fails.
    """
    client = session_manager.get_client('sns', region_name=region)

    try:
        client.unsubscribe(SubscriptionArn=subscription_arn)
        logger.info("Unsubscribed: %s", subscription_arn)
        return True

    except Exception as e:
        error_msg = "Failed to unsubscribe {}: {}".format(subscription_arn, str(e))
        logger.error(error_msg)
        raise SNSError(error_msg) from e


def delete_notification_topic(session_manager: AWSSessionManager,
                              region: str,
                              topic_arn: str) -> bool:
    """Delete the notification SNS topic.

    Deleting a topic also removes all subscriptions to it.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        topic_arn: ARN of the topic to delete.

    Returns:
        True if deleted successfully.

    Raises:
        SNSError: If deletion fails.
    """
    client = session_manager.get_client('sns', region_name=region)

    try:
        client.delete_topic(TopicArn=topic_arn)
        logger.info("Deleted notification topic: %s", topic_arn)
        return True

    except Exception as e:
        error_msg = "Failed to delete notification topic {}: {}".format(topic_arn, str(e))
        logger.error(error_msg)
        raise SNSError(error_msg) from e
