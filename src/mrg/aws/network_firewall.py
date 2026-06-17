"""
Network Firewall API wrapper for Managed Rule Group Generator

Provides functions to:
- List managed rule groups (with StrictOrder filtering)
- Describe rule groups (get rules and metadata)
- Create, update, and delete user-managed rule groups
- List user-managed rule groups

All AWS calls go through AWSSessionManager.get_client() for profile support.

Only STRICT_ORDER rule groups are supported. Source rule groups must match
the pattern ThreatSignatures*StrictOrder from the aws-managed account.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

from src.aws.aws_session_manager import AWSSessionManager

logger = logging.getLogger(__name__)

# Pattern for compatible managed rule groups: ThreatSignatures*StrictOrder
_STRICT_ORDER_PATTERN = re.compile(r'^ThreatSignatures\w*StrictOrder$')

# The ARN prefix for AWS-managed rule groups
_AWS_MANAGED_ARN_PREFIX = 'arn:aws:network-firewall:'
_AWS_MANAGED_ACCOUNT = 'aws-managed'

# Default capacity for output rule groups
DEFAULT_RULE_GROUP_CAPACITY = 8000


class NetworkFirewallError(Exception):
    """Base exception for Network Firewall operations."""
    pass


class RuleGroupNotFoundError(NetworkFirewallError):
    """Raised when a rule group is not found."""
    pass


class RuleGroupCapacityError(NetworkFirewallError):
    """Raised when a rule group capacity issue occurs."""
    pass


class UpdateTokenMismatchError(NetworkFirewallError):
    """Raised when the update token is stale (concurrent modification)."""
    pass


def is_compatible_managed_rule_group(name: str, arn: str) -> bool:
    """Check if a managed rule group is compatible with this tool.

    Compatible rule groups must:
    - Have a name matching ThreatSignatures*StrictOrder
    - Be from the aws-managed account

    Incompatible rule groups (filtered out):
    - Non-strict-order variants (ActionOrder / DefaultActionOrder)
    - Domain-list rule groups (MalwareDomains*, BotNetCommandAndControl*, etc.)
    - Partner-managed rule groups (Fortinet, ThreatSTOP, etc.)

    Args:
        name: The rule group name.
        arn: The rule group ARN.

    Returns:
        True if the rule group is compatible.
    """
    # Must match the StrictOrder naming pattern
    if not _STRICT_ORDER_PATTERN.match(name):
        return False

    # Must be from the aws-managed account
    if ':aws-managed:' not in arn and _AWS_MANAGED_ACCOUNT not in arn:
        return False

    return True


def list_managed_rule_groups(session_manager: AWSSessionManager,
                             region: str) -> List[Dict]:
    """List compatible AWS-managed strict-order threat signature rule groups.

    Queries ListRuleGroups with scope=MANAGED, type=STATEFUL, then filters
    to only include compatible StrictOrder rule groups.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region to query.

    Returns:
        List of dicts with keys: 'Name', 'Arn', 'Priority' (if available).
        Only compatible StrictOrder rule groups are included.

    Raises:
        NetworkFirewallError: If the API call fails.
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        rule_groups = []
        # Use paginator if available, otherwise single call
        paginator = client.get_paginator('list_rule_groups')
        page_iterator = paginator.paginate(
            Scope='MANAGED',
            Type='STATEFUL',
        )

        for page in page_iterator:
            for rg in page.get('RuleGroups', []):
                name = rg.get('Name', '')
                arn = rg.get('Arn', '')
                if is_compatible_managed_rule_group(name, arn):
                    rule_groups.append({
                        'Name': name,
                        'Arn': arn,
                    })

        logger.info("Found %d compatible managed rule groups in %s", len(rule_groups), region)
        return rule_groups

    except Exception as e:
        error_msg = "Failed to list managed rule groups in {}: {}".format(region, str(e))
        logger.error(error_msg)
        raise NetworkFirewallError(error_msg) from e


def list_user_rule_groups(session_manager: AWSSessionManager,
                          region: str) -> List[Dict]:
    """List user-managed stateful rule groups in the account.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region to query.

    Returns:
        List of dicts with keys: 'Name', 'Arn'.

    Raises:
        NetworkFirewallError: If the API call fails.
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        rule_groups = []
        paginator = client.get_paginator('list_rule_groups')
        page_iterator = paginator.paginate(
            Scope='ACCOUNT',
            Type='STATEFUL',
        )

        for page in page_iterator:
            for rg in page.get('RuleGroups', []):
                rule_groups.append({
                    'Name': rg.get('Name', ''),
                    'Arn': rg.get('Arn', ''),
                })

        logger.info("Found %d user rule groups in %s", len(rule_groups), region)
        return rule_groups

    except Exception as e:
        error_msg = "Failed to list user rule groups in {}: {}".format(region, str(e))
        logger.error(error_msg)
        raise NetworkFirewallError(error_msg) from e


def describe_rule_group(session_manager: AWSSessionManager,
                        region: str,
                        rule_group_arn: Optional[str] = None,
                        rule_group_name: Optional[str] = None,
                        rule_group_type: str = 'STATEFUL') -> Dict:
    """Describe a rule group and return its details including rules.

    Must provide either rule_group_arn or rule_group_name.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        rule_group_arn: ARN of the rule group (preferred).
        rule_group_name: Name of the rule group (alternative to ARN).
        rule_group_type: 'STATEFUL' or 'STATELESS'. Default is 'STATEFUL'.

    Returns:
        Dict with keys:
        - 'RuleGroupArn': The rule group ARN
        - 'RuleGroupName': The rule group name
        - 'RulesString': The raw Suricata rules string
        - 'UpdateToken': Token needed for updates
        - 'Capacity': The rule group capacity
        - 'Description': Rule group description (if any)
        - 'LastModifiedTime': Last modification timestamp (ISO 8601)
        - 'Tags': List of tags

    Raises:
        RuleGroupNotFoundError: If the rule group doesn't exist.
        NetworkFirewallError: If the API call fails.
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        kwargs = {'Type': rule_group_type}
        if rule_group_arn:
            kwargs['RuleGroupArn'] = rule_group_arn
        elif rule_group_name:
            kwargs['RuleGroupName'] = rule_group_name
        else:
            raise ValueError("Must provide either rule_group_arn or rule_group_name")

        response = client.describe_rule_group(**kwargs)

        rule_group_response = response.get('RuleGroupResponse', {})
        rule_group = response.get('RuleGroup', {})
        rules_source = rule_group.get('RulesSource', {})

        result = {
            'RuleGroupArn': rule_group_response.get('RuleGroupArn', ''),
            'RuleGroupName': rule_group_response.get('RuleGroupName', ''),
            'RulesString': rules_source.get('RulesString', ''),
            'UpdateToken': response.get('UpdateToken', ''),
            'Capacity': rule_group_response.get('Capacity', 0),
            'Description': rule_group_response.get('Description', ''),
            'LastModifiedTime': '',
            'Tags': rule_group_response.get('Tags', []),
        }

        # Extract LastModifiedTime - may be a datetime object
        last_modified = rule_group_response.get('LastModifiedTime')
        if last_modified:
            if hasattr(last_modified, 'isoformat'):
                result['LastModifiedTime'] = last_modified.isoformat()
            else:
                result['LastModifiedTime'] = str(last_modified)

        logger.info("Described rule group: %s", result['RuleGroupName'] or result['RuleGroupArn'])
        return result

    except client.exceptions.ResourceNotFoundException:
        identifier = rule_group_arn or rule_group_name
        raise RuleGroupNotFoundError(
            "Rule group not found: {}".format(identifier)
        )
    except Exception as e:
        if 'ResourceNotFoundException' in str(type(e)):
            identifier = rule_group_arn or rule_group_name
            raise RuleGroupNotFoundError(
                "Rule group not found: {}".format(identifier)
            ) from e
        error_msg = "Failed to describe rule group: {}".format(str(e))
        logger.error(error_msg)
        raise NetworkFirewallError(error_msg) from e


def create_rule_group(session_manager: AWSSessionManager,
                      region: str,
                      name: str,
                      rules_string: str,
                      capacity: int = DEFAULT_RULE_GROUP_CAPACITY,
                      description: str = '',
                      tags: Optional[List[Dict]] = None) -> Dict:
    """Create a new stateful rule group with STRICT_ORDER.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        name: Name for the rule group.
        rules_string: The Suricata rules string content.
        capacity: Rule group capacity (fixed at creation, cannot be changed).
        description: Optional description.
        tags: Optional list of tag dicts [{'Key': 'k', 'Value': 'v'}, ...].

    Returns:
        Dict with keys:
        - 'RuleGroupArn': The created rule group's ARN
        - 'UpdateToken': Token for subsequent updates
        - 'RuleGroupName': The name

    Raises:
        NetworkFirewallError: If creation fails.
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        kwargs = {
            'RuleGroupName': name,
            'Type': 'STATEFUL',
            'Capacity': capacity,
            'RuleGroup': {
                'RulesSource': {
                    'RulesString': rules_string,
                },
                'StatefulRuleOptions': {
                    'RuleOrder': 'STRICT_ORDER',
                },
            },
        }

        if description:
            kwargs['Description'] = description

        if tags:
            kwargs['Tags'] = tags

        response = client.create_rule_group(**kwargs)
        rule_group_response = response.get('RuleGroupResponse', {})

        result = {
            'RuleGroupArn': rule_group_response.get('RuleGroupArn', ''),
            'UpdateToken': response.get('UpdateToken', ''),
            'RuleGroupName': rule_group_response.get('RuleGroupName', name),
        }

        logger.info("Created rule group: %s (ARN: %s)", name, result['RuleGroupArn'])
        return result

    except Exception as e:
        error_msg = "Failed to create rule group '{}' in {}: {}".format(name, region, str(e))
        logger.error(error_msg)
        raise NetworkFirewallError(error_msg) from e


def update_rule_group(session_manager: AWSSessionManager,
                      region: str,
                      rules_string: str,
                      update_token: str,
                      rule_group_arn: Optional[str] = None,
                      rule_group_name: Optional[str] = None,
                      description: Optional[str] = None) -> Dict:
    """Update an existing stateful rule group with new rules.

    Must provide either rule_group_arn or rule_group_name.
    Requires the current UpdateToken to prevent concurrent modification.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        rules_string: New Suricata rules string content.
        update_token: Current update token from describe_rule_group.
        rule_group_arn: ARN of the rule group (preferred).
        rule_group_name: Name of the rule group (alternative).
        description: Optional updated description.

    Returns:
        Dict with keys:
        - 'RuleGroupArn': The rule group ARN
        - 'UpdateToken': New update token for subsequent updates
        - 'RuleGroupName': The name

    Raises:
        UpdateTokenMismatchError: If the update token is stale.
        RuleGroupNotFoundError: If the rule group doesn't exist.
        NetworkFirewallError: If the update fails.
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        kwargs = {
            'UpdateToken': update_token,
            'Type': 'STATEFUL',
            'RuleGroup': {
                'RulesSource': {
                    'RulesString': rules_string,
                },
                'StatefulRuleOptions': {
                    'RuleOrder': 'STRICT_ORDER',
                },
            },
        }

        if rule_group_arn:
            kwargs['RuleGroupArn'] = rule_group_arn
        elif rule_group_name:
            kwargs['RuleGroupName'] = rule_group_name
        else:
            raise ValueError("Must provide either rule_group_arn or rule_group_name")

        if description is not None:
            kwargs['Description'] = description

        response = client.update_rule_group(**kwargs)
        rule_group_response = response.get('RuleGroupResponse', {})

        result = {
            'RuleGroupArn': rule_group_response.get('RuleGroupArn', ''),
            'UpdateToken': response.get('UpdateToken', ''),
            'RuleGroupName': rule_group_response.get('RuleGroupName', ''),
        }

        logger.info("Updated rule group: %s", result['RuleGroupName'] or result['RuleGroupArn'])
        return result

    except Exception as e:
        error_str = str(e)
        if 'InvalidTokenException' in error_str or 'UpdateToken' in error_str:
            raise UpdateTokenMismatchError(
                "Update token is stale. The rule group was modified by another process. "
                "Re-fetch the rule group to get the current token."
            ) from e
        if 'ResourceNotFoundException' in str(type(e)) or 'ResourceNotFoundException' in error_str:
            identifier = rule_group_arn or rule_group_name
            raise RuleGroupNotFoundError(
                "Rule group not found: {}".format(identifier)
            ) from e
        error_msg = "Failed to update rule group: {}".format(error_str)
        logger.error(error_msg)
        raise NetworkFirewallError(error_msg) from e


def delete_rule_group(session_manager: AWSSessionManager,
                      region: str,
                      rule_group_arn: Optional[str] = None,
                      rule_group_name: Optional[str] = None) -> bool:
    """Delete a stateful rule group.

    Must provide either rule_group_arn or rule_group_name.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        rule_group_arn: ARN of the rule group (preferred).
        rule_group_name: Name of the rule group (alternative).

    Returns:
        True if deleted successfully.

    Raises:
        RuleGroupNotFoundError: If the rule group doesn't exist.
        NetworkFirewallError: If deletion fails.
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        kwargs = {'Type': 'STATEFUL'}
        if rule_group_arn:
            kwargs['RuleGroupArn'] = rule_group_arn
        elif rule_group_name:
            kwargs['RuleGroupName'] = rule_group_name
        else:
            raise ValueError("Must provide either rule_group_arn or rule_group_name")

        client.delete_rule_group(**kwargs)

        identifier = rule_group_arn or rule_group_name
        logger.info("Deleted rule group: %s", identifier)
        return True

    except Exception as e:
        if 'ResourceNotFoundException' in str(type(e)) or 'ResourceNotFoundException' in str(e):
            identifier = rule_group_arn or rule_group_name
            raise RuleGroupNotFoundError(
                "Rule group not found: {}".format(identifier)
            ) from e
        error_msg = "Failed to delete rule group: {}".format(str(e))
        logger.error(error_msg)
        raise NetworkFirewallError(error_msg) from e


def create_backup_rule_group(session_manager: AWSSessionManager,
                             region: str,
                             source_name: str,
                             source_arn: str,
                             backup_suffix: str,
                             description: str = '') -> Dict:
    """Create a backup copy of a rule group.

    Fetches the current rules from the source rule group and creates
    a new rule group with the backup name.

    The backup name follows the pattern: <source_name>_<backup_suffix>
    where backup_suffix is typically YYYYMMDD_HHMMSS.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        source_name: Name of the source rule group to backup.
        source_arn: ARN of the source rule group.
        backup_suffix: Suffix for the backup name (e.g., '20260220_213000').
        description: Optional description for the backup.

    Returns:
        Dict from create_rule_group with backup rule group details.

    Raises:
        RuleGroupNotFoundError: If the source rule group doesn't exist.
        NetworkFirewallError: If backup creation fails.
    """
    # Fetch current rules from source
    source_details = describe_rule_group(
        session_manager, region, rule_group_arn=source_arn
    )

    backup_name = "{}-bak-{}".format(source_name, backup_suffix)

    if not description:
        description = "Backup of {} created at {}".format(source_name, backup_suffix)

    return create_rule_group(
        session_manager=session_manager,
        region=region,
        name=backup_name,
        rules_string=source_details['RulesString'],
        capacity=source_details['Capacity'],
        description=description,
        tags=[
            {'Key': 'ManagedRuleGenerator', 'Value': 'backup'},
            {'Key': 'SourceRuleGroup', 'Value': source_name},
            {'Key': 'BackupTimestamp', 'Value': backup_suffix},
        ],
    )


def tag_resource(session_manager: AWSSessionManager,
                 region: str,
                 resource_arn: str,
                 tags: List[Dict]) -> bool:
    """Add or update tags on a Network Firewall resource.

    Uses the TagResource API to add or overwrite tags on an existing
    rule group. Existing tags with different keys are preserved.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        resource_arn: ARN of the resource to tag.
        tags: List of tag dicts [{'Key': 'k', 'Value': 'v'}, ...].

    Returns:
        True if tags were applied successfully.

    Raises:
        NetworkFirewallError: If tagging fails.
    """
    client = session_manager.get_client('network-firewall', region_name=region)

    try:
        client.tag_resource(
            ResourceArn=resource_arn,
            Tags=tags,
        )
        logger.info("Tagged resource %s with %d tag(s)", resource_arn, len(tags))
        return True

    except Exception as e:
        error_msg = "Failed to tag resource {}: {}".format(resource_arn, str(e))
        logger.error(error_msg)
        raise NetworkFirewallError(error_msg) from e


def rule_group_exists(session_manager: AWSSessionManager,
                      region: str,
                      rule_group_name: str) -> bool:
    """Check if a rule group exists by name.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        rule_group_name: Name to check.

    Returns:
        True if the rule group exists, False otherwise.
    """
    try:
        describe_rule_group(
            session_manager, region, rule_group_name=rule_group_name
        )
        return True
    except RuleGroupNotFoundError:
        return False
    except NetworkFirewallError:
        # Other errors (permissions, etc.) - we can't confirm existence
        return False


def validate_rule_group_name(name: str) -> List[str]:
    """Validate a rule group name against AWS naming rules.

    AWS rule group names must:
    - Be 1-128 characters
    - Contain only alphanumeric characters, hyphens, and underscores

    Args:
        name: The proposed rule group name.

    Returns:
        List of validation error messages. Empty if valid.
    """
    errors = []

    if not name:
        errors.append("Rule group name cannot be empty.")
        return errors

    if len(name) > 128:
        errors.append(
            "Rule group name must be 128 characters or fewer (got {}).".format(len(name))
        )

    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        errors.append(
            "Rule group name must contain only alphanumeric characters, "
            "hyphens (-), and underscores (_)."
        )

    return errors
