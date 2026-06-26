"""
Managed Rule Group Generator - Lambda Handler

Processes SNS notifications from the AWS-Managed-Threat-Signatures topic
and automatically updates user-managed rule groups with filtered rules.

This handler:
- Is triggered by SNS notifications when AWS updates managed rule groups
- Implements a 30-second debounce to absorb concurrent notifications
- Re-fetches ALL source rule groups for affected configurations
- Applies filters, deduplication, and test mode transformations
- Creates backups before updating rule groups
- Sends change notifications via SNS
- Handles UpdateToken conflicts with retry logic
- Logs errors to CloudWatch and sends error notifications

All AWS API calls use boto3 directly (Lambda runs with an IAM role,
not through AWSSessionManager which is for the local GUI tool).
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from botocore.exceptions import ClientError

# Import core modules - these are packaged alongside the handler
from core.rule_parser import ParsedRule, parse_rules_string, get_rules_with_sid
from core.rule_filter import (
    FilterCondition,
    FilterConfig,
    FilterResult,
    apply_filters,
    filter_config_from_dict,
)
from core.deduplicator import deduplicate_rules
from core.test_mode import apply_test_mode_bulk

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration
DEBOUNCE_SECONDS = 30
MAX_UPDATE_RETRIES = 3
RETRY_DELAY_SECONDS = 2

# Environment variable keys
CONFIG_KEY = 'RULE_GROUP_CONFIGS'


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main Lambda entry point. Processes SNS notification events.

    Args:
        event: SNS event dict containing Records from AWS-Managed-Threat-Signatures.
        context: Lambda context object.

    Returns:
        Response dict with processing status and summary.
    """
    logger.info("Received event with %d record(s)", len(event.get('Records', [])))

    try:
        # Parse SNS records to identify updated rule groups
        updated_arns = _extract_updated_rule_group_arns(event)
        logger.info("Updated rule group ARNs from SNS: %s", updated_arns)

        # Load configurations from environment variable
        configs = _load_configs()
        if not configs:
            logger.info("No configurations found in RULE_GROUP_CONFIGS. Nothing to do.")
            return _response(200, "No configurations found", processed=0)

        # Identify which configurations are affected
        affected_configs = _find_affected_configs(configs, updated_arns)
        if not affected_configs:
            logger.info("No configurations affected by this update. Nothing to do.")
            return _response(200, "No affected configurations", processed=0)

        logger.info(
            "%d configuration(s) affected: %s",
            len(affected_configs),
            [c.get('name', 'unnamed') for c in affected_configs],
        )

        # Debounce: wait to absorb concurrent notifications
        logger.info("Debouncing for %d seconds...", DEBOUNCE_SECONDS)
        time.sleep(DEBOUNCE_SECONDS)

        # Determine region from Lambda ARN in context or from config ARNs
        region = _get_region(context, configs)

        # Process each affected configuration
        results = []
        for config in affected_configs:
            try:
                result = _process_config(config, region, updated_arns)
                results.append(result)
            except Exception as e:
                config_name = config.get('name', 'unnamed')
                logger.error("Failed to process config '%s': %s", config_name, str(e))
                _send_error_notification(config, region, str(e))
                results.append({
                    'config_name': config_name,
                    'status': 'error',
                    'error': str(e),
                })

        return _response(200, "Processing complete", processed=len(results), results=results)

    except Exception as e:
        logger.error("Unhandled error in lambda_handler: %s", str(e), exc_info=True)
        return _response(500, "Unhandled error: {}".format(str(e)), processed=0)


def _extract_updated_rule_group_arns(event: Dict[str, Any]) -> Set[str]:
    """Extract the ARNs of updated managed rule groups from the SNS event.

    The SNS message from AWS-Managed-Threat-Signatures may contain information
    about which rule group was updated. We parse the message to extract ARNs.
    If we cannot determine specific ARNs, we return an empty set which signals
    that all configurations should be re-evaluated.

    Args:
        event: The Lambda event dict with SNS Records.

    Returns:
        Set of rule group ARNs that were updated, or empty set if
        all configs should be re-evaluated.
    """
    updated_arns = set()

    for record in event.get('Records', []):
        sns_data = record.get('Sns', {})
        message_str = sns_data.get('Message', '')
        subject = sns_data.get('Subject', '')

        logger.info("SNS Subject: %s", subject)
        logger.info("SNS Message: %s", message_str[:500])

        # Try to parse the message as JSON
        try:
            message = json.loads(message_str)
        except (json.JSONDecodeError, TypeError):
            message = {}

        # Look for rule group ARN in the message
        # AWS SNS messages for managed rule groups may contain the ARN
        # in various fields depending on the message format
        for field_name in ('rule_group_arn', 'ruleGroupArn', 'RuleGroupArn',
                           'arn', 'Arn', 'resource', 'Resource'):
            arn_value = message.get(field_name, '')
            if arn_value and ':stateful-rulegroup/' in str(arn_value):
                updated_arns.add(str(arn_value))

        # Also check if the ARN is in a list format
        for field_name in ('rule_groups', 'ruleGroups', 'RuleGroups',
                           'resources', 'Resources'):
            arns_list = message.get(field_name, [])
            if isinstance(arns_list, list):
                for arn in arns_list:
                    if isinstance(arn, str) and ':stateful-rulegroup/' in arn:
                        updated_arns.add(arn)
                    elif isinstance(arn, dict):
                        for k in ('arn', 'Arn', 'ARN'):
                            if k in arn and ':stateful-rulegroup/' in str(arn[k]):
                                updated_arns.add(str(arn[k]))

        # Check the subject line for rule group names
        if 'ThreatSignatures' in subject:
            # Subject might mention the rule group name directly
            logger.info("Subject contains ThreatSignatures reference")

    return updated_arns


def _load_configs() -> List[Dict]:
    """Load rule group configurations from the RULE_GROUP_CONFIGS environment variable.

    Returns:
        List of configuration dicts. Empty list if not configured.
    """
    config_json = os.environ.get(CONFIG_KEY, '')
    if not config_json:
        return []

    try:
        config_data = json.loads(config_json)
        return config_data.get('configs', [])
    except json.JSONDecodeError as e:
        logger.error("Failed to parse RULE_GROUP_CONFIGS: %s", str(e))
        return []


def _find_affected_configs(configs: List[Dict], updated_arns: Set[str]) -> List[Dict]:
    """Find configurations whose source rule groups were updated.

    If updated_arns is empty (we couldn't determine which rule groups were
    updated), all configurations are considered affected.

    Args:
        configs: List of rule group configuration dicts.
        updated_arns: Set of updated rule group ARNs.

    Returns:
        List of affected configuration dicts.
    """
    if not updated_arns:
        # Cannot determine which rule groups were updated - re-evaluate all
        logger.info("No specific updated ARNs identified; re-evaluating all configurations")
        return configs

    affected = []
    for config in configs:
        source_arns = set(config.get('source_rule_groups', []))
        if source_arns & updated_arns:
            affected.append(config)
        else:
            logger.info(
                "Config '%s' not affected (sources: %s)",
                config.get('name', 'unnamed'),
                source_arns,
            )

    return affected


def _get_region(context: Any, configs: List[Dict]) -> str:
    """Determine the AWS region from the Lambda context or configuration.

    Args:
        context: Lambda context object (has invoked_function_arn).
        configs: List of configurations (may contain ARNs with region).

    Returns:
        AWS region string.
    """
    # Try to get region from Lambda context ARN
    if context and hasattr(context, 'invoked_function_arn'):
        arn = context.invoked_function_arn
        # ARN format: arn:aws:lambda:REGION:ACCOUNT:function:NAME
        parts = arn.split(':')
        if len(parts) >= 4:
            return parts[3]

    # Try to get region from config ARNs
    for config in configs:
        arn = config.get('output_rule_group_arn', '')
        if arn:
            parts = arn.split(':')
            if len(parts) >= 4:
                return parts[3]

    # Fallback to environment variable or default
    return os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'))


def _process_config(config: Dict, region: str, trigger_arns: Set[str]) -> Dict:
    """Process a single rule group configuration.

    Steps:
    1. Fetch ALL source rule groups (not just the updated one)
    2. Parse rules from each source
    3. Apply filters
    4. Deduplicate
    5. Apply test mode if configured
    6. Compare with current rule group content
    7. Create backup
    8. Update rule group
    9. Send change notification

    Args:
        config: The rule group configuration dict.
        region: AWS region.
        trigger_arns: Set of ARNs that triggered this update.

    Returns:
        Dict with processing results.
    """
    config_name = config.get('name', 'unnamed')
    output_arn = config.get('output_rule_group_arn', '')
    source_arns = config.get('source_rule_groups', [])
    notification_topic_arn = config.get('notification_topic_arn', '')

    logger.info("Processing config '%s' with %d source rule groups", config_name, len(source_arns))

    nfw_client = boto3.client('network-firewall', region_name=region)
    sns_client = boto3.client('sns', region_name=region) if notification_topic_arn else None

    # Step 1-2: Fetch and parse all source rule groups
    all_parsed_rules = []
    for source_arn in source_arns:
        try:
            source_rules = _fetch_and_parse_source(nfw_client, source_arn)
            all_parsed_rules.extend(source_rules)
            logger.info(
                "Fetched %d rules from %s",
                len(source_rules),
                source_arn,
            )
        except Exception as e:
            logger.error("Failed to fetch source rule group %s: %s", source_arn, str(e))
            raise RuntimeError(
                "Failed to fetch source rule group {}: {}".format(source_arn, str(e))
            )

    # Step 3: Apply filters
    filter_config = _build_filter_config(config)
    filter_result = apply_filters(all_parsed_rules, filter_config)
    logger.info(
        "Filter results for '%s': scanned=%d, matching=%d, missing_metadata=%d",
        config_name,
        filter_result.total_scanned,
        filter_result.total_matching,
        filter_result.total_missing_metadata,
    )

    # Step 4: Deduplicate
    deduped_rules = deduplicate_rules(filter_result.matching_rules)
    logger.info(
        "After deduplication: %d rules (from %d matching)",
        len(deduped_rules),
        filter_result.total_matching,
    )

    # Step 5: Apply test mode if configured
    deployment_mode = config.get('deployment_mode', 'as_is')
    if deployment_mode == 'test_mode':
        deduped_rules = apply_test_mode_bulk(deduped_rules)
        logger.info("Applied test mode to %d rules", len(deduped_rules))

    # Build the new rules string
    new_rules_string = _build_rules_string(deduped_rules)

    # Build rule_variables if home_net or external_net is defined
    rule_variables = None
    home_net = config.get('home_net')
    external_net = config.get('external_net')
    if home_net:
        rule_variables = {
            'IPSets': {
                'HOME_NET': {
                    'Definition': [cidr.strip() for cidr in home_net.split(',')]
                }
            }
        }
    if external_net:
        if rule_variables is None:
            rule_variables = {'IPSets': {}}
        rule_variables['IPSets']['EXTERNAL_NET'] = {
            'Definition': [cidr.strip() for cidr in external_net.split(',')]
        }

    # Step 6: Fetch current rule group and compare
    current_details = _describe_rule_group(nfw_client, output_arn)
    current_rules_string = current_details.get('RulesString', '')
    update_token = current_details.get('UpdateToken', '')
    current_name = current_details.get('RuleGroupName', config_name)

    if new_rules_string.strip() == current_rules_string.strip():
        logger.info("No changes detected for '%s'. Skipping update.", config_name)
        return {
            'config_name': config_name,
            'status': 'no_change',
            'rule_count': len(deduped_rules),
        }

    # Compute change summary before updating
    change_summary = _compute_change_summary(current_rules_string, new_rules_string)

    # Step 7: Create backup
    backup_name = None
    try:
        backup_name = _create_backup(
            nfw_client, current_name, output_arn,
            current_rules_string, current_details.get('Capacity', 8000)
        )
        logger.info("Created backup: %s", backup_name)
    except Exception as e:
        logger.warning("Failed to create backup for '%s': %s", config_name, str(e))
        # Continue with update even if backup fails - but log the warning

    # Step 8: Update rule group with retry for stale UpdateToken
    _update_rule_group_with_retry(nfw_client, output_arn, new_rules_string, update_token,
                                  rule_variables=rule_variables)
    logger.info("Updated rule group '%s' with %d rules", config_name, len(deduped_rules))

    # Step 8b: Update tags on the rule group
    try:
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        nfw_client.tag_resource(
            ResourceArn=output_arn,
            Tags=[
                {'Key': 'ManagedRuleGenerator', 'Value': config_name},
                {'Key': 'LastUpdated', 'Value': now_str},
            ],
        )
        logger.info("Updated tags on rule group '%s'", config_name)
    except Exception as e:
        logger.warning("Failed to update tags on '%s': %s", config_name, str(e))

    # Step 9: Send change notification
    if sns_client and notification_topic_arn:
        try:
            _send_change_notification(
                sns_client, notification_topic_arn, config_name,
                output_arn, trigger_arns, change_summary, backup_name,
            )
        except Exception as e:
            logger.warning("Failed to send change notification for '%s': %s", config_name, str(e))

    return {
        'config_name': config_name,
        'status': 'updated',
        'rule_count': len(deduped_rules),
        'rules_added': change_summary.get('added_count', 0),
        'rules_removed': change_summary.get('removed_count', 0),
        'rules_modified': change_summary.get('modified_count', 0),
        'backup_name': backup_name,
    }


def _fetch_and_parse_source(nfw_client: Any, source_arn: str) -> List[ParsedRule]:
    """Fetch a source rule group from AWS and parse its rules.

    Args:
        nfw_client: boto3 Network Firewall client.
        source_arn: ARN of the managed rule group.

    Returns:
        List of ParsedRule objects from the source rule group.
    """
    response = nfw_client.describe_rule_group(
        RuleGroupArn=source_arn,
        Type='STATEFUL',
    )

    rule_group = response.get('RuleGroup', {})
    rules_source = rule_group.get('RulesSource', {})
    rules_string = rules_source.get('RulesString', '')

    rule_group_response = response.get('RuleGroupResponse', {})

    # Get LastModifiedTime for deduplication precedence
    last_modified = rule_group_response.get('LastModifiedTime')
    last_modified_str = ''
    if last_modified:
        if hasattr(last_modified, 'isoformat'):
            last_modified_str = last_modified.isoformat()
        else:
            last_modified_str = str(last_modified)

    parsed = parse_rules_string(
        rules_string,
        source_rule_group=source_arn,
        source_last_modified=last_modified_str,
    )

    # Return only active rules with SIDs
    return get_rules_with_sid(parsed)


def _build_filter_config(config: Dict) -> FilterConfig:
    """Build a FilterConfig from a Lambda configuration dict.

    Args:
        config: Rule group configuration from RULE_GROUP_CONFIGS.

    Returns:
        FilterConfig object.
    """
    filters_data = config.get('filters', {})
    missing_behavior = config.get('missing_metadata_behavior', 'exclude')

    # If filters_data has conditions, use filter_config_from_dict
    if filters_data and filters_data.get('conditions'):
        fc = filter_config_from_dict(filters_data)
        # Override missing_metadata_behavior from config level if present
        if missing_behavior in ('exclude', 'include'):
            fc.missing_metadata_behavior = missing_behavior
        return fc

    # No filters = include all rules
    return FilterConfig(
        conditions=[],
        missing_metadata_behavior=missing_behavior,
    )


def _build_rules_string(rules: List[ParsedRule]) -> str:
    """Build a rules string from a list of ParsedRule objects.

    Args:
        rules: List of parsed rules to serialize.

    Returns:
        Multi-line string with one rule per line.
    """
    return '\n'.join(rule.raw for rule in rules)


def _describe_rule_group(nfw_client: Any, rule_group_arn: str) -> Dict:
    """Describe a rule group and return key details.

    Args:
        nfw_client: boto3 Network Firewall client.
        rule_group_arn: ARN of the rule group.

    Returns:
        Dict with RuleGroupName, RulesString, UpdateToken, Capacity.
    """
    response = nfw_client.describe_rule_group(
        RuleGroupArn=rule_group_arn,
        Type='STATEFUL',
    )

    rule_group_response = response.get('RuleGroupResponse', {})
    rule_group = response.get('RuleGroup', {})
    rules_source = rule_group.get('RulesSource', {})

    return {
        'RuleGroupName': rule_group_response.get('RuleGroupName', ''),
        'RulesString': rules_source.get('RulesString', ''),
        'UpdateToken': response.get('UpdateToken', ''),
        'Capacity': rule_group_response.get('Capacity', 8000),
    }


def _create_backup(nfw_client: Any, source_name: str, source_arn: str,
                   rules_string: str, capacity: int) -> str:
    """Create a backup of the current rule group.

    Args:
        nfw_client: boto3 Network Firewall client.
        source_name: Name of the source rule group.
        source_arn: ARN of the source rule group (for region/account extraction).
        rules_string: Current rules string to backup.
        capacity: Rule group capacity.

    Returns:
        The backup rule group name.
    """
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    backup_name = "{}-bak-{}".format(source_name, timestamp)

    nfw_client.create_rule_group(
        RuleGroupName=backup_name,
        Type='STATEFUL',
        Capacity=capacity,
        RuleGroup={
            'RulesSource': {
                'RulesString': rules_string,
            },
            'StatefulRuleOptions': {
                'RuleOrder': 'STRICT_ORDER',
            },
        },
        Description="Backup of {} created at {}".format(source_name, timestamp.replace('-', '_')),
        Tags=[
            {'Key': 'ManagedRuleGenerator', 'Value': 'backup'},
            {'Key': 'SourceRuleGroup', 'Value': source_name},
            {'Key': 'BackupTimestamp', 'Value': timestamp},
        ],
    )

    return backup_name


def _update_rule_group_with_retry(nfw_client: Any, rule_group_arn: str,
                                  rules_string: str, update_token: str,
                                  rule_variables: Optional[Dict] = None) -> None:
    """Update a rule group with retry logic for stale UpdateToken.

    If the UpdateToken is stale (another process updated the rule group
    concurrently), re-fetches the current token and retries.

    Args:
        nfw_client: boto3 Network Firewall client.
        rule_group_arn: ARN of the rule group to update.
        rules_string: New rules string content.
        update_token: Current update token.
        rule_variables: Optional RuleVariables dict (e.g. IPSets for $HOME_NET).

    Raises:
        RuntimeError: If all retries fail.
    """
    current_token = update_token

    for attempt in range(MAX_UPDATE_RETRIES):
        try:
            kwargs = {
                'UpdateToken': current_token,
                'RuleGroupArn': rule_group_arn,
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

            if rule_variables:
                kwargs['RuleGroup']['RuleVariables'] = rule_variables

            nfw_client.update_rule_group(**kwargs)
            return  # Success

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = str(e)

            if 'InvalidTokenException' in error_code or 'InvalidTokenException' in error_message or 'UpdateToken' in error_message:
                if attempt < MAX_UPDATE_RETRIES - 1:
                    logger.warning(
                        "UpdateToken stale (attempt %d/%d). Re-fetching...",
                        attempt + 1, MAX_UPDATE_RETRIES,
                    )
                    time.sleep(RETRY_DELAY_SECONDS)
                    # Re-fetch the current token
                    details = _describe_rule_group(nfw_client, rule_group_arn)
                    current_token = details['UpdateToken']

                    # Check if content is already current (another invocation updated it)
                    if details['RulesString'].strip() == rules_string.strip():
                        logger.info("Rule group already has current content. Skipping update.")
                        return
                else:
                    raise RuntimeError(
                        "Failed to update rule group after {} retries due to stale UpdateToken: {}".format(
                            MAX_UPDATE_RETRIES, error_message
                        )
                    )
            else:
                raise RuntimeError("Failed to update rule group: {}".format(error_message))

        except Exception as e:
            raise RuntimeError("Failed to update rule group: {}".format(str(e)))


def _compute_change_summary(old_rules_string: str, new_rules_string: str) -> Dict:
    """Compute a summary of changes between old and new rule strings.

    Compares rules by SID to identify added, removed, and modified rules.

    Args:
        old_rules_string: The current rules string.
        new_rules_string: The new rules string.

    Returns:
        Dict with change summary including counts and details.
    """
    old_rules = parse_rules_string(old_rules_string)
    new_rules = parse_rules_string(new_rules_string)

    # Build SID -> rule maps
    old_by_sid = {}
    for r in get_rules_with_sid(old_rules):
        old_by_sid[r.sid] = r

    new_by_sid = {}
    for r in get_rules_with_sid(new_rules):
        new_by_sid[r.sid] = r

    old_sids = set(old_by_sid.keys())
    new_sids = set(new_by_sid.keys())

    added_sids = new_sids - old_sids
    removed_sids = old_sids - new_sids
    common_sids = old_sids & new_sids

    # Detect modified rules (same SID, different content)
    modified_sids = set()
    for sid in common_sids:
        old_raw = old_by_sid[sid].raw.strip()
        new_raw = new_by_sid[sid].raw.strip()
        if old_raw != new_raw:
            modified_sids.add(sid)

    # Build detailed lists
    added_details = []
    for sid in sorted(added_sids):
        rule = new_by_sid[sid]
        added_details.append({
            'sid': sid,
            'msg': rule.msg or 'No message',
        })

    removed_details = []
    for sid in sorted(removed_sids):
        rule = old_by_sid[sid]
        removed_details.append({
            'sid': sid,
            'msg': rule.msg or 'No message',
        })

    modified_details = []
    for sid in sorted(modified_sids):
        old_rule = old_by_sid[sid]
        new_rule = new_by_sid[sid]
        detail = {
            'sid': sid,
            'msg': new_rule.msg or 'No message',
        }
        if old_rule.rev is not None and new_rule.rev is not None:
            detail['old_rev'] = old_rule.rev
            detail['new_rev'] = new_rule.rev
        modified_details.append(detail)

    return {
        'added_count': len(added_sids),
        'removed_count': len(removed_sids),
        'modified_count': len(modified_sids),
        'old_total': len(old_sids),
        'new_total': len(new_sids),
        'added': added_details,
        'removed': removed_details,
        'modified': modified_details,
    }


def _send_change_notification(sns_client: Any, topic_arn: str,
                              config_name: str, output_arn: str,
                              trigger_arns: Set[str],
                              change_summary: Dict,
                              backup_name: Optional[str]) -> None:
    """Send a change notification to the SNS topic.

    Formats and publishes a human-readable summary of the changes
    per the spec Section 10.2.

    Args:
        sns_client: boto3 SNS client.
        topic_arn: ARN of the notification topic.
        config_name: Name of the configuration.
        output_arn: ARN of the output rule group.
        trigger_arns: Set of ARNs that triggered the update.
        change_summary: Dict with change details.
        backup_name: Name of the backup rule group created, or None.
    """
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # Format trigger sources for display
    trigger_names = []
    for arn in trigger_arns:
        # Extract name from ARN: ...stateful-rulegroup/NAME
        if '/stateful-rulegroup/' in arn:
            trigger_names.append(arn.split('/stateful-rulegroup/')[-1])
        elif '/' in arn:
            trigger_names.append(arn.split('/')[-1])
        else:
            trigger_names.append(arn)

    trigger_display = ', '.join(trigger_names) if trigger_names else 'AWS managed rule group update'

    # Build message body
    lines = [
        'Rule Group "{}" has been updated.'.format(config_name),
        '',
        'Triggered by update to: {}'.format(trigger_display),
        'Timestamp: {}'.format(timestamp),
        '',
        'Changes:',
        '  + {} rules added'.format(change_summary['added_count']),
        '  - {} rules removed'.format(change_summary['removed_count']),
        '  ~ {} rules modified'.format(change_summary['modified_count']),
    ]

    # Added rules details
    if change_summary.get('added'):
        lines.append('')
        lines.append('  Added:')
        for rule_info in change_summary['added'][:20]:  # Limit to 20 for readability
            lines.append('    SID {} - "{}"'.format(rule_info['sid'], rule_info['msg']))
        if len(change_summary['added']) > 20:
            lines.append('    ... and {} more'.format(len(change_summary['added']) - 20))

    # Removed rules details
    if change_summary.get('removed'):
        lines.append('')
        lines.append('  Removed:')
        for rule_info in change_summary['removed'][:20]:
            lines.append('    SID {} - "{}"'.format(rule_info['sid'], rule_info['msg']))
        if len(change_summary['removed']) > 20:
            lines.append('    ... and {} more'.format(len(change_summary['removed']) - 20))

    # Modified rules details
    if change_summary.get('modified'):
        lines.append('')
        lines.append('  Modified:')
        for rule_info in change_summary['modified'][:20]:
            if 'old_rev' in rule_info and 'new_rev' in rule_info:
                lines.append('    SID {} - "{}" (rev {} -> {})'.format(
                    rule_info['sid'], rule_info['msg'],
                    rule_info['old_rev'], rule_info['new_rev'],
                ))
            else:
                lines.append('    SID {} - "{}"'.format(rule_info['sid'], rule_info['msg']))
        if len(change_summary['modified']) > 20:
            lines.append('    ... and {} more'.format(len(change_summary['modified']) - 20))

    lines.append('')
    lines.append('Totals: {} -> {} rules'.format(
        change_summary['old_total'], change_summary['new_total']
    ))

    if backup_name:
        lines.append('')
        lines.append('Backup created: {}'.format(backup_name))

    message = '\n'.join(lines)
    subject = '[ManagedRuleGenerator] Rule Group Updated: {}'.format(config_name)

    # SNS subject is limited to 100 characters
    if len(subject) > 100:
        subject = subject[:97] + '...'

    sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=message,
    )

    logger.info("Sent change notification for '%s' to %s", config_name, topic_arn)


def _send_error_notification(config: Dict, region: str, error_message: str) -> None:
    """Send an error notification to the SNS topic.

    Called when processing a configuration fails. Does not raise exceptions
    to avoid masking the original error.

    Args:
        config: The rule group configuration dict.
        region: AWS region.
        error_message: The error message to include.
    """
    notification_topic_arn = config.get('notification_topic_arn', '')
    if not notification_topic_arn:
        return

    config_name = config.get('name', 'unnamed')
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    try:
        sns_client = boto3.client('sns', region_name=region)

        subject = '[ManagedRuleGenerator] ERROR: {}'.format(config_name)
        if len(subject) > 100:
            subject = subject[:97] + '...'

        message = '\n'.join([
            'Error processing rule group configuration "{}".'.format(config_name),
            '',
            'Timestamp: {}'.format(timestamp),
            'Error: {}'.format(error_message),
            '',
            'The existing rule group has NOT been modified.',
            'Please check CloudWatch Logs for details.',
        ])

        sns_client.publish(
            TopicArn=notification_topic_arn,
            Subject=subject,
            Message=message,
        )

        logger.info("Sent error notification for '%s' to %s", config_name, notification_topic_arn)

    except Exception as e:
        logger.warning(
            "Failed to send error notification for '%s': %s",
            config_name, str(e),
        )


def _response(status_code: int, message: str, processed: int = 0,
              results: Optional[List[Dict]] = None) -> Dict[str, Any]:
    """Build a standard Lambda response dict.

    Args:
        status_code: HTTP-style status code.
        message: Human-readable message.
        processed: Number of configurations processed.
        results: Optional list of per-config results.

    Returns:
        Response dict.
    """
    body = {
        'message': message,
        'processed': processed,
    }
    if results is not None:
        body['results'] = results

    return {
        'statusCode': status_code,
        'body': json.dumps(body, default=str),
    }
