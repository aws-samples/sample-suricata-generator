"""
MRG File Reader/Writer for Managed Rule Group Generator

Handles reading and writing .mrg configuration files in JSON format.
The .mrg file captures all user configuration choices plus deployment metadata.

Schema follows Section 5.4 of the feature spec.

Fields populated by the user:
- version, region, aws_profile, name, output_rule_group_name, output_rule_group_capacity
- source_rule_groups, filters, action_override, missing_metadata_behavior
- notification_email, deployment_mode

Fields populated after deployment:
- last_deployed_at, output_rule_group_arn, lambda_function_arn
- notification_topic_arn, last_deployment_stats

The created_at and last_modified_at fields are managed automatically.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .rule_filter import (
    FilterConfig,
    filter_config_from_dict,
    filter_config_to_dict,
)

# Current file format version
MRG_FILE_VERSION = '1.0'

# Default values
DEFAULT_CAPACITY = 8000
DEFAULT_MISSING_METADATA_BEHAVIOR = 'exclude'
DEFAULT_DEPLOYMENT_MODE = 'as_is'


class MRGFileError(Exception):
    """Base exception for MRG file operations."""
    pass


class MRGFileFormatError(MRGFileError):
    """Raised when the MRG file format is invalid."""
    pass


class MRGConfig:
    """Represents a Managed Rule Group configuration.

    This is the in-memory representation of a .mrg file. It holds all
    configuration parameters and deployment metadata.

    Attributes:
        version: File format version string.
        created_at: ISO 8601 timestamp of file creation.
        last_modified_at: ISO 8601 timestamp of last modification.
        last_deployed_at: ISO 8601 timestamp of last deployment (None if never deployed).
        region: AWS region.
        aws_profile: AWS profile name (None for default).
        name: Configuration name (user-facing label).
        output_rule_group_name: Name of the output rule group in AWS.
        output_rule_group_arn: ARN of the output rule group (None if not deployed).
        output_rule_group_capacity: Capacity of the output rule group.
        source_rule_groups: List of source managed rule group ARNs.
        filters: Filter configuration (FilterConfig-compatible dict).
        missing_metadata_behavior: 'exclude' or 'include'.
        deployment_mode: 'as_is' or 'test_mode'.
        action_override: Action override (None for no override).
        notification_email: Email for change notifications (None if not set).
        notification_topic_arn: ARN of the notification SNS topic (None if not deployed).
        lambda_function_arn: ARN of the Lambda function (None if not deployed).
        last_deployment_stats: Stats from last deployment (None if never deployed).
    """

    def __init__(self):
        self.version: str = MRG_FILE_VERSION
        self.created_at: str = _now_iso()
        self.last_modified_at: str = _now_iso()
        self.last_deployed_at: Optional[str] = None
        self.region: str = 'us-east-1'
        self.aws_profile: Optional[str] = None
        self.name: str = ''
        self.output_rule_group_name: str = ''
        self.output_rule_group_arn: Optional[str] = None
        self.output_rule_group_capacity: int = DEFAULT_CAPACITY
        self.source_rule_groups: List[str] = []
        self.filters: Dict = {
            'logic': 'AND',
            'conditions': [],
        }
        self.missing_metadata_behavior: str = DEFAULT_MISSING_METADATA_BEHAVIOR
        self.deployment_mode: str = DEFAULT_DEPLOYMENT_MODE
        self.action_override: Optional[str] = None
        self.notification_email: Optional[str] = None
        self.notification_topic_arn: Optional[str] = None
        self.lambda_function_arn: Optional[str] = None
        self.last_deployment_stats: Optional[Dict] = None

    def get_filter_config(self) -> FilterConfig:
        """Convert the filters dict to a FilterConfig object.

        Returns:
            FilterConfig instance ready for use with the filter engine.
        """
        config = filter_config_from_dict(self.filters)
        config.missing_metadata_behavior = self.missing_metadata_behavior
        return config

    def set_filter_config(self, filter_config: FilterConfig) -> None:
        """Set the filters dict from a FilterConfig object.

        Args:
            filter_config: FilterConfig to serialize into the MRG config.
        """
        self.filters = filter_config_to_dict(filter_config)
        self.missing_metadata_behavior = filter_config.missing_metadata_behavior

    def is_deployed(self) -> bool:
        """Check if this configuration has been deployed to AWS.

        Returns:
            True if last_deployed_at is set (not None).
        """
        return self.last_deployed_at is not None

    def clear_deployment_metadata(self) -> None:
        """Clear all deployment-related metadata.

        Used when removing a configuration from AWS.
        """
        self.last_deployed_at = None
        self.output_rule_group_arn = None
        self.lambda_function_arn = None
        self.notification_topic_arn = None
        self.last_deployment_stats = None

    def update_deployment_stats(self, stats: Dict) -> None:
        """Update the deployment statistics and timestamp.

        Args:
            stats: Dict with keys like 'total_rules_scanned', 'rules_matching_filter',
                  'rules_excluded_missing_metadata', 'deduplicated_rules'.
        """
        self.last_deployed_at = _now_iso()
        self.last_deployment_stats = stats

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the configuration to a dictionary.

        Returns:
            Dictionary suitable for JSON serialization.
        """
        self.last_modified_at = _now_iso()

        return {
            'version': self.version,
            'created_at': self.created_at,
            'last_modified_at': self.last_modified_at,
            'last_deployed_at': self.last_deployed_at,
            'region': self.region,
            'aws_profile': self.aws_profile,
            'name': self.name,
            'output_rule_group_name': self.output_rule_group_name,
            'output_rule_group_arn': self.output_rule_group_arn,
            'output_rule_group_capacity': self.output_rule_group_capacity,
            'source_rule_groups': self.source_rule_groups,
            'filters': self.filters,
            'missing_metadata_behavior': self.missing_metadata_behavior,
            'deployment_mode': self.deployment_mode,
            'action_override': self.action_override,
            'notification_email': self.notification_email,
            'notification_topic_arn': self.notification_topic_arn,
            'lambda_function_arn': self.lambda_function_arn,
            'last_deployment_stats': self.last_deployment_stats,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MRGConfig':
        """Deserialize a configuration from a dictionary.

        Args:
            data: Dictionary loaded from a .mrg JSON file.

        Returns:
            MRGConfig instance populated with the data.

        Raises:
            MRGFileFormatError: If required fields are missing or invalid.
        """
        config = cls.__new__(cls)

        config.version = data.get('version', MRG_FILE_VERSION)
        config.created_at = data.get('created_at', _now_iso())
        config.last_modified_at = data.get('last_modified_at', _now_iso())
        config.last_deployed_at = data.get('last_deployed_at')
        config.region = data.get('region', 'us-east-1')
        config.aws_profile = data.get('aws_profile')
        config.name = data.get('name', '')
        config.output_rule_group_name = data.get('output_rule_group_name', '')
        config.output_rule_group_arn = data.get('output_rule_group_arn')
        config.output_rule_group_capacity = data.get('output_rule_group_capacity', DEFAULT_CAPACITY)
        config.source_rule_groups = data.get('source_rule_groups', [])
        config.filters = data.get('filters', {'logic': 'AND', 'conditions': []})
        config.missing_metadata_behavior = data.get(
            'missing_metadata_behavior', DEFAULT_MISSING_METADATA_BEHAVIOR
        )
        config.deployment_mode = data.get('deployment_mode', DEFAULT_DEPLOYMENT_MODE)
        config.action_override = data.get('action_override')
        config.notification_email = data.get('notification_email')
        config.notification_topic_arn = data.get('notification_topic_arn')
        config.lambda_function_arn = data.get('lambda_function_arn')
        config.last_deployment_stats = data.get('last_deployment_stats')

        # Validate critical fields
        if config.missing_metadata_behavior not in ('exclude', 'include'):
            config.missing_metadata_behavior = DEFAULT_MISSING_METADATA_BEHAVIOR

        if config.deployment_mode not in ('as_is', 'test_mode'):
            config.deployment_mode = DEFAULT_DEPLOYMENT_MODE

        if not isinstance(config.source_rule_groups, list):
            config.source_rule_groups = []

        if not isinstance(config.filters, dict):
            config.filters = {'logic': 'AND', 'conditions': []}

        return config

    def __repr__(self) -> str:
        return "MRGConfig(name='{}', region='{}', sources={}, deployed={})".format(
            self.name, self.region, len(self.source_rule_groups), self.is_deployed()
        )


def read_mrg_file(filepath: str) -> MRGConfig:
    """Read and parse a .mrg configuration file.

    Args:
        filepath: Path to the .mrg file.

    Returns:
        MRGConfig instance with all configuration data.

    Raises:
        MRGFileError: If the file cannot be read.
        MRGFileFormatError: If the file content is not valid JSON or is malformed.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        raise MRGFileError("Configuration file not found: {}".format(filepath))
    except PermissionError:
        raise MRGFileError("Permission denied reading file: {}".format(filepath))
    except Exception as e:
        raise MRGFileError("Failed to read file '{}': {}".format(filepath, str(e)))

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise MRGFileFormatError(
            "Invalid JSON in file '{}': {}".format(filepath, str(e))
        )

    if not isinstance(data, dict):
        raise MRGFileFormatError(
            "Invalid .mrg file format: expected a JSON object, got {}".format(type(data).__name__)
        )

    try:
        return MRGConfig.from_dict(data)
    except Exception as e:
        raise MRGFileFormatError(
            "Failed to parse .mrg file '{}': {}".format(filepath, str(e))
        )


def write_mrg_file(filepath: str, config: MRGConfig) -> None:
    """Write an MRGConfig to a .mrg file.

    Creates parent directories if they don't exist.
    Writes with pretty-printed JSON for human readability.

    Args:
        filepath: Path to write the .mrg file to.
        config: MRGConfig instance to serialize.

    Raises:
        MRGFileError: If the file cannot be written.
    """
    data = config.to_dict()

    try:
        # Create parent directories if needed
        parent_dir = os.path.dirname(filepath)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write('\n')  # Trailing newline

    except PermissionError:
        raise MRGFileError("Permission denied writing file: {}".format(filepath))
    except Exception as e:
        raise MRGFileError("Failed to write file '{}': {}".format(filepath, str(e)))


def create_new_config(name: str = '',
                      region: str = 'us-east-1',
                      aws_profile: Optional[str] = None) -> MRGConfig:
    """Create a new MRGConfig with default values.

    Convenience function for initializing a new configuration.

    Args:
        name: Configuration name.
        region: AWS region.
        aws_profile: AWS profile name (None for default).

    Returns:
        New MRGConfig instance with defaults.
    """
    config = MRGConfig()
    config.name = name
    config.output_rule_group_name = name
    config.region = region
    config.aws_profile = aws_profile
    return config


def _rewrite_arn_region(arn: str, target_region: str) -> str:
    """Rewrite the region in an AWS ARN to match the target region.

    ARN format: arn:aws:network-firewall:REGION:ACCOUNT:...

    Args:
        arn: The original ARN string.
        target_region: The region to set in the ARN.

    Returns:
        The ARN with the region component replaced.
    """
    parts = arn.split(':')
    if len(parts) >= 4 and parts[0] == 'arn':
        parts[3] = target_region
        return ':'.join(parts)
    return arn


def build_lambda_config(mrg_config: MRGConfig) -> Dict:
    """Build the Lambda environment variable configuration from an MRGConfig.

    Creates the configuration dict format expected by the Lambda function's
    RULE_GROUP_CONFIGS environment variable (Section 6 of spec).

    Source rule group ARNs are rewritten to match the configuration's target
    region, ensuring the Lambda fetches sources from the correct region
    regardless of which region the ARNs were originally selected from.

    Args:
        mrg_config: The MRG configuration to convert.

    Returns:
        Dict matching the Lambda configuration schema.
    """
    # Rewrite source ARN regions to match the deployment region
    target_region = mrg_config.region
    source_arns = [
        _rewrite_arn_region(arn, target_region)
        for arn in mrg_config.source_rule_groups
    ]

    config = {
        'name': mrg_config.name,
        'output_rule_group_arn': mrg_config.output_rule_group_arn or '',
        'output_rule_group_capacity': mrg_config.output_rule_group_capacity,
        'rule_order': 'STRICT_ORDER',
        'source_rule_groups': source_arns,
        'filters': mrg_config.filters,
        'missing_metadata_behavior': mrg_config.missing_metadata_behavior,
        'deployment_mode': mrg_config.deployment_mode,
        'action_override': mrg_config.action_override,
    }

    if mrg_config.notification_topic_arn:
        config['notification_topic_arn'] = mrg_config.notification_topic_arn

    return config


def validate_mrg_config(config: MRGConfig) -> List[str]:
    """Validate an MRG configuration for completeness and correctness.

    Checks that all required fields are populated and valid.
    Does NOT validate against AWS (no API calls).

    Args:
        config: The MRG configuration to validate.

    Returns:
        List of validation error messages. Empty if valid.
    """
    errors = []

    if not config.name:
        errors.append("Configuration name is required.")

    if not config.output_rule_group_name:
        errors.append("Output rule group name is required.")

    if not config.region:
        errors.append("AWS region is required.")

    if not config.source_rule_groups:
        errors.append("At least one source rule group must be selected.")

    if config.output_rule_group_capacity <= 0:
        errors.append("Rule group capacity must be a positive integer.")

    if config.missing_metadata_behavior not in ('exclude', 'include'):
        errors.append(
            "Missing metadata behavior must be 'exclude' or 'include', "
            "got '{}'.".format(config.missing_metadata_behavior)
        )

    if config.deployment_mode not in ('as_is', 'test_mode'):
        errors.append(
            "Deployment mode must be 'as_is' or 'test_mode', "
            "got '{}'.".format(config.deployment_mode)
        )

    # Validate rule group name format
    import re
    if config.output_rule_group_name:
        if len(config.output_rule_group_name) > 128:
            errors.append("Output rule group name must be 128 characters or fewer.")
        if not re.match(r'^[a-zA-Z0-9_-]+$', config.output_rule_group_name):
            errors.append(
                "Output rule group name must contain only alphanumeric characters, "
                "hyphens, and underscores."
            )

    # Validate email format (basic check)
    if config.notification_email:
        if '@' not in config.notification_email:
            errors.append("Notification email appears to be invalid.")

    # Validate filter configuration
    try:
        filter_config = config.get_filter_config()
        from .rule_filter import validate_filter_config
        filter_errors = validate_filter_config(filter_config)
        errors.extend(filter_errors)
    except Exception as e:
        errors.append("Invalid filter configuration: {}".format(str(e)))

    return errors


def _now_iso() -> str:
    """Get the current UTC time as an ISO 8601 string.

    Returns:
        ISO 8601 formatted datetime string.
    """
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
