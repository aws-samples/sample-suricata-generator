"""
Lambda Function Deployer for Managed Rule Group Generator

Manages the Lambda function that processes SNS notifications and
keeps user-managed rule groups in sync with AWS managed rule groups.

Provides functions to:
- Create and update the Lambda function
- Manage environment variables (rule group configurations)
- Package Lambda code as a zip for deployment
- Handle the 4KB environment variable limit with S3 overflow

All AWS calls go through AWSSessionManager.get_client() for profile support.
"""

import io
import json
import logging
import os
import zipfile
from typing import Dict, List, Optional

from src.aws.aws_session_manager import AWSSessionManager

logger = logging.getLogger(__name__)

# Lambda function naming convention
LAMBDA_FUNCTION_NAME_TEMPLATE = 'ManagedRuleGenerator-{region}'

# Lambda configuration
LAMBDA_RUNTIME = 'python3.12'
LAMBDA_HANDLER = 'handler.lambda_handler'
LAMBDA_TIMEOUT = 300  # 5 minutes
LAMBDA_MEMORY_SIZE = 512  # MB

# Environment variable size limit (AWS limit is 4KB total)
ENV_VAR_SIZE_LIMIT = 4096

# Configuration environment variable keys
CONFIG_KEY = 'RULE_GROUP_CONFIGS'
CONFIG_SOURCE_KEY = 'CONFIG_SOURCE'
CONFIG_S3_URI_KEY = 'CONFIG_S3_URI'

# Default paths for Lambda packaging (relative to project root)
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
DEFAULT_MRG_CORE_PATH = os.path.join(_PROJECT_ROOT, 'src', 'mrg', 'core')
DEFAULT_HANDLER_PATH = os.path.join(_PROJECT_ROOT, 'src', 'mrg', 'lambda_handler', 'handler.py')


class LambdaDeployerError(Exception):
    """Base exception for Lambda deployment operations."""
    pass


class LambdaNotFoundError(LambdaDeployerError):
    """Raised when a Lambda function is not found."""
    pass


class EnvironmentVariableLimitError(LambdaDeployerError):
    """Raised when environment variables exceed the 4KB limit."""
    pass


def get_function_name(region: str) -> str:
    """Get the standard Lambda function name for a region.

    Args:
        region: AWS region.

    Returns:
        Lambda function name string.
    """
    return LAMBDA_FUNCTION_NAME_TEMPLATE.format(region=region)


def _package_lambda_zip(mrg_core_path: str, handler_path: str) -> bytes:
    """Package handler + core modules into deployment zip.

    Creates a zip file with the following structure:
        deployment.zip
        ├── handler.py
        └── core/
            ├── __init__.py
            ├── rule_parser.py
            ├── rule_filter.py
            ├── deduplicator.py
            └── test_mode.py

    The handler.py uses 'from core.xxx import ...' which works in the
    Lambda environment where core/ is a sibling directory to handler.py.

    Args:
        mrg_core_path: Absolute path to the src/mrg/core/ directory.
        handler_path: Absolute path to the src/mrg/lambda_handler/handler.py file.

    Returns:
        Bytes of the zip file content.

    Raises:
        FileNotFoundError: If handler_path or required core modules don't exist.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(handler_path, 'handler.py')
        # Write a minimal __init__.py that only imports the bundled modules.
        # We cannot use the real src/mrg/core/__init__.py because it imports
        # mrg_file.py which is not needed by the Lambda and is not bundled.
        zf.writestr('core/__init__.py',
                    '# Core engine package (Lambda deployment subset)\n'
                    'from .rule_parser import ParsedRule, parse_rules_string\n'
                    'from .rule_filter import FilterConfig, apply_filters, filter_config_from_dict\n'
                    'from .deduplicator import deduplicate_rules\n'
                    'from .test_mode import apply_test_mode_bulk\n')
        for module in ('rule_parser.py', 'rule_filter.py', 'deduplicator.py', 'test_mode.py'):
            zf.write(os.path.join(mrg_core_path, module), f'core/{module}')
    return buffer.getvalue()


def create_lambda_package(handler_code: Optional[str] = None,
                          mrg_core_path: Optional[str] = None,
                          handler_path: Optional[str] = None) -> bytes:
    """Create a zip package for the Lambda function.

    Packages the handler code and core modules into a zip file suitable
    for Lambda deployment. The core modules (rule_parser, rule_filter,
    deduplicator, test_mode) are placed in a 'core/' directory inside
    the zip so the handler can import them.

    If handler_code is provided as a string, it is written directly as
    handler.py. Otherwise, the handler is read from handler_path.

    Args:
        handler_code: Optional Python source code for handler.py. If provided,
                     this is used instead of reading from handler_path.
        mrg_core_path: Path to the MRG core modules directory.
                      Defaults to src/mrg/core/.
        handler_path: Path to the Lambda handler file.
                     Defaults to src/mrg/lambda_handler/handler.py.

    Returns:
        Bytes of the zip file content.
    """
    if mrg_core_path is None:
        mrg_core_path = DEFAULT_MRG_CORE_PATH
    if handler_path is None:
        handler_path = DEFAULT_HANDLER_PATH

    if handler_code is not None:
        # Write handler_code directly into zip along with core modules
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('handler.py', handler_code)
            # Write a minimal __init__.py for the Lambda subset (not the full one
            # which imports mrg_file.py that isn't bundled)
            zf.writestr('core/__init__.py',
                        '# Core engine package (Lambda deployment subset)\n'
                        'from .rule_parser import ParsedRule, parse_rules_string\n'
                        'from .rule_filter import FilterConfig, apply_filters, filter_config_from_dict\n'
                        'from .deduplicator import deduplicate_rules\n'
                        'from .test_mode import apply_test_mode_bulk\n')
            for module in ('rule_parser.py', 'rule_filter.py', 'deduplicator.py', 'test_mode.py'):
                module_path = os.path.join(mrg_core_path, module)
                if os.path.isfile(module_path):
                    zf.write(module_path, f'core/{module}')
                else:
                    logger.warning("Core module not found: %s", module_path)
        return buffer.getvalue()
    else:
        # Use _package_lambda_zip with the file paths
        return _package_lambda_zip(mrg_core_path, handler_path)


def wait_for_function_active(session_manager: AWSSessionManager,
                             region: str,
                             max_wait_seconds: int = 60,
                             poll_interval: int = 2) -> bool:
    """Wait for the Lambda function to reach the Active state.

    After creating or updating a Lambda function, AWS may keep it in
    'Pending' state briefly. This function polls until the state is
    'Active' or the timeout is reached.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        max_wait_seconds: Maximum time to wait in seconds. Default 60.
        poll_interval: Seconds between polls. Default 2.

    Returns:
        True if the function reached Active state, False if timed out.
    """
    import time
    client = session_manager.get_client('lambda', region_name=region)
    function_name = get_function_name(region)

    elapsed = 0
    while elapsed < max_wait_seconds:
        try:
            response = client.get_function_configuration(FunctionName=function_name)
            state = response.get('State', '')
            last_update = response.get('LastUpdateStatus', '')

            # Function is ready if State is Active and no pending updates
            if state == 'Active' and last_update in ('', 'Successful'):
                logger.info("Lambda function '%s' is Active (waited %ds)", function_name, elapsed)
                return True

            # If state is Failed, no point waiting
            if state == 'Failed':
                logger.warning("Lambda function '%s' is in Failed state", function_name)
                return False

            logger.debug("Lambda '%s' state=%s, lastUpdate=%s, waiting...",
                        function_name, state, last_update)
        except Exception as e:
            logger.debug("Error checking Lambda state: %s", str(e))

        time.sleep(poll_interval)
        elapsed += poll_interval

    logger.warning("Timed out waiting for Lambda '%s' to become Active after %ds",
                   function_name, max_wait_seconds)
    return False


def create_lambda_function(session_manager: AWSSessionManager,
                           region: str,
                           role_arn: str,
                           configs: Optional[List[Dict]] = None,
                           handler_code: Optional[str] = None,
                           description: str = '') -> Dict:
    """Create a new Lambda function for rule group management.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        role_arn: ARN of the IAM role for the Lambda function.
        configs: Optional list of rule group configuration dicts to store
                in environment variables.
        handler_code: Optional Python source code for the handler. If None,
                     packages the real handler from src/mrg/lambda_handler/handler.py.
        description: Optional function description.

    Returns:
        Dict with keys:
        - 'FunctionName': The function name
        - 'FunctionArn': The function ARN
        - 'Created': True (always, since this creates a new function)

    Raises:
        LambdaDeployerError: If function creation fails.
    """
    client = session_manager.get_client('lambda', region_name=region)
    function_name = get_function_name(region)

    if not description:
        description = 'Managed Rule Group Generator - processes SNS events and updates rule groups'

    # Build environment variables
    env_vars = _build_environment_variables(configs or [])

    # Create the deployment package
    zip_content = create_lambda_package(handler_code)

    try:
        response = client.create_function(
            FunctionName=function_name,
            Runtime=LAMBDA_RUNTIME,
            Role=role_arn,
            Handler=LAMBDA_HANDLER,
            Code={'ZipFile': zip_content},
            Description=description,
            Timeout=LAMBDA_TIMEOUT,
            MemorySize=LAMBDA_MEMORY_SIZE,
            Environment={'Variables': env_vars},
            Tags={
                'ManagedRuleGenerator': 'lambda-function',
                'Region': region,
            },
        )

        result = {
            'FunctionName': response.get('FunctionName', function_name),
            'FunctionArn': response.get('FunctionArn', ''),
            'Created': True,
        }

        logger.info("Created Lambda function: %s (ARN: %s)",
                     result['FunctionName'], result['FunctionArn'])
        return result

    except Exception as e:
        error_msg = "Failed to create Lambda function '{}' in {}: {}".format(
            function_name, region, str(e)
        )
        logger.error(error_msg)
        raise LambdaDeployerError(error_msg) from e


def update_lambda_function_code(session_manager: AWSSessionManager,
                                region: str,
                                handler_code: Optional[str] = None) -> Dict:
    """Update the Lambda function's code.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        handler_code: Python source code for the handler. If None, packages
                     the real handler from src/mrg/lambda_handler/handler.py.

    Returns:
        Dict with keys:
        - 'FunctionName': The function name
        - 'FunctionArn': The function ARN

    Raises:
        LambdaNotFoundError: If the function doesn't exist.
        LambdaDeployerError: If the update fails.
    """
    client = session_manager.get_client('lambda', region_name=region)
    function_name = get_function_name(region)

    zip_content = create_lambda_package(handler_code)

    try:
        response = client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_content,
        )

        result = {
            'FunctionName': response.get('FunctionName', function_name),
            'FunctionArn': response.get('FunctionArn', ''),
        }

        logger.info("Updated Lambda function code: %s", result['FunctionName'])
        return result

    except Exception as e:
        error_str = str(e)
        if 'ResourceNotFoundException' in error_str or 'Function not found' in error_str:
            raise LambdaNotFoundError(
                "Lambda function not found: {}".format(function_name)
            ) from e
        error_msg = "Failed to update Lambda function code '{}': {}".format(
            function_name, error_str
        )
        logger.error(error_msg)
        raise LambdaDeployerError(error_msg) from e


def update_lambda_environment(session_manager: AWSSessionManager,
                              region: str,
                              configs: List[Dict]) -> Dict:
    """Update the Lambda function's environment variables with new configs.

    Reads the existing environment variables, updates the RULE_GROUP_CONFIGS,
    and writes them back.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        configs: List of rule group configuration dicts.

    Returns:
        Dict with 'FunctionName' and 'ConfigCount'.

    Raises:
        LambdaNotFoundError: If the function doesn't exist.
        LambdaDeployerError: If the update fails.
    """
    client = session_manager.get_client('lambda', region_name=region)
    function_name = get_function_name(region)

    try:
        # Get existing configuration
        response = client.get_function_configuration(
            FunctionName=function_name
        )
        existing_env = response.get('Environment', {}).get('Variables', {})

        # Build new environment variables
        env_vars = _build_environment_variables(configs)

        # Preserve any non-config environment variables
        for key, value in existing_env.items():
            if key not in (CONFIG_KEY, CONFIG_SOURCE_KEY, CONFIG_S3_URI_KEY):
                env_vars[key] = value

        # Update the function configuration
        client.update_function_configuration(
            FunctionName=function_name,
            Environment={'Variables': env_vars},
        )

        result = {
            'FunctionName': function_name,
            'ConfigCount': len(configs),
        }

        logger.info("Updated Lambda environment: %s (%d configs)",
                     function_name, len(configs))
        return result

    except Exception as e:
        error_str = str(e)
        if 'ResourceNotFoundException' in error_str or 'Function not found' in error_str:
            raise LambdaNotFoundError(
                "Lambda function not found: {}".format(function_name)
            ) from e
        error_msg = "Failed to update Lambda environment '{}': {}".format(
            function_name, error_str
        )
        logger.error(error_msg)
        raise LambdaDeployerError(error_msg) from e


def get_lambda_configs(session_manager: AWSSessionManager,
                       region: str) -> List[Dict]:
    """Get the current rule group configurations from the Lambda function.

    Reads the RULE_GROUP_CONFIGS environment variable and parses it.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.

    Returns:
        List of rule group configuration dicts. Empty list if no configs
        or function doesn't exist.

    Raises:
        LambdaNotFoundError: If the function doesn't exist.
        LambdaDeployerError: If reading fails.
    """
    client = session_manager.get_client('lambda', region_name=region)
    function_name = get_function_name(region)

    try:
        response = client.get_function_configuration(
            FunctionName=function_name
        )
        env_vars = response.get('Environment', {}).get('Variables', {})

        config_json = env_vars.get(CONFIG_KEY, '{"configs": []}')
        config_data = json.loads(config_json)
        return config_data.get('configs', [])

    except Exception as e:
        error_str = str(e)
        if 'ResourceNotFoundException' in error_str or 'Function not found' in error_str:
            raise LambdaNotFoundError(
                "Lambda function not found: {}".format(function_name)
            ) from e
        error_msg = "Failed to get Lambda configs from '{}': {}".format(
            function_name, error_str
        )
        logger.error(error_msg)
        raise LambdaDeployerError(error_msg) from e


def add_or_update_config(session_manager: AWSSessionManager,
                         region: str,
                         config: Dict) -> Dict:
    """Add or update a single rule group configuration in the Lambda.

    If a configuration with the same 'name' already exists, it is replaced.
    Otherwise, the new configuration is appended.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        config: Rule group configuration dict. Must have a 'name' key.

    Returns:
        Dict with 'FunctionName', 'ConfigName', 'Action' ('added' or 'updated').

    Raises:
        ValueError: If config doesn't have a 'name' key.
        LambdaNotFoundError: If the function doesn't exist.
        LambdaDeployerError: If the update fails.
    """
    if 'name' not in config:
        raise ValueError("Configuration must have a 'name' key")

    config_name = config['name']

    # Get existing configs
    try:
        existing_configs = get_lambda_configs(session_manager, region)
    except LambdaNotFoundError:
        raise
    except Exception:
        existing_configs = []

    # Find and replace existing config with same name, or append
    action = 'added'
    new_configs = []
    found = False
    for existing in existing_configs:
        if existing.get('name') == config_name:
            new_configs.append(config)
            found = True
            action = 'updated'
        else:
            new_configs.append(existing)

    if not found:
        new_configs.append(config)

    # Update Lambda environment
    update_lambda_environment(session_manager, region, new_configs)

    return {
        'FunctionName': get_function_name(region),
        'ConfigName': config_name,
        'Action': action,
    }


def remove_config(session_manager: AWSSessionManager,
                  region: str,
                  config_name: str) -> Dict:
    """Remove a rule group configuration from the Lambda.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        config_name: Name of the configuration to remove.

    Returns:
        Dict with 'FunctionName', 'ConfigName', 'RemainingConfigs'.

    Raises:
        LambdaNotFoundError: If the function doesn't exist.
        LambdaDeployerError: If the update fails.
    """
    existing_configs = get_lambda_configs(session_manager, region)

    new_configs = [c for c in existing_configs if c.get('name') != config_name]

    if len(new_configs) == len(existing_configs):
        logger.warning("Configuration '%s' not found in Lambda", config_name)

    update_lambda_environment(session_manager, region, new_configs)

    return {
        'FunctionName': get_function_name(region),
        'ConfigName': config_name,
        'RemainingConfigs': len(new_configs),
    }


def get_lambda_function(session_manager: AWSSessionManager,
                        region: str) -> Optional[Dict]:
    """Get the Lambda function details, if it exists.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.

    Returns:
        Dict with 'FunctionName', 'FunctionArn', 'Runtime', 'State'
        if the function exists, None otherwise.
    """
    client = session_manager.get_client('lambda', region_name=region)
    function_name = get_function_name(region)

    try:
        response = client.get_function(FunctionName=function_name)
        config = response.get('Configuration', {})
        return {
            'FunctionName': config.get('FunctionName', function_name),
            'FunctionArn': config.get('FunctionArn', ''),
            'Runtime': config.get('Runtime', ''),
            'State': config.get('State', ''),
        }
    except Exception as e:
        if 'ResourceNotFoundException' in str(e) or 'Function not found' in str(e):
            return None
        logger.warning("Failed to get Lambda function '%s': %s", function_name, str(e))
        return None


def delete_lambda_function(session_manager: AWSSessionManager,
                           region: str) -> bool:
    """Delete the Lambda function.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.

    Returns:
        True if deleted successfully, False if the function didn't exist.

    Raises:
        LambdaDeployerError: If deletion fails.
    """
    client = session_manager.get_client('lambda', region_name=region)
    function_name = get_function_name(region)

    try:
        client.delete_function(FunctionName=function_name)
        logger.info("Deleted Lambda function: %s", function_name)
        return True
    except Exception as e:
        if 'ResourceNotFoundException' in str(e) or 'Function not found' in str(e):
            logger.info("Lambda function '%s' does not exist, nothing to delete", function_name)
            return False
        error_msg = "Failed to delete Lambda function '{}': {}".format(function_name, str(e))
        logger.error(error_msg)
        raise LambdaDeployerError(error_msg) from e


def invoke_lambda_function(session_manager: AWSSessionManager,
                           region: str,
                           payload: Optional[Dict] = None) -> Dict:
    """Invoke the Lambda function synchronously (for Force Sync).

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        payload: Optional event payload dict.

    Returns:
        Dict with 'StatusCode' and 'Response' (parsed response payload).

    Raises:
        LambdaNotFoundError: If the function doesn't exist.
        LambdaDeployerError: If invocation fails.
    """
    client = session_manager.get_client('lambda', region_name=region)
    function_name = get_function_name(region)

    try:
        invoke_kwargs = {
            'FunctionName': function_name,
            'InvocationType': 'RequestResponse',
        }
        if payload:
            invoke_kwargs['Payload'] = json.dumps(payload)

        response = client.invoke(**invoke_kwargs)

        # Read the response payload
        response_payload = {}
        if 'Payload' in response:
            payload_bytes = response['Payload'].read()
            if payload_bytes:
                try:
                    response_payload = json.loads(payload_bytes)
                except json.JSONDecodeError:
                    response_payload = {'raw': payload_bytes.decode('utf-8', errors='replace')}

        return {
            'StatusCode': response.get('StatusCode', 0),
            'Response': response_payload,
        }

    except Exception as e:
        error_str = str(e)
        if 'ResourceNotFoundException' in error_str or 'Function not found' in error_str:
            raise LambdaNotFoundError(
                "Lambda function not found: {}".format(function_name)
            ) from e
        error_msg = "Failed to invoke Lambda function '{}': {}".format(
            function_name, error_str
        )
        logger.error(error_msg)
        raise LambdaDeployerError(error_msg) from e


def _build_environment_variables(configs: List[Dict]) -> Dict[str, str]:
    """Build the environment variables dict for the Lambda function.

    Stores configurations in the RULE_GROUP_CONFIGS environment variable.
    If the serialized configs exceed the 4KB limit, logs a warning.
    (S3-backed config overflow will be implemented in a future phase.)

    Args:
        configs: List of rule group configuration dicts.

    Returns:
        Dict of environment variable key-value pairs.
    """
    config_json = json.dumps({'configs': configs}, separators=(',', ':'))

    env_vars = {
        CONFIG_KEY: config_json,
        CONFIG_SOURCE_KEY: 'env',
    }

    # Check total size
    total_size = sum(len(k) + len(v) for k, v in env_vars.items())
    if total_size > ENV_VAR_SIZE_LIMIT:
        logger.warning(
            "Environment variables total %d bytes, exceeding the %d byte limit. "
            "Consider using S3-backed configuration for large deployments.",
            total_size, ENV_VAR_SIZE_LIMIT
        )

    return env_vars


def estimate_config_size(configs: List[Dict]) -> int:
    """Estimate the total environment variable size for a set of configs.

    Useful for checking if configs will fit within the 4KB limit
    before attempting deployment.

    Args:
        configs: List of rule group configuration dicts.

    Returns:
        Estimated total size in bytes.
    """
    config_json = json.dumps({'configs': configs}, separators=(',', ':'))
    env_vars = {
        CONFIG_KEY: config_json,
        CONFIG_SOURCE_KEY: 'env',
    }
    return sum(len(k) + len(v) for k, v in env_vars.items())


def lambda_function_exists(session_manager: AWSSessionManager,
                           region: str) -> bool:
    """Check if the Lambda function exists in the given region.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.

    Returns:
        True if the function exists, False otherwise.
    """
    return get_lambda_function(session_manager, region) is not None
