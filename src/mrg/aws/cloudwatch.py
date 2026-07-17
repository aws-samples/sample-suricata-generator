"""
CloudWatch Dashboard Management for Managed Rule Group Generator

Manages:
- Creation and update of CloudWatch Dashboards (PutDashboard)
- Deletion of CloudWatch Dashboards (DeleteDashboards)
- Construction of CloudWatch Console URLs
- Generation of dashboard body JSON with Logs Insights widgets

All AWS calls go through AWSSessionManager.get_client() for profile support.
"""

import json
import logging
from typing import Dict, List, Optional

from src.aws.aws_session_manager import AWSSessionManager

logger = logging.getLogger(__name__)


class CloudWatchDashboardError(Exception):
    """Base exception for CloudWatch dashboard operations."""
    pass


def put_dashboard(
    session_manager: AWSSessionManager,
    region: str,
    dashboard_name: str,
    dashboard_body: str,
    tags: Optional[List[Dict]] = None,
) -> Dict:
    """Create or update a CloudWatch Dashboard.

    Calls the cloudwatch:PutDashboard API to create or update a dashboard
    with the given name and body. Optionally tags the dashboard resource.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        dashboard_name: Name of the dashboard to create/update.
        dashboard_body: JSON string of the dashboard body.
        tags: Optional list of tag dicts with 'Key' and 'Value' keys.

    Returns:
        Dict with 'DashboardArn' key.

    Raises:
        CloudWatchDashboardError: If the PutDashboard API call fails.
    """
    client = session_manager.get_client('cloudwatch', region_name=region)

    try:
        response = client.put_dashboard(
            DashboardName=dashboard_name,
            DashboardBody=dashboard_body,
        )

        # Check for validation messages (PutDashboard returns these on partial issues)
        validation_messages = response.get('DashboardValidationMessages', [])
        if validation_messages:
            messages = '; '.join(
                msg.get('Message', 'Unknown validation error')
                for msg in validation_messages
            )
            logger.warning(
                "Dashboard '%s' created with validation warnings: %s",
                dashboard_name, messages
            )

        # Construct the dashboard ARN for tagging and return value
        # ARN format: arn:aws:cloudwatch::<account-id>:dashboard/<name>
        # We retrieve it via the ListDashboards or construct it; PutDashboard
        # doesn't return an ARN directly, so we use tag_resource if tags provided.
        dashboard_arn = None

        if tags:
            try:
                # Get the dashboard ARN by listing dashboards with prefix filter
                list_response = client.list_dashboards(
                    DashboardNamePrefix=dashboard_name
                )
                for entry in list_response.get('DashboardEntries', []):
                    if entry.get('DashboardName') == dashboard_name:
                        dashboard_arn = entry.get('DashboardArn')
                        break

                if dashboard_arn:
                    client.tag_resource(
                        ResourceARN=dashboard_arn,
                        Tags=tags,
                    )
                    logger.info(
                        "Tagged dashboard '%s' with %d tag(s).",
                        dashboard_name, len(tags)
                    )
                else:
                    logger.warning(
                        "Could not retrieve ARN for dashboard '%s' to apply tags.",
                        dashboard_name
                    )
            except Exception as tag_err:
                logger.warning(
                    "Dashboard '%s' created but tagging failed: %s",
                    dashboard_name, str(tag_err)
                )

        logger.info(
            "Successfully created/updated dashboard '%s' in region '%s'.",
            dashboard_name, region
        )

        return {
            'DashboardArn': dashboard_arn,
        }

    except Exception as e:
        error_msg = "Failed to create/update dashboard '{}' in {}: {}".format(
            dashboard_name, region, str(e)
        )
        logger.error(error_msg)
        raise CloudWatchDashboardError(error_msg) from e


def delete_dashboards(
    session_manager: AWSSessionManager,
    region: str,
    dashboard_names: List[str],
) -> bool:
    """Delete one or more CloudWatch Dashboards.

    Calls the cloudwatch:DeleteDashboards API to remove dashboards by name.

    Args:
        session_manager: AWSSessionManager instance for client creation.
        region: AWS region.
        dashboard_names: List of dashboard names to delete.

    Returns:
        True on success.

    Raises:
        CloudWatchDashboardError: If the DeleteDashboards API call fails.
    """
    client = session_manager.get_client('cloudwatch', region_name=region)

    try:
        client.delete_dashboards(
            DashboardNames=dashboard_names,
        )

        logger.info(
            "Successfully deleted dashboard(s) %s in region '%s'.",
            dashboard_names, region
        )

        return True

    except Exception as e:
        error_msg = "Failed to delete dashboard(s) {} in {}: {}".format(
            dashboard_names, region, str(e)
        )
        logger.error(error_msg)
        raise CloudWatchDashboardError(error_msg) from e


def get_dashboard_url(region: str, dashboard_name: str) -> str:
    """Construct the CloudWatch Console URL for a dashboard.

    Args:
        region: AWS region.
        dashboard_name: Name of the dashboard.

    Returns:
        The CloudWatch Console URL string.
    """
    return (
        f"https://{region}.console.aws.amazon.com/cloudwatch/home"
        f"?region={region}#dashboards/dashboard/{dashboard_name}"
    )


def generate_dashboard_body(
    region: str,
    log_group_name: str,
    config_names: List[str],
    source_arns: List[str],
    creation_date: str,
    config_sources: Optional[Dict[str, List[str]]] = None,
) -> str:
    """Generate the complete dashboard JSON body string.

    Produces a CloudWatch Dashboard body conforming to the Dashboard Body
    Structure API, containing all required analytics widgets with embedded
    Logs Insights queries filtered by the provided config names.

    Args:
        region: AWS region for the dashboard.
        log_group_name: CloudWatch log group path.
        config_names: List of MRG configuration names to include.
        source_arns: List of source rule group ARNs (retained for API compatibility).
        creation_date: ISO 8601 UTC timestamp of dashboard creation.
        config_sources: Optional mapping of config name to its source ARN list.
            Used to generate the monitored sources reference widget.

    Returns:
        JSON string suitable for PutDashboard API.
    """
    # Build the config_names filter clause for multi-config queries
    config_names_filter = _build_config_names_in_clause(config_names)

    widgets = []

    # 1. Header Text Widget (x=0, y=0, w=24, h=3)
    widgets.append(_build_header_text_widget(creation_date))

    # 2. Monitored Sources + Update Summary + Latest Changes per config
    y_offset = 3
    for config_name in config_names:
        # Monitored sources for this config
        sources = (config_sources or {}).get(config_name, [])
        if sources:
            friendly_names = [arn.rsplit('/', 1)[-1] if '/' in arn else arn for arn in sources]
            md = "**Monitored Sources:** " + ", ".join(friendly_names)
            widgets.append({
                "type": "text",
                "x": 0,
                "y": y_offset,
                "width": 24,
                "height": 2,
                "properties": {"markdown": f"### {config_name}\n\n{md}"},
            })
            y_offset += 2

        widgets.append(_build_pass_through_rate_widget(
            region, log_group_name, config_name, y_offset
        ))
        widgets.append(_build_latest_changes_widget(
            region, log_group_name, config_name, y_offset
        ))
        y_offset += 3

    # 3. Source Frequency Table
    widgets.append(_build_source_frequency_widget(
        region, log_group_name, config_names_filter, y_offset
    ))
    y_offset += 6

    # 4. Recent Events Table
    widgets.append(_build_recent_events_widget(
        region, log_group_name, config_names_filter, y_offset
    ))
    y_offset += 6

    # 6. Change Breakdown Stacked Area per config (x=0, w=24, h=6 each)
    for config_name in config_names:
        widgets.append(_build_change_breakdown_widget(
            region, log_group_name, config_name, y_offset
        ))
        y_offset += 6

    # 7. Rule Changes Table (x=0, w=24, h=6)
    widgets.append(_build_rule_changes_table_widget(
        region, log_group_name, config_names_filter, y_offset
    ))

    dashboard_body = {"widgets": widgets}
    return json.dumps(dashboard_body)


# --- Private helper functions ---


def _build_config_names_in_clause(config_names: List[str]) -> str:
    """Build the config_name IN clause for Logs Insights queries."""
    escaped = [name.replace("'", "\\'") for name in config_names]
    items = ", ".join(f"'{name}'" for name in escaped)
    return f"[{items}]"


def _build_header_text_widget(creation_date: str) -> Dict:
    """Build the header text widget (Req 3.1)."""
    markdown = (
        "## MRG Update History Analytics\n\n"
        f"**Dashboard Creation Date:** {creation_date}"
    )
    return {
        "type": "text",
        "x": 0,
        "y": 0,
        "width": 24,
        "height": 3,
        "properties": {
            "markdown": markdown,
        },
    }


def _build_source_frequency_widget(
    region: str,
    log_group_name: str,
    config_names_filter: str,
    y: int,
) -> Dict:
    """Build the Source Rule Group Update Frequency table widget (Req 3.3)."""
    query = (
        f"SOURCE '{log_group_name}'\n"
        f"| filter event_type = 'mrg_update_event'\n"
        f"| filter config_name in {config_names_filter}\n"
        f"| stats count(*) as update_count by trigger_source\n"
        f"| sort update_count desc\n"
        f"| display trigger_source, update_count"
    )
    return {
        "type": "log",
        "x": 0,
        "y": y,
        "width": 24,
        "height": 6,
        "properties": {
            "region": region,
            "title": "Source Rule Group Update Frequency",
            "query": query,
            "view": "table",
        },
    }


def _build_pass_through_rate_widget(
    region: str,
    log_group_name: str,
    config_name: str,
    y: int,
) -> Dict:
    """Build the Pass-Through Rate widget for a single config (Req 3.4)."""
    escaped_name = config_name.replace("'", "\\'")
    query = (
        f"SOURCE '{log_group_name}'\n"
        f"| filter event_type = 'mrg_update_event'\n"
        f"| filter config_name = '{escaped_name}'\n"
        f"| stats sum(case(status = 'updated', 1, 0)) as total_updates, "
        f"count(*) as total_source_rule_group_updates\n"
        f"| display total_updates, total_source_rule_group_updates"
    )
    return {
        "type": "log",
        "x": 0,
        "y": y,
        "width": 12,
        "height": 3,
        "properties": {
            "region": region,
            "title": f"Update Summary: {config_name}",
            "query": query,
            "view": "table",
        },
    }


def _build_latest_changes_widget(
    region: str,
    log_group_name: str,
    config_name: str,
    y: int,
) -> Dict:
    """Build the Latest Changes widget for a single config (Req 3.5)."""
    escaped_name = config_name.replace("'", "\\'")
    query = (
        f"SOURCE '{log_group_name}'\n"
        f"| filter event_type = 'mrg_update_event'\n"
        f"| filter config_name = '{escaped_name}'\n"
        f"| filter status = 'updated'\n"
        f"| sort @timestamp desc\n"
        f"| limit 1\n"
        f"| fields timestamp, rules_added, rules_removed, rules_modified"
    )
    return {
        "type": "log",
        "x": 12,
        "y": y,
        "width": 12,
        "height": 3,
        "properties": {
            "region": region,
            "title": f"Latest Changes: {config_name}",
            "query": query,
            "view": "table",
        },
    }


def _build_recent_events_widget(
    region: str,
    log_group_name: str,
    config_names_filter: str,
    y: int,
) -> Dict:
    """Build the Recent Update Events Table widget (Req 3.6)."""
    query = (
        f"SOURCE '{log_group_name}'\n"
        f"| filter event_type = 'mrg_update_event'\n"
        f"| filter config_name in {config_names_filter}\n"
        f"| sort @timestamp desc\n"
        f"| limit 20\n"
        f"| fields timestamp, config_name, status, trigger_source, "
        f"rules_added, rules_removed, rules_modified"
    )
    return {
        "type": "log",
        "x": 0,
        "y": y,
        "width": 24,
        "height": 6,
        "properties": {
            "region": region,
            "title": "Recent Events (Last 20)",
            "query": query,
            "view": "table",
        },
    }


def _build_change_breakdown_widget(
    region: str,
    log_group_name: str,
    config_name: str,
    y: int,
) -> Dict:
    """Build the Change Breakdown Stacked Area widget for a single config (Req 3.8)."""
    escaped_name = config_name.replace("'", "\\'")
    query = (
        f"SOURCE '{log_group_name}'\n"
        f"| filter event_type = 'mrg_update_event'\n"
        f"| filter status = 'updated'\n"
        f"| filter config_name = '{escaped_name}'\n"
        f"| stats sum(rules_added) as added, sum(rules_removed) as removed, "
        f"sum(rules_modified) as modified by bin(1d)"
    )
    return {
        "type": "log",
        "x": 0,
        "y": y,
        "width": 24,
        "height": 6,
        "properties": {
            "region": region,
            "title": f"Rule Changes Breakdown: {config_name}",
            "query": query,
            "view": "timeSeries",
            "stacked": True,
        },
    }


def _build_rule_changes_table_widget(
    region: str,
    log_group_name: str,
    config_names_filter: str,
    y: int,
) -> Dict:
    """Build the Rule Changes Table widget (Req 3.12)."""
    query = (
        f"SOURCE '{log_group_name}'\n"
        f"| filter event_type = 'mrg_rule_change'\n"
        f"| filter ispresent(sid)\n"
        f"| filter config_name in {config_names_filter}\n"
        f"| sort @timestamp desc\n"
        f"| limit 1000\n"
        f"| fields sid, description, change_type, timestamp, config_name"
    )
    return {
        "type": "log",
        "x": 0,
        "y": y,
        "width": 24,
        "height": 6,
        "properties": {
            "region": region,
            "title": "Rule Change Log (SID Detail)",
            "query": query,
            "view": "table",
        },
    }
