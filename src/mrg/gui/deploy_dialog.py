"""
Deploy Dialog for Managed Rule Group Generator.
Progress dialogs for Deploy, Remove Configuration, and Full Teardown.
"""
import logging
import platform
import threading
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional
from src.aws.aws_session_manager import AWSSessionManager

logger = logging.getLogger(__name__)


class DeployProgressDialog:
    """Modal progress dialog for multi-step AWS operations."""

    def __init__(self, parent, title="Deploying to AWS"):
        self._parent = parent
        self._dialog = tk.Toplevel(parent)
        self._dialog.title(title)
        self._dialog.geometry("500x320")
        self._dialog.resizable(True, True)
        if platform.system() != 'Darwin':
            self._dialog.transient(parent)
        self._dialog.grab_set()
        self._dialog.protocol("WM_DELETE_WINDOW", self._on_close_attempt)
        self._is_running = False
        self._is_complete = False
        self._error = None
        self._result = None
        self._setup_ui()

    def _setup_ui(self):
        mf = ttk.Frame(self._dialog, padding=16)
        mf.pack(fill=tk.BOTH, expand=True)
        self._title_label = ttk.Label(mf, text="Preparing...", font=('TkDefaultFont', 11, 'bold'))
        self._title_label.pack(anchor=tk.W, pady=(0, 12))
        self._progress_var = tk.DoubleVar(value=0)
        self._progress_bar = ttk.Progressbar(mf, variable=self._progress_var, maximum=100, mode='determinate', length=460)
        self._progress_bar.pack(fill=tk.X, pady=(0, 8))
        self._step_label = ttk.Label(mf, text="", font=('TkDefaultFont', 9))
        self._step_label.pack(anchor=tk.W, pady=(0, 12))
        lf = ttk.Frame(mf)
        lf.pack(fill=tk.BOTH, expand=True, pady=(0, 12))
        self._log_text = tk.Text(lf, height=8, width=60, state=tk.DISABLED, font=('TkDefaultFont', 9), wrap=tk.WORD)
        sb = ttk.Scrollbar(lf, orient=tk.VERTICAL, command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=sb.set)
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._log_text.tag_configure('success', foreground='#2E7D32')
        self._log_text.tag_configure('error', foreground='#D32F2F')
        self._log_text.tag_configure('info', foreground='#1976D2')
        self._close_btn = ttk.Button(mf, text="Close", command=self._close, state=tk.DISABLED)
        self._close_btn.pack(anchor=tk.E)

    def _on_close_attempt(self):
        if not self._is_running:
            self._close()

    def _close(self):
        if self._dialog.winfo_exists():
            self._dialog.grab_release()
            self._dialog.destroy()

    def update_progress(self, percent, step_text):
        self._parent.after(0, lambda: self._do_update(percent, step_text))

    def _do_update(self, percent, step_text):
        if self._dialog.winfo_exists():
            self._progress_var.set(percent)
            self._step_label.config(text=step_text)

    def log_message(self, message, tag=''):
        self._parent.after(0, lambda: self._do_log(message, tag))

    def _do_log(self, message, tag):
        if not self._dialog.winfo_exists():
            return
        self._log_text.config(state=tk.NORMAL)
        if tag:
            self._log_text.insert(tk.END, message + '\n', tag)
        else:
            self._log_text.insert(tk.END, message + '\n')
        self._log_text.see(tk.END)
        self._log_text.config(state=tk.DISABLED)

    def set_complete(self, success, message=''):
        self._parent.after(0, lambda: self._do_complete(success, message))

    def _do_complete(self, success, message):
        if not self._dialog.winfo_exists():
            return
        self._is_running = False
        self._is_complete = True
        self._close_btn.config(state=tk.NORMAL)
        self._progress_var.set(100)
        if success:
            self._title_label.config(text="Complete")
            self._step_label.config(text=message or "All steps completed successfully.")
            self._do_log(message or "Successful!", 'success')
        else:
            self._title_label.config(text="Failed")
            self._step_label.config(text=message or "Operation failed.")
            self._do_log(message or "Failed.", 'error')

    def run_in_thread(self, target):
        self._is_running = True
        def wrapper():
            try:
                target(self)
            except Exception as e:
                self._error = str(e)
                self.set_complete(False, "Error: {}".format(str(e)))
        threading.Thread(target=wrapper, daemon=True).start()

    def wait(self):
        if self._dialog.winfo_exists():
            self._parent.wait_window(self._dialog)

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, value):
        self._result = value

    @property
    def error(self):
        return self._error

    @property
    def is_complete(self):
        return self._is_complete


def _get_dashboard_config_names(
    session_manager: AWSSessionManager,
    region: str,
    current_config_name: str,
    all_configs_with_dashboard: List[str],
) -> List[str]:
    """Gather config names that should appear in the shared dashboard.

    Combines the known configs that have create_dashboard=True with any
    additional configs that are deployed in the region (from Lambda env)
    that already reference a dashboard. The current config name is always
    included in the returned list if it has create_dashboard=True.

    Args:
        session_manager: AWS session manager.
        region: AWS region.
        current_config_name: Name of the config being deployed/modified.
        all_configs_with_dashboard: List of config names known to have
            create_dashboard=True (typically just the current one unless
            we can discover others from .mrg files on disk).

    Returns:
        Deduplicated list of config names for dashboard filter clauses.
    """
    config_names = list(all_configs_with_dashboard)
    if current_config_name and current_config_name not in config_names:
        config_names.append(current_config_name)
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for name in config_names:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


def _get_existing_dashboard_creation_date(
    session_manager: AWSSessionManager,
    region: str,
    dashboard_name: str,
) -> Optional[str]:
    """Read the Dashboard Creation Date from an existing dashboard's Text widget.

    Parses the dashboard body JSON to extract the creation date embedded
    in the header markdown text widget. Returns None if the dashboard
    cannot be read or the date cannot be extracted.

    Args:
        session_manager: AWS session manager.
        region: AWS region.
        dashboard_name: Name of the dashboard to read.

    Returns:
        ISO 8601 creation date string, or None if not found.
    """
    import json
    import re

    try:
        client = session_manager.get_client('cloudwatch', region_name=region)
        response = client.get_dashboard(DashboardName=dashboard_name)
        body = json.loads(response.get('DashboardBody', '{}'))
        widgets = body.get('widgets', [])

        # The creation date is in the first text widget's markdown
        for widget in widgets:
            if widget.get('type') == 'text':
                markdown = widget.get('properties', {}).get('markdown', '')
                # Look for "Dashboard Creation Date:" followed by an ISO timestamp
                match = re.search(
                    r'\*\*Dashboard Creation Date:\*\*\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)',
                    markdown
                )
                if match:
                    return match.group(1)
                break  # Only check the first text widget
    except Exception:
        pass

    return None


def _manage_dashboard_lifecycle(
    dlg,
    session_manager: AWSSessionManager,
    config,
    region: str,
    action: str,
    all_configs_with_dashboard: Optional[List[str]] = None,
    config_sources: Optional[Dict[str, List[str]]] = None,
):
    """Manage CloudWatch Dashboard lifecycle during deploy/remove operations.

    Handles:
    - Adding a config to an existing dashboard (update filter clauses)
    - Removing a config when others remain (update filter clauses)
    - Removing the last config (delete dashboard)
    - create_dashboard changing from True to False (update or delete)

    All operations are non-blocking: failures emit warnings but do not
    raise exceptions or block the calling operation.

    Args:
        dlg: DeployProgressDialog instance for logging.
        session_manager: AWS session manager.
        config: The MRGConfig being deployed/removed/modified.
        region: AWS region.
        action: One of 'deploy', 'remove', 'opt_out'.
            - 'deploy': config is being deployed with create_dashboard=True
            - 'remove': config is being removed from AWS
            - 'opt_out': config's create_dashboard changed from True to False
        all_configs_with_dashboard: List of OTHER config names that still
            have create_dashboard=True in this region (excluding the current
            config for 'remove'/'opt_out' actions).

    Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9
    """
    from datetime import datetime, timezone

    try:
        from src.mrg.aws.cloudwatch import (
            CloudWatchDashboardError,
            delete_dashboards,
            generate_dashboard_body,
            put_dashboard,
        )
    except ImportError as e:
        dlg.log_message(
            "  Warning: CloudWatch module not available: {}".format(str(e)), 'error'
        )
        return

    dashboard_name = "MRG-Update-Analytics-{}".format(region)
    if all_configs_with_dashboard is None:
        all_configs_with_dashboard = []

    try:
        if action == 'deploy':
            # Req 4.1: Deploying a config with create_dashboard=True
            # Gather ALL config names that should be in the dashboard
            config_names = _get_dashboard_config_names(
                session_manager, region, config.name, all_configs_with_dashboard
            )
            source_arns = config.source_rule_groups

            # Preserve existing creation date on re-deploy to retain historical data.
            # Only set a new creation date on first-time dashboard creation.
            if config.dashboard_name:
                # Dashboard already exists — try to read its current creation date
                creation_date = _get_existing_dashboard_creation_date(
                    session_manager, region, dashboard_name
                )
                if not creation_date:
                    # Fallback: use current time if we can't read the existing date
                    creation_date = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            else:
                creation_date = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

            log_group = '/aws/lambda/ManagedRuleGenerator-{}'.format(region)
            body = generate_dashboard_body(
                region=region,
                log_group_name=log_group,
                config_names=config_names,
                source_arns=source_arns,
                creation_date=creation_date,
                config_sources=config_sources or {config.name: config.source_rule_groups},
            )

            put_dashboard(
                session_manager, region, dashboard_name, body,
                tags=[{'Key': 'ManagedRuleGenerator', 'Value': 'update-analytics'}]
            )
            config.dashboard_name = dashboard_name
            dlg.log_message(
                "  Dashboard '{}' created/updated with configs: {}".format(
                    dashboard_name, config_names
                ), 'success'
            )

        elif action == 'remove':
            # Config is being removed from AWS
            if all_configs_with_dashboard:
                # Req 4.2, 4.3: Other configs remain - update dashboard
                # to remove the current config from filter clauses
                config_names = [n for n in all_configs_with_dashboard if n != config.name]
                if config_names:
                    source_arns = config.source_rule_groups
                    # Preserve existing creation date
                    creation_date = _get_existing_dashboard_creation_date(
                        session_manager, region, dashboard_name
                    ) or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

                    body = generate_dashboard_body(
                        region=region,
                        log_group_name='/aws/lambda/ManagedRuleGenerator-{}'.format(region),
                        config_names=config_names,
                        source_arns=source_arns,
                        creation_date=creation_date,
                    )

                    put_dashboard(session_manager, region, dashboard_name, body)
                    dlg.log_message(
                        "  Dashboard updated - removed '{}' from filters.".format(
                            config.name
                        ), 'success'
                    )
                    # Req 4.3: Remove dashboard_name from removed config only
                    config.dashboard_name = None
                else:
                    # Edge case: all_configs_with_dashboard only had the current config
                    _delete_dashboard_and_clear(
                        dlg, session_manager, region, dashboard_name, config
                    )
            else:
                # Req 4.4, 4.5: Last config with create_dashboard=True - delete dashboard
                _delete_dashboard_and_clear(
                    dlg, session_manager, region, dashboard_name, config
                )

        elif action == 'opt_out':
            # Req 4.8, 4.9: create_dashboard changed from True to False
            if all_configs_with_dashboard:
                # Req 4.8: Others remain - update dashboard to remove this config
                config_names = [n for n in all_configs_with_dashboard if n != config.name]
                if config_names:
                    source_arns = config.source_rule_groups
                    # Preserve existing creation date
                    creation_date = _get_existing_dashboard_creation_date(
                        session_manager, region, dashboard_name
                    ) or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

                    body = generate_dashboard_body(
                        region=region,
                        log_group_name='/aws/lambda/ManagedRuleGenerator-{}'.format(region),
                        config_names=config_names,
                        source_arns=source_arns,
                        creation_date=creation_date,
                    )

                    put_dashboard(session_manager, region, dashboard_name, body)
                    dlg.log_message(
                        "  Dashboard updated - removed opted-out config '{}' from filters.".format(
                            config.name
                        ), 'success'
                    )
                else:
                    _delete_dashboard_and_clear(
                        dlg, session_manager, region, dashboard_name, config
                    )
            else:
                # Req 4.9: Only config with create_dashboard=True - delete dashboard
                _delete_dashboard_and_clear(
                    dlg, session_manager, region, dashboard_name, config
                )
            # Clear dashboard_name from the opted-out config
            config.dashboard_name = None

    except CloudWatchDashboardError as e:
        # Req 4.6, 4.7: Non-blocking warning on API failure
        if action in ('remove', 'opt_out') and not all_configs_with_dashboard:
            # Req 4.7: Include dashboard name in warning for manual cleanup
            dlg.log_message(
                "  Warning: Dashboard '{}' could not be removed: {}. "
                "You may need to delete it manually.".format(dashboard_name, str(e)),
                'error'
            )
        else:
            dlg.log_message(
                "  Warning: Dashboard could not be updated: {}".format(str(e)), 'error'
            )
    except Exception as e:
        # Catch-all for unexpected errors - non-blocking
        dlg.log_message(
            "  Warning: Dashboard lifecycle error: {}".format(str(e)), 'error'
        )


def _delete_dashboard_and_clear(dlg, session_manager, region, dashboard_name, config):
    """Delete a dashboard and clear dashboard_name from config.

    Helper for _manage_dashboard_lifecycle.

    Args:
        dlg: DeployProgressDialog for logging.
        session_manager: AWS session manager.
        region: AWS region.
        dashboard_name: Name of dashboard to delete.
        config: MRGConfig to clear dashboard_name from.

    Requirements: 4.4, 4.5
    """
    from src.mrg.aws.cloudwatch import delete_dashboards

    delete_dashboards(session_manager, region, [dashboard_name])
    config.dashboard_name = None
    dlg.log_message(
        "  Dashboard '{}' deleted (no remaining configs with dashboard enabled).".format(
            dashboard_name
        ), 'success'
    )


def _run_deploy_steps(dlg, session_manager, config, rules_string, build_results):
    """Internal: run all deploy steps. Called from background thread."""
    from src.mrg.aws.iam import create_lambda_role
    from src.mrg.aws.lambda_deployer import (add_or_update_config, create_lambda_function,
                                          lambda_function_exists, update_lambda_function_code,
                                          wait_for_function_active)
    from src.mrg.aws.network_firewall import (create_rule_group, describe_rule_group,
                                           rule_group_exists, tag_resource,
                                           update_rule_group)
    from src.mrg.aws.sns import (add_lambda_sns_permission, create_notification_topic,
                              subscribe_email_to_notification_topic, subscribe_lambda_to_managed_topic)
    from src.mrg.core.mrg_file import build_lambda_config

    region = config.region
    name = config.output_rule_group_name
    capacity = config.output_rule_group_capacity
    has_email = bool(config.notification_email)
    total = 8 if has_email else 6
    step_n = [0]

    def advance(text):
        step_n[0] += 1
        dlg.update_progress(int((step_n[0] / total) * 100), text)

    # Generate timestamp for LastUpdated tag
    from datetime import datetime, timezone
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    config_name = config.name or name

    # Tags applied to output rule groups
    output_tags = [
        {'Key': 'ManagedRuleGenerator', 'Value': config_name},
        {'Key': 'LastUpdated', 'Value': now_str},
    ]

    # Build rule_variables if home_net or external_net is defined
    rule_variables = None
    if hasattr(config, 'home_net') and config.home_net:
        rule_variables = {
            'IPSets': {
                'HOME_NET': {
                    'Definition': [cidr.strip() for cidr in config.home_net.split(',')]
                }
            }
        }
    if hasattr(config, 'external_net') and config.external_net:
        if rule_variables is None:
            rule_variables = {'IPSets': {}}
        rule_variables['IPSets']['EXTERNAL_NET'] = {
            'Definition': [cidr.strip() for cidr in config.external_net.split(',')]
        }

    # Step 1: Rule group
    dlg.update_progress(5, "Step 1: Creating/updating rule group...")
    dlg.log_message("Creating/updating rule group '{}'...".format(name), 'info')
    rg_result = None
    if config.output_rule_group_arn:
        try:
            info = describe_rule_group(session_manager, region, rule_group_arn=config.output_rule_group_arn)
            rg_result = update_rule_group(session_manager, region, rules_string=rules_string,
                                           update_token=info['UpdateToken'], rule_group_arn=config.output_rule_group_arn,
                                           rule_variables=rule_variables)
            dlg.log_message("  Updated existing rule group.", 'success')
        except Exception:
            rg_result = None
    if rg_result is None:
        if rule_group_exists(session_manager, region, name):
            info = describe_rule_group(session_manager, region, rule_group_name=name)
            rg_result = update_rule_group(session_manager, region, rules_string=rules_string,
                                           update_token=info['UpdateToken'], rule_group_name=name,
                                           rule_variables=rule_variables)
            dlg.log_message("  Updated existing rule group.", 'success')
        else:
            rg_result = create_rule_group(session_manager, region, name=name, rules_string=rules_string,
                                           capacity=capacity, description='Generated by Managed Rule Group Generator',
                                           tags=output_tags, rule_variables=rule_variables)
            dlg.log_message("  Created new rule group.", 'success')
    rule_group_arn = rg_result.get('RuleGroupArn', '')
    config.output_rule_group_arn = rule_group_arn

    # Update tags on the rule group (covers both create and update paths)
    try:
        tag_resource(session_manager, region, rule_group_arn, output_tags)
        dlg.log_message("  Tags updated.", 'success')
    except Exception as e:
        dlg.log_message("  Warning: Could not update tags: {}".format(str(e)), 'error')

    advance("Rule group ready.")

    # Step 2: IAM role
    dlg.log_message("Creating/verifying IAM role...", 'info')
    role_result = create_lambda_role(session_manager, region)
    role_arn = role_result['RoleArn']
    dlg.log_message("  IAM role {}.".format("created" if role_result['Created'] else "already exists"), 'success')
    advance("IAM role ready.")

    # Step 3: Lambda function
    dlg.log_message("Creating/updating Lambda function...", 'info')
    if lambda_function_exists(session_manager, region):
        code_result = update_lambda_function_code(session_manager, region)
        lambda_arn = code_result.get('FunctionArn', '')
        dlg.log_message("  Updated Lambda function code.", 'success')
    else:
        func_result = create_lambda_function(session_manager, region, role_arn=role_arn)
        lambda_arn = func_result.get('FunctionArn', '')
        dlg.log_message("  Created Lambda function.", 'success')
    config.lambda_function_arn = lambda_arn

    # Wait for Lambda to become Active before updating environment
    dlg.log_message("  Waiting for Lambda to become Active...", 'info')
    if not wait_for_function_active(session_manager, region, max_wait_seconds=60):
        dlg.log_message("  Warning: Lambda may still be initializing.", 'error')
    else:
        dlg.log_message("  Lambda is Active.", 'success')

    # Ensure the log group exists so dashboard queries don't error
    # before the Lambda is first invoked
    log_group_name = '/aws/lambda/ManagedRuleGenerator-{}'.format(region)
    try:
        logs_client = session_manager.get_client('logs', region_name=region)
        logs_client.create_log_group(logGroupName=log_group_name)
        dlg.log_message("  Log group '{}' created.".format(log_group_name), 'success')
    except Exception as lg_err:
        if 'ResourceAlreadyExistsException' in str(lg_err):
            pass  # Already exists, no action needed
        else:
            dlg.log_message(
                "  Warning: Could not create log group: {}".format(str(lg_err)), 'error'
            )

    advance("Lambda function ready.")

    # Step 4: Notification topic (must be created BEFORE Lambda config
    # so that notification_topic_arn is included in the environment variable)
    notification_topic_arn = None
    if has_email:
        dlg.log_message("Creating notification topic...", 'info')
        tr = create_notification_topic(session_manager, region, config_name=config_name)
        notification_topic_arn = tr.get('TopicArn', '')
        config.notification_topic_arn = notification_topic_arn
        dlg.log_message("  Notification topic ready.", 'success')
        advance("Notification topic ready.")
        dlg.log_message("Subscribing email: {}".format(config.notification_email), 'info')
        subscribe_email_to_notification_topic(session_manager, region, notification_topic_arn, config.notification_email)
        dlg.log_message("  Email subscription created (confirmation pending).", 'success')
        advance("Email subscription created.")

    # Step 5: Lambda config (after notification topic so the ARN is included)
    dlg.log_message("Updating Lambda configuration...", 'info')
    lc = build_lambda_config(config)
    cr = add_or_update_config(session_manager, region, lc)
    dlg.log_message("  Configuration {}.".format(cr.get('Action', 'added')), 'success')
    advance("Lambda configuration updated.")

    # Step 6: SNS permission + Subscribe Lambda to managed topic
    dlg.log_message("Setting up SNS subscription to AWS-Managed-Threat-Signatures...", 'info')
    try:
        add_lambda_sns_permission(session_manager, region, lambda_arn)
        dlg.log_message("  SNS permission configured.", 'success')
        subscribe_lambda_to_managed_topic(session_manager, region, lambda_arn)
        dlg.log_message("  Lambda subscribed to managed topic.", 'success')
    except Exception as e:
        dlg.log_message("  Warning: Could not subscribe to managed topic: {}".format(str(e)), 'error')
        dlg.log_message("  The Lambda can still be triggered manually via Tools > Force Sync.", 'info')
    advance("SNS subscription step complete.")
    advance("SNS setup complete.")

    # Step 7: CloudWatch Dashboard (optional, non-blocking)
    if config.create_dashboard:
        dlg.log_message("Creating/updating CloudWatch Dashboard...", 'info')
        try:
            from src.mrg.aws.lambda_deployer import get_lambda_configs, LambdaNotFoundError

            # Gather all config names deployed in this region to include in dashboard
            # This enables multi-config dashboard aggregation (Req 4.1)
            other_dashboard_configs = []
            existing_configs = []
            try:
                existing_configs = get_lambda_configs(session_manager, region)
                for lc in existing_configs:
                    lc_name = lc.get('name', '')
                    if lc_name and lc_name != config.name:
                        other_dashboard_configs.append(lc_name)
            except (LambdaNotFoundError, Exception):
                pass

            # Include current config + any others already deployed in this region
            all_configs_with_dashboard = [config.name] + other_dashboard_configs

            # Build config_sources mapping for the monitored sources widget
            config_sources = {config.name: config.source_rule_groups}
            for lc in existing_configs:
                lc_name = lc.get('name', '')
                if lc_name and lc_name != config.name:
                    config_sources[lc_name] = lc.get('source_rule_groups', [])

            _manage_dashboard_lifecycle(
                dlg, session_manager, config, region,
                action='deploy',
                all_configs_with_dashboard=all_configs_with_dashboard,
                config_sources=config_sources,
            )
        except Exception as e:
            dlg.log_message(
                "  Warning: Dashboard could not be created: {}".format(str(e)), 'error'
            )
    elif not config.create_dashboard and config.dashboard_name:
        # Req 4.8, 4.9: create_dashboard changed from True to False
        # The config previously had a dashboard but user opted out
        dlg.log_message("Handling dashboard opt-out...", 'info')
        try:
            from src.mrg.aws.lambda_deployer import get_lambda_configs, LambdaNotFoundError

            # Find other configs in this region that might still want a dashboard
            other_dashboard_configs = []
            try:
                existing_configs = get_lambda_configs(session_manager, region)
                for lc in existing_configs:
                    lc_name = lc.get('name', '')
                    if lc_name and lc_name != config.name:
                        other_dashboard_configs.append(lc_name)
            except (LambdaNotFoundError, Exception):
                pass

            _manage_dashboard_lifecycle(
                dlg, session_manager, config, region,
                action='opt_out',
                all_configs_with_dashboard=other_dashboard_configs,
            )
        except Exception as e:
            dlg.log_message(
                "  Warning: Dashboard opt-out could not be processed: {}".format(str(e)), 'error'
            )

    # Update deployment metadata
    deploy_stats = {
        'total_rules_scanned': build_results.get('total_scanned', 0),
        'rules_matching_filter': build_results.get('matching', 0),
        'rules_excluded_missing_metadata': build_results.get('missing_metadata', 0),
        'deduplicated_rules': build_results.get('deduplicated', 0),
    }
    config.update_deployment_stats(deploy_stats)
    return {
        'rule_group_arn': rule_group_arn, 'lambda_function_arn': lambda_arn,
        'notification_topic_arn': notification_topic_arn, 'deploy_stats': deploy_stats,
    }


def deploy_to_aws(parent, session_manager, config, rules_string, build_results):
    """Deploy to AWS with progress dialog. Returns result dict or None."""
    dialog = DeployProgressDialog(parent, title="Deploying to AWS")
    holder = {'result': None}

    def _do(dlg):
        try:
            r = _run_deploy_steps(dlg, session_manager, config, rules_string, build_results)
            holder['result'] = r
            dlg.result = r
            dlg.set_complete(True, "Deployment completed! {} rules deployed.".format(
                build_results.get('final_count', 0)))
        except Exception as e:
            logger.exception("Deployment failed")
            dlg.log_message("ERROR: {}".format(str(e)), 'error')
            dlg.set_complete(False, "Deployment failed: {}".format(str(e)))

    dialog.run_in_thread(_do)
    dialog.wait()
    return holder['result']


def _run_remove_steps(dlg, session_manager, config, delete_rg, delete_backups):
    """Internal: run remove configuration steps."""
    from src.mrg.aws.lambda_deployer import lambda_function_exists, remove_config as lambda_remove_config
    from src.mrg.aws.network_firewall import (delete_rule_group as nf_delete_rg,
                                           list_user_rule_groups, RuleGroupNotFoundError)
    from src.mrg.aws.sns import list_topic_subscriptions, unsubscribe

    region = config.region
    name = config.name or config.output_rule_group_name

    # Step 1: Delete rule group
    if delete_rg:
        dlg.update_progress(10, "Step 1: Deleting rule group...")
        dlg.log_message("Deleting rule group '{}'...".format(config.output_rule_group_name), 'info')
        deleted = False
        # Try by ARN first
        if config.output_rule_group_arn:
            try:
                nf_delete_rg(session_manager, region, rule_group_arn=config.output_rule_group_arn)
                dlg.log_message("  Rule group deleted.", 'success')
                deleted = True
            except RuleGroupNotFoundError:
                dlg.log_message("  Rule group not found by ARN, trying by name...", 'info')
            except Exception as e:
                dlg.log_message("  Warning (ARN): {}".format(str(e)), 'error')
        # Fallback: try by name
        if not deleted and config.output_rule_group_name:
            try:
                nf_delete_rg(session_manager, region, rule_group_name=config.output_rule_group_name)
                dlg.log_message("  Rule group deleted by name.", 'success')
                deleted = True
            except RuleGroupNotFoundError:
                dlg.log_message("  Rule group already deleted.", 'info')
            except Exception as e:
                dlg.log_message("  Warning (name): {}".format(str(e)), 'error')
    else:
        dlg.update_progress(10, "Step 1: Skipping rule group deletion.")
        dlg.log_message("Skipping rule group deletion.", 'info')

    if delete_backups and config.output_rule_group_name:
        dlg.log_message("Deleting backup rule groups...", 'info')
        try:
            user_rgs = list_user_rule_groups(session_manager, region)
            pfx = config.output_rule_group_name + '-bak-'
            for rg in user_rgs:
                if rg['Name'].startswith(pfx):
                    try:
                        nf_delete_rg(session_manager, region, rule_group_arn=rg['Arn'])
                        dlg.log_message("  Deleted backup: {}".format(rg['Name']), 'success')
                    except Exception:
                        dlg.log_message("  Warning: Could not delete: {}".format(rg['Name']), 'error')
        except Exception:
            dlg.log_message("  Warning: Could not list backups.", 'error')

    # Step 2: Remove from Lambda
    dlg.update_progress(50, "Step 2: Removing Lambda configuration...")
    dlg.log_message("Removing configuration from Lambda...", 'info')
    remaining = 0
    if lambda_function_exists(session_manager, region):
        try:
            res = lambda_remove_config(session_manager, region, name)
            remaining = res.get('RemainingConfigs', 0)
            dlg.log_message("  Removed. {} configs remaining.".format(remaining), 'success')
        except Exception as e:
            dlg.log_message("  Warning: {}".format(str(e)), 'error')
    else:
        dlg.log_message("  Lambda not found.", 'info')

    # Step 3: Remove email subscription
    dlg.update_progress(80, "Step 3: Removing notification subscription...")
    dlg.log_message("Checking notification subscriptions...", 'info')
    if config.notification_topic_arn and config.notification_email:
        try:
            subs = list_topic_subscriptions(session_manager, region, config.notification_topic_arn)
            found = False
            for s in subs:
                if s.get('Protocol') == 'email' and s.get('Endpoint') == config.notification_email:
                    sa = s.get('SubscriptionArn', '')
                    if sa and sa != 'PendingConfirmation':
                        unsubscribe(session_manager, region, sa)
                        dlg.log_message("  Removed email subscription.", 'success')
                        found = True
                        break
            if not found:
                dlg.log_message("  No matching subscription found.", 'info')

            # Delete the per-config notification topic
            from src.mrg.aws.sns import delete_notification_topic
            try:
                delete_notification_topic(session_manager, region, config.notification_topic_arn)
                dlg.log_message("  Notification topic deleted.", 'success')
            except Exception as dt_err:
                dlg.log_message("  Warning: Could not delete topic: {}".format(str(dt_err)), 'error')
        except Exception as e:
            dlg.log_message("  Warning: {}".format(str(e)), 'error')
    else:
        dlg.log_message("  No subscription to remove.", 'info')

    # Step 4: Dashboard lifecycle management (non-blocking)
    # Req 4.2, 4.3, 4.4, 4.5: Update or delete dashboard when config is removed
    if config.dashboard_name or config.create_dashboard:
        dlg.update_progress(90, "Step 4: Managing CloudWatch Dashboard...")
        dlg.log_message("Managing CloudWatch Dashboard...", 'info')

        # Determine which other configs still have create_dashboard=True
        # by checking remaining Lambda configs (after our config was removed)
        other_dashboard_configs = []
        try:
            from src.mrg.aws.lambda_deployer import get_lambda_configs, LambdaNotFoundError
            try:
                remaining_configs = get_lambda_configs(session_manager, region)
                for lc in remaining_configs:
                    lc_name = lc.get('name', '')
                    if lc_name and lc_name != name:
                        other_dashboard_configs.append(lc_name)
            except (LambdaNotFoundError, Exception):
                pass
        except ImportError:
            pass

        _manage_dashboard_lifecycle(
            dlg, session_manager, config, region,
            action='remove',
            all_configs_with_dashboard=other_dashboard_configs,
        )

    config.clear_deployment_metadata()
    return {'remaining_configs': remaining}


def remove_configuration(parent, session_manager, config, delete_rule_group_flag=True, delete_backups=False):
    """Remove a single configuration. Returns True on success."""
    dialog = DeployProgressDialog(parent, title="Removing Configuration")
    holder = {'success': False}

    def _do(dlg):
        try:
            r = _run_remove_steps(dlg, session_manager, config, delete_rule_group_flag, delete_backups)
            dlg.result = r
            holder['success'] = True
            cname = config.name or config.output_rule_group_name
            dlg.set_complete(True, "Configuration '{}' removed.".format(cname))
        except Exception as e:
            logger.exception("Remove failed")
            dlg.log_message("ERROR: {}".format(str(e)), 'error')
            dlg.set_complete(False, "Failed: {}".format(str(e)))

    dialog.run_in_thread(_do)
    dialog.wait()
    return holder['success']


def _run_teardown_steps(dlg, session_manager, region, delete_rgs, delete_backups):
    """Internal: run full teardown steps."""
    from src.mrg.aws.iam import delete_lambda_role
    from src.mrg.aws.lambda_deployer import (delete_lambda_function, get_lambda_configs,
                                          lambda_function_exists)
    from src.mrg.aws.network_firewall import (delete_rule_group as nf_delete_rg, list_user_rule_groups)
    from src.mrg.aws.sns import (delete_notification_topic, get_managed_threat_signatures_topic_arn,
                              get_all_notification_topics,
                              list_topic_subscriptions, unsubscribe)

    # Collect config info before deleting Lambda
    rg_arns = []
    rg_names = []
    if lambda_function_exists(session_manager, region):
        try:
            cfgs = get_lambda_configs(session_manager, region)
            for c in cfgs:
                a = c.get('output_rule_group_arn', '')
                n = c.get('name', '')
                if a:
                    rg_arns.append(a)
                if n:
                    rg_names.append(n)
        except Exception:
            pass

    # Step 1: Delete Lambda
    dlg.update_progress(10, "Step 1: Deleting Lambda function...")
    dlg.log_message("Deleting Lambda function...", 'info')
    try:
        d = delete_lambda_function(session_manager, region)
        dlg.log_message("  " + ("Lambda deleted." if d else "Lambda not found."),
                        'success' if d else 'info')
    except Exception as e:
        dlg.log_message("  Warning: {}".format(str(e)), 'error')

    # Step 2: Delete IAM role
    dlg.update_progress(30, "Step 2: Deleting IAM role...")
    dlg.log_message("Deleting IAM role...", 'info')
    try:
        d = delete_lambda_role(session_manager, region)
        dlg.log_message("  " + ("IAM role deleted." if d else "IAM role not found."),
                        'success' if d else 'info')
    except Exception as e:
        dlg.log_message("  Warning: {}".format(str(e)), 'error')

    # Step 3: SNS subscriptions
    dlg.update_progress(50, "Step 3: Removing SNS subscriptions...")
    dlg.log_message("Removing SNS subscriptions...", 'info')

    # 3a: Remove Lambda subscription from the AWS-Managed-Threat-Signatures topic
    managed_topic_arn = get_managed_threat_signatures_topic_arn(region, session_manager)
    if managed_topic_arn:
        dlg.log_message("  Checking AWS-Managed-Threat-Signatures topic...", 'info')
        try:
            managed_subs = list_topic_subscriptions(session_manager, region, managed_topic_arn)
            lambda_function_name = 'ManagedRuleGenerator-{}'.format(region)
            found_managed_sub = False
            for s in managed_subs:
                endpoint = s.get('Endpoint', '')
                sa = s.get('SubscriptionArn', '')
                # Match subscriptions pointing to our Lambda function
                if s.get('Protocol') == 'lambda' and lambda_function_name in endpoint:
                    if sa and sa != 'PendingConfirmation':
                        try:
                            unsubscribe(session_manager, region, sa)
                            dlg.log_message("  Removed managed topic subscription: {} ({})".format(
                                endpoint, s.get('Protocol', '')), 'success')
                            found_managed_sub = True
                        except Exception as e:
                            dlg.log_message("  Warning: Could not remove managed topic subscription: {}".format(
                                str(e)), 'error')
            if not found_managed_sub:
                dlg.log_message("  No Lambda subscription found on managed topic.", 'info')
        except Exception as e:
            # Authorization errors on cross-account topics are expected (we can't list
            # subscriptions on AWS-managed topics). Show as debug-level info, not error.
            if 'AuthorizationError' in str(e) or 'not authorized' in str(e):
                dlg.log_message("  Skipped managed topic cleanup (cross-account, no access).", 'info')
            else:
                dlg.log_message("  Warning: Could not list managed topic subscriptions: {}".format(str(e)), 'error')
    else:
        dlg.log_message("  No managed threat signatures topic found for region.", 'info')

    # 3b: Remove subscriptions from all MRG notification topics (legacy + per-config)
    all_notification_topics = get_all_notification_topics(session_manager, region)
    if all_notification_topics:
        for nt in all_notification_topics:
            try:
                subs = list_topic_subscriptions(session_manager, region, nt['TopicArn'])
                for s in subs:
                    sa = s.get('SubscriptionArn', '')
                    if sa and sa != 'PendingConfirmation':
                        try:
                            unsubscribe(session_manager, region, sa)
                            dlg.log_message("  Removed: {} ({}) from {}".format(
                                s.get('Endpoint', ''), s.get('Protocol', ''),
                                nt['TopicName']), 'success')
                        except Exception:
                            pass
            except Exception as e:
                dlg.log_message("  Warning: {}".format(str(e)), 'error')
    else:
        dlg.log_message("  No notification topics found.", 'info')

    # Step 4: Delete all MRG notification topics
    dlg.update_progress(65, "Step 4: Deleting notification topics...")
    dlg.log_message("Deleting notification topics...", 'info')
    if all_notification_topics:
        for nt in all_notification_topics:
            try:
                delete_notification_topic(session_manager, region, nt['TopicArn'])
                dlg.log_message("  Deleted: {}".format(nt['TopicName']), 'success')
            except Exception as e:
                dlg.log_message("  Warning: {}".format(str(e)), 'error')
    else:
        dlg.log_message("  No topics to delete.", 'info')

    # Step 5: Delete CloudWatch log group
    dlg.update_progress(75, "Step 5: Deleting CloudWatch log group...")
    dlg.log_message("Deleting CloudWatch log group...", 'info')
    log_group_name = '/aws/lambda/ManagedRuleGenerator-{}'.format(region)
    try:
        logs_client = session_manager.get_client('logs', region_name=region)
        logs_client.delete_log_group(logGroupName=log_group_name)
        dlg.log_message("  Log group '{}' deleted.".format(log_group_name), 'success')
    except Exception as e:
        error_str = str(e)
        if 'ResourceNotFoundException' in error_str:
            dlg.log_message("  Log group not found.", 'info')
        else:
            dlg.log_message("  Warning: {}".format(error_str), 'error')

    # Step 6: Delete rule groups
    if delete_rgs:
        dlg.update_progress(85, "Step 6: Deleting rule groups...")
        dlg.log_message("Deleting MRG-managed rule groups...", 'info')
        for arn in rg_arns:
            short = arn.split('/')[-1] if '/' in arn else arn
            try:
                nf_delete_rg(session_manager, region, rule_group_arn=arn)
                dlg.log_message("  Deleted: {}".format(short), 'success')
            except Exception:
                dlg.log_message("  Warning: Could not delete: {}".format(short), 'error')
        if delete_backups and rg_names:
            dlg.log_message("Deleting backup rule groups...", 'info')
            try:
                user_rgs = list_user_rule_groups(session_manager, region)
                for rg in user_rgs:
                    for cn in rg_names:
                        if rg['Name'].startswith(cn + '-bak-'):
                            try:
                                nf_delete_rg(session_manager, region, rule_group_arn=rg['Arn'])
                                dlg.log_message("  Deleted backup: {}".format(rg['Name']), 'success')
                            except Exception:
                                dlg.log_message("  Warning: {}".format(rg['Name']), 'error')
                            break
            except Exception:
                dlg.log_message("  Warning: Could not list backups.", 'error')


def full_teardown(parent, session_manager, region, delete_rule_groups=True, delete_backups=True):
    """Full teardown of all infrastructure in region. Returns True on success."""
    dialog = DeployProgressDialog(parent, title="Full Teardown")
    holder = {'success': False}

    def _do(dlg):
        try:
            _run_teardown_steps(dlg, session_manager, region, delete_rule_groups, delete_backups)
            holder['success'] = True
            dlg.set_complete(True, "Full teardown of {} complete.".format(region))
        except Exception as e:
            logger.exception("Teardown failed")
            dlg.log_message("ERROR: {}".format(str(e)), 'error')
            dlg.set_complete(False, "Teardown failed: {}".format(str(e)))

    dialog.run_in_thread(_do)
    dialog.wait()
    return holder['success']