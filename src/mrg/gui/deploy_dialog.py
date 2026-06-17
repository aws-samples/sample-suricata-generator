"""
Deploy Dialog for Managed Rule Group Generator.
Progress dialogs for Deploy, Remove Configuration, and Full Teardown.
"""
import logging
import platform
import threading
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, Optional
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

    # Step 1: Rule group
    dlg.update_progress(5, "Step 1: Creating/updating rule group...")
    dlg.log_message("Creating/updating rule group '{}'...".format(name), 'info')
    rg_result = None
    if config.output_rule_group_arn:
        try:
            info = describe_rule_group(session_manager, region, rule_group_arn=config.output_rule_group_arn)
            rg_result = update_rule_group(session_manager, region, rules_string=rules_string,
                                           update_token=info['UpdateToken'], rule_group_arn=config.output_rule_group_arn)
            dlg.log_message("  Updated existing rule group.", 'success')
        except Exception:
            rg_result = None
    if rg_result is None:
        if rule_group_exists(session_manager, region, name):
            info = describe_rule_group(session_manager, region, rule_group_name=name)
            rg_result = update_rule_group(session_manager, region, rules_string=rules_string,
                                           update_token=info['UpdateToken'], rule_group_name=name)
            dlg.log_message("  Updated existing rule group.", 'success')
        else:
            rg_result = create_rule_group(session_manager, region, name=name, rules_string=rules_string,
                                           capacity=capacity, description='Generated by Managed Rule Group Generator',
                                           tags=output_tags)
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
    advance("Lambda function ready.")

    # Step 4: Notification topic (must be created BEFORE Lambda config
    # so that notification_topic_arn is included in the environment variable)
    notification_topic_arn = None
    if has_email:
        dlg.log_message("Creating notification topic...", 'info')
        tr = create_notification_topic(session_manager, region)
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
        except Exception as e:
            dlg.log_message("  Warning: {}".format(str(e)), 'error')
    else:
        dlg.log_message("  No subscription to remove.", 'info')

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
                              get_notification_topic,
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

    # 3b: Remove subscriptions from the notification topic
    nt = get_notification_topic(session_manager, region)
    if nt:
        try:
            subs = list_topic_subscriptions(session_manager, region, nt['TopicArn'])
            for s in subs:
                sa = s.get('SubscriptionArn', '')
                if sa and sa != 'PendingConfirmation':
                    try:
                        unsubscribe(session_manager, region, sa)
                        dlg.log_message("  Removed: {} ({})".format(
                            s.get('Endpoint', ''), s.get('Protocol', '')), 'success')
                    except Exception:
                        pass
        except Exception as e:
            dlg.log_message("  Warning: {}".format(str(e)), 'error')
    else:
        dlg.log_message("  No notification topic found.", 'info')

    # Step 4: Delete notification topic
    dlg.update_progress(65, "Step 4: Deleting notification topic...")
    dlg.log_message("Deleting notification topic...", 'info')
    if nt:
        try:
            delete_notification_topic(session_manager, region, nt['TopicArn'])
            dlg.log_message("  Topic deleted.", 'success')
        except Exception as e:
            dlg.log_message("  Warning: {}".format(str(e)), 'error')
    else:
        dlg.log_message("  No topic to delete.", 'info')

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