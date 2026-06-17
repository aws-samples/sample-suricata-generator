"""
Rollback Dialog for Managed Rule Group Generator.

Tools > Rollback dialog:
- Displays available backup rule groups for the current configuration.
- User selects a backup to restore.
- Confirmation dialog with details (timestamp, rule count, warning).
- Copies rules from backup into primary rule group using UpdateRuleGroup.
- Sends a notification confirming the rollback.

See Feature Spec Section 9.3 (Manual Rollback).
"""

import logging
import platform
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Dict, List, Optional

from src.aws.aws_session_manager import AWSSessionManager

logger = logging.getLogger(__name__)


def perform_rollback(session_manager: AWSSessionManager,
                     region: str,
                     backup_arn: str,
                     target_arn: str,
                     target_name: str,
                     notification_topic_arn: Optional[str] = None) -> Dict:
    """Perform a rollback by copying rules from a backup into the primary rule group.

    Args:
        session_manager: AWSSessionManager instance.
        region: AWS region.
        backup_arn: ARN of the backup rule group to restore from.
        target_arn: ARN of the primary rule group to restore to.
        target_name: Name of the primary rule group (for notifications).
        notification_topic_arn: Optional ARN of SNS topic for rollback notification.

    Returns:
        Dict with:
        - 'success': True if rollback succeeded
        - 'rules_restored': Number of rules restored
        - 'update_token': New update token after the update
        - 'backup_name': Name of the backup used

    Raises:
        Exception: If rollback fails.
    """
    from src.mrg.aws.network_firewall import describe_rule_group, update_rule_group

    # Fetch backup rules
    backup_info = describe_rule_group(session_manager, region, rule_group_arn=backup_arn)
    backup_rules_string = backup_info.get('RulesString', '')
    backup_name = backup_info.get('RuleGroupName', '')

    # Count rules in backup
    rule_count = 0
    if backup_rules_string.strip():
        for line in backup_rules_string.split('\n'):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                rule_count += 1

    # Fetch current target to get UpdateToken
    target_info = describe_rule_group(session_manager, region, rule_group_arn=target_arn)
    update_token = target_info.get('UpdateToken', '')

    # Update primary rule group with backup rules
    result = update_rule_group(
        session_manager, region,
        rules_string=backup_rules_string,
        update_token=update_token,
        rule_group_arn=target_arn,
    )

    # Send rollback notification if topic is configured
    if notification_topic_arn:
        try:
            from src.mrg.aws.sns import publish_notification
            subject = "[ManagedRuleGenerator] Rollback: {}".format(target_name)
            message = (
                'Rule Group "{}" has been rolled back.\n\n'
                'Restored from backup: {}\n'
                'Rules restored: {}\n\n'
                'This was a manual rollback initiated from the GUI.'
            ).format(target_name, backup_name, rule_count)
            publish_notification(session_manager, region, notification_topic_arn,
                                subject, message)
        except Exception as e:
            logger.warning("Failed to send rollback notification: %s", str(e))

    return {
        'success': True,
        'rules_restored': rule_count,
        'update_token': result.get('UpdateToken', ''),
        'backup_name': backup_name,
    }


class RollbackDialog:
    """Modal dialog for rolling back to a backup rule group.

    Displays a list of available backups, allows the user to select one,
    shows a confirmation dialog, and performs the rollback.
    """

    def __init__(self, parent, session_manager: AWSSessionManager,
                 region: str, base_name: str, target_arn: str,
                 notification_topic_arn: Optional[str] = None):
        """Create the rollback dialog.

        Args:
            parent: Parent tkinter widget.
            session_manager: AWSSessionManager instance.
            region: AWS region.
            base_name: Output rule group name to find backups for.
            target_arn: ARN of the primary rule group to restore to.
            notification_topic_arn: Optional SNS topic for rollback notifications.
        """
        self._parent = parent
        self._session_manager = session_manager
        self._region = region
        self._base_name = base_name
        self._target_arn = target_arn
        self._notification_topic_arn = notification_topic_arn
        self._backups = []
        self._rule_counts = {}
        self._rollback_result = None

        self._dialog = tk.Toplevel(parent)
        self._dialog.title("Rollback — {}".format(base_name))
        self._dialog.geometry("650x480")
        self._dialog.minsize(550, 380)
        if platform.system() != 'Darwin':
            self._dialog.transient(parent)
        self._dialog.grab_set()
        self._dialog.protocol("WM_DELETE_WINDOW", self._close)

        self._setup_ui()
        self._load_backups()

    def _setup_ui(self):
        main_frame = ttk.Frame(self._dialog, padding=12)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Label(main_frame,
                           text="Rollback '{}'".format(self._base_name),
                           font=('TkDefaultFont', 11, 'bold'))
        header.pack(anchor=tk.W, pady=(0, 4))

        desc = ttk.Label(main_frame,
                         text="Select a backup to restore. The current rule group will be "
                              "overwritten with the backup's rules.",
                         wraplength=600, font=('TkDefaultFont', 9))
        desc.pack(anchor=tk.W, pady=(0, 8))

        self._status_label = ttk.Label(main_frame, text="Loading backups...",
                                       font=('TkDefaultFont', 9))
        self._status_label.pack(anchor=tk.W, pady=(0, 8))

        # Treeview for backup list
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        columns = ('name', 'timestamp', 'rules')
        self._tree = ttk.Treeview(tree_frame, columns=columns, show='headings',
                                  selectmode='browse')
        self._tree.heading('name', text='Backup Name')
        self._tree.heading('timestamp', text='Timestamp')
        self._tree.heading('rules', text='Rules')
        self._tree.column('name', width=300, minwidth=150)
        self._tree.column('timestamp', width=170, minwidth=120)
        self._tree.column('rules', width=80, minwidth=60, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Warning label
        self._warning_frame = ttk.Frame(main_frame)
        self._warning_frame.pack(fill=tk.X, pady=(0, 8))
        self._warning_label = ttk.Label(
            self._warning_frame,
            text="\u26a0 WARNING: Rolling back will overwrite the current rule group. "
                 "A backup of the current state is NOT automatically created.",
            foreground='#D32F2F', wraplength=600, font=('TkDefaultFont', 9, 'bold'))
        self._warning_label.pack(anchor=tk.W)

        # Button frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 4))

        self._rollback_btn = ttk.Button(btn_frame, text="Rollback to Selected",
                                        command=self._do_rollback, state=tk.DISABLED)
        self._rollback_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._refresh_btn = ttk.Button(btn_frame, text="Refresh",
                                       command=self._load_backups)
        self._refresh_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._close_btn = ttk.Button(btn_frame, text="Cancel", command=self._close)
        self._close_btn.pack(side=tk.RIGHT)

        # Bind selection event
        self._tree.bind('<<TreeviewSelect>>', self._on_selection_change)

    def _on_selection_change(self, event=None):
        """Enable/disable rollback button based on selection."""
        selected = self._tree.selection()
        if selected:
            self._rollback_btn.config(state=tk.NORMAL)
        else:
            self._rollback_btn.config(state=tk.DISABLED)

    def _load_backups(self):
        """Load backup list from AWS in a background thread."""
        self._status_label.config(text="Loading backups...")
        self._tree.delete(*self._tree.get_children())
        self._rollback_btn.config(state=tk.DISABLED)
        self._refresh_btn.config(state=tk.DISABLED)

        def _do_load():
            try:
                from src.mrg.gui.backup_manager import (
                    get_backup_rule_count,
                    list_backups_for_config,
                )

                backups = list_backups_for_config(
                    self._session_manager, self._region, self._base_name)

                rule_counts = {}
                for backup in backups:
                    count = get_backup_rule_count(
                        self._session_manager, self._region, backup['Arn'])
                    rule_counts[backup['Arn']] = count

                self._parent.after(0, lambda: self._on_load_complete(backups, rule_counts))
            except Exception as e:
                self._parent.after(0, lambda: self._on_load_error(str(e)))

        threading.Thread(target=_do_load, daemon=True).start()

    def _on_load_complete(self, backups: List[Dict], rule_counts: Dict):
        """Populate the treeview after loading."""
        if not self._dialog.winfo_exists():
            return

        self._backups = backups
        self._rule_counts = rule_counts
        self._tree.delete(*self._tree.get_children())

        for backup in backups:
            count = rule_counts.get(backup['Arn'], -1)
            count_str = str(count) if count >= 0 else '?'
            self._tree.insert('', tk.END, iid=backup['Arn'],
                              values=(backup['Name'],
                                      backup['FormattedTimestamp'],
                                      count_str))

        count = len(backups)
        if count == 0:
            self._status_label.config(text="No backups found.")
        else:
            self._status_label.config(
                text="{} backup{} available.".format(count, 's' if count != 1 else ''))
        self._refresh_btn.config(state=tk.NORMAL)

    def _on_load_error(self, error_msg: str):
        """Handle load failure."""
        if not self._dialog.winfo_exists():
            return
        self._status_label.config(text="Error loading backups: {}".format(error_msg))
        self._refresh_btn.config(state=tk.NORMAL)

    def _do_rollback(self):
        """Perform the rollback after confirmation."""
        selected = self._tree.selection()
        if not selected:
            return

        backup_arn = selected[0]

        # Find backup details
        backup_info = None
        for b in self._backups:
            if b['Arn'] == backup_arn:
                backup_info = b
                break

        if not backup_info:
            return

        backup_name = backup_info['Name']
        backup_ts = backup_info['FormattedTimestamp']
        rule_count = self._rule_counts.get(backup_arn, -1)
        count_str = str(rule_count) if rule_count >= 0 else 'unknown'

        # Confirmation dialog
        msg = (
            "Rollback '{}' to backup?\n\n"
            "Backup: {}\n"
            "Timestamp: {}\n"
            "Rule count: {}\n\n"
            "WARNING: This will overwrite the current rule group content.\n"
            "The current rules will be replaced with the backup's rules.\n\n"
            "Do you want to proceed?"
        ).format(self._base_name, backup_name, backup_ts, count_str)

        if not messagebox.askyesno("Confirm Rollback", msg, icon='warning',
                                   parent=self._dialog):
            return

        # Disable buttons during rollback
        self._rollback_btn.config(state=tk.DISABLED)
        self._refresh_btn.config(state=tk.DISABLED)
        self._close_btn.config(state=tk.DISABLED)
        self._status_label.config(text="Rolling back to {}...".format(backup_name))

        def _do():
            try:
                result = perform_rollback(
                    self._session_manager, self._region,
                    backup_arn=backup_arn,
                    target_arn=self._target_arn,
                    target_name=self._base_name,
                    notification_topic_arn=self._notification_topic_arn,
                )
                self._parent.after(0, lambda: self._on_rollback_complete(result))
            except Exception as e:
                self._parent.after(0, lambda: self._on_rollback_error(str(e)))

        threading.Thread(target=_do, daemon=True).start()

    def _on_rollback_complete(self, result: Dict):
        """Handle successful rollback."""
        if not self._dialog.winfo_exists():
            return

        self._rollback_result = result
        rules = result.get('rules_restored', 0)
        backup_name = result.get('backup_name', '')
        self._status_label.config(
            text="Rollback complete! Restored {} rules from '{}'.".format(rules, backup_name))
        self._close_btn.config(state=tk.NORMAL)
        self._refresh_btn.config(state=tk.NORMAL)

        messagebox.showinfo(
            "Rollback Successful",
            "Successfully rolled back '{}' to backup '{}'.\n\n"
            "Rules restored: {}".format(self._base_name, backup_name, rules),
            parent=self._dialog)

    def _on_rollback_error(self, error_msg: str):
        """Handle rollback failure."""
        if not self._dialog.winfo_exists():
            return

        self._status_label.config(text="Rollback failed.")
        self._rollback_btn.config(state=tk.NORMAL)
        self._refresh_btn.config(state=tk.NORMAL)
        self._close_btn.config(state=tk.NORMAL)

        messagebox.showerror(
            "Rollback Failed",
            "Failed to rollback:\n\n{}".format(error_msg),
            parent=self._dialog)

    def _close(self):
        """Close the dialog."""
        if self._dialog.winfo_exists():
            self._dialog.grab_release()
            self._dialog.destroy()

    def wait(self):
        """Wait for the dialog to close."""
        if self._dialog.winfo_exists():
            self._parent.wait_window(self._dialog)

    @property
    def dialog(self):
        """Return the Toplevel widget (for testing)."""
        return self._dialog

    @property
    def rollback_result(self):
        """Return the rollback result (for testing)."""
        return self._rollback_result

    @property
    def backups(self):
        """Return the loaded backup list (for testing)."""
        return self._backups


def rollback_to_backup(parent, session_manager: AWSSessionManager,
                       region: str, base_name: str, target_arn: str,
                       notification_topic_arn: Optional[str] = None) -> Optional[Dict]:
    """Show the Rollback dialog and return the result.

    Args:
        parent: Parent tkinter widget.
        session_manager: AWSSessionManager instance.
        region: AWS region.
        base_name: Output rule group name to find backups for.
        target_arn: ARN of the primary rule group to restore to.
        notification_topic_arn: Optional SNS topic for rollback notifications.

    Returns:
        Rollback result dict if rollback was performed, None otherwise.
    """
    dialog = RollbackDialog(parent, session_manager, region, base_name,
                            target_arn, notification_topic_arn=notification_topic_arn)
    dialog.wait()
    return dialog.rollback_result