"""
Backup Manager Dialog for Managed Rule Group Generator.

Tools > Manage Backups dialog:
- Lists all backup rule groups for the current configuration
  (pattern: <name>_YYYYMMDD_HHMMSS), sorted by date (newest first).
- Shows backup name, timestamp, rule count.
- Allows deleting individual backups or cleaning up old backups (keep N most recent).

See Feature Spec Section 9 (Backup & Rollback), Section 9.2 (Backup Retention).
"""

import logging
import platform
import re
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, Dict, List, Optional

from src.aws.aws_session_manager import AWSSessionManager

logger = logging.getLogger(__name__)

# Pattern for backup rule group names:
#   New format: <name>-bak-YYYYMMDD-HHMMSS
#   Legacy format: <name>_YYYYMMDD_HHMMSS
_BACKUP_NEW_PATTERN = re.compile(r'^(.+)-bak-(\d{8}-\d{6})$')
_BACKUP_LEGACY_PATTERN = re.compile(r'^(.+)_(\d{8}_\d{6})$')


def parse_backup_timestamp(backup_name: str, base_name: str) -> Optional[str]:
    """Extract the timestamp suffix from a backup rule group name.

    Supports both new format (<name>-bak-YYYYMMDD-HHMMSS) and legacy
    format (<name>_YYYYMMDD_HHMMSS) for backwards compatibility.

    Args:
        backup_name: Full backup rule group name.
        base_name: Base rule group name (without timestamp).

    Returns:
        Timestamp string (YYYYMMDD-HHMMSS or YYYYMMDD_HHMMSS) if matched,
        None otherwise.
    """
    # Try new format first: <name>-bak-YYYYMMDD-HHMMSS
    new_prefix = base_name + '-bak-'
    if backup_name.startswith(new_prefix):
        suffix = backup_name[len(new_prefix):]
        if re.match(r'^\d{8}-\d{6}$', suffix):
            return suffix

    # Try legacy format: <name>_YYYYMMDD_HHMMSS
    legacy_prefix = base_name + '_'
    if backup_name.startswith(legacy_prefix):
        suffix = backup_name[len(legacy_prefix):]
        if re.match(r'^\d{8}_\d{6}$', suffix):
            return suffix

    return None


def format_timestamp(ts: str) -> str:
    """Format a backup timestamp for display.

    Supports both new format (YYYYMMDD-HHMMSS) and legacy (YYYYMMDD_HHMMSS).

    Args:
        ts: Timestamp string like '20260220-213000' or '20260220_213000'.

    Returns:
        Formatted string like '2026-02-20 21:30:00'.
    """
    if len(ts) != 15:
        return ts
    try:
        # Handle both separator styles (hyphen or underscore at position 8)
        return '{}-{}-{} {}:{}:{}'.format(
            ts[0:4], ts[4:6], ts[6:8],
            ts[9:11], ts[11:13], ts[13:15],
        )
    except (IndexError, ValueError):
        return ts


def list_backups_for_config(session_manager: AWSSessionManager,
                            region: str,
                            base_name: str) -> List[Dict]:
    """List all backup rule groups for a given configuration.

    Scans all user-managed rule groups and finds those matching
    the pattern <base_name>_YYYYMMDD_HHMMSS.

    Args:
        session_manager: AWSSessionManager instance.
        region: AWS region.
        base_name: The output rule group name to find backups for.

    Returns:
        List of dicts sorted by timestamp (newest first), each with:
        - 'Name': Backup rule group name
        - 'Arn': Backup rule group ARN
        - 'Timestamp': Extracted timestamp string (YYYYMMDD_HHMMSS)
        - 'FormattedTimestamp': Human-readable timestamp
    """
    from src.mrg.aws.network_firewall import list_user_rule_groups

    all_rgs = list_user_rule_groups(session_manager, region)
    backups = []
    for rg in all_rgs:
        name = rg.get('Name', '')
        ts = parse_backup_timestamp(name, base_name)
        if ts:
            backups.append({
                'Name': name,
                'Arn': rg.get('Arn', ''),
                'Timestamp': ts,
                'FormattedTimestamp': format_timestamp(ts),
            })

    # Sort newest first
    backups.sort(key=lambda b: b['Timestamp'], reverse=True)
    return backups


def get_backup_rule_count(session_manager: AWSSessionManager,
                          region: str,
                          rule_group_arn: str) -> int:
    """Get the rule count for a backup rule group.

    Args:
        session_manager: AWSSessionManager instance.
        region: AWS region.
        rule_group_arn: ARN of the backup rule group.

    Returns:
        Number of rules in the backup, or -1 on error.
    """
    from src.mrg.aws.network_firewall import describe_rule_group

    try:
        info = describe_rule_group(session_manager, region, rule_group_arn=rule_group_arn)
        rules_string = info.get('RulesString', '')
        if not rules_string.strip():
            return 0
        # Count non-empty, non-comment lines
        count = 0
        for line in rules_string.split('\n'):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                count += 1
        return count
    except Exception as e:
        logger.warning("Failed to get rule count for %s: %s", rule_group_arn, str(e))
        return -1


def delete_backup(session_manager: AWSSessionManager,
                  region: str,
                  rule_group_arn: str) -> bool:
    """Delete a single backup rule group.

    Args:
        session_manager: AWSSessionManager instance.
        region: AWS region.
        rule_group_arn: ARN of the backup rule group to delete.

    Returns:
        True if deleted successfully.

    Raises:
        Exception: If deletion fails.
    """
    from src.mrg.aws.network_firewall import delete_rule_group

    return delete_rule_group(session_manager, region, rule_group_arn=rule_group_arn)


def cleanup_old_backups(session_manager: AWSSessionManager,
                        region: str,
                        base_name: str,
                        keep_count: int) -> Dict:
    """Delete old backups, keeping only the N most recent.

    Args:
        session_manager: AWSSessionManager instance.
        region: AWS region.
        base_name: The output rule group name to find backups for.
        keep_count: Number of most recent backups to keep.

    Returns:
        Dict with:
        - 'total_found': Total number of backups found
        - 'kept': Number kept
        - 'deleted': Number deleted
        - 'errors': Number of deletion errors
        - 'deleted_names': List of deleted backup names
    """
    backups = list_backups_for_config(session_manager, region, base_name)
    total = len(backups)

    if total <= keep_count:
        return {
            'total_found': total,
            'kept': total,
            'deleted': 0,
            'errors': 0,
            'deleted_names': [],
        }

    to_delete = backups[keep_count:]
    deleted = 0
    errors = 0
    deleted_names = []

    for backup in to_delete:
        try:
            delete_backup(session_manager, region, backup['Arn'])
            deleted += 1
            deleted_names.append(backup['Name'])
        except Exception as e:
            errors += 1
            logger.warning("Failed to delete backup %s: %s", backup['Name'], str(e))

    return {
        'total_found': total,
        'kept': keep_count,
        'deleted': deleted,
        'errors': errors,
        'deleted_names': deleted_names,
    }


class BackupManagerDialog:
    """Modal dialog for managing backup rule groups.

    Displays a list of backups for the current configuration, allows
    deleting individual backups, and provides a cleanup function to
    keep only the N most recent backups.
    """

    def __init__(self, parent, session_manager: AWSSessionManager,
                 region: str, base_name: str,
                 on_rollback: Optional[Callable] = None):
        """Create the backup manager dialog.

        Args:
            parent: Parent tkinter widget.
            session_manager: AWSSessionManager instance.
            region: AWS region.
            base_name: Output rule group name to find backups for.
            on_rollback: Optional callback when user wants to rollback from here.
        """
        self._parent = parent
        self._session_manager = session_manager
        self._region = region
        self._base_name = base_name
        self._on_rollback = on_rollback
        self._backups = []
        self._rule_counts = {}  # arn -> count

        self._dialog = tk.Toplevel(parent)
        self._dialog.title("Manage Backups — {}".format(base_name))
        self._dialog.geometry("650x450")
        self._dialog.minsize(550, 350)
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
                           text="Backup rule groups for '{}'".format(self._base_name),
                           font=('TkDefaultFont', 11, 'bold'))
        header.pack(anchor=tk.W, pady=(0, 8))

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

        # Button frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 4))

        self._delete_btn = ttk.Button(btn_frame, text="Delete Selected",
                                      command=self._delete_selected, state=tk.DISABLED)
        self._delete_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._cleanup_btn = ttk.Button(btn_frame, text="Cleanup Old Backups...",
                                       command=self._cleanup_backups, state=tk.DISABLED)
        self._cleanup_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._refresh_btn = ttk.Button(btn_frame, text="Refresh",
                                       command=self._load_backups)
        self._refresh_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._close_btn = ttk.Button(btn_frame, text="Close", command=self._close)
        self._close_btn.pack(side=tk.RIGHT)

        # Bind selection event
        self._tree.bind('<<TreeviewSelect>>', self._on_selection_change)

    def _on_selection_change(self, event=None):
        """Enable/disable buttons based on selection."""
        selected = self._tree.selection()
        if selected:
            self._delete_btn.config(state=tk.NORMAL)
        else:
            self._delete_btn.config(state=tk.DISABLED)

    def _load_backups(self):
        """Load backup list from AWS in a background thread."""
        self._status_label.config(text="Loading backups...")
        self._tree.delete(*self._tree.get_children())
        self._delete_btn.config(state=tk.DISABLED)
        self._cleanup_btn.config(state=tk.DISABLED)
        self._refresh_btn.config(state=tk.DISABLED)

        def _do_load():
            try:
                backups = list_backups_for_config(
                    self._session_manager, self._region, self._base_name)

                # Get rule counts for each backup
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
        self._status_label.config(
            text="{} backup{} found.".format(count, 's' if count != 1 else ''))
        self._refresh_btn.config(state=tk.NORMAL)
        self._cleanup_btn.config(state=tk.NORMAL if count > 0 else tk.DISABLED)

    def _on_load_error(self, error_msg: str):
        """Handle load failure."""
        if not self._dialog.winfo_exists():
            return
        self._status_label.config(text="Error loading backups: {}".format(error_msg))
        self._refresh_btn.config(state=tk.NORMAL)

    def _delete_selected(self):
        """Delete the selected backup rule group."""
        selected = self._tree.selection()
        if not selected:
            return

        arn = selected[0]
        # Find backup name
        backup_name = ''
        for b in self._backups:
            if b['Arn'] == arn:
                backup_name = b['Name']
                break

        if not messagebox.askyesno(
                "Delete Backup",
                "Delete backup '{}'?\n\nThis cannot be undone.".format(backup_name),
                parent=self._dialog):
            return

        self._status_label.config(text="Deleting {}...".format(backup_name))
        self._delete_btn.config(state=tk.DISABLED)

        def _do_delete():
            try:
                delete_backup(self._session_manager, self._region, arn)
                self._parent.after(0, lambda: self._on_delete_complete(backup_name))
            except Exception as e:
                self._parent.after(0, lambda: self._on_delete_error(backup_name, str(e)))

        threading.Thread(target=_do_delete, daemon=True).start()

    def _on_delete_complete(self, backup_name: str):
        """Handle successful deletion."""
        if not self._dialog.winfo_exists():
            return
        self._status_label.config(text="Deleted '{}'.".format(backup_name))
        self._load_backups()

    def _on_delete_error(self, backup_name: str, error_msg: str):
        """Handle deletion failure."""
        if not self._dialog.winfo_exists():
            return
        self._status_label.config(text="Error deleting backup.")
        self._delete_btn.config(state=tk.NORMAL)
        messagebox.showerror("Delete Error",
                             "Failed to delete '{}':\n\n{}".format(backup_name, error_msg),
                             parent=self._dialog)

    def _cleanup_backups(self):
        """Show cleanup dialog and delete old backups."""
        if not self._backups:
            messagebox.showinfo("No Backups", "No backups to clean up.",
                                parent=self._dialog)
            return

        # Ask user how many to keep
        cleanup_dialog = tk.Toplevel(self._dialog)
        cleanup_dialog.title("Cleanup Old Backups")
        cleanup_dialog.geometry("350x180")
        cleanup_dialog.resizable(False, False)
        if platform.system() != 'Darwin':
            cleanup_dialog.transient(self._dialog)
        cleanup_dialog.grab_set()

        frame = ttk.Frame(cleanup_dialog, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Keep the most recent backups:",
                  font=('TkDefaultFont', 10)).pack(anchor=tk.W, pady=(0, 8))

        count_frame = ttk.Frame(frame)
        count_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(count_frame, text="Number to keep:").pack(side=tk.LEFT, padx=(0, 8))
        keep_var = tk.StringVar(value='5')
        keep_spin = ttk.Spinbox(count_frame, from_=1, to=100,
                                textvariable=keep_var, width=8)
        keep_spin.pack(side=tk.LEFT)

        total_count = len(self._backups)
        info_label = ttk.Label(frame,
                               text="Currently {} backup{}.".format(
                                   total_count, 's' if total_count != 1 else ''),
                               font=('TkDefaultFont', 9))
        info_label.pack(anchor=tk.W, pady=(0, 12))

        result = {'confirmed': False, 'keep': 5}

        def _on_ok():
            try:
                keep = int(keep_var.get())
                if keep < 1:
                    keep = 1
                result['keep'] = keep
                result['confirmed'] = True
            except ValueError:
                result['keep'] = 5
                result['confirmed'] = True
            cleanup_dialog.destroy()

        def _on_cancel():
            cleanup_dialog.destroy()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Cleanup", command=_on_ok).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text="Cancel", command=_on_cancel).pack(side=tk.LEFT)

        cleanup_dialog.protocol("WM_DELETE_WINDOW", _on_cancel)
        if cleanup_dialog.winfo_exists():
            self._dialog.wait_window(cleanup_dialog)

        if not result['confirmed']:
            return

        keep_count = result['keep']
        to_delete_count = max(0, total_count - keep_count)

        if to_delete_count == 0:
            messagebox.showinfo("Nothing to Delete",
                                "All {} backup{} will be kept (keeping {}).".format(
                                    total_count, 's' if total_count != 1 else '', keep_count),
                                parent=self._dialog)
            return

        if not messagebox.askyesno(
                "Confirm Cleanup",
                "Delete {} old backup{}?\n\n"
                "Keeping the {} most recent backup{}.".format(
                    to_delete_count, 's' if to_delete_count != 1 else '',
                    keep_count, 's' if keep_count != 1 else ''),
                parent=self._dialog):
            return

        self._status_label.config(text="Cleaning up old backups...")
        self._cleanup_btn.config(state=tk.DISABLED)
        self._delete_btn.config(state=tk.DISABLED)

        def _do_cleanup():
            try:
                result_info = cleanup_old_backups(
                    self._session_manager, self._region,
                    self._base_name, keep_count)
                self._parent.after(0, lambda: self._on_cleanup_complete(result_info))
            except Exception as e:
                self._parent.after(0, lambda: self._on_cleanup_error(str(e)))

        threading.Thread(target=_do_cleanup, daemon=True).start()

    def _on_cleanup_complete(self, result: Dict):
        """Handle cleanup completion."""
        if not self._dialog.winfo_exists():
            return

        msg = "Cleanup: {} deleted, {} kept".format(
            result['deleted'], result['kept'])
        if result['errors'] > 0:
            msg += ", {} errors".format(result['errors'])
        msg += "."
        self._status_label.config(text=msg)
        self._load_backups()

    def _on_cleanup_error(self, error_msg: str):
        """Handle cleanup failure."""
        if not self._dialog.winfo_exists():
            return
        self._status_label.config(text="Cleanup error.")
        self._cleanup_btn.config(state=tk.NORMAL)
        messagebox.showerror("Cleanup Error",
                             "Failed to cleanup backups:\n\n{}".format(error_msg),
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
    def backups(self):
        """Return the loaded backup list (for testing)."""
        return self._backups


def manage_backups(parent, session_manager: AWSSessionManager,
                   region: str, base_name: str,
                   on_rollback: Optional[Callable] = None):
    """Show the Manage Backups dialog.

    Args:
        parent: Parent tkinter widget.
        session_manager: AWSSessionManager instance.
        region: AWS region.
        base_name: Output rule group name to find backups for.
        on_rollback: Optional callback for rollback action.
    """
    dialog = BackupManagerDialog(parent, session_manager, region, base_name,
                                 on_rollback=on_rollback)
    dialog.wait()