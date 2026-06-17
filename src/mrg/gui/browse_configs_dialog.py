"""
Browse Deployed Configurations Dialog for Managed Rule Group Generator

Allows users to:
- Select a region and check for deployed MRG configurations
- View all configurations currently deployed to that region's Lambda
- Download/save specific configurations as .mrg files to disk

The Lambda function stores configurations in its RULE_GROUP_CONFIGS
environment variable. This dialog reads those configs and presents them
in a browsable list with details.
"""

import json
import logging
import os
import platform
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional

from src.aws.aws_session_manager import AWSSessionManager

logger = logging.getLogger(__name__)

# Regions list (same as config_panel)
AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-south-2',
    'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4',
    'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ca-central-1', 'ca-west-1',
    'eu-central-1', 'eu-central-2', 'eu-west-1', 'eu-west-2', 'eu-west-3',
    'eu-south-1', 'eu-south-2', 'eu-north-1',
    'il-central-1', 'me-south-1', 'me-central-1', 'sa-east-1',
]


def lambda_config_to_mrg_config(lambda_config: Dict, region: str,
                                aws_profile: Optional[str] = None):
    """Convert a Lambda configuration dict back to an MRGConfig object.

    The Lambda config stores a subset of the full MRGConfig fields.
    This reconstructs a usable MRGConfig for saving as a .mrg file.

    Args:
        lambda_config: Configuration dict from the Lambda's RULE_GROUP_CONFIGS.
        region: AWS region the Lambda is deployed in.
        aws_profile: AWS profile name used to access the config.

    Returns:
        MRGConfig instance populated from the Lambda config.
    """
    from src.mrg.core.mrg_file import MRGConfig

    config = MRGConfig()
    config.region = region
    config.aws_profile = aws_profile

    # Core fields from Lambda config
    config.name = lambda_config.get('name', '')
    config.output_rule_group_name = lambda_config.get('name', '')
    config.output_rule_group_arn = lambda_config.get('output_rule_group_arn', '')
    config.output_rule_group_capacity = lambda_config.get('output_rule_group_capacity', 8000)
    config.source_rule_groups = lambda_config.get('source_rule_groups', [])
    config.filters = lambda_config.get('filters', {'logic': 'AND', 'conditions': []})
    config.missing_metadata_behavior = lambda_config.get('missing_metadata_behavior', 'exclude')
    config.deployment_mode = lambda_config.get('deployment_mode', 'as_is')
    config.action_override = lambda_config.get('action_override')
    config.notification_topic_arn = lambda_config.get('notification_topic_arn')

    # Mark as deployed since it was retrieved from a live Lambda
    from src.mrg.core.mrg_file import _now_iso
    config.last_deployed_at = _now_iso()

    return config


class BrowseDeployedConfigsDialog:
    """Dialog for browsing and downloading deployed configurations.

    Connects to the MRG Lambda function in a selected region, retrieves
    all stored configurations, and presents them in a list. Users can
    select configurations and save them as .mrg files.
    """

    def __init__(self, parent: tk.Tk, session_manager: AWSSessionManager,
                 current_region: str = 'us-east-1',
                 current_profile: Optional[str] = None):
        """Initialize the browse dialog.

        Args:
            parent: Parent tkinter window.
            session_manager: AWSSessionManager instance.
            current_region: Pre-selected region.
            current_profile: Current AWS profile name.
        """
        self._parent = parent
        self._session_manager = session_manager
        self._current_region = current_region
        self._current_profile = current_profile
        self._configs: List[Dict] = []
        self._is_loading = False

        self._dialog = tk.Toplevel(parent)
        self._dialog.title("Browse Deployed Configurations")
        self._dialog.geometry("780x520")
        self._dialog.minsize(650, 400)
        self._dialog.resizable(True, True)

        if platform.system() != 'Darwin':
            self._dialog.transient(parent)
        self._dialog.grab_set()

        self._setup_ui()

    def _setup_ui(self):
        """Build all dialog widgets."""
        main_frame = ttk.Frame(self._dialog, padding=12)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # â”€â”€ Top bar: Region selector + Scan button â”€â”€
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(top_frame, text="Region:").pack(side=tk.LEFT, padx=(0, 4))
        self._region_var = tk.StringVar(value=self._current_region)
        self._region_combo = ttk.Combobox(
            top_frame,
            textvariable=self._region_var,
            values=AWS_REGIONS,
            state='readonly',
            width=16,
        )
        self._region_combo.pack(side=tk.LEFT, padx=(0, 8))

        profile_display = self._current_profile or '(default)'
        ttk.Label(top_frame, text="Profile:").pack(side=tk.LEFT, padx=(0, 4))
        self._profile_label = ttk.Label(
            top_frame, text=profile_display,
            font=('TkDefaultFont', 9, 'bold'),
        )
        self._profile_label.pack(side=tk.LEFT, padx=(0, 12))

        self._scan_btn = ttk.Button(
            top_frame,
            text="Scan Region",
            command=self._scan_region,
        )
        self._scan_btn.pack(side=tk.LEFT, padx=(0, 8))

        # â”€â”€ Status label â”€â”€
        self._status_label = ttk.Label(
            main_frame, text="Select a region and click Scan Region to check for deployed configurations.",
            font=('TkDefaultFont', 9),
        )
        self._status_label.pack(fill=tk.X, pady=(0, 8))

        # â”€â”€ Progress bar (hidden by default) â”€â”€
        self._progress_frame = ttk.Frame(main_frame)
        self._progress_bar = ttk.Progressbar(
            self._progress_frame, mode='indeterminate', length=400,
        )
        self._progress_bar.pack(fill=tk.X, padx=4, pady=4)

        # â”€â”€ Configuration list (treeview) â”€â”€
        list_label_frame = ttk.LabelFrame(main_frame, text="Deployed Configurations")
        list_label_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        columns = ('name', 'capacity', 'sources', 'filters', 'mode', 'rule_group_arn')
        self._tree = ttk.Treeview(
            list_label_frame,
            columns=columns,
            show='headings',
            selectmode='extended',
        )

        self._tree.heading('name', text='Name')
        self._tree.heading('capacity', text='Capacity')
        self._tree.heading('sources', text='Sources')
        self._tree.heading('filters', text='Filter Conditions')
        self._tree.heading('mode', text='Mode')
        self._tree.heading('rule_group_arn', text='Rule Group ARN')

        self._tree.column('name', width=160, minwidth=100)
        self._tree.column('capacity', width=70, minwidth=50, anchor=tk.CENTER)
        self._tree.column('sources', width=60, minwidth=40, anchor=tk.CENTER)
        self._tree.column('filters', width=120, minwidth=80)
        self._tree.column('mode', width=70, minwidth=50, anchor=tk.CENTER)
        self._tree.column('rule_group_arn', width=280, minwidth=150)

        # Scrollbars
        vsb = ttk.Scrollbar(list_label_frame, orient=tk.VERTICAL, command=self._tree.yview)
        hsb = ttk.Scrollbar(list_label_frame, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        list_label_frame.grid_rowconfigure(0, weight=1)
        list_label_frame.grid_columnconfigure(0, weight=1)

        # Bind selection event
        self._tree.bind('<<TreeviewSelect>>', self._on_selection_changed)

        # â”€â”€ Detail panel â”€â”€
        detail_frame = ttk.LabelFrame(main_frame, text="Configuration Details")
        detail_frame.pack(fill=tk.X, pady=(0, 8))

        self._detail_text = tk.Text(
            detail_frame, height=6, wrap=tk.WORD, state=tk.DISABLED,
            font=('TkDefaultFont', 9),
        )
        detail_sb = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self._detail_text.yview)
        self._detail_text.configure(yscrollcommand=detail_sb.set)
        self._detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0), pady=4)
        detail_sb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 4), pady=4)

        # â”€â”€ Bottom button bar â”€â”€
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        self._download_btn = ttk.Button(
            btn_frame,
            text="Download Selected as .mrg",
            command=self._download_selected,
            state=tk.DISABLED,
        )
        self._download_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._download_all_btn = ttk.Button(
            btn_frame,
            text="Download All",
            command=self._download_all,
            state=tk.DISABLED,
        )
        self._download_all_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._close_btn = ttk.Button(
            btn_frame,
            text="Close",
            command=self._close,
        )
        self._close_btn.pack(side=tk.RIGHT)

    # â”€â”€â”€ Scan Region â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _scan_region(self):
        """Scan the selected region for deployed configurations."""
        if self._is_loading:
            return

        region = self._region_var.get()
        if not region:
            messagebox.showwarning("No Region", "Please select an AWS region.", parent=self._dialog)
            return

        self._is_loading = True
        self._scan_btn.config(state=tk.DISABLED)
        self._download_btn.config(state=tk.DISABLED)
        self._download_all_btn.config(state=tk.DISABLED)
        self._tree.delete(*self._tree.get_children())
        self._configs = []
        self._clear_detail()
        self._status_label.config(text="Scanning {}...".format(region))
        self._progress_frame.pack(fill=tk.X, pady=(0, 4))
        self._progress_bar.start(15)

        def _do_scan():
            from src.mrg.aws.lambda_deployer import (
                get_lambda_configs,
                get_lambda_function,
                LambdaNotFoundError,
            )
            try:
                # Step 1: Check if Lambda exists
                func_info = get_lambda_function(self._session_manager, region)
                if func_info is None:
                    self._parent.after(0, lambda: self._on_scan_complete(
                        None, region,
                        "No Managed Rule Generator Lambda function found in {}.".format(region)
                    ))
                    return

                # Step 2: Get configs from Lambda
                configs = get_lambda_configs(self._session_manager, region)
                self._parent.after(0, lambda: self._on_scan_complete(configs, region, None))

            except LambdaNotFoundError:
                self._parent.after(0, lambda: self._on_scan_complete(
                    None, region,
                    "No Managed Rule Generator Lambda function found in {}.".format(region)
                ))
            except Exception as e:
                error_msg = str(e)
                self._parent.after(0, lambda: self._on_scan_complete(
                    None, region,
                    "Error scanning {}: {}".format(region, error_msg)
                ))

        threading.Thread(target=_do_scan, daemon=True).start()

    def _on_scan_complete(self, configs: Optional[List[Dict]], region: str,
                          error_msg: Optional[str]):
        """Handle scan completion on the main thread.

        Args:
            configs: List of config dicts from Lambda, or None on error.
            region: The scanned region.
            error_msg: Error message if scan failed, None on success.
        """
        self._is_loading = False
        self._scan_btn.config(state=tk.NORMAL)
        self._progress_bar.stop()
        self._progress_frame.pack_forget()

        if error_msg:
            self._status_label.config(text=error_msg)
            self._configs = []
            return

        if not configs:
            self._status_label.config(
                text="Lambda function found in {}, but no configurations are deployed.".format(region)
            )
            self._configs = []
            return

        self._configs = configs
        count = len(configs)
        self._status_label.config(
            text="Found {} configuration{} deployed in {}.".format(
                count, 's' if count != 1 else '', region
            )
        )

        # Populate treeview
        for i, cfg in enumerate(configs):
            name = cfg.get('name', '(unnamed)')
            capacity = cfg.get('output_rule_group_capacity', '?')
            sources = len(cfg.get('source_rule_groups', []))
            filters_data = cfg.get('filters', {})
            conditions = filters_data.get('conditions', [])
            filter_summary = self._build_filter_summary(conditions)
            mode = cfg.get('deployment_mode', 'as_is')
            mode_display = 'Test Mode' if mode == 'test_mode' else 'As-Is'
            rg_arn = cfg.get('output_rule_group_arn', '')

            self._tree.insert('', tk.END, iid=str(i), values=(
                name,
                str(capacity),
                str(sources),
                filter_summary,
                mode_display,
                rg_arn,
            ))

        self._download_all_btn.config(state=tk.NORMAL)

    def _build_filter_summary(self, conditions: List[Dict]) -> str:
        """Build a short text summary of filter conditions.

        Args:
            conditions: List of condition dicts from the config.

        Returns:
            Short summary string like "severity=Major,Critical; deployment=Internal".
        """
        if not conditions:
            return '(no filters)'

        parts = []
        for cond in conditions:
            field = cond.get('field', '?')
            # Shorten known field names
            short_field = field.replace('signature_', '').replace('_', ' ')
            operator = cond.get('operator', '=')
            values = cond.get('values', [])
            values_str = ','.join(str(v) for v in values)
            if operator in ('equals', 'in'):
                parts.append("{}={}".format(short_field, values_str))
            elif operator == 'not_equals':
                parts.append("{}!={}".format(short_field, values_str))
            elif operator == 'not_in':
                parts.append("{} not in {}".format(short_field, values_str))
            elif operator == 'contains':
                parts.append("{} contains {}".format(short_field, values_str))
            else:
                parts.append("{} {} {}".format(short_field, operator, values_str))

        return '; '.join(parts)

    # â”€â”€â”€ Selection & Details â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _on_selection_changed(self, event=None):
        """Handle treeview selection change."""
        selected = self._tree.selection()
        if selected:
            self._download_btn.config(state=tk.NORMAL)
            # Show details for the first selected item
            idx = int(selected[0])
            if 0 <= idx < len(self._configs):
                self._show_config_detail(self._configs[idx])
        else:
            self._download_btn.config(state=tk.DISABLED)
            self._clear_detail()

    def _show_config_detail(self, cfg: Dict):
        """Display detailed information about a configuration.

        Args:
            cfg: Configuration dict from the Lambda.
        """
        self._detail_text.config(state=tk.NORMAL)
        self._detail_text.delete('1.0', tk.END)

        lines = []
        lines.append("Name: {}".format(cfg.get('name', '(unnamed)')))
        lines.append("Rule Group ARN: {}".format(cfg.get('output_rule_group_arn', 'N/A')))
        lines.append("Capacity: {}".format(cfg.get('output_rule_group_capacity', '?')))
        lines.append("Rule Order: {}".format(cfg.get('rule_order', 'STRICT_ORDER')))
        lines.append("Deployment Mode: {}".format(
            'Test Mode' if cfg.get('deployment_mode') == 'test_mode' else 'As-Is'))
        lines.append("Missing Metadata: {}".format(cfg.get('missing_metadata_behavior', 'exclude')))

        # Source rule groups
        sources = cfg.get('source_rule_groups', [])
        lines.append("")
        lines.append("Source Rule Groups ({}):" .format(len(sources)))
        for src in sources:
            short_name = src.split('/')[-1] if '/' in src else src
            lines.append("  - {}".format(short_name))

        # Filters
        filters_data = cfg.get('filters', {})
        conditions = filters_data.get('conditions', [])
        logic = filters_data.get('logic', 'AND')
        lines.append("")
        lines.append("Filters (logic: {}):".format(logic))
        if not conditions:
            lines.append("  (no filter conditions)")
        for cond in conditions:
            field = cond.get('field', '?')
            operator = cond.get('operator', '?')
            values = cond.get('values', [])
            lines.append("  {} {} {}".format(field, operator, ', '.join(str(v) for v in values)))

        # Notification
        notif_arn = cfg.get('notification_topic_arn')
        if notif_arn:
            lines.append("")
            lines.append("Notification Topic: {}".format(notif_arn))

        self._detail_text.insert('1.0', '\n'.join(lines))
        self._detail_text.config(state=tk.DISABLED)

    def _clear_detail(self):
        """Clear the detail text panel."""
        self._detail_text.config(state=tk.NORMAL)
        self._detail_text.delete('1.0', tk.END)
        self._detail_text.config(state=tk.DISABLED)

    # â”€â”€â”€ Download â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _download_selected(self):
        """Download selected configurations as .mrg files."""
        selected = self._tree.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Please select one or more configurations to download.",
                                parent=self._dialog)
            return

        region = self._region_var.get()
        configs_to_save = []
        for item_id in selected:
            idx = int(item_id)
            if 0 <= idx < len(self._configs):
                configs_to_save.append(self._configs[idx])

        if len(configs_to_save) == 1:
            # Single config - use Save As dialog
            self._save_single_config(configs_to_save[0], region)
        else:
            # Multiple configs - ask for directory
            self._save_multiple_configs(configs_to_save, region)

    def _download_all(self):
        """Download all configurations as .mrg files."""
        if not self._configs:
            messagebox.showinfo("No Configurations", "No configurations to download.",
                                parent=self._dialog)
            return

        region = self._region_var.get()
        if len(self._configs) == 1:
            self._save_single_config(self._configs[0], region)
        else:
            self._save_multiple_configs(self._configs, region)

    def _save_single_config(self, lambda_config: Dict, region: str):
        """Save a single configuration as a .mrg file with Save As dialog.

        Args:
            lambda_config: The Lambda configuration dict.
            region: AWS region.
        """
        name = lambda_config.get('name', 'config')
        initial_name = "{}.mrg".format(name)

        filepath = filedialog.asksaveasfilename(
            parent=self._dialog,
            title="Save Configuration As",
            filetypes=[("MRG Configuration", "*.mrg"), ("All Files", "*.*")],
            defaultextension=".mrg",
            initialfile=initial_name,
        )
        if not filepath:
            return

        try:
            mrg_config = lambda_config_to_mrg_config(
                lambda_config, region, aws_profile=self._current_profile
            )
            from src.mrg.core.mrg_file import write_mrg_file
            write_mrg_file(filepath, mrg_config)

            filename = os.path.basename(filepath)
            messagebox.showinfo(
                "Configuration Saved",
                "Configuration '{}' saved to:\n{}".format(name, filename),
                parent=self._dialog,
            )
            logger.info("Saved deployed config '%s' to %s", name, filepath)

        except Exception as e:
            messagebox.showerror(
                "Save Error",
                "Failed to save configuration:\n\n{}".format(str(e)),
                parent=self._dialog,
            )

    def _save_multiple_configs(self, lambda_configs: List[Dict], region: str):
        """Save multiple configurations as .mrg files in a chosen directory.

        Args:
            lambda_configs: List of Lambda configuration dicts.
            region: AWS region.
        """
        directory = filedialog.askdirectory(
            parent=self._dialog,
            title="Select Directory to Save {} Configurations".format(len(lambda_configs)),
        )
        if not directory:
            return

        saved = 0
        errors = []
        for cfg in lambda_configs:
            name = cfg.get('name', 'config')
            # Sanitize name for use as filename
            safe_name = _sanitize_filename(name)
            filepath = os.path.join(directory, "{}.mrg".format(safe_name))

            # Avoid overwriting - add suffix if file exists
            filepath = _unique_filepath(filepath)

            try:
                mrg_config = lambda_config_to_mrg_config(
                    cfg, region, aws_profile=self._current_profile
                )
                from src.mrg.core.mrg_file import write_mrg_file
                write_mrg_file(filepath, mrg_config)
                saved += 1
                logger.info("Saved deployed config '%s' to %s", name, filepath)
            except Exception as e:
                errors.append("'{}': {}".format(name, str(e)))

        # Report results
        if errors:
            messagebox.showwarning(
                "Partial Save",
                "Saved {} of {} configurations.\n\nErrors:\n{}".format(
                    saved, len(lambda_configs), "\n".join(errors)
                ),
                parent=self._dialog,
            )
        else:
            messagebox.showinfo(
                "Configurations Saved",
                "All {} configurations saved to:\n{}".format(saved, directory),
                parent=self._dialog,
            )

    # â”€â”€â”€ Close â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _close(self):
        """Close the dialog."""
        if self._dialog.winfo_exists():
            self._dialog.grab_release()
            self._dialog.destroy()

    def wait(self):
        """Wait for the dialog to close."""
        if self._dialog.winfo_exists():
            self._parent.wait_window(self._dialog)


def _sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename.

    Replaces characters that are not alphanumeric, hyphens, or underscores
    with underscores.

    Args:
        name: The raw name string.

    Returns:
        Sanitized filename-safe string.
    """
    import re
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    return sanitized if sanitized else 'config'


def _unique_filepath(filepath: str) -> str:
    """Ensure the filepath is unique by appending a counter if needed.

    Args:
        filepath: The desired file path.

    Returns:
        A unique file path (may have _2, _3, etc. appended before extension).
    """
    if not os.path.exists(filepath):
        return filepath

    base, ext = os.path.splitext(filepath)
    counter = 2
    while os.path.exists("{}_{:d}{}".format(base, counter, ext)):
        counter += 1
    return "{}_{:d}{}".format(base, counter, ext)


def browse_deployed_configs(parent: tk.Tk,
                            session_manager: AWSSessionManager,
                            current_region: str = 'us-east-1',
                            current_profile: Optional[str] = None):
    """Open the Browse Deployed Configurations dialog.

    Convenience function that creates and displays the dialog.

    Args:
        parent: Parent tkinter window.
        session_manager: AWSSessionManager instance.
        current_region: Pre-selected region.
        current_profile: Current AWS profile name.
    """
    dialog = BrowseDeployedConfigsDialog(
        parent, session_manager,
        current_region=current_region,
        current_profile=current_profile,
    )
    dialog.wait()
