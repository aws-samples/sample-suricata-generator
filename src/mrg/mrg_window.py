"""
MRG Window - Toplevel Orchestrator for Managed Rule Group Generator

This module provides the MRGWindow class, a tk.Toplevel-based window that
integrates all MRG GUI components and orchestrates the build/deploy pipeline.

The MRGWindow is designed to be launched from the main Suricata Generator
application. It shares the parent's AWSSessionManager for credential management
but maintains its own profile state (changes are local to the MRG window).

Key responsibilities:
- Creates Toplevel window with own menu bar (File, Tools, Help)
- Wires together ConfigPanel, RuleTable, StatusBar, ViewFilterBar, SearchBar
- Manages build pipeline: fetch -> parse -> filter -> dedup -> test_mode -> display
- Manages deploy workflow via DeployDialog
- Tracks unsaved-changes state
- Registers/unregisters from parent's MRG window set
- Implements profile isolation (MRG profile changes don't affect main app)
- Implements capacity auto-calculation (rule count + 1000 buffer)
- Implements deploy button disabling when count exceeds capacity or rules > 2MB
"""

import json
import logging
import os
import platform
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Dict, List, Optional

from src.aws.aws_session_manager import AWSSessionManager
from src.mrg.core.mrg_file import (
    MRGConfig,
    MRGFileError,
    create_new_config,
    read_mrg_file,
    write_mrg_file,
)
from src.mrg.gui.config_panel import ConfigPanel
from src.mrg.gui.log_viewer import GUILogHandler, LogViewerWindow
from src.mrg.gui.rule_table import RuleTable
from src.mrg.gui.search_bar import SearchBar
from src.mrg.gui.status_bar import StatusBar
from src.mrg.gui.view_filter_bar import ViewFilterBar
from src.mrg.version import MRG_VERSION

logger = logging.getLogger(__name__)

# Application metadata
APP_TITLE = "Managed Rule Group Generator"
RECENT_FILES_MAX = 10
RECENT_FILES_KEY = 'recent_files'

# File type filter for dialogs
MRG_FILE_TYPES = [
    ("MRG Configuration", "*.mrg"),
    ("All Files", "*.*"),
]


def _rewrite_arn_region(arn: str, target_region: str) -> str:
    """Rewrite the region in an AWS ARN to match the target region.

    AWS managed rule groups have the same names across regions, but their
    ARNs encode the region. When a .mrg file is saved with one region and
    opened with a different region, the ARNs need to be updated.

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


def _accel(shortcut: str) -> str:
    """Platform-aware accelerator label."""
    if platform.system() == 'Darwin':
        return shortcut.replace('Ctrl', 'Cmd')
    return shortcut


class MRGWindow:
    """Toplevel window orchestrator for Managed Rule Group functionality.

    Provides an independent window for managing AWS Network Firewall managed
    rule groups. Shares the parent application's AWSSessionManager but maintains
    isolated profile state.

    Args:
        parent: Main tk.Tk root (for Toplevel parenting)
        session_manager: Shared AWSSessionManager from main app
        send_to_editor_callback: Callback to inject rules into main editor
        mrg_filepath: Optional .mrg file to open on launch
    """

    def __init__(
        self,
        parent: tk.Tk,
        session_manager: AWSSessionManager,
        send_to_editor_callback: Callable[[List], None],
        mrg_filepath: Optional[str] = None,
    ):
        self._parent = parent
        self._session_manager = session_manager
        self._send_to_editor_callback = send_to_editor_callback
        self._current_config: Optional[MRGConfig] = None
        self._current_filepath: Optional[str] = None
        self._unsaved_changes = False
        self._build_results: Optional[Dict] = None
        self._is_building = False
        self._log_viewer_window = None

        # Create a private AWSSessionManager for profile isolation.
        # This ensures profile changes in the MRG window do NOT propagate
        # back to the main application's session manager.
        self._local_session_manager = AWSSessionManager()

        # Inherit the main app's active profile for new configs,
        # or restore from file for opened configs.
        if mrg_filepath is None:
            # New configuration: inherit main profile
            inherited_profile = session_manager.profile_name
            self._local_session_manager.profile_name = inherited_profile
        # For opened files, profile will be set from the .mrg file in _open_file()

        # Install GUI log handler scoped to MRG activity
        self._log_handler = GUILogHandler()
        mrg_logger = logging.getLogger('src.mrg')
        mrg_logger.setLevel(logging.DEBUG)
        mrg_logger.addHandler(self._log_handler)

        # Create the Toplevel window
        self._window = tk.Toplevel(parent)
        self._window.title("{} v{}".format(APP_TITLE, MRG_VERSION))
        self._window.minsize(900, 600)
        self._window.geometry("1100x900")
        self._window.protocol("WM_DELETE_WINDOW", self._on_close)

        # Register with parent's MRG window set
        self._register_with_parent()

        # Build UI
        self._setup_menu()
        self._setup_ui()
        self._setup_keybindings()

        # Initialize state
        if mrg_filepath:
            self._open_file(mrg_filepath)
        else:
            self._new_configuration()

    # ─── Registration with Parent ─────────────────────────────

    def _register_with_parent(self):
        """Register this window in the parent's MRG window tracking set."""
        if hasattr(self._parent, '_mrg_windows'):
            self._parent._mrg_windows.add(self)

    def _unregister_from_parent(self):
        """Remove this window from the parent's MRG window tracking set."""
        if hasattr(self._parent, '_mrg_windows'):
            self._parent._mrg_windows.discard(self)

    # ─── Window Setup ─────────────────────────────────────────

    def _setup_menu(self):
        """Create the window's menu bar with File, Tools, Help menus."""
        self._menubar = tk.Menu(self._window)
        self._window.config(menu=self._menubar)

        # File menu
        self._file_menu = tk.Menu(self._menubar, tearoff=0)
        self._menubar.add_cascade(label="File", menu=self._file_menu)
        self._file_menu.add_command(
            label="New Configuration", command=self._new_configuration,
            accelerator=_accel("Ctrl+N"))
        self._file_menu.add_command(
            label="Open Configuration...", command=self._open_configuration,
            accelerator=_accel("Ctrl+O"))
        self._file_menu.add_separator()
        self._file_menu.add_command(
            label="Save", command=self._save_configuration,
            accelerator=_accel("Ctrl+S"))
        self._file_menu.add_command(
            label="Save As...", command=self._save_as_configuration,
            accelerator=_accel("Ctrl+Shift+S"))
        self._file_menu.add_separator()
        self._file_menu.add_command(label="Close Window", command=self._on_close)

        # Tools menu
        self._tools_menu = tk.Menu(self._menubar, tearoff=0)
        self._menubar.add_cascade(label="Tools", menu=self._tools_menu)
        self._tools_menu.add_command(
            label="Browse Deployed Configs...", command=self._browse_deployed_configs)
        self._tools_menu.add_command(
            label="Force Sync", command=self._force_sync)
        self._tools_menu.add_separator()
        self._tools_menu.add_command(
            label="Manage Backups", command=self._manage_backups)
        self._tools_menu.add_command(
            label="Rollback", command=self._rollback)
        self._tools_menu.add_separator()
        self._tools_menu.add_command(
            label="Remove Configuration", command=self._remove_configuration)
        self._tools_menu.add_separator()
        self._tools_menu.add_command(
            label="Logs", command=self._show_logs)

        # Help menu
        self._help_menu = tk.Menu(self._menubar, tearoff=0)
        self._menubar.add_cascade(label="Help", menu=self._help_menu)
        self._help_menu.add_command(
            label="AWS Setup Guide", command=self._show_aws_setup_guide)
        self._help_menu.add_separator()
        self._help_menu.add_command(label="About", command=self._show_about)

    def _setup_ui(self):
        """Build the main UI: config panel, summary, view filter, search, rule table, buttons, status bar."""
        main_frame = ttk.Frame(self._window)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Configuration panel (top, collapsible)
        self._config_panel = ConfigPanel(
            main_frame,
            session_manager=self._local_session_manager,
            on_build=self._on_build,
        )
        self._config_panel.pack(fill=tk.X, padx=0, pady=0)

        # Summary frame
        self._summary_frame = ttk.LabelFrame(main_frame, text="Summary")
        self._summary_frame.pack(fill=tk.X, padx=4, pady=(0, 4))
        self._summary_label = ttk.Label(
            self._summary_frame,
            text="No build performed yet. Configure settings and click Build Rule Group.")
        self._summary_label.pack(fill=tk.X, padx=8, pady=4)

        # Progress bar (hidden until build starts)
        self._progress_frame = ttk.Frame(self._summary_frame)
        self._progress_var = tk.DoubleVar(value=0)
        self._progress_bar = ttk.Progressbar(
            self._progress_frame, variable=self._progress_var,
            maximum=100, mode='determinate')
        self._progress_bar.pack(fill=tk.X, padx=8, pady=(0, 4))
        self._progress_status_label = ttk.Label(
            self._progress_frame, text='', font=('TkDefaultFont', 9))
        self._progress_status_label.pack(fill=tk.X, padx=8, pady=(0, 4))
        self._progress_frame.pack_forget()

        # View filter bar
        self._view_filter_bar = ViewFilterBar(
            main_frame, on_filter_change=self._on_view_filter_change)
        self._view_filter_bar.pack(fill=tk.X, padx=0, pady=0)

        # Search bar (hidden by default, shown with Ctrl+F)
        self._search_bar = SearchBar(main_frame)

        # Rule table
        self._rule_table = RuleTable(main_frame)
        self._rule_table.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        self._search_bar.set_rule_table(self._rule_table)

        # Bottom button bar
        btn_bar = ttk.Frame(main_frame)
        btn_bar.pack(fill=tk.X, padx=4, pady=(0, 4))

        self._deploy_btn = ttk.Button(
            btn_bar, text="Deploy to AWS",
            command=self._deploy_to_aws, state=tk.DISABLED)
        self._deploy_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Deploy warning label
        self._deploy_warning_label = ttk.Label(
            btn_bar, text="", foreground='#D32F2F', font=('TkDefaultFont', 9))
        self._deploy_warning_label.pack(side=tk.LEFT, padx=(0, 8))

        self._save_suricata_btn = ttk.Button(
            btn_bar, text="Save as .suricata",
            command=self._save_as_suricata, state=tk.DISABLED)
        self._save_suricata_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._send_to_editor_btn = ttk.Button(
            btn_bar, text="Send to Editor",
            command=self._send_to_editor, state=tk.DISABLED)
        self._send_to_editor_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._save_config_btn = ttk.Button(
            btn_bar, text="Save Config (.mrg)",
            command=self._save_configuration)
        self._save_config_btn.pack(side=tk.LEFT)

        # Status bar (bottom)
        self._status_bar = StatusBar(
            main_frame,
            session_manager=self._local_session_manager,
            on_profile_change=self._on_status_bar_profile_change,
        )
        self._status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _setup_keybindings(self):
        """Bind keyboard shortcuts to the Toplevel window."""
        modifier = 'Command' if platform.system() == 'Darwin' else 'Control'
        self._window.bind('<{}-n>'.format(modifier), lambda e: self._new_configuration())
        self._window.bind('<{}-N>'.format(modifier), lambda e: self._new_configuration())
        self._window.bind('<{}-o>'.format(modifier), lambda e: self._open_configuration())
        self._window.bind('<{}-O>'.format(modifier), lambda e: self._open_configuration())
        self._window.bind('<{}-s>'.format(modifier), lambda e: self._save_configuration())
        self._window.bind('<{}-S>'.format(modifier), lambda e: self._save_configuration())
        self._window.bind('<{}-Shift-s>'.format(modifier), lambda e: self._save_as_configuration())
        self._window.bind('<{}-Shift-S>'.format(modifier), lambda e: self._save_as_configuration())
        if platform.system() == 'Darwin':
            self._window.bind('<Control-n>', lambda e: self._new_configuration())
            self._window.bind('<Control-o>', lambda e: self._open_configuration())
            self._window.bind('<Control-s>', lambda e: self._save_configuration())
        self._search_bar.bind_shortcuts(self._window)

    # ─── File Menu Actions ────────────────────────────────────

    def _new_configuration(self):
        """Create a new blank configuration, inheriting the main app's active profile."""
        if self._unsaved_changes:
            if not self._ask_save_changes():
                return

        self._current_config = create_new_config()
        self._current_filepath = None
        self._unsaved_changes = False
        self._build_results = None

        # Inherit current profile from main app for new configs
        inherited_profile = self._session_manager.profile_name
        self._local_session_manager.profile_name = inherited_profile

        self._config_panel.reset()
        self._config_panel.set_profile(inherited_profile)
        self._rule_table.clear()
        self._update_summary_no_build()
        self._update_title()
        self._update_deploy_button_state()

        self._status_bar.set_status_text("New configuration created.")
        self._status_bar.update_capacity(0, 0)
        self._status_bar.update_action_counts({'pass': 0, 'alert': 0, 'drop': 0, 'reject': 0})
        self._status_bar.update_sid_range(None, None)
        self._status_bar.update_rules_size(-1)
        self._status_bar.update_source_count(0)
        self._status_bar.update_deployment_mode('as_is')
        self._status_bar.update_aws_profile(inherited_profile)
        self._view_filter_bar.clear_filters()

        logger.info("New MRG configuration created (profile: %s)",
                    inherited_profile or '(default)')

    def _open_configuration(self):
        """Open a .mrg file from disk."""
        if self._unsaved_changes:
            if not self._ask_save_changes():
                return

        filepath = filedialog.askopenfilename(
            title="Open Configuration",
            filetypes=MRG_FILE_TYPES,
            defaultextension=".mrg",
            parent=self._window,
        )
        if not filepath:
            return
        self._open_file(filepath)

    def _open_file(self, filepath: str):
        """Load a .mrg configuration file and restore all settings."""
        try:
            config = read_mrg_file(filepath)
        except MRGFileError as e:
            messagebox.showerror("Error Opening File", str(e), parent=self._window)
            return

        self._current_config = config
        self._current_filepath = filepath
        self._unsaved_changes = False
        self._build_results = None

        # Restore profile from file (profile isolation: does NOT affect main app)
        saved_profile = config.aws_profile
        self._local_session_manager.profile_name = saved_profile

        # Load config into panel; warnings are shown to user
        warnings = self._config_panel.load_from_mrg_config(config)
        for warning in warnings:
            messagebox.showwarning("Configuration Warning", warning, parent=self._window)

        self._rule_table.clear()
        self._status_bar.update_capacity(0, config.output_rule_group_capacity)
        self._status_bar.update_source_count(len(config.source_rule_groups))
        self._status_bar.update_deployment_mode(config.deployment_mode)
        self._status_bar.update_aws_profile(saved_profile)
        self._update_summary_no_build()
        self._update_title()
        self._update_deploy_button_state()
        self._status_bar.set_status_text("Opened: {}".format(os.path.basename(filepath)))

        logger.info("Opened MRG config: %s (profile: %s)",
                    os.path.basename(filepath), saved_profile or '(default)')

    def _save_configuration(self):
        """Save to current filepath, or Save As if no filepath."""
        if self._current_filepath:
            self._save_to_file(self._current_filepath)
        else:
            self._save_as_configuration()

    def _save_as_configuration(self):
        """Save configuration to a new file path."""
        initial_name = ""
        config_name = self._config_panel.get_name()
        if config_name:
            initial_name = config_name + ".mrg"

        filepath = filedialog.asksaveasfilename(
            title="Save Configuration As",
            filetypes=MRG_FILE_TYPES,
            defaultextension=".mrg",
            initialfile=initial_name,
            parent=self._window,
        )
        if not filepath:
            return
        self._save_to_file(filepath)

    def _save_to_file(self, filepath: str):
        """Write current config to disk."""
        if self._current_config is None:
            self._current_config = create_new_config()

        self._config_panel.save_to_mrg_config(self._current_config)

        # Save the local profile into the config
        self._current_config.aws_profile = self._local_session_manager.profile_name

        try:
            write_mrg_file(filepath, self._current_config)
        except MRGFileError as e:
            messagebox.showerror("Error Saving File", str(e), parent=self._window)
            return

        self._current_filepath = filepath
        self._unsaved_changes = False
        self._update_title()
        self._status_bar.set_status_text("Saved: {}".format(os.path.basename(filepath)))
        messagebox.showinfo(
            "Configuration Saved",
            "Configuration saved to:\n{}".format(os.path.basename(filepath)),
            parent=self._window)

        logger.info("Saved MRG config: %s", os.path.basename(filepath))

    # ─── Build Pipeline ───────────────────────────────────────

    def _on_build(self):
        """Handle Build button click from ConfigPanel."""
        if self._is_building:
            return

        errors = self._config_panel.validate()
        if errors:
            messagebox.showwarning(
                "Configuration Errors",
                "Please fix the following issues:\n\n" + "\n".join(
                    "- {}".format(e) for e in errors),
                parent=self._window)
            return

        region = self._config_panel.get_region()
        source_arns = self._config_panel.get_selected_source_arns()
        filter_config = self._config_panel.get_filter_config()
        deployment_mode = self._config_panel.get_deployment_mode()

        self._is_building = True
        self._show_progress(True)
        self._update_progress(0, "Starting build...")
        self._summary_label.config(text="Building... Fetching source rule groups...")
        self._status_bar.set_status_text("Building rule group...")

        logger.info("Starting build: region=%s, sources=%d, mode=%s",
                    region, len(source_arns), deployment_mode)

        def _do_build():
            try:
                results = self._execute_build_pipeline(
                    region, source_arns, filter_config, deployment_mode)
                self._window.after(0, lambda: self._on_build_complete(results))
            except Exception as e:
                error_msg = str(e)
                logger.error("Build failed: %s", error_msg, exc_info=True)
                self._window.after(0, lambda: self._on_build_error(error_msg))

        threading.Thread(target=_do_build, daemon=True).start()

    def _execute_build_pipeline(self, region, source_arns, filter_config, deployment_mode):
        """Execute the full build pipeline: fetch -> parse -> filter -> dedup -> test_mode.

        Runs in a background thread. Progress updates are marshalled to the
        main thread via window.after().
        """
        from src.mrg.aws.network_firewall import describe_rule_group
        from src.mrg.core.deduplicator import deduplicate_rules
        from src.mrg.core.rule_filter import apply_filters
        from src.mrg.core.rule_parser import parse_rules_string
        from src.mrg.core.test_mode import apply_test_mode_bulk

        all_rules = []
        total_sources = len(source_arns)

        for i, arn in enumerate(source_arns, 1):
            # Rewrite ARN region to match selected build region
            arn = _rewrite_arn_region(arn, region)
            arn_name = arn.split('/')[-1] if '/' in arn else arn
            progress_pct = int((i - 1) / total_sources * 50)
            status_text = "Fetching {}... {}/{}".format(arn_name, i, total_sources)
            self._window.after(
                0, lambda p=progress_pct, s=status_text: self._update_progress(p, s))

            logger.info("Fetching source: %s", arn_name)
            rg_info = describe_rule_group(
                self._local_session_manager, region, rule_group_arn=arn)
            rules_string = rg_info.get('RulesString', '')
            last_modified = rg_info.get('LastModifiedTime', '')
            parsed = parse_rules_string(
                rules_string, source_rule_group=arn,
                source_last_modified=last_modified)
            all_rules.extend(parsed)

        self._window.after(0, lambda: self._update_progress(60, "Applying filters..."))
        filter_result = apply_filters(all_rules, filter_config)

        self._window.after(0, lambda: self._update_progress(75, "Deduplicating by SID..."))
        deduped = deduplicate_rules(filter_result.matching_rules)

        if deployment_mode == 'test_mode':
            self._window.after(0, lambda: self._update_progress(90, "Applying test mode..."))
            final_rules = apply_test_mode_bulk(deduped)
        else:
            final_rules = deduped

        # Calculate rules string size (for AWS 2MB limit indicator)
        rules_string = '\n'.join(r.raw for r in final_rules if r.raw)
        rules_string_size = len(rules_string.encode('utf-8'))

        self._window.after(0, lambda: self._update_progress(100, "Build complete."))

        logger.info("Build complete: %d rules (size: %d bytes)",
                    len(final_rules), rules_string_size)

        return {
            'total_scanned': filter_result.total_scanned,
            'matching': filter_result.total_matching,
            'missing_metadata': filter_result.total_missing_metadata,
            'deduplicated': len(deduped),
            'final_count': len(final_rules),
            'final_rules': final_rules,
            'deployment_mode': deployment_mode,
            'rules_string_size': rules_string_size,
        }

    def _on_build_complete(self, results: Dict):
        """Handle successful build completion (main thread)."""
        self._build_results = results
        self._unsaved_changes = True
        self._is_building = False
        self._show_progress(False)

        summary = (
            "Scanned: {:,} | Matching: {:,} | Missing metadata: {:,} | "
            "Deduplicated: {:,} | Final: {:,}".format(
                results['total_scanned'], results['matching'],
                results['missing_metadata'], results['deduplicated'],
                results['final_count']))
        mode_text = "Test Mode" if results['deployment_mode'] == 'test_mode' else "As-Is"
        summary += " | Mode: {}".format(mode_text)
        self._summary_label.config(text=summary)

        final_rules = results.get('final_rules', [])
        self._rule_table.load_rules(final_rules)

        # Pass active filter conditions to rule table for highlight
        filter_config = self._config_panel.get_filter_config()
        filter_conditions = []
        if hasattr(filter_config, 'conditions'):
            for cond in filter_config.conditions:
                filter_conditions.append({
                    'field': cond.field if hasattr(cond, 'field') else '',
                    'operator': cond.operator if hasattr(cond, 'operator') else '',
                    'values': list(cond.values) if hasattr(cond, 'values') else [],
                })
        self._rule_table.set_active_filters(filter_conditions)

        self._view_filter_bar.update_available_protocols(self._rule_table.get_protocol_set())
        self._view_filter_bar.update_available_variables(self._rule_table.get_network_variables())

        # Auto-calculate capacity: rule count + 1000 buffer
        rule_count = results['final_count']
        auto_capacity = rule_count + 1000
        self._config_panel.set_capacity(auto_capacity)

        # Update status bar
        source_arns = self._config_panel.get_selected_source_arns()
        capacity = self._config_panel.get_capacity()
        profile = self._config_panel.get_profile()
        self._status_bar.update_from_rules(
            final_rules, capacity=capacity,
            source_count=len(source_arns),
            deployment_mode=results['deployment_mode'],
            profile=profile)
        self._status_bar.update_rules_size(results.get('rules_string_size', 0))
        self._status_bar.set_status_text(
            "Build complete: {} rules.".format(results['final_count']))
        self._update_title()
        self._update_deploy_button_state()

        # Auto-collapse config panel after successful build
        if not self._config_panel.is_collapsed():
            self._config_panel.collapse()

    def _on_build_error(self, error_msg: str):
        """Handle build failure (main thread)."""
        self._is_building = False
        self._show_progress(False)
        self._summary_label.config(text="Build failed: {}".format(error_msg))
        self._status_bar.set_status_text("Build failed.")
        self._update_deploy_button_state()
        messagebox.showerror(
            "Build Error",
            "Failed to build rule group:\n\n{}".format(error_msg),
            parent=self._window)

    # ─── Deploy Button State ──────────────────────────────────

    def _update_deploy_button_state(self):
        """Update Deploy/Send/Save buttons based on build results and constraints."""
        if not self._build_results:
            self._deploy_btn.config(state=tk.DISABLED)
            self._save_suricata_btn.config(state=tk.DISABLED)
            self._send_to_editor_btn.config(state=tk.DISABLED)
            self._deploy_warning_label.config(text="Build a rule group first.")
            return

        rule_count = self._build_results.get('final_count', 0)
        capacity = self._config_panel.get_capacity()

        # Enable save/send whenever there are rules
        if rule_count > 0:
            self._save_suricata_btn.config(state=tk.NORMAL)
            self._send_to_editor_btn.config(state=tk.NORMAL)
        else:
            self._save_suricata_btn.config(state=tk.DISABLED)
            self._send_to_editor_btn.config(state=tk.DISABLED)

        # Check rules string size against AWS 2MB limit
        rules_string_size = self._build_results.get('rules_string_size', 0)
        max_size = 2_000_000

        if rule_count == 0:
            self._deploy_btn.config(state=tk.DISABLED)
            self._deploy_warning_label.config(
                text="\u26a0 No rules to deploy (filters too restrictive).")
        elif rule_count > capacity:
            self._deploy_btn.config(state=tk.DISABLED)
            self._deploy_warning_label.config(
                text="\u26a0 Rule count ({:,}) exceeds capacity ({:,}).".format(
                    rule_count, capacity))
        elif rules_string_size > max_size:
            self._deploy_btn.config(state=tk.DISABLED)
            size_mb = rules_string_size / 1_000_000
            self._deploy_warning_label.config(
                text="\u26a0 Rules string size ({:.1f} MB) exceeds AWS 2 MB limit.".format(
                    size_mb))
        else:
            self._deploy_btn.config(state=tk.NORMAL)
            self._deploy_warning_label.config(text="")

    # ─── Deploy to AWS ────────────────────────────────────────

    def _deploy_to_aws(self):
        """Deploy the current configuration to AWS via DeployDialog."""
        if not self._build_results or not self._build_results.get('final_rules'):
            messagebox.showwarning(
                "Cannot Deploy",
                "No rules to deploy. Build the rule group first.",
                parent=self._window)
            return

        # Validate config
        errors = self._config_panel.validate()
        capacity = self._config_panel.get_capacity()
        if capacity <= 0:
            errors.append(
                "Rule group capacity must be a positive integer. "
                "Build the rule group first to auto-calculate.")
        if errors:
            messagebox.showwarning(
                "Configuration Errors",
                "Please fix the following issues:\n\n" + "\n".join(
                    "- {}".format(e) for e in errors),
                parent=self._window)
            return

        # Build rules string
        final_rules = self._build_results['final_rules']
        rules_string = '\n'.join(r.raw for r in final_rules if r.raw)

        # Check AWS 2MB limit
        rules_size = len(rules_string.encode('utf-8'))
        max_size = 2_000_000
        if rules_size > max_size:
            messagebox.showerror(
                "Rules Too Large",
                "The combined rules string is {:,.0f} bytes, which exceeds the AWS "
                "Network Firewall limit of {:,.0f} bytes (2 MB).\n\n"
                "To reduce the size:\n"
                "- Select fewer source rule groups\n"
                "- Add more restrictive filters\n"
                "- Use multiple configurations with different filter criteria".format(
                    rules_size, max_size),
                parent=self._window)
            return

        # Update config from panel
        if self._current_config is None:
            self._current_config = create_new_config()
        self._config_panel.save_to_mrg_config(self._current_config)
        self._current_config.aws_profile = self._local_session_manager.profile_name

        # Confirmation dialog
        name = self._current_config.output_rule_group_name
        count = len(final_rules)
        profile = self._config_panel.get_profile() or '(default)'
        region = self._config_panel.get_region()
        msg = (
            "Deploy {} rules to AWS?\n\n"
            "Rule Group: {}\n"
            "Region: {}\n"
            "Profile: {}\n\n"
            "This will create or update AWS resources.".format(
                count, name, region, profile))

        if not messagebox.askyesno("Confirm Deployment", msg, parent=self._window):
            return

        logger.info("Deploying %d rules to %s (region: %s, profile: %s)",
                    count, name, region, profile)

        from src.mrg.gui.deploy_dialog import deploy_to_aws
        result = deploy_to_aws(
            self._window, self._local_session_manager, self._current_config,
            rules_string, self._build_results)

        if result:
            self._unsaved_changes = True
            self._update_title()
            self._status_bar.set_status_text(
                "Deployed: {} rules to {}".format(count, name))
            logger.info("Deployment successful: %d rules to %s", count, name)

            # Auto-save if we have a filepath
            if self._current_filepath:
                try:
                    write_mrg_file(self._current_filepath, self._current_config)
                    self._unsaved_changes = False
                    self._update_title()
                except Exception:
                    pass  # Non-critical
        else:
            self._status_bar.set_status_text("Deployment failed or cancelled.")
            logger.warning("Deployment failed or cancelled.")

    # ─── Send to Editor ───────────────────────────────────────

    def _send_to_editor(self):
        """Send filtered rules to the main editor via callback."""
        if not self._build_results or not self._build_results.get('final_rules'):
            messagebox.showinfo(
                "No Rules",
                "No rules to send. Build the rule group first.",
                parent=self._window)
            return

        final_rules = self._build_results['final_rules']
        count = len(final_rules)

        if not messagebox.askyesno(
            "Send to Editor",
            "Send {} rules to the main Suricata Generator editor?\n\n"
            "This will replace the current rules in the main window.".format(count),
            parent=self._window,
        ):
            return

        logger.info("Sending %d rules to main editor.", count)
        self._send_to_editor_callback(final_rules)

        # Close the MRG window after sending (same behavior as clicking close)
        self._on_close()

    # ─── Save as .suricata ────────────────────────────────────

    def _save_as_suricata(self):
        """Export filtered rules to a .suricata file."""
        if not self._build_results or not self._build_results.get('final_rules'):
            messagebox.showinfo(
                "No Rules", "No rules to export. Build the rule group first.",
                parent=self._window)
            return

        # Suggest filename from rule group name
        default_name = ""
        if self._current_config and self._current_config.output_rule_group_name:
            default_name = self._current_config.output_rule_group_name + ".suricata"

        filepath = filedialog.asksaveasfilename(
            title="Save as .suricata",
            filetypes=[("Suricata Rules", "*.suricata"), ("All Files", "*.*")],
            defaultextension=".suricata",
            initialfile=default_name,
            parent=self._window,
        )
        if not filepath:
            return

        from src.mrg.gui.help_dialogs import export_rules_to_suricata
        try:
            count = export_rules_to_suricata(self._build_results['final_rules'], filepath)
            filename = os.path.basename(filepath)
            self._status_bar.set_status_text(
                "Exported {} rules to {}".format(count, filename))
            messagebox.showinfo(
                "Export Complete",
                "Exported {} rules to:\n{}".format(count, filepath),
                parent=self._window)
            logger.info("Exported %d rules to %s", count, filename)
        except Exception as e:
            messagebox.showerror(
                "Export Error",
                "Failed to export rules:\n\n{}".format(str(e)),
                parent=self._window)
            logger.error("Export failed: %s", str(e))

    # ─── Tools Menu Actions ───────────────────────────────────

    def _browse_deployed_configs(self):
        """Open Browse Deployed Configurations dialog."""
        region = self._config_panel.get_region() or 'us-east-1'
        profile = self._config_panel.get_profile()

        from src.mrg.gui.browse_configs_dialog import browse_deployed_configs
        browse_deployed_configs(
            self._window,
            self._local_session_manager,
            current_region=region,
            current_profile=profile,
        )

    def _force_sync(self):
        """Invoke Lambda to re-evaluate all configurations."""
        if not self._current_config:
            messagebox.showinfo("No Configuration", "No configuration is loaded.",
                                parent=self._window)
            return

        if not self._current_config.is_deployed():
            messagebox.showinfo(
                "Not Deployed",
                "This configuration has not been deployed to AWS.\n"
                "Deploy first, then use Force Sync to test the Lambda.",
                parent=self._window)
            return

        region = self._config_panel.get_region()
        if not region:
            messagebox.showwarning("No Region", "Please select an AWS region.",
                                   parent=self._window)
            return

        if not messagebox.askyesno(
            "Force Sync",
            "Invoke the Lambda function to re-evaluate all configurations "
            "and update rule groups in {}?\n\n"
            "This simulates what happens when AWS updates a managed rule group.".format(region),
            parent=self._window,
        ):
            return

        self._status_bar.set_status_text("Invoking Lambda for force sync...")
        logger.info("Force sync initiated for region: %s", region)

        def _do_sync():
            try:
                from src.mrg.aws.lambda_deployer import invoke_lambda_function
                test_event = {
                    "source": "managed-rule-generator",
                    "action": "force-sync",
                    "detail-type": "Force Sync from GUI",
                }
                result = invoke_lambda_function(
                    self._local_session_manager, region, payload=test_event)
                status_code = result.get('StatusCode', 0)
                response = result.get('Response', {})

                if status_code == 200:
                    response_body = json.dumps(response, indent=2, default=str)
                    self._window.after(
                        0, lambda: self._on_force_sync_complete(True, response_body))
                else:
                    error_msg = "Lambda returned status code: {}".format(status_code)
                    self._window.after(
                        0, lambda: self._on_force_sync_complete(False, error_msg))
            except Exception as e:
                error_msg = str(e)
                logger.error("Force sync failed: %s", error_msg, exc_info=True)
                self._window.after(
                    0, lambda: self._on_force_sync_complete(False, error_msg))

        threading.Thread(target=_do_sync, daemon=True).start()

    def _on_force_sync_complete(self, success: bool, detail: str):
        """Handle force sync completion."""
        if success:
            self._status_bar.set_status_text("Force sync complete.")
            logger.info("Force sync completed successfully.")
            messagebox.showinfo(
                "Force Sync Complete",
                "Lambda invoked successfully.\n\nResponse:\n{}".format(detail[:500]),
                parent=self._window)
        else:
            self._status_bar.set_status_text("Force sync failed.")
            logger.error("Force sync failed: %s", detail)
            messagebox.showerror(
                "Force Sync Failed",
                "Failed to invoke Lambda:\n\n{}".format(detail[:500]),
                parent=self._window)

    def _manage_backups(self):
        """Open Manage Backups dialog."""
        if not self._current_config:
            messagebox.showinfo("No Configuration", "No configuration is loaded.",
                                parent=self._window)
            return

        name = self._current_config.output_rule_group_name
        if not name:
            messagebox.showinfo(
                "No Rule Group Name",
                "Please set an output rule group name in the configuration.",
                parent=self._window)
            return

        if not self._current_config.is_deployed():
            messagebox.showinfo(
                "Not Deployed",
                "This configuration has not been deployed to AWS.\n\n"
                "Backups are created automatically during Lambda updates.\n"
                "Deploy first, then backups will appear here after updates.",
                parent=self._window)
            return

        region = self._current_config.region
        from src.mrg.gui.backup_manager import manage_backups
        manage_backups(self._window, self._local_session_manager, region, name)

    def _rollback(self):
        """Open Rollback dialog."""
        if not self._current_config:
            messagebox.showinfo("No Configuration", "No configuration is loaded.",
                                parent=self._window)
            return

        if not self._current_config.is_deployed():
            messagebox.showinfo(
                "Not Deployed",
                "This configuration has not been deployed to AWS.\n\n"
                "You must deploy before you can rollback.",
                parent=self._window)
            return

        name = self._current_config.output_rule_group_name
        target_arn = self._current_config.output_rule_group_arn
        if not target_arn:
            messagebox.showinfo(
                "No Rule Group ARN",
                "The deployed rule group ARN is not available.\n"
                "Please redeploy the configuration.",
                parent=self._window)
            return

        region = self._current_config.region
        notification_topic_arn = getattr(
            self._current_config, 'notification_topic_arn', None)

        from src.mrg.gui.rollback_dialog import rollback_to_backup
        result = rollback_to_backup(
            self._window, self._local_session_manager, region, name, target_arn,
            notification_topic_arn=notification_topic_arn,
        )

        if result and result.get('success'):
            rules_restored = result.get('rules_restored', 0)
            backup_name = result.get('backup_name', '')
            self._status_bar.set_status_text(
                "Rolled back to '{}': {} rules restored.".format(
                    backup_name, rules_restored))
            logger.info("Rollback successful: %d rules restored from %s",
                        rules_restored, backup_name)

    def _remove_configuration(self):
        """Remove current configuration from AWS."""
        if not self._current_config:
            messagebox.showinfo("No Configuration", "No configuration is loaded.",
                                parent=self._window)
            return

        if not self._current_config.is_deployed():
            messagebox.showinfo("Not Deployed",
                                "This configuration has not been deployed to AWS.",
                                parent=self._window)
            return

        name = self._current_config.name or self._current_config.output_rule_group_name
        region = self._current_config.region
        msg = (
            "Remove configuration '{}' from AWS?\n\n"
            "This will:\n"
            "- Delete the rule group from Network Firewall\n"
            "- Remove the configuration from the Lambda function\n"
            "- Remove notification subscriptions\n\n"
            "Region: {}\n\n"
            "The local .mrg file will NOT be deleted.".format(name, region))

        if not messagebox.askyesno("Confirm Remove Configuration", msg,
                                   parent=self._window):
            return

        delete_backups = messagebox.askyesno(
            "Delete Backups?",
            "Also delete backup rule groups for '{}'?".format(name),
            parent=self._window)

        from src.mrg.gui.deploy_dialog import remove_configuration
        success = remove_configuration(
            self._window, self._local_session_manager, self._current_config,
            delete_rule_group_flag=True, delete_backups=delete_backups,
        )

        if success:
            self._unsaved_changes = True
            self._update_title()
            self._update_deploy_button_state()
            self._status_bar.set_status_text(
                "Configuration '{}' removed from AWS.".format(name))
            logger.info("Configuration '%s' removed from AWS.", name)

            # Auto-save to mark as undeployed
            if self._current_filepath:
                try:
                    write_mrg_file(self._current_filepath, self._current_config)
                    self._unsaved_changes = False
                    self._update_title()
                except Exception:
                    pass

    def _full_teardown(self):
        """Remove ALL MRG infrastructure in the selected region."""
        region = self._config_panel.get_region()
        if not region:
            messagebox.showwarning("No Region", "Please select an AWS region first.",
                                   parent=self._window)
            return

        profile = self._config_panel.get_profile() or '(default)'
        msg = (
            "FULL TEARDOWN - Remove ALL Managed Rule Generator infrastructure?\n\n"
            "This will delete in region '{}':\n"
            "- Lambda function\n"
            "- IAM role and policy\n"
            "- All SNS subscriptions\n"
            "- Notification topic\n\n"
            "Profile: {}\n\n"
            "This action cannot be undone!".format(region, profile))

        if not messagebox.askyesno("Confirm Full Teardown", msg, icon='warning',
                                   parent=self._window):
            return

        delete_rgs = messagebox.askyesno(
            "Delete Rule Groups?",
            "Also delete all MRG-managed rule groups and backups?",
            parent=self._window)

        from src.mrg.gui.deploy_dialog import full_teardown
        success = full_teardown(
            self._window, self._local_session_manager, region,
            delete_rule_groups=delete_rgs, delete_backups=delete_rgs,
        )

        if success:
            if self._current_config and self._current_config.region == region:
                self._current_config.clear_deployment_metadata()
                self._unsaved_changes = True
                self._update_title()
                self._update_deploy_button_state()

                if self._current_filepath:
                    try:
                        write_mrg_file(self._current_filepath, self._current_config)
                        self._unsaved_changes = False
                        self._update_title()
                    except Exception:
                        pass

            self._status_bar.set_status_text(
                "Full teardown of {} complete.".format(region))
            logger.info("Full teardown of %s complete.", region)

    def _show_logs(self):
        """Open the session log viewer window."""
        if self._log_viewer_window and self._log_viewer_window.is_open:
            self._log_viewer_window.focus()
        else:
            self._log_viewer_window = LogViewerWindow(self._window, self._log_handler)

    # ─── Help Menu ────────────────────────────────────────────

    def _show_about(self):
        """Show the About dialog with MRG version."""
        from src.mrg.gui.help_dialogs import show_about
        show_about(self._window)

    def _show_aws_setup_guide(self):
        """Show the AWS Setup Guide dialog."""
        from src.mrg.gui.help_dialogs import show_aws_setup_guide
        show_aws_setup_guide(self._window, session_manager=self._local_session_manager)

    # ─── Progress Bar ─────────────────────────────────────────

    def _show_progress(self, show: bool):
        """Show or hide the build progress bar."""
        if show:
            self._progress_frame.pack(fill=tk.X, padx=0, pady=0)
            self._progress_var.set(0)
        else:
            self._progress_frame.pack_forget()

    def _update_progress(self, percent: int, status_text: str):
        """Update progress bar value and status text."""
        self._progress_var.set(percent)
        self._progress_status_label.config(text=status_text)

    # ─── Profile Change ───────────────────────────────────────

    def _on_status_bar_profile_change(self, profile_name: str):
        """Handle profile change from the status bar dropdown.

        Profile changes remain local to this MRG window and do NOT
        propagate to the main application's session manager.
        """
        effective = None if profile_name == '(default)' else profile_name
        self._local_session_manager.profile_name = effective
        self._config_panel.set_profile(effective)
        logger.info("Profile changed to: %s", profile_name)

    # ─── View Filter ──────────────────────────────────────────

    def _on_view_filter_change(self):
        """Apply view filter bar changes to the rule table."""
        filter_func = self._view_filter_bar.build_filter_func()
        self._rule_table.set_view_filter(filter_func)

    # ─── Unsaved Changes ──────────────────────────────────────

    def _ask_save_changes(self) -> bool:
        """Prompt user about unsaved changes. Returns False to cancel the action."""
        result = messagebox.askyesnocancel(
            "Unsaved Changes",
            "You have unsaved changes. Do you want to save changes to the Managed Rule Generator configuration before continuing?",
            parent=self._window)
        if result is None:
            return False  # Cancel
        elif result:
            self._save_configuration()
        return True

    def _on_close(self):
        """Handle window close request."""
        if self._unsaved_changes:
            if not self._ask_save_changes():
                return
        self._unregister_from_parent()
        # Clean up log handler
        mrg_logger = logging.getLogger('src.mrg')
        mrg_logger.removeHandler(self._log_handler)
        self._window.destroy()

    def force_close(self):
        """Force-close this window without prompting (used by parent close guard)."""
        self._unregister_from_parent()
        mrg_logger = logging.getLogger('src.mrg')
        mrg_logger.removeHandler(self._log_handler)
        try:
            self._window.destroy()
        except Exception:
            pass

    # ─── UI Helpers ───────────────────────────────────────────

    def _update_title(self):
        """Update the window title with filename and unsaved indicator."""
        parts = [APP_TITLE, "v{}".format(MRG_VERSION)]
        if self._current_filepath:
            filename = os.path.basename(self._current_filepath)
            parts.insert(0, filename)
        elif self._current_config and self._current_config.name:
            parts.insert(0, self._current_config.name)
        if self._unsaved_changes:
            parts[0] = "*" + parts[0]
        self._window.title(" - ".join(parts))

    def _update_summary_no_build(self):
        """Reset summary label to no-build state."""
        self._summary_label.config(
            text="No build performed yet. Configure settings and click Build Rule Group.")

    # ─── Public API ───────────────────────────────────────────

    def get_config_panel(self) -> ConfigPanel:
        """Get the configuration panel widget."""
        return self._config_panel

    def get_session_manager(self) -> AWSSessionManager:
        """Get the local (isolated) session manager for this window."""
        return self._local_session_manager

    def get_current_config(self) -> Optional[MRGConfig]:
        """Get the current MRG configuration."""
        return self._current_config

    def get_current_filepath(self) -> Optional[str]:
        """Get the current .mrg file path."""
        return self._current_filepath

    def get_build_results(self) -> Optional[Dict]:
        """Get the most recent build results."""
        return self._build_results

    def has_unsaved_changes(self) -> bool:
        """Check if there are unsaved changes."""
        return self._unsaved_changes

    def get_rule_table(self) -> RuleTable:
        """Get the rule table widget."""
        return self._rule_table

    def get_status_bar(self) -> StatusBar:
        """Get the status bar widget."""
        return self._status_bar

    def get_view_filter_bar(self) -> ViewFilterBar:
        """Get the view filter bar widget."""
        return self._view_filter_bar

    def get_search_bar(self) -> SearchBar:
        """Get the search bar widget."""
        return self._search_bar

    def get_deploy_button(self):
        """Get the deploy button widget."""
        return self._deploy_btn

    def get_deploy_warning_label(self):
        """Get the deploy warning label widget."""
        return self._deploy_warning_label

    def get_send_to_editor_button(self):
        """Get the 'Send to Editor' button widget."""
        return self._send_to_editor_btn

    def get_window(self) -> tk.Toplevel:
        """Get the underlying Toplevel window."""
        return self._window
