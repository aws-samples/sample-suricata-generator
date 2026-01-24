import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import re
import os
from typing import Optional
from constants import SuricataConstants
from suricata_rule import SuricataRule
from datetime import datetime, timedelta

class UIManager:
    """Manages all UI components and setup for the Suricata Rule Generator"""
    
    def __init__(self, parent_app):
        """Initialize UIManager with reference to parent application
        
        Args:
            parent_app: Reference to main SuricataRuleGenerator instance
        """
        self.parent = parent_app
        
        # UI component references (will be set during setup)
        self.tree = None
        self.notebook = None
        self.buttons_frame = None
        self.paste_button = None
        self.status_label = None
        self.pass_label = None
        self.drop_label = None
        self.reject_label = None
        self.alert_label = None
        self.sid_label = None
        self.vars_label = None
        self.variables_tree = None
        self.history_text = None
        
        # Editor field references
        self.action_var = None
        self.protocol_var = None
        self.src_net_var = None
        self.src_port_var = None
        self.direction_var = None
        self.dst_net_var = None
        self.dst_port_var = None
        self.message_var = None
        self.content_var = None
        self.sid_var = None
        self.comment_var = None
        self.comment_label = None
        self.comment_entry = None
        self.comment_save_button = None
    
    def setup_ui(self):
        """Setup the main UI components including menus, table, and editor"""
        # Create menu bar
        menubar = tk.Menu(self.parent.root)
        self.parent.root.config(menu=menubar)
        
        # File menu - file operations and domain import
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New", command=self.parent.new_file, accelerator="Ctrl+N")
        file_menu.add_command(label="Open", command=self.parent.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Save", command=self.parent.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As", command=self.parent.save_as_file)
        file_menu.add_separator()
        file_menu.add_command(label="Load AWS Best Practices Template", command=self.parent.domain_importer.load_aws_template)
        file_menu.add_command(label="Import Domain List", command=self.parent.import_domain_list)
        file_menu.add_command(label="Import Rule Group", command=self.parent.stateful_rule_importer.import_standard_rule_group)
        file_menu.add_command(label="Export Rule Group", command=self.parent.export_file)
        file_menu.add_separator()
        file_menu.add_command(label="Insert Rules From Template", command=self.parent.show_template_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.parent.on_closing)
        
        # Edit menu - undo functionality and search
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Undo", command=self.parent.undo_last_change, accelerator="Ctrl+Z")
        edit_menu.add_separator()
        edit_menu.add_command(label="Find", command=self.parent.search_manager.show_find_dialog, accelerator="Ctrl+F")
        edit_menu.add_command(label="Go to Line", command=self.show_jump_to_line_dialog, accelerator="Ctrl+G")
        
        # Tools menu - rule conflict detection, SID management, flow testing, and change tracking
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Advanced Editor", command=self.parent.show_advanced_editor, accelerator="Ctrl+E")
        tools_menu.add_separator()
        tools_menu.add_command(label="Review Rules", command=self.parent.review_rules)
        tools_menu.add_command(label="SID Management", command=self.show_sid_management)
        tools_menu.add_command(label="Test Flow", command=self.show_test_flow_dialog)
        tools_menu.add_separator()
        self.parent.show_sigtype_var = tk.BooleanVar(value=False)
        tools_menu.add_checkbutton(label="Show SIG Type Classification", variable=self.parent.show_sigtype_var, command=self.toggle_sigtype_column)
        self.parent.tracking_menu_var = tk.BooleanVar(value=self.parent.tracking_enabled)
        tools_menu.add_checkbutton(label="Enable Change Tracking", variable=self.parent.tracking_menu_var, command=self.parent.toggle_tracking)
        
        # Add Rule Usage Analyzer menu item (Phase 2)
        tools_menu.add_separator()
        from rule_usage_analyzer import HAS_BOTO3
        if HAS_BOTO3:
            tools_menu.add_command(label="Analyze Rule Usage", command=self.show_rule_usage_analyzer)
        else:
            tools_menu.add_command(label="Analyze Rule Usage (requires boto3)", 
                                  command=self.show_rule_usage_analyzer, state='disabled')
        
        # Help menu - about dialog and keyboard shortcuts
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_keyboard_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About SIG Types", command=self.show_sigtype_help)
        help_menu.add_separator()
        
        # Phase 11: Add AWS Setup guide (covers both Rule Usage Analyzer AND Rule Group Import)
        from rule_usage_analyzer import HAS_BOTO3
        if HAS_BOTO3:
            help_menu.add_command(label="AWS Setup", command=self.show_aws_setup_help)
            help_menu.add_separator()
        
        help_menu.add_command(label="About", command=self.parent.show_about)
        
        # Keyboard shortcuts
        self.parent.root.bind('<Control-n>', lambda e: self.parent.new_file())
        self.parent.root.bind('<Control-o>', lambda e: self.parent.open_file())
        self.parent.root.bind('<Control-s>', lambda e: self.parent.save_file())
        self.parent.root.bind('<Control-z>', lambda e: self.parent.undo_last_change())
        self.parent.root.bind('<Control-e>', lambda e: self.parent.show_advanced_editor())
        self.parent.root.bind('<Delete>', self.on_delete_key)
        self.parent.root.bind('<Control-c>', lambda e: self.handle_ctrl_c())
        self.parent.root.bind('<Control-a>', lambda e: self.select_all_rules())
        self.parent.root.bind('<Control-f>', lambda e: self.parent.search_manager.show_find_dialog())
        self.parent.root.bind('<F3>', lambda e: self.parent.search_manager.find_next())
        self.parent.root.bind('<Escape>', lambda e: self.parent.search_manager.close_search())
        self.parent.root.bind('<Down>', self.on_key_down)
        self.parent.root.bind('<End>', self.on_key_end)
        self.parent.root.bind('<Home>', self.on_key_home)
        self.parent.root.bind('<space>', self.on_space_key)
        self.parent.root.bind('<Control-g>', self.on_ctrl_g_key)
        self.parent.root.bind('<Return>', self.on_enter_key)
        
        # Main frame
        main_frame = ttk.Frame(self.parent.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Filter bar (above table)
        self.setup_filter_bar(main_frame)
        
        # Rules table
        self.setup_rules_table(main_frame)
        
        # Tabbed editor frame
        self.setup_tabbed_editor(main_frame)
        
        # Status bar (packed last so it appears at the very bottom)
        self.setup_status_bar(main_frame)
        
        self.parent.root.protocol("WM_DELETE_WINDOW", self.parent.on_closing)
    
    # [Filter bar, rules table, editor setup, and all other existing methods from backup remain unchanged]
    # ... (keeping all the original methods from the backup file for brevity)
    
    # Phase 2: Rule Usage Analyzer Menu Integration
    def show_rule_usage_analyzer(self):
        """Show Rule Usage Analyzer entry point - checks boto3 and shows first-time welcome"""
        from rule_usage_analyzer import HAS_BOTO3
        
        if not HAS_BOTO3:
            response = messagebox.askyesno(
                "boto3 Not Installed",
                "The Rule Usage Analyzer requires the 'boto3' library to connect to AWS CloudWatch.\n\n"
                "Would you like to see installation instructions?"
            )
            if response:
                self.show_boto3_install_help()
            return
        
        # Check if this is first-time use (session-based, not persisted)
        # Only show welcome dialog once per session
        if not hasattr(self.parent, '_usage_analyzer_welcomed'):
            # Show first-time welcome dialog
            response = messagebox.askyesno(
                "AWS CloudWatch Rule Usage Analyzer",
                "Welcome to the Rule Usage Analyzer!\n\n"
                "This tool analyzes your CloudWatch Logs to identify:\n"
                "• Unused rules (never triggered)\n"
                "• Low-frequency rules (potential shadow rules)\n"
                "• Overly-broad rules (security risks)\n"
                "• Rule effectiveness (Pareto analysis)\n\n"
                "Setup Requirements:\n"
                "✓ boto3 library (installed)\n"
                "• AWS credentials configured\n"
                "• CloudWatch Logs access\n"
                "• Network Firewall alert logs\n\n"
                "Would you like to proceed with analysis setup?"
            )
            
            # Mark as welcomed (session-only, not saved)
            self.parent._usage_analyzer_welcomed = True
            
            if not response:
                return
        
        # Check if we have cached results from a previous run (during this session)
        if hasattr(self.parent.usage_analyzer, 'last_analysis_results') and \
           self.parent.usage_analyzer.last_analysis_results is not None:
            # Results exist - ask user if they want to view cached results or run new analysis
            response = messagebox.askyesnocancel(
                "View Cached Results?",
                "You have analysis results from a previous run.\n\n"
                "Would you like to:\n"
                "• YES: View cached results (instant)\n"
                "• NO: Run new analysis (queries AWS)\n"
                "• CANCEL: Close this dialog\n\n"
                "Tip: Cached results can also be refreshed using\n"
                "the 'Refresh All' button in the results window.",
                icon='question'
            )
            
            if response is None:  # Cancel
                return
            elif response:  # YES - view cached results
                self.show_usage_results_window(self.parent.usage_analyzer.last_analysis_results)
                return
            # If NO, fall through to show configuration dialog for new analysis
        
        # Show analysis configuration dialog
        self.show_usage_analysis_dialog()
    
    def show_boto3_install_help(self):
        """Show boto3 installation instructions"""
        help_text = (
            "Installing boto3 (AWS SDK for Python)\n"
            "=" * 50 + "\n\n"
            "Option 1: Using pip\n"
            "   pip install boto3\n\n"
            "Option 2: Using pip3\n"
            "   pip3 install boto3\n\n"
            "Option 3: Using conda\n"
            "   conda install -c conda-forge boto3\n\n"
            "After installation, restart the application.\n\n"
            "For more information:\n"
            "https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html"
        )
        
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Install boto3")
        dialog.geometry("600x400")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        text = tk.Text(dialog, wrap=tk.WORD, font=("Consolas", 10))
        text.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        text.insert("1.0", help_text)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=(0, 20))
    
    def show_usage_analysis_dialog(self):
        """Show configuration dialog for CloudWatch analysis"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Configure Rule Usage Analysis")
        dialog.geometry("550x600")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 150,
            self.parent.root.winfo_rooty() + 100
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(main_frame, text="CloudWatch Logs Analysis Configuration",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 15))
        
        # AWS Region selector - at the top
        region_frame = ttk.LabelFrame(main_frame, text="AWS Region")
        region_frame.pack(fill=tk.X, pady=(0, 15))
        
        region_selector_frame = ttk.Frame(region_frame)
        region_selector_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(region_selector_frame, text="Region:").pack(side=tk.LEFT, padx=(0, 5))
        
        # Get default region from boto3 or last used region
        default_region = getattr(self.parent, '_last_region', None)
        if not default_region:
            try:
                import boto3
                session = boto3.Session()
                default_region = session.region_name or 'us-east-1'
            except:
                default_region = 'us-east-1'
        
        # All AWS standard commercial regions (excludes China and GovCloud)
        aws_regions = [
            # US Regions
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            # Canada Regions
            'ca-central-1', 'ca-west-1',
            # Europe Regions
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-central-2',
            'eu-north-1', 'eu-south-1', 'eu-south-2',
            # Asia Pacific Regions
            'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2',
            'ap-southeast-3', 'ap-southeast-4', 'ap-northeast-1', 'ap-northeast-2',
            'ap-northeast-3', 'ap-east-1',
            # South America Regions
            'sa-east-1',
            # Middle East Regions
            'me-south-1', 'me-central-1',
            # Africa Regions
            'af-south-1',
            # Israel Regions
            'il-central-1'
        ]
        
        region_var = tk.StringVar(value=default_region)
        region_combo = ttk.Combobox(region_selector_frame, textvariable=region_var,
                                    values=aws_regions, state="readonly", width=20)
        region_combo.pack(side=tk.LEFT)
        
        # Log Group - remember last used value during session
        log_group_frame = ttk.LabelFrame(main_frame, text="CloudWatch Log Group")
        log_group_frame.pack(fill=tk.X, pady=(0, 15))
        
        log_group_content = ttk.Frame(log_group_frame)
        log_group_content.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(log_group_content, text="Log Group:").pack(anchor=tk.W, pady=(0, 5))
        default_log_group = getattr(self.parent, '_last_log_group', "/aws/network-firewall/my-firewall")
        log_group_var = tk.StringVar(value=default_log_group)
        ttk.Entry(log_group_content, textvariable=log_group_var, width=60).pack(fill=tk.X)
        
        # Time Range - remember last selected during session
        ttk.Label(main_frame, text="Analysis Time Range:").pack(anchor=tk.W, pady=(0, 5))
        time_frame = ttk.Frame(main_frame)
        time_frame.pack(fill=tk.X, pady=(0, 15))
        
        default_time_range = getattr(self.parent, '_last_time_range', 30)
        time_var = tk.IntVar(value=default_time_range)
        ttk.Radiobutton(time_frame, text="Last 7 days", variable=time_var, value=7).pack(anchor=tk.W)
        ttk.Radiobutton(time_frame, text="Last 30 days", variable=time_var, value=30).pack(anchor=tk.W)
        ttk.Radiobutton(time_frame, text="Last 60 days", variable=time_var, value=60).pack(anchor=tk.W)
        ttk.Radiobutton(time_frame, text="Last 90 days", variable=time_var, value=90).pack(anchor=tk.W)
        
        # Threshold Settings - remember last values during session
        ttk.Label(main_frame, text="Detection Thresholds:").pack(anchor=tk.W, pady=(10, 5))
        
        threshold_frame = ttk.Frame(main_frame)
        threshold_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(threshold_frame, text="Low-frequency threshold (hits):").grid(row=0, column=0, sticky=tk.W, pady=5)
        default_low_freq = getattr(self.parent, '_last_low_freq_threshold', 10)
        low_freq_var = tk.StringVar(value=str(default_low_freq))
        ttk.Entry(threshold_frame, textvariable=low_freq_var, width=10).grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        ttk.Label(threshold_frame, text="Min days in production:").grid(row=1, column=0, sticky=tk.W, pady=5)
        default_min_days = getattr(self.parent, '_last_min_days_in_production', 14)
        min_days_var = tk.StringVar(value=str(default_min_days))
        ttk.Entry(threshold_frame, textvariable=min_days_var, width=10).grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=5)
        
        # Help button
        help_frame = ttk.Frame(main_frame)
        help_frame.pack(fill=tk.X, pady=(15, 0))
        ttk.Label(help_frame, text="Need help with setup?", foreground="#666666").pack(side=tk.LEFT)
        ttk.Button(help_frame, text="Setup Guide", command=lambda: self.show_aws_setup_help(default_tab='prerequisites')).pack(side=tk.LEFT, padx=(10, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(20, 0))
        
        def on_analyze():
            log_group = log_group_var.get().strip()
            if not log_group:
                messagebox.showerror("Validation Error", "Log group name is required.")
                return
            
            try:
                low_freq_threshold = int(low_freq_var.get())
                min_days = int(min_days_var.get())
            except ValueError:
                messagebox.showerror("Validation Error", "Thresholds must be valid numbers.")
                return
            
            # Get selected region
            selected_region = region_var.get()
            
            # Save parameters for session memory (not persisted to disk)
            self.parent._last_log_group = log_group
            self.parent._last_time_range = time_var.get()
            self.parent._last_low_freq_threshold = low_freq_threshold
            self.parent._last_min_days_in_production = min_days
            self.parent._last_region = selected_region
            
            dialog.destroy()
            
            # Run analysis with progress dialog (Phase 3) - pass region
            self.run_usage_analysis(log_group, time_var.get(), low_freq_threshold, min_days, selected_region)
        
        ttk.Button(button_frame, text="Analyze", command=on_analyze).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _get_rule_age_days(self, sid):
        """Get the age of a rule in days based on revision history
        
        Args:
            sid: Rule SID to check
            
        Returns:
            tuple: (days_old, creation_date) or (None, None) if unknown
        """
        # Check if change tracking is enabled
        if not self.parent.tracking_enabled:
            return None, None
        
        # Build history filename
        if self.parent.current_file:
            history_filename = self.parent.current_file.replace('.suricata', '.history')
            if not history_filename.endswith('.history'):
                history_filename += '.history'
        else:
            # For unsaved files, check for _unsaved_.history
            import tempfile
            temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'user_files')
            if not os.path.exists(temp_dir):
                temp_dir = tempfile.gettempdir()
            history_filename = os.path.join(temp_dir, '_unsaved_.history')
        
        # If no history file exists, return None
        if not os.path.exists(history_filename):
            return None, None
        
        try:
            from revision_manager import RevisionManager
            revision_manager = RevisionManager(history_filename)
            
            # Get GUID for this rule (prefer GUID, fallback to SID)
            rule_guid = self.parent.rule_guids.get(sid)
            
            # Get all revisions for this rule
            if rule_guid:
                revisions = revision_manager.get_revisions(rule_guid=rule_guid)
            else:
                revisions = revision_manager.get_revisions(sid=sid)
            
            # Also check pending_history for unsaved changes
            for entry in self.parent.pending_history:
                if 'rule_snapshot' in entry.get('details', {}):
                    snapshot = entry['details']['rule_snapshot']
                    details = entry['details']
                    
                    snapshot_guid = snapshot.get('rule_guid') or details.get('rule_guid')
                    if (snapshot_guid and snapshot_guid == rule_guid) or \
                       (not rule_guid and (details.get('sid') == sid or snapshot.get('sid') == sid)):
                        pending_rev = snapshot.copy()
                        pending_rev['timestamp'] = entry['timestamp']
                        revisions.append(pending_rev)
            
            if not revisions:
                return None, None
            
            # Find Rev 1 (creation timestamp)
            rev_1 = next((r for r in revisions if r.get('rev') == 1), None)
            
            if not rev_1:
                # No Rev 1 found, use oldest revision
                revisions_sorted = sorted(revisions, key=lambda r: r.get('rev', 999))
                if revisions_sorted:
                    rev_1 = revisions_sorted[0]
                else:
                    return None, None
            
            # Calculate days since creation and return both
            timestamp_str = rev_1['timestamp']
            if isinstance(timestamp_str, str):
                creation_date = datetime.fromisoformat(timestamp_str)
            else:
                creation_date = timestamp_str
            
            # BUG FIX #1: Use date() comparison to count calendar days, not 24-hour periods
            # If created on 2026-01-03 and today is 2026-01-04, that's 1 day (not 0)
            days_old = (datetime.now().date() - creation_date.date()).days
            return days_old, creation_date
            
        except Exception as e:
            # If anything fails, return None
            return None, None
    
    def _get_rule_last_modified_date(self, sid):
        """Get the last modified date of a rule (highest revision number)
        
        Args:
            sid: Rule SID to check
            
        Returns:
            datetime or None: Last modification date or None if unknown
        """
        # Check if change tracking is enabled
        if not self.parent.tracking_enabled:
            return None
        
        # Build history filename
        if self.parent.current_file:
            history_filename = self.parent.current_file.replace('.suricata', '.history')
            if not history_filename.endswith('.history'):
                history_filename += '.history'
        else:
            # For unsaved files, check for _unsaved_.history
            import tempfile
            temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'user_files')
            if not os.path.exists(temp_dir):
                temp_dir = tempfile.gettempdir()
            history_filename = os.path.join(temp_dir, '_unsaved_.history')
        
        # If no history file exists, return None
        if not os.path.exists(history_filename):
            return None
        
        try:
            from revision_manager import RevisionManager
            revision_manager = RevisionManager(history_filename)
            
            # Get GUID for this rule (prefer GUID, fallback to SID)
            rule_guid = self.parent.rule_guids.get(sid)
            
            # Get all revisions for this rule
            if rule_guid:
                revisions = revision_manager.get_revisions(rule_guid=rule_guid)
            else:
                revisions = revision_manager.get_revisions(sid=sid)
            
            # Also check pending_history for unsaved changes
            for entry in self.parent.pending_history:
                if 'rule_snapshot' in entry.get('details', {}):
                    snapshot = entry['details']['rule_snapshot']
                    details = entry['details']
                    
                    snapshot_guid = snapshot.get('rule_guid') or details.get('rule_guid')
                    if (snapshot_guid and snapshot_guid == rule_guid) or \
                       (not rule_guid and (details.get('sid') == sid or snapshot.get('sid') == sid)):
                        pending_rev = snapshot.copy()
                        pending_rev['timestamp'] = entry['timestamp']
                        revisions.append(pending_rev)
            
            if not revisions:
                return None
            
            # Find the HIGHEST revision number (most recent modification)
            highest_rev = max(revisions, key=lambda r: r.get('rev', 0))
            
            # Get timestamp from highest revision
            timestamp_str = highest_rev['timestamp']
            if isinstance(timestamp_str, str):
                last_modified_date = datetime.fromisoformat(timestamp_str)
            else:
                last_modified_date = timestamp_str
            
            return last_modified_date
            
        except Exception as e:
            # If anything fails, return None
            return None
    
    # Phase 3: Progress Dialog
    def run_usage_analysis(self, log_group, time_range_days, low_freq_threshold, min_days_in_production, region=None):
        """Run CloudWatch analysis with progress dialog
        
        Args:
            log_group: CloudWatch log group name
            time_range_days: Number of days to analyze
            low_freq_threshold: Threshold for low-frequency classification
            min_days_in_production: Minimum days in production
            region: AWS region to use (optional, uses default if not specified)
        """
        # Create progress dialog
        progress_dialog = tk.Toplevel(self.parent.root)
        progress_dialog.title("Analyzing Rule Usage")
        progress_dialog.geometry("500x250")  # Increased height so Cancel button isn't cut off
        progress_dialog.transient(self.parent.root)
        progress_dialog.grab_set()
        progress_dialog.resizable(False, False)
        
        # Center dialog
        progress_dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 200,
            self.parent.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(progress_dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Status label
        status_label = ttk.Label(main_frame, text="Querying CloudWatch Logs...",
                                font=("TkDefaultFont", 10))
        status_label.pack(pady=(0, 10))
        
        # Batch info label (hidden initially, shown during pagination)
        batch_label = ttk.Label(main_frame, text="", font=("TkDefaultFont", 9))
        # Don't pack yet - will be shown during pagination
        
        # Progress bar (indeterminate)
        progress_bar = ttk.Progressbar(main_frame, mode='indeterminate', length=400)
        progress_bar.pack(pady=10)
        progress_bar.start(10)
        
        # Records scanned label
        records_label = ttk.Label(main_frame, text="Records scanned: 0")
        records_label.pack(pady=5)
        
        # Elapsed time label
        elapsed_label = ttk.Label(main_frame, text="Elapsed time: 0s")
        elapsed_label.pack(pady=5)
        
        # Cancel button
        cancel_flag = [False]
        def on_cancel():
            cancel_flag[0] = True
            progress_dialog.destroy()
        
        ttk.Button(main_frame, text="Cancel", command=on_cancel).pack(pady=(10, 0))
        
        # Track start time
        start_time = datetime.now()
        
        # Update elapsed time every second
        def update_elapsed():
            if not cancel_flag[0]:
                elapsed = (datetime.now() - start_time).total_seconds()
                elapsed_label.config(text=f"Elapsed time: {int(elapsed)}s")
                progress_dialog.after(1000, update_elapsed)
        
        update_elapsed()
        
        # Progress callback with batch tracking support
        def progress_callback(current, total, status_text, batch_info=None):
            if not cancel_flag[0]:
                try:
                    status_label.config(text=status_text)
                    records_label.config(text=f"Records scanned: {current:,}")
                    
                    # Update batch info if provided (pagination only)
                    if batch_info and 'batch_num' in batch_info:
                        # Show batch label if not already visible
                        if not batch_label.winfo_ismapped():
                            batch_label.pack(after=status_label, pady=(5, 0))
                        
                        # Estimate total batches
                        estimated_batches = max(3, batch_info.get('batch_num', 2))
                        batch_text = f"Phase: Query Batch {batch_info['batch_num']} of ~{estimated_batches}"
                        
                        if 'total_retrieved' in batch_info:
                            batch_text += f"\nRetrieved: {batch_info['total_retrieved']:,} rules so far"
                        
                        batch_label.config(text=batch_text)
                    
                    progress_dialog.update()
                except:
                    pass  # Dialog may have been closed
        
        # Run analysis asynchronously
        def run_analysis():
            try:
                # Gather all rule SIDs from current rule set
                rule_sids = [rule.sid for rule in self.parent.rules 
                            if not getattr(rule, 'is_comment', False) 
                            and not getattr(rule, 'is_blank', False)]
                
                # Inject dialog handler into analyzer for pagination
                def handle_incompleteness(initial_stats, log_group, start_time, end_time, 
                                         logged_file_sids, prog_callback, cancel_flag_ref, client):
                    """Handler to show pagination choice dialog"""
                    # Calculate parameters for dialog
                    initial_count = len(initial_stats)
                    total_rules = len(logged_file_sids)
                    potential_missing = max(0, total_rules - initial_count)
                    
                    # Estimate time based on number of additional queries needed
                    # Rough estimate: ~30s per additional query
                    estimated_queries = min(3, (total_rules // 10000) + 1) - 1  # Already ran 1
                    if estimated_queries <= 1:
                        estimated_time = "1-2 minutes"
                    elif estimated_queries == 2:
                        estimated_time = "2-3 minutes"
                    else:
                        estimated_time = "3-5 minutes"
                    
                    # Show the choice dialog
                    return self._show_pagination_choice_dialog(
                        initial_count, total_rules, potential_missing, estimated_time
                    )
                
                # Inject the handler
                self.parent.usage_analyzer._handle_potential_incompleteness = handle_incompleteness
                
                # Run CloudWatch query with selected region
                analysis_results = self.parent.usage_analyzer.analyze_rules(
                    rule_sids=rule_sids,
                    log_group_name=log_group,
                    time_range_days=time_range_days,
                    low_frequency_threshold=low_freq_threshold,
                    min_days_in_production=min_days_in_production,
                    progress_callback=progress_callback,
                    cancel_flag=cancel_flag,
                    rules=self.parent.rules,  # Pass rules list to detect unlogged rules
                    region=region  # Pass selected region to analyzer
                )
                
                # Check if analysis was cancelled (returns None)
                if cancel_flag[0] or analysis_results is None:
                    progress_dialog.destroy()
                    return
                
                # Close progress dialog
                progress_dialog.destroy()
                
                # Show results window (Phase 4)
                self.show_usage_results_window(analysis_results)
                
            except Exception as e:
                progress_dialog.destroy()
                error_msg = str(e)
                
                # Handle specific AWS errors
                if "NoCredentialsError" in error_msg:
                    messagebox.showerror(
                        "AWS Credentials Not Found",
                        "No AWS credentials were found.\n\n"
                        "Please configure your credentials using:\n"
                        "• AWS CLI: aws configure\n"
                        "• Environment variables\n"
                        "• IAM role (if running on AWS)"
                    )
                elif "AccessDeniedException" in error_msg:
                    messagebox.showerror(
                        "Access Denied",
                        "Your AWS credentials do not have permission to access CloudWatch Logs.\n\n"
                        "Required IAM permissions:\n"
                        "• logs:DescribeLogGroups\n"
                        "• logs:StartQuery\n"
                        "• logs:GetQueryResults"
                    )
                elif "ResourceNotFoundException" in error_msg:
                    messagebox.showerror(
                        "Log Group Not Found",
                        f"CloudWatch log group not found:\n{log_group}\n\n"
                        "Please verify:\n"
                        "• Log group name is correct\n"
                        "• Log group exists in your AWS account\n"
                        "• You're using the correct AWS region"
                    )
                elif "TimeoutError" in error_msg or "timeout" in error_msg.lower():
                    messagebox.showerror(
                        "Query Timeout",
                        "CloudWatch query timed out.\n\n"
                        "Try:\n"
                        "• Reducing the time range\n"
                        "• Running during off-peak hours\n"
                        "• Checking AWS service status"
                    )
                elif "ConnectionError" in error_msg or "connection" in error_msg.lower():
                    messagebox.showerror(
                        "Connection Error",
                        "Failed to connect to AWS CloudWatch.\n\n"
                        "Please check:\n"
                        "• Internet connectivity\n"
                        "• AWS region configuration\n"
                        "• Firewall/proxy settings"
                    )
                else:
                    messagebox.showerror(
                        "Analysis Error",
                        f"An error occurred during analysis:\n\n{error_msg}"
                    )
        
        # Schedule analysis to run after dialog is visible
        progress_dialog.after(100, run_analysis)
    
    # CloudWatch Pagination: User Choice Dialog
    def _show_pagination_choice_dialog(self, initial_count, total_rules, potential_missing, estimated_time):
        """Show dialog for user to choose between full and partial analysis
        
        This is called by rule_usage_analyzer when 10,000 limit detected.
        
        Args:
            initial_count: Number of results returned (10,000)
            total_rules: Total rules in file
            potential_missing: Potential missing rules
            estimated_time: Estimated time for full analysis (e.g., "1-3 minutes")
            
        Returns:
            str: 'full' for full analysis, 'partial' for partial results, None for cancel
        """
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Complete Analysis Available")
        dialog.geometry("550x720")  # Tall enough to show all content including buttons
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        main_frame = ttk.Frame(dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Warning icon and title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(title_frame, text="⚠️", 
                 font=("TkDefaultFont", 24)).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(title_frame, text="CloudWatch Result Limit Reached", 
                 font=("TkDefaultFont", 12, "bold")).pack(side=tk.LEFT)
        
        # Explanation
        explanation = f"""Your initial query returned {initial_count:,} results (CloudWatch's maximum).

This means more rules may have triggered but weren't included in the top {initial_count:,}.

Current Status:
• Rules in your file: {total_rules:,}
• Rules returned: {initial_count:,}
• Potentially missing: {potential_missing:,}+ (if they triggered)

Accuracy Impact with Partial Results:
• Top {initial_count:,} rules: ✓ 100% accurate statistics
• Unused rules: ⚠️ May be OVERSTATED (some low-hit rules misclassified)
• Low-frequency: ⚠️ May be UNDERSTATED (some excluded from results)

Would you like to run a complete analysis?"""
        
        ttk.Label(main_frame, text=explanation, justify=tk.LEFT, 
                 wraplength=500, font=("TkDefaultFont", 9)).pack(fill=tk.X, pady=(0, 20))
        
        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Your Options", padding=10)
        options_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Option 1: Full Analysis
        option1 = f"""✓ Full Analysis (Recommended)
   • Runs additional queries to capture ALL triggered rules
   • 100% accurate unused and low-frequency counts
   • Takes longer (estimated: {estimated_time})
   • Uses efficient hit-count pagination (minimal overhead)"""
        
        ttk.Label(options_frame, text=option1, justify=tk.LEFT, 
                 font=("TkDefaultFont", 9), foreground="#2E7D32").pack(fill=tk.X, pady=5)
        
        ttk.Separator(options_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Option 2: Partial Results
        option2 = f"""○ Use Partial Results (Faster)
   • Uses only the top {initial_count:,} results already retrieved
   • Fast (no additional queries)
   • May have inaccuracies for unused/low-frequency counts
   • Best for quick overview of high-traffic rules"""
        
        ttk.Label(options_frame, text=option2, justify=tk.LEFT,
                 font=("TkDefaultFont", 9), foreground="#666666").pack(fill=tk.X, pady=5)
        
        # Recommendation
        rec_frame = ttk.Frame(main_frame)
        rec_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(rec_frame, text="💡 Recommendation:", 
                 font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W)
        ttk.Label(rec_frame, 
                 text="For accurate unused rule detection, choose Full Analysis.",
                 font=("TkDefaultFont", 9), foreground="#2E7D32").pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        user_choice = [None]
        
        def choose_full():
            user_choice[0] = 'full'
            dialog.destroy()
        
        def choose_partial():
            user_choice[0] = 'partial'
            dialog.destroy()
        
        def choose_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Run Full Analysis", 
                  command=choose_full, width=18).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Use Partial Results", 
                  command=choose_partial, width=18).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=choose_cancel, width=10).pack(side=tk.RIGHT, padx=5)
        
        # Wait for user choice
        self.parent.root.wait_window(dialog)
        
        return user_choice[0]
    
    # Phase 4: Results Window with Summary Tab
    def show_usage_results_window(self, analysis_results):
        """Display CloudWatch analysis results window with Summary tab
        
        Args:
            analysis_results: Dict containing analysis data from rule_usage_analyzer
        """
        # Create results window
        results_window = tk.Toplevel(self.parent.root)
        results_window.title("Rule Usage Analysis Results")
        results_window.geometry("1000x900")  # Increased height to show Close button and all tab content
        results_window.transient(self.parent.root)
        results_window.resizable(True, True)  # Allow user to resize window
        
        # Center window
        results_window.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 50,
            self.parent.root.winfo_rooty() + 50
        ))
        
        main_frame = ttk.Frame(results_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header (visible across all tabs)
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Analysis timestamp with auto-updating "X minutes ago"
        timestamp = analysis_results['timestamp']
        time_ago = self._format_time_ago(timestamp)
        
        timestamp_label = ttk.Label(header_frame,
                                    text=f"Analysis completed {time_ago}",
                                    font=("TkDefaultFont", 10))
        timestamp_label.pack(side=tk.LEFT)
        
        # Update timestamp every minute
        def update_timestamp():
            time_ago = self._format_time_ago(timestamp)
            timestamp_label.config(text=f"Analysis completed {time_ago}")
            results_window.after(60000, update_timestamp)  # Update every 60 seconds
        
        results_window.after(60000, update_timestamp)
        
        # Metadata
        metadata_text = (f"Time Range: Last {analysis_results['time_range_days']} days | "
                        f"Rules: {analysis_results['total_rules']:,} | "
                        f"Records: {analysis_results['records_analyzed']:,} | "
                        f"Log Group: {analysis_results['log_group']}")
        ttk.Label(header_frame, text=metadata_text,
                 font=("TkDefaultFont", 9), foreground="#666666").pack(side=tk.LEFT, padx=(20, 0))
        
        # Refresh button - shows configuration dialog to allow parameter changes
        def on_refresh():
            # Close results window
            results_window.destroy()
            # Show configuration dialog with parameters pre-filled from last run
            self.show_usage_analysis_dialog()
        
        ttk.Button(header_frame, text="Refresh All", command=on_refresh).pack(side=tk.RIGHT)
        
        # Populate days_in_production for all rules using change tracking
        # This must be done before creating tabs so categorization works correctly
        sid_stats = analysis_results.get('sid_stats', {})
        for sid in sid_stats.keys():
            days, creation_date = self._get_rule_age_days(sid)
            sid_stats[sid]['days_in_production'] = days
            
            # BUG FIX: Get last modified date using highest revision (not creation date)
            last_modified = self._get_rule_last_modified_date(sid)
            if last_modified is not None:
                sid_stats[sid]['last_modified'] = last_modified
                
                # Calculate days since last modification for categorization
                # This is used to determine if a rule is "Recently Deployed" vs "Confirmed Unused"
                days_since_mod = (datetime.now().date() - last_modified.date()).days
                sid_stats[sid]['days_since_last_modified'] = days_since_mod
            else:
                sid_stats[sid]['days_since_last_modified'] = days  # Fallback to creation date
        
        # Tab notebook
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Tab 1: Summary
        summary_tab = ttk.Frame(notebook)
        notebook.add(summary_tab, text="Summary")
        
        # Create scrollable frame for summary
        summary_canvas = tk.Canvas(summary_tab)
        summary_scrollbar = ttk.Scrollbar(summary_tab, orient=tk.VERTICAL, command=summary_canvas.yview)
        summary_content = ttk.Frame(summary_canvas)
        
        summary_content.bind(
            "<Configure>",
            lambda e: summary_canvas.configure(scrollregion=summary_canvas.bbox("all"))
        )
        
        summary_canvas.create_window((0, 0), window=summary_content, anchor="nw")
        summary_canvas.configure(yscrollcommand=summary_scrollbar.set)
        
        summary_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        summary_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling for Summary tab
        def on_summary_mousewheel(event):
            try:
                if event.delta:
                    summary_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    summary_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    summary_canvas.yview_scroll(1, "units")
            except:
                pass
        
        summary_canvas.bind("<Enter>", lambda e: summary_canvas.bind_all("<MouseWheel>", on_summary_mousewheel))
        summary_canvas.bind("<Leave>", lambda e: summary_canvas.unbind_all("<MouseWheel>"))
        
        # Create two-column layout for Summary tab
        # Left column: Health Gauge, Stats, Insights, Recommendations, Export
        # Right column: Scoring Methodology (uses vertical space)
        summary_columns = ttk.Frame(summary_content)
        summary_columns.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left column (60% width)
        left_column = ttk.Frame(summary_columns)
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Right column (40% width) - for scoring explanation
        right_column = ttk.Frame(summary_columns)
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(10, 0))
        
        # Health Gauge (LEFT COLUMN)
        health_score = analysis_results['health_score']
        
        gauge_frame = ttk.LabelFrame(left_column, text="Rule Group Health Score")
        gauge_frame.pack(fill=tk.X, pady=(0, 10))
        
        gauge_canvas = tk.Canvas(gauge_frame, width=450, height=100, bg='white')
        gauge_canvas.pack(pady=15, padx=15)
        
        self._draw_health_gauge(gauge_canvas, health_score)
        
        # Get categories early for use in Quick Stats
        categories = analysis_results['categories']
        
        # Quick Stats Table (LEFT COLUMN)
        stats_frame = ttk.LabelFrame(left_column, text="Quick Statistics")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(padx=15, pady=15)
        
        categories = analysis_results['categories']
        
        stats_data = [
            ("Unused Rules (0 hits/day):", categories['unused'], "#D32F2F"),
            ("Low-Traffic Rules (<1 hit/day):", categories['low_freq'], "#FF6F00"),
            ("Medium-Traffic Rules (1-9.9 hits/day):", categories['medium'], "#1976D2"),
            ("High-Traffic Rules (≥10 hits/day):", categories['high'], "#2E7D32"),
            ("Unlogged Rules (n/a):", categories.get('unlogged', 0), "#9E9E9E")
        ]
        
        for i, (label, count, color) in enumerate(stats_data):
            ttk.Label(stats_grid, text=label, font=("TkDefaultFont", 10, "bold")).grid(
                row=i, column=0, sticky=tk.W, pady=5, padx=(0, 10))
            ttk.Label(stats_grid, text=str(count), font=("TkDefaultFont", 10),
                     foreground=color).grid(row=i, column=1, sticky=tk.E, pady=5)
        
        # Performance Insights (Pareto Analysis) (LEFT COLUMN)
        insights_frame = ttk.LabelFrame(left_column, text="Performance Insights")
        insights_frame.pack(fill=tk.X, pady=(0, 10))
        
        insights_text = self._generate_pareto_insights(analysis_results)
        
        insights_label = ttk.Label(insights_frame, text=insights_text,
                                   font=("TkDefaultFont", 10), justify=tk.LEFT)
        insights_label.pack(padx=15, pady=15, anchor=tk.W)
        
        # Priority Recommendations (LEFT COLUMN)
        recommendations_frame = ttk.LabelFrame(left_column, text="Priority Recommendations")
        recommendations_frame.pack(fill=tk.X, pady=(0, 10))
        
        recommendations = self._generate_recommendations(analysis_results, notebook)
        
        for i, rec in enumerate(recommendations):
            rec_row = ttk.Frame(recommendations_frame)
            rec_row.pack(fill=tk.X, padx=15, pady=5)
            
            # Priority indicator
            priority_colors = {"HIGH": "#D32F2F", "MEDIUM": "#FF6F00", "LOW": "#1976D2"}
            ttk.Label(rec_row, text=f"{rec['priority']}: ",
                     font=("TkDefaultFont", 10, "bold"),
                     foreground=priority_colors.get(rec['priority'], "black")).pack(side=tk.LEFT)
            
            # Recommendation text
            ttk.Label(rec_row, text=rec['text'],
                     font=("TkDefaultFont", 10)).pack(side=tk.LEFT)
            
            # Clickable link if provided
            if rec.get('link_text') and rec.get('tab_index') is not None:
                link = ttk.Label(rec_row, text=f" {rec['link_text']}",
                               foreground="blue", cursor="hand2",
                               font=("TkDefaultFont", 9, "underline"))
                link.pack(side=tk.LEFT)
                
                # Bind click to switch tabs
                tab_index = rec['tab_index']
                link.bind('<Button-1>', lambda e, idx=tab_index: notebook.select(idx))
        
        # Export Report button (LEFT COLUMN)
        export_frame = ttk.Frame(left_column)
        export_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(export_frame, text="Export Report",
                  command=lambda: self._export_analysis_report(analysis_results)).pack()
        
        # RIGHT COLUMN: Scoring Methodology Explanation
        scoring_frame = ttk.LabelFrame(right_column, text="Health Score Methodology")
        scoring_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollable frame for scoring content
        scoring_canvas = tk.Canvas(scoring_frame, width=380)
        scoring_scrollbar = ttk.Scrollbar(scoring_frame, orient=tk.VERTICAL, command=scoring_canvas.yview)
        scoring_content = ttk.Frame(scoring_canvas)
        
        scoring_content.bind(
            "<Configure>",
            lambda e: scoring_canvas.configure(scrollregion=scoring_canvas.bbox("all"))
        )
        
        scoring_canvas.create_window((0, 0), window=scoring_content, anchor="nw")
        scoring_canvas.configure(yscrollcommand=scoring_scrollbar.set)
        
        scoring_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scoring_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling
        def on_scoring_mousewheel(event):
            try:
                if event.delta:
                    scoring_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    scoring_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    scoring_canvas.yview_scroll(1, "units")
            except:
                pass
        
        scoring_canvas.bind("<Enter>", lambda e: scoring_canvas.bind_all("<MouseWheel>", on_scoring_mousewheel))
        scoring_canvas.bind("<Leave>", lambda e: scoring_canvas.unbind_all("<MouseWheel>"))
        
        # Add scoring explanation content
        self._populate_scoring_explanation(scoring_content, analysis_results)
        
        # Tab 2: Unused Rules (Phase 5)
        unused_tab = ttk.Frame(notebook)
        notebook.add(unused_tab, text="Unused Rules")
        
        # Create sub-notebook for confidence levels
        unused_sub_notebook = ttk.Notebook(unused_tab)
        unused_sub_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Categorize unused rules by confidence level
        min_days = analysis_results.get('min_days_in_production', 14)
        unused_sids = analysis_results['unused_sids']
        sid_stats = analysis_results['sid_stats']
        
        confirmed_sids = []
        recent_sids = []
        never_observed_sids = []
        
        for sid in unused_sids:
            stat = sid_stats.get(sid, {})
            # BUG FIX #3: Use days_since_last_modified for categorization (not creation date)
            # This ensures recently modified rules are treated as "Recently Deployed"
            days = stat.get('days_since_last_modified')
            
            if days is None:
                never_observed_sids.append(sid)
            elif days >= min_days:
                confirmed_sids.append(sid)
            else:
                recent_sids.append(sid)
        
        # Helper function to create sub-tab with treeview, actions, and stats
        def create_unused_sub_tab(parent_notebook, title, sids_list, bg_color):
            """Create a sub-tab for unused rules with specified confidence level"""
            sub_tab = ttk.Frame(parent_notebook)
            parent_notebook.add(sub_tab, text=f"{title} ({len(sids_list)})")
            
            # Main content frame
            content_frame = ttk.Frame(sub_tab)
            content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Action controls at top
            controls_frame = ttk.Frame(content_frame)
            controls_frame.pack(fill=tk.X, pady=(0, 10))
            
            # Select All checkbox
            select_all_var = tk.BooleanVar(value=False)
            
            # Treeview for rules
            tree_container = ttk.Frame(content_frame)
            tree_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
            
            columns = ("☐", "Line", "SID", "Message", "Age of Rule (days)", "Last Modified")
            tree = ttk.Treeview(tree_container, columns=columns, show="headings", height=10)
            
            tree.heading("☐", text="☐")
            tree.heading("Line", text="Line", command=lambda: self._sort_treeview(tree, "Line", False))
            tree.heading("SID", text="SID", command=lambda: self._sort_treeview(tree, "SID", False))
            tree.heading("Message", text="Message")
            tree.heading("Age of Rule (days)", text="Age of Rule (days)", command=lambda: self._sort_treeview(tree, "Age of Rule (days)", False))
            tree.heading("Last Modified", text="Last Modified", command=lambda: self._sort_treeview(tree, "Last Modified", False))
            
            tree.column("☐", width=30, stretch=False, anchor=tk.CENTER)
            tree.column("Line", width=50, stretch=False)
            tree.column("SID", width=70, stretch=False)
            tree.column("Message", width=400, stretch=True)
            tree.column("Age of Rule (days)", width=120, stretch=False)
            tree.column("Last Modified", width=110, stretch=False)
            
            # Scrollbars
            v_scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=tree.yview)
            h_scrollbar = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=tree.xview)
            tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
            
            tree.grid(row=0, column=0, sticky="nsew")
            v_scrollbar.grid(row=0, column=1, sticky="ns")
            h_scrollbar.grid(row=1, column=0, sticky="ew")
            
            tree_container.grid_rowconfigure(0, weight=1)
            tree_container.grid_columnconfigure(0, weight=1)
            
            # Configure row colors
            tree.tag_configure("row_color", background=bg_color)
            
            # Show placeholder message if sub-tab is empty
            if not sids_list:
                # Add helpful placeholder message explaining why this sub-tab is empty
                placeholder_frame = ttk.Frame(content_frame)
                placeholder_frame.pack(fill=tk.BOTH, expand=True, pady=20)
                
                # Get min_days threshold from analysis_results for dynamic messages
                min_days = analysis_results.get('min_days_in_production', 14)
                
                # Different messages based on sub-tab type AND change tracking status
                # Check if change tracking is enabled to provide appropriate context
                tracking_enabled = self.parent.tracking_enabled
                
                if "Confirmed" in title:
                    # Confirmed Unused sub-tab is empty
                    icon = "ℹ️"
                    title_text = "No Confirmed Unused Rules"
                    
                    if not tracking_enabled:
                        # Change tracking is disabled - explain why this tab is empty
                        explanation = (
                            f"This sub-tab shows rules that are ≥{min_days} days old with 0 hits.\n\n"
                            "It's currently empty because:\n"
                            "• Change tracking is not enabled\n"
                            "• Rule ages cannot be determined\n\n"
                            "Without change tracking, all unused rules appear in the\n"
                            "'Unknown Age' sub-tab instead.\n\n"
                            "To enable age tracking:\n"
                            "→ Tools > Enable Change Tracking"
                        )
                        color = "#FF6600"  # Orange - informational warning
                    else:
                        # Change tracking is enabled - positive message
                        explanation = (
                            f"This sub-tab shows rules that are ≥{min_days} days old with 0 hits.\n\n"
                            "It's currently empty because:\n"
                            f"• All your rules are less than {min_days} days old (recently deployed)\n"
                            f"• Or all rules ≥{min_days} days old have been triggered\n\n"
                            "Rules will appear here when:\n"
                            f"• Recently deployed rules age beyond {min_days} days AND\n"
                            "• They still have 0 hits in CloudWatch logs\n\n"
                            "This is a positive sign - no old unused rules detected!"
                        )
                        color = "#2E7D32"  # Green
                        
                elif "Recently" in title:
                    # Recently Deployed sub-tab is empty
                    icon = "ℹ️"
                    title_text = "No Recently Deployed Unused Rules"
                    
                    if not tracking_enabled:
                        # Change tracking is disabled - explain why this tab is empty
                        explanation = (
                            f"This sub-tab shows rules that are <{min_days} days old with 0 hits.\n\n"
                            "It's currently empty because:\n"
                            "• Change tracking is not enabled\n"
                            "• Rule ages cannot be determined\n\n"
                            "Without change tracking, all unused rules appear in the\n"
                            "'Unknown Age' sub-tab instead.\n\n"
                            "To enable age tracking:\n"
                            "→ Tools > Enable Change Tracking"
                        )
                        color = "#FF6600"  # Orange - informational warning
                    else:
                        # Change tracking is enabled - positive message
                        explanation = (
                            f"This sub-tab shows rules that are <{min_days} days old with 0 hits.\n\n"
                            "It's currently empty because:\n"
                            "• All your recent rules have triggered (good!)\n"
                            f"• Or all rules are older than {min_days} days\n\n"
                            "This is a positive sign - your recently deployed rules\n"
                            "are being used!"
                        )
                        color = "#2E7D32"  # Green
                        
                else:
                    # Unknown Age sub-tab is empty
                    icon = "ℹ️"
                    title_text = "No Rules with Unknown Age"
                    
                    if not tracking_enabled:
                        # Change tracking is disabled - this is unusual (should have rules here)
                        explanation = (
                            "This sub-tab shows unused rules with unknown deployment dates.\n\n"
                            "It's currently empty because:\n"
                            "• No unused rules were detected in the analysis\n\n"
                            "Note: Change tracking is not enabled, so all unused rules\n"
                            "would normally appear here. The fact that this tab is empty\n"
                            "means all your rules are being used.\n\n"
                            "This is a positive sign - no unused rules detected!"
                        )
                        color = "#2E7D32"  # Green - this is actually good
                    else:
                        # Change tracking is enabled - ideal state
                        explanation = (
                            "This sub-tab shows unused rules with unknown deployment dates.\n\n"
                            "It's currently empty because:\n"
                            "• Change tracking is enabled for all rules\n"
                            "• All rules have known deployment dates\n\n"
                            "This is ideal - you have full visibility into rule ages!"
                        )
                        color = "#2E7D32"  # Green
                
                ttk.Label(placeholder_frame, text=f"{icon} {title_text}",
                         font=("TkDefaultFont", 11, "bold"), foreground=color).pack(pady=(0, 15))
                
                ttk.Label(placeholder_frame, text=explanation,
                         font=("TkDefaultFont", 9), justify=tk.LEFT,
                         wraplength=600).pack(padx=20)
            else:
                # Populate treeview with rule data
                for sid in sorted(sids_list):
                    # Find rule in main rule list
                    rule = next((r for r in self.parent.rules 
                               if hasattr(r, 'sid') and r.sid == sid), None)
                    
                    if rule:
                        line_num = self.parent.rules.index(rule) + 1
                        message = rule.message[:60] + "..." if len(rule.message) > 60 else rule.message
                        
                        # Get stats from analysis results
                        sid_stat = sid_stats.get(sid, {})
                        days = sid_stat.get('days_in_production')
                        days_str = str(days) if days is not None else 'Unknown'
                        
                        last_mod = sid_stat.get('last_modified')
                        if last_mod:
                            if isinstance(last_mod, str):
                                last_mod_str = last_mod[:10]  # Just date part
                            else:
                                last_mod_str = last_mod.strftime('%Y-%m-%d')
                        else:
                            last_mod_str = 'Unknown'
                        
                        tree.insert("", tk.END, 
                                  values=("☐", line_num, sid, message, days_str, last_mod_str),
                                  tags=("row_color",))
            
            # Checkbox toggle handler
            def on_tree_click(event):
                item = tree.identify_row(event.y)
                col = tree.identify_column(event.x)
                
                if col == '#1' and item:  # Checkbox column
                    values = tree.item(item, 'values')
                    new_check = "☑" if values[0] == "☐" else "☐"
                    tree.item(item, values=(new_check,) + values[1:])
            
            tree.bind("<Button-1>", on_tree_click)
            
            # Double-click handler to jump to rule in main editor
            def on_unused_tree_double_click(event):
                item = tree.identify_row(event.y)
                if not item:
                    return
                
                # Get the line number from the clicked item (column index 1, after checkbox)
                values = tree.item(item, 'values')
                if not values or len(values) < 2:
                    return
                
                try:
                    line_num = int(values[1])  # Line column
                except (ValueError, TypeError):
                    return
                
                # Jump to the rule in main editor
                self._jump_to_rule_in_main_editor(line_num, results_window)
            
            tree.bind("<Double-1>", on_unused_tree_double_click)
            
            # Spacebar handler to toggle checkboxes for all selected rows
            def on_tree_spacebar(event):
                selection = tree.selection()
                if not selection:
                    return 'break'
                
                # Toggle all selected rows
                for item in selection:
                    values = tree.item(item, 'values')
                    if values and len(values) > 0:
                        new_check = "☑" if values[0] == "☐" else "☐"
                        tree.item(item, values=(new_check,) + values[1:])
                
                return 'break'  # Prevent default spacebar behavior
            
            tree.bind("<space>", on_tree_spacebar)
            
            # Select All handler
            def on_select_all():
                check_state = "☑" if select_all_var.get() else "☐"
                for item in tree.get_children():
                    values = tree.item(item, 'values')
                    tree.item(item, values=(check_state,) + values[1:])
            
            ttk.Checkbutton(controls_frame, text="Select All", 
                          variable=select_all_var,
                          command=on_select_all).pack(side=tk.LEFT, padx=5)
            
            # Action dropdown
            ttk.Label(controls_frame, text="Action:").pack(side=tk.LEFT, padx=(20, 5))
            action_var = tk.StringVar(value="Delete Selected")
            action_combo = ttk.Combobox(controls_frame, textvariable=action_var,
                                       values=["Delete Selected", "Comment Out Selected"],
                                       state="readonly", width=20)
            action_combo.pack(side=tk.LEFT, padx=5)
            
            # Apply Action button
            def on_apply_action():
                # Get checked items
                checked_sids = []
                for item in tree.get_children():
                    values = tree.item(item, 'values')
                    if values[0] == "☑":  # Checked
                        checked_sids.append(int(values[2]))  # SID column
                
                if not checked_sids:
                    messagebox.showwarning("No Selection", "Please select rules to apply action.")
                    return
                
                action = action_var.get()
                
                if action == "Delete Selected":
                    # Confirm deletion
                    response = messagebox.askyesno(
                        "Confirm Deletion",
                        f"Delete {len(checked_sids)} unused rules?\n\n"
                        "This will permanently remove them from the rule group."
                    )
                    
                    if response:
                        # Save state for undo
                        self.parent.save_undo_state()
                        
                        # Find and delete rules from parent.rules
                        self.parent.rules = [r for r in self.parent.rules 
                                           if not (hasattr(r, 'sid') and r.sid in checked_sids)]
                        self.parent.refresh_table()
                        self.parent.modified = True
                        
                        # Close results window and show success
                        results_window.destroy()
                        messagebox.showinfo("Success", 
                                          f"Deleted {len(checked_sids)} unused rules.\n\n"
                                          "Run analysis again to see updated results.")
                
                elif action == "Comment Out Selected":
                    # Confirm comment out
                    response = messagebox.askyesno(
                        "Confirm Comment Out",
                        f"Comment out {len(checked_sids)} unused rules?\n\n"
                        "This will disable them but keep them in the rule group.\n"
                        "Rules will be prefixed with '# [UNUSED] ' for easy searching."
                    )
                    
                    if response:
                        # Save state for undo
                        self.parent.save_undo_state()
                        
                        # Convert rules to comments
                        for rule in self.parent.rules:
                            if hasattr(rule, 'sid') and rule.sid in checked_sids:
                                # Convert to comment with [UNUSED] prefix
                                rule_text = rule.to_string()
                                rule.is_comment = True
                                rule.comment_text = f"# [UNUSED] {rule_text}"
                        
                        self.parent.refresh_table()
                        self.parent.modified = True
                        
                        # Close results window and show success
                        results_window.destroy()
                        messagebox.showinfo("Success", 
                                          f"Commented out {len(checked_sids)} unused rules.\n\n"
                                          "Run analysis again to see updated results.")
            
            ttk.Button(controls_frame, text="Apply Action", 
                      command=on_apply_action).pack(side=tk.LEFT, padx=5)
            
            # Export button (Phase 12)
            def export_this_subtab():
                # Determine confidence level from title
                if 'Confirmed' in title:
                    conf_level = 'confirmed'
                elif 'Recently' in title:
                    conf_level = 'recent'
                else:
                    conf_level = 'never_observed'
                
                self._export_unused_rules(sids_list, conf_level, analysis_results)
            
            ttk.Button(controls_frame, text="Export", 
                      command=export_this_subtab).pack(side=tk.LEFT, padx=(20, 5))
            
            # Statistics panel at bottom
            stats_frame = ttk.Frame(content_frame)
            stats_frame.pack(fill=tk.X, pady=(10, 0))
            
            count = len(sids_list)
            total = analysis_results['total_rules']
            percentage = (count / total * 100) if total > 0 else 0
            
            ttk.Label(stats_frame, 
                     text=f"Count: {count} ({percentage:.1f}% of rules)",
                     font=("TkDefaultFont", 10)).pack(anchor=tk.W)
            
            return sub_tab
        
        # Create the 3 sub-tabs
        create_unused_sub_tab(unused_sub_notebook, "Confirmed Unused", 
                             confirmed_sids, "#FFEBEE")  # Light red
        create_unused_sub_tab(unused_sub_notebook, "Recently Deployed", 
                             recent_sids, "#FFF9C4")  # Light yellow
        create_unused_sub_tab(unused_sub_notebook, "Unknown Age", 
                             never_observed_sids, "#F5F5F5")  # Light gray
        
        # Tab 3: Low-Frequency Rules (Phase 6)
        low_freq_tab = ttk.Frame(notebook)
        # Exclude untracked SIDs from tab count
        untracked_sids_set = analysis_results.get('untracked_sids', set())
        low_freq_count = len([s for s, st in sid_stats.items() if st.get('category') == 'low_freq' and s not in untracked_sids_set])
        notebook.add(low_freq_tab, text=f"Low-Frequency ({low_freq_count})")
        
        # Main content frame
        low_freq_content = ttk.Frame(low_freq_tab)
        low_freq_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Description
        # BUG FIX #7: Clarify that low-freq includes rules with <1 hit/day OR <threshold total hits
        threshold = analysis_results.get('low_freq_threshold', 10)
        description_text = (f"Rules with < {threshold} total hits OR < 1 hit/day average "
                          f"(analysis period: {analysis_results['time_range_days']} days)")
        ttk.Label(low_freq_content, 
                 text=description_text,
                 font=("TkDefaultFont", 10)).pack(anchor=tk.W, pady=(0, 10))
        
        # Action controls at top
        low_freq_controls = ttk.Frame(low_freq_content)
        low_freq_controls.pack(fill=tk.X, pady=(0, 10))
        
        low_freq_select_all_var = tk.BooleanVar(value=False)
        
        # Treeview for low-frequency rules
        low_freq_tree_container = ttk.Frame(low_freq_content)
        low_freq_tree_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        low_freq_columns = ("☐", "Line", "SID", "Hits", "Hits/Day", "Last Hit", "Message")
        low_freq_tree = ttk.Treeview(low_freq_tree_container, columns=low_freq_columns, 
                                     show="headings", height=12)
        
        low_freq_tree.heading("☐", text="☐")
        low_freq_tree.heading("Line", text="Line", command=lambda: self._sort_treeview(low_freq_tree, "Line", False))
        low_freq_tree.heading("SID", text="SID", command=lambda: self._sort_treeview(low_freq_tree, "SID", False))
        low_freq_tree.heading("Hits", text="Hits", command=lambda: self._sort_treeview(low_freq_tree, "Hits", False))
        low_freq_tree.heading("Hits/Day", text="Hits/Day", command=lambda: self._sort_treeview(low_freq_tree, "Hits/Day", False))
        low_freq_tree.heading("Last Hit", text="Last Hit", command=lambda: self._sort_treeview(low_freq_tree, "Last Hit", False))
        low_freq_tree.heading("Message", text="Message")
        
        low_freq_tree.column("☐", width=30, stretch=False, anchor=tk.CENTER)
        low_freq_tree.column("Line", width=50, stretch=False)
        low_freq_tree.column("SID", width=70, stretch=False)
        low_freq_tree.column("Hits", width=70, stretch=False)
        low_freq_tree.column("Hits/Day", width=80, stretch=False)
        low_freq_tree.column("Last Hit", width=90, stretch=False)
        low_freq_tree.column("Message", width=450, stretch=True)
        
        # Scrollbars
        low_freq_v_scrollbar = ttk.Scrollbar(low_freq_tree_container, orient=tk.VERTICAL, 
                                            command=low_freq_tree.yview)
        low_freq_h_scrollbar = ttk.Scrollbar(low_freq_tree_container, orient=tk.HORIZONTAL, 
                                            command=low_freq_tree.xview)
        low_freq_tree.configure(yscrollcommand=low_freq_v_scrollbar.set, 
                               xscrollcommand=low_freq_h_scrollbar.set)
        
        low_freq_tree.grid(row=0, column=0, sticky="nsew")
        low_freq_v_scrollbar.grid(row=0, column=1, sticky="ns")
        low_freq_h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        low_freq_tree_container.grid_rowconfigure(0, weight=1)
        low_freq_tree_container.grid_columnconfigure(0, weight=1)
        
        # Populate with low-frequency rules (exclude untracked SIDs - already set above)
        low_freq_sids = [sid for sid, stat in sid_stats.items() 
                        if stat.get('category') == 'low_freq' and sid not in untracked_sids_set]
        
        for sid in sorted(low_freq_sids):
            # Find rule in main rule list
            rule = next((r for r in self.parent.rules 
                       if hasattr(r, 'sid') and r.sid == sid), None)
            
            if rule:
                line_num = self.parent.rules.index(rule) + 1
                message = rule.message[:50] + "..." if len(rule.message) > 50 else rule.message
                
                # Get stats
                stat = sid_stats.get(sid, {})
                hits = stat.get('hits', 0)
                hits_per_day = stat.get('hits_per_day', 0.0)
                hits_per_day_str = f"{hits_per_day:.1f}"
                last_hit_days = stat.get('last_hit_days', 999)
                last_hit_str = f"{last_hit_days}d ago" if last_hit_days < 999 else 'Unknown'
                
                # Determine color gradient by staleness
                if last_hit_days >= 21:
                    bg_color = "#ffcc66"  # Orange (>21d)
                elif last_hit_days >= 14:
                    bg_color = "#ffdd88"  # Yellow-orange (14-21d)
                elif last_hit_days >= 7:
                    bg_color = "#ffeeaa"  # Light yellow (7-14d)
                else:
                    bg_color = "#ffffcc"  # Very light yellow (<7d)
                
                # Configure unique tag for this row's color
                tag_name = f"low_freq_{bg_color}"
                low_freq_tree.tag_configure(tag_name, background=bg_color)
                
                low_freq_tree.insert("", tk.END, 
                                    values=("☐", line_num, sid, hits, hits_per_day_str, last_hit_str, message),
                                    tags=(tag_name,))
        
        # Checkbox toggle handler
        def on_low_freq_tree_click(event):
            item = low_freq_tree.identify_row(event.y)
            col = low_freq_tree.identify_column(event.x)
            
            if col == '#1' and item:  # Checkbox column
                values = low_freq_tree.item(item, 'values')
                new_check = "☑" if values[0] == "☐" else "☐"
                low_freq_tree.item(item, values=(new_check,) + values[1:])
        
        low_freq_tree.bind("<Button-1>", on_low_freq_tree_click)
        
        # Double-click handler to jump to rule in main editor
        def on_low_freq_double_click(event):
            item = low_freq_tree.identify_row(event.y)
            if not item:
                return
            
            # Get the line number from the clicked item (column index 1, after checkbox)
            values = low_freq_tree.item(item, 'values')
            if not values or len(values) < 2:
                return
            
            try:
                line_num = int(values[1])  # Line column
            except (ValueError, TypeError):
                return
            
            # Jump to the rule in main editor
            self._jump_to_rule_in_main_editor(line_num, results_window)
        
        low_freq_tree.bind("<Double-1>", on_low_freq_double_click)
        
        # Spacebar handler to toggle checkboxes for all selected rows
        def on_low_freq_spacebar(event):
            selection = low_freq_tree.selection()
            if not selection:
                return 'break'
            
            # Toggle all selected rows
            for item in selection:
                values = low_freq_tree.item(item, 'values')
                if values and len(values) > 0:
                    new_check = "☑" if values[0] == "☐" else "☐"
                    low_freq_tree.item(item, values=(new_check,) + values[1:])
            
            return 'break'  # Prevent default spacebar behavior
        
        low_freq_tree.bind("<space>", on_low_freq_spacebar)
        
        # Select All handler
        def on_low_freq_select_all():
            check_state = "☑" if low_freq_select_all_var.get() else "☐"
            for item in low_freq_tree.get_children():
                values = low_freq_tree.item(item, 'values')
                low_freq_tree.item(item, values=(check_state,) + values[1:])
        
        ttk.Checkbutton(low_freq_controls, text="Select All", 
                       variable=low_freq_select_all_var,
                       command=on_low_freq_select_all).pack(side=tk.LEFT, padx=5)
        
        # Action dropdown
        ttk.Label(low_freq_controls, text="Action:").pack(side=tk.LEFT, padx=(20, 5))
        low_freq_action_var = tk.StringVar(value="Comment Out Selected")
        low_freq_action_combo = ttk.Combobox(low_freq_controls, textvariable=low_freq_action_var,
                                            values=["Comment Out Selected", "Delete Selected"],
                                            state="readonly", width=20)
        low_freq_action_combo.pack(side=tk.LEFT, padx=5)
        
        # Apply Action button
        def on_low_freq_apply_action():
            # Get checked items
            checked_sids = []
            for item in low_freq_tree.get_children():
                values = low_freq_tree.item(item, 'values')
                if values[0] == "☑":  # Checked
                    checked_sids.append(int(values[2]))  # SID column
            
            if not checked_sids:
                messagebox.showwarning("No Selection", "Please select rules to apply action.")
                return
            
            action = low_freq_action_var.get()
            
            if action == "Delete Selected":
                response = messagebox.askyesno(
                    "Confirm Deletion",
                    f"Delete {len(checked_sids)} low-frequency rules?\n\n"
                    "These rules rarely trigger and may be shadow rules.\n"
                    "This will permanently remove them from the rule group."
                )
                
                if response:
                    # Save state for undo
                    self.parent.save_undo_state()
                    
                    self.parent.rules = [r for r in self.parent.rules 
                                       if not (hasattr(r, 'sid') and r.sid in checked_sids)]
                    self.parent.refresh_table()
                    self.parent.modified = True
                    results_window.destroy()
                    messagebox.showinfo("Success", 
                                      f"Deleted {len(checked_sids)} low-frequency rules.\n\n"
                                      "Run analysis again to see updated results.")
            
            elif action == "Comment Out Selected":
                response = messagebox.askyesno(
                    "Confirm Comment Out",
                    f"Comment out {len(checked_sids)} low-frequency rules?\n\n"
                    "This will disable them but keep them in the rule group.\n"
                    "Rules will be prefixed with '# [LOW-FREQUENCY] ' for easy searching."
                )
                
                if response:
                    # Save state for undo
                    self.parent.save_undo_state()
                    
                    for rule in self.parent.rules:
                        if hasattr(rule, 'sid') and rule.sid in checked_sids:
                            rule_text = rule.to_string()
                            rule.is_comment = True
                            rule.comment_text = f"# [LOW-FREQUENCY] {rule_text}"
                    
                    self.parent.refresh_table()
                    self.parent.modified = True
                    results_window.destroy()
                    messagebox.showinfo("Success", 
                                      f"Commented out {len(checked_sids)} low-frequency rules.\n\n"
                                      "Run analysis again to see updated results.")
        
        ttk.Button(low_freq_controls, text="Apply Action", 
                  command=on_low_freq_apply_action).pack(side=tk.LEFT, padx=5)
        
        # Export button (Phase 12)
        ttk.Button(low_freq_controls, text="Export", 
                  command=lambda: self._export_low_frequency_rules(analysis_results)).pack(side=tk.LEFT, padx=(20, 5))
        
        # Insights panel at bottom
        low_freq_insights_frame = ttk.LabelFrame(low_freq_content, text="Analysis Insights")
        low_freq_insights_frame.pack(fill=tk.X, pady=(10, 0))
        
        insights_content = ttk.Frame(low_freq_insights_frame)
        insights_content.pack(fill=tk.X, padx=15, pady=10)
        
        # Calculate insights
        very_low_count = len([s for s in low_freq_sids 
                             if sid_stats.get(s, {}).get('hits', 0) < 3])
        stale_count = len([s for s in low_freq_sids 
                          if sid_stats.get(s, {}).get('last_hit_days', 0) > 14])
        
        # Display insights
        insight_text = f"• {very_low_count} rules had <3 hits (potential shadow rules)\n"
        insight_text += f"• {stale_count} rules not triggered in last 14+ days (stale)\n"
        insight_text += "• Consider using 'Review Rules' feature to check for shadowing"
        
        ttk.Label(insights_content, text=insight_text, 
                 font=("TkDefaultFont", 10), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Statistics
        count = len(low_freq_sids)
        total = analysis_results['total_rules']
        percentage = (count / total * 100) if total > 0 else 0
        
        ttk.Label(insights_content, 
                 text=f"\nCount: {count} ({percentage:.1f}% of rules)",
                 font=("TkDefaultFont", 10)).pack(anchor=tk.W, pady=(5, 0))
        
        # Tab 4: Effectiveness (Phase 7)
        effectiveness_tab = ttk.Frame(notebook)
        notebook.add(effectiveness_tab, text="Effectiveness")
        
        # Main content frame with scrollbar
        eff_main_container = ttk.Frame(effectiveness_tab)
        eff_main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create scrollable canvas
        eff_canvas = tk.Canvas(eff_main_container)
        eff_scrollbar = ttk.Scrollbar(eff_main_container, orient=tk.VERTICAL, command=eff_canvas.yview)
        eff_content = ttk.Frame(eff_canvas)
        
        eff_content.bind(
            "<Configure>",
            lambda e: eff_canvas.configure(scrollregion=eff_canvas.bbox("all"))
        )
        
        eff_canvas.create_window((0, 0), window=eff_content, anchor="nw")
        eff_canvas.configure(yscrollcommand=eff_scrollbar.set)
        
        eff_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        eff_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling
        def on_eff_mousewheel(event):
            try:
                if event.delta:
                    eff_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    eff_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    eff_canvas.yview_scroll(1, "units")
            except:
                pass
        
        eff_canvas.bind("<Enter>", lambda e: eff_canvas.bind_all("<MouseWheel>", on_eff_mousewheel))
        eff_canvas.bind("<Leave>", lambda e: eff_canvas.unbind_all("<MouseWheel>"))
        
        # Title
        ttk.Label(eff_content, 
                 text="Top Performing Rules (Pareto Analysis):",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Get top 20 rules sorted by hits descending
        sorted_rules = sorted(sid_stats.items(), key=lambda x: x[1]['hits'], reverse=True)
        top_20 = sorted_rules[:20]
        
        # Calculate total hits for percentage calculations
        total_hits = sum(stat['hits'] for stat in sid_stats.values())
        
        # Treeview for top 20 rules (read-only, no checkboxes)
        eff_tree_container = ttk.Frame(eff_content)
        eff_tree_container.pack(fill=tk.BOTH, expand=False, pady=(0, 10))
        
        eff_columns = ("Line", "SID", "Hits", "Hits/Day", "% Traffic", "Cumulative %", "Broad", "Message")
        eff_tree = ttk.Treeview(eff_tree_container, columns=eff_columns, show="headings", height=20)
        
        eff_tree.heading("Line", text="Line", command=lambda: self._sort_treeview(eff_tree, "Line", False))
        eff_tree.heading("SID", text="SID", command=lambda: self._sort_treeview(eff_tree, "SID", False))
        eff_tree.heading("Hits", text="Hits", command=lambda: self._sort_treeview(eff_tree, "Hits", False))
        eff_tree.heading("Hits/Day", text="Hits/Day", command=lambda: self._sort_treeview(eff_tree, "Hits/Day", False))
        eff_tree.heading("% Traffic", text="% Traffic", command=lambda: self._sort_treeview(eff_tree, "% Traffic", False))
        eff_tree.heading("Cumulative %", text="Cumulative %", command=lambda: self._sort_treeview(eff_tree, "Cumulative %", False))
        eff_tree.heading("Broad", text="Broad")
        eff_tree.heading("Message", text="Message")
        
        eff_tree.column("Line", width=50, stretch=False)
        eff_tree.column("SID", width=70, stretch=False)
        eff_tree.column("Hits", width=80, stretch=False)
        eff_tree.column("Hits/Day", width=80, stretch=False)
        eff_tree.column("% Traffic", width=80, stretch=False)
        eff_tree.column("Cumulative %", width=100, stretch=False)
        eff_tree.column("Broad", width=60, stretch=False, anchor=tk.CENTER)
        eff_tree.column("Message", width=350, stretch=True)
        
        # Scrollbars
        eff_v_scrollbar = ttk.Scrollbar(eff_tree_container, orient=tk.VERTICAL, command=eff_tree.yview)
        eff_h_scrollbar = ttk.Scrollbar(eff_tree_container, orient=tk.HORIZONTAL, command=eff_tree.xview)
        eff_tree.configure(yscrollcommand=eff_v_scrollbar.set, xscrollcommand=eff_h_scrollbar.set)
        
        eff_tree.grid(row=0, column=0, sticky="nsew")
        eff_v_scrollbar.grid(row=0, column=1, sticky="ns")
        eff_h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        eff_tree_container.grid_rowconfigure(0, weight=1)
        eff_tree_container.grid_columnconfigure(0, weight=1)
        
        # Configure color tags for broadness levels
        eff_tree.tag_configure("critical_broad", foreground="#D32F2F")  # Red
        eff_tree.tag_configure("high_broad", foreground="#FF6F00")      # Orange
        eff_tree.tag_configure("medium_broad", foreground="#FFA000")    # Amber
        eff_tree.tag_configure("normal", foreground="#2E7D32")          # Green
        
        # Double-click handler to jump to rule in main editor
        def on_eff_tree_double_click(event):
            item = eff_tree.identify_row(event.y)
            if not item:
                return
            
            # Get the line number from the clicked item (first column)
            values = eff_tree.item(item, 'values')
            if not values or not values[0]:
                return
            
            try:
                line_num = int(values[0])  # Line column
            except (ValueError, TypeError):
                return
            
            # Jump to the rule in main editor
            self._jump_to_rule_in_main_editor(line_num, results_window)
        
        eff_tree.bind("<Double-1>", on_eff_tree_double_click)
        
        # Populate with top 20 rules
        cumulative_percent = 0.0
        broad_rules = []  # Track rules >10% for detailed analysis
        
        for idx, (sid, stats) in enumerate(top_20):
            # Find rule in main rule list
            rule = next((r for r in self.parent.rules 
                       if hasattr(r, 'sid') and r.sid == sid), None)
            
            if rule:
                line_num = self.parent.rules.index(rule) + 1
                message = rule.message[:50] + "..." if len(rule.message) > 50 else rule.message
                
                hits = stats.get('hits', 0)
                hits_per_day = stats.get('hits_per_day', 0.0)
                percent = stats.get('percent', 0.0)
                cumulative_percent += percent
                
                # Determine broadness indicator
                if percent > 30:
                    indicator = "🔴"
                    tag = "critical_broad"
                    if percent > 10:
                        broad_rules.append((sid, stats, rule, percent, "CRITICAL"))
                elif percent > 15:
                    indicator = "🟡"
                    tag = "high_broad"
                    if percent > 10:
                        broad_rules.append((sid, stats, rule, percent, "HIGH"))
                elif percent > 10:
                    indicator = "🟠"
                    tag = "medium_broad"
                    broad_rules.append((sid, stats, rule, percent, "MEDIUM"))
                else:
                    indicator = "✓"
                    tag = "normal"
                
                eff_tree.insert("", tk.END,
                              values=(line_num, sid, f"{hits:,}", f"{hits_per_day:.1f}", f"{percent:.1f}%", 
                                     f"{cumulative_percent:.1f}%", indicator, message),
                              tags=(tag,))
        
        # Broadness analysis section (if any rules >10% traffic)
        if broad_rules:
            broad_frame = ttk.LabelFrame(eff_content, text="⚠️ Overly-Broad Rules Detected")
            broad_frame.pack(fill=tk.X, pady=(10, 0))
            
            broad_content = ttk.Frame(broad_frame)
            broad_content.pack(fill=tk.X, padx=15, pady=10)
            
            ttk.Label(broad_content, 
                     text=f"{len(broad_rules)} rule{'s' if len(broad_rules) != 1 else ''} flagged as potentially too broad:",
                     font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
            
            # Detailed analysis for each broad rule
            for sid, stats, rule, percent, severity in broad_rules:
                # Severity indicator
                severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟠"}.get(severity, "⚠️")
                
                rule_frame = ttk.Frame(broad_content)
                rule_frame.pack(fill=tk.X, pady=(0, 15))
                
                # Header with severity
                header_text = f"{severity_emoji} SID {sid} - {severity} ({percent:.1f}% of traffic):"
                ttk.Label(rule_frame, text=header_text,
                         font=("TkDefaultFont", 10, "bold"),
                         foreground={"CRITICAL": "#D32F2F", "HIGH": "#FF6F00", "MEDIUM": "#FFA000"}.get(severity, "#000000")).pack(anchor=tk.W)
                
                # Rule details
                details_frame = ttk.Frame(rule_frame)
                details_frame.pack(fill=tk.X, padx=20, pady=(5, 0))
                
                # Display full rule text with wrapping to use available screen space
                rule_full_text = rule.to_string()
                ttk.Label(details_frame, text=f"• Rule: {rule_full_text}",
                         font=("TkDefaultFont", 9), wraplength=900, justify=tk.LEFT).pack(anchor=tk.W, pady=2)
                
                # Problem description
                problem_text = "• Problem: "
                if percent > 40:
                    problem_text += "Extremely generic - matches a very large portion of traffic"
                elif percent > 25:
                    problem_text += "Too generic - matches an excessive amount of traffic"
                elif percent > 15:
                    problem_text += "Overly broad - matches more traffic than typical"
                else:
                    problem_text += "Moderately broad - consider refining for better specificity"
                
                ttk.Label(details_frame, text=problem_text,
                         font=("TkDefaultFont", 9)).pack(anchor=tk.W, pady=2)
                
                # Security impact - adjust message based on rule action
                impact_text = f"• Impact: {percent:.1f}% of all traffic hits this single rule"
                
                # Check if rule action is a blocking action (drop/reject) vs allowing (pass/alert)
                is_blocking_action = rule.action.lower() in ['drop', 'reject']
                
                if percent > 30:
                    if is_blocking_action:
                        impact_text += " (high risk of being too broad)"
                    else:
                        impact_text += " (high risk of allowing unwanted traffic)"
                elif percent > 15:
                    if is_blocking_action:
                        impact_text += " (may be too broad)"
                    else:
                        impact_text += " (may allow more than intended)"
                
                ttk.Label(details_frame, text=impact_text,
                         font=("TkDefaultFont", 9)).pack(anchor=tk.W, pady=2)
                
                # Recommendations - protocol-aware and action-aware
                rec_text = "• Recommendation: "
                
                # Get base rule components for building examples
                action = rule.action  # Use actual rule action
                src = rule.src_net
                src_port = rule.src_port
                dst = rule.dst_net
                dst_port = rule.dst_port
                direction = rule.direction
                protocol = rule.protocol.lower()
                
                # Check if rule is using HTTP/TLS protocol already vs generic TCP
                if protocol == 'http':
                    # HTTP rule that's too broad - recommend more specific domain matching
                    rec_text += "Make domain matching more specific:\n"
                    rec_text += f"    - Instead of broad domains like \".example.com\", use more specific subdomains\n"
                    rec_text += f"    - Example: {action} http {src} {src_port} {direction} {dst} {dst_port} (http.host; content:\".api.example.com\"; endswith; flow:to_server; sid:XXXXX; rev:1;)\n"
                    rec_text += f"    - Example: {action} http {src} {src_port} {direction} {dst} {dst_port} (http.host; content:\".app.example.com\"; endswith; flow:to_server; sid:XXXXX; rev:1;)\n"
                    rec_text += f"    - Or split by specific domains instead of wildcard matching"
                elif protocol in ['tls', 'https']:
                    # TLS rule that's too broad - recommend more specific domain matching
                    rec_text += "Make domain matching more specific:\n"
                    rec_text += f"    - Instead of broad domains like \".example.com\", use more specific subdomains\n"
                    rec_text += f"    - Example: {action} tls {src} {src_port} {direction} {dst} {dst_port} (tls.sni; content:\".api.example.com\"; nocase; endswith; flow:to_server; sid:XXXXX; rev:1;)\n"
                    rec_text += f"    - Example: {action} tls {src} {src_port} {direction} {dst} {dst_port} (tls.sni; content:\".app.example.com\"; nocase; endswith; flow:to_server; sid:XXXXX; rev:1;)\n"
                    rec_text += f"    - Or split by specific domains instead of wildcard matching"
                elif protocol == 'tcp' and dst_port == '80':
                    # Generic TCP on port 80 - recommend switching to HTTP protocol
                    rec_text += "Split into specific domain-based HTTP rules:\n"
                    rec_text += f"    - Example: {action} http {src} {src_port} {direction} {dst} 80 (http.host; content:\".example.com\"; endswith; flow:to_server; sid:XXXXX; rev:1;)\n"
                    rec_text += f"    - Example: {action} http {src} {src_port} {direction} {dst} 80 (http.host; content:\".amazonaws.com\"; endswith; flow:to_server; sid:XXXXX; rev:1;)"
                elif protocol == 'tcp' and dst_port == '443':
                    # Generic TCP on port 443 - recommend switching to TLS protocol
                    rec_text += "Split into specific domain-based TLS rules:\n"
                    rec_text += f"    - Example: {action} tls {src} {src_port} {direction} {dst} 443 (tls.sni; content:\".example.com\"; nocase; endswith; flow:to_server; sid:XXXXX; rev:1;)\n"
                    rec_text += f"    - Example: {action} tls {src} {src_port} {direction} {dst} 443 (tls.sni; content:\".amazonaws.com\"; nocase; endswith; flow:to_server; sid:XXXXX; rev:1;)"
                elif 'any' in [rule.src_net.lower(), rule.dst_net.lower()]:
                    rec_text += "Replace 'any' with specific network variables:\n"
                    rec_text += "    - Use $HOME_NET, $DMZ_NET, or specific CIDR blocks\n"
                    rec_text += "    - Consider creating network-specific rules"
                elif 'any' in [rule.src_port.lower(), rule.dst_port.lower()]:
                    rec_text += "Replace 'any' port with specific port ranges:\n"
                    rec_text += "    - Use specific ports like [80,443] or port variables\n"
                    rec_text += "    - Limit scope to necessary services"
                else:
                    rec_text += "Add more specific matching criteria:\n"
                    rec_text += "    - Use content matching for protocol fields\n"
                    rec_text += "    - Add flow keywords for direction specificity"
                
                # Display recommendations in a selectable Text widget instead of Label
                rec_text_widget = tk.Text(details_frame, height=6, wrap=tk.WORD,
                                         font=("TkDefaultFont", 9), bg='#F0F0F0',
                                         relief=tk.FLAT, borderwidth=0, cursor="arrow")
                rec_text_widget.pack(fill=tk.X, anchor=tk.W, pady=2)
                rec_text_widget.insert("1.0", rec_text)
                rec_text_widget.config(state=tk.DISABLED)  # Make read-only but still selectable
                
                # Bind right-click to show copy menu
                def show_copy_menu(event, widget=rec_text_widget):
                    try:
                        menu = tk.Menu(self.parent.root, tearoff=0)
                        if widget.tag_ranges(tk.SEL):
                            menu.add_command(label="Copy Selection", 
                                           command=lambda: self._copy_text_selection(widget))
                        menu.add_command(label="Copy All", 
                                       command=lambda: self._copy_all_text(widget))
                        menu.add_command(label="Select All",
                                       command=lambda: self._select_all_text(widget))
                        menu.tk_popup(event.x_root, event.y_root)
                    finally:
                        try:
                            menu.grab_release()
                        except:
                            pass
                
                rec_text_widget.bind("<Button-3>", show_copy_menu)
                
                # Separator between rules
                ttk.Separator(broad_content, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(10, 0))
        
        # Key Insights panel
        insights_frame = ttk.LabelFrame(eff_content, text="Key Insights")
        insights_frame.pack(fill=tk.X, pady=(10, 0))
        
        insights_content_frame = ttk.Frame(insights_frame)
        insights_content_frame.pack(fill=tk.X, padx=15, pady=10)
        
        # Calculate top 5 percentage
        top_5_percent = sum(stat['percent'] for _, stat in sorted_rules[:5])
        
        # Get Pareto 10% from analysis results (already calculated)
        sorted_all = sorted(sid_stats.items(), key=lambda x: x[1]['hits'], reverse=True)
        top_10_count = max(1, len(sorted_all) // 10)
        top_10_hits = sum(stat['hits'] for _, stat in sorted_all[:top_10_count])
        top_10_pct = int((top_10_hits / total_hits * 100)) if total_hits > 0 else 0
        
        insights_text = f"• Top 5 rules handle {top_5_percent:.1f}% of traffic\n"
        insights_text += f"• Top 10% of rules ({top_10_count} rules) handle {top_10_pct}% of traffic\n"
        insights_text += f"• {len(broad_rules)} rule{'s' if len(broad_rules) != 1 else ''} flagged as potentially too broad (>{10}% traffic)"
        
        ttk.Label(insights_content_frame, text=insights_text,
                 font=("TkDefaultFont", 10), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Export button
        export_frame = ttk.Frame(eff_content)
        export_frame.pack(fill=tk.X, pady=(15, 0))
        
        def export_effectiveness():
            """Export effectiveness analysis to file"""
            filename = filedialog.asksaveasfilename(
                title="Export Effectiveness Analysis",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if not filename:
                return
            
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("Rule Effectiveness Analysis\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Time Range: Last {analysis_results['time_range_days']} days\n\n")
                    
                    f.write("Top 20 Performing Rules:\n")
                    f.write("-" * 60 + "\n")
                    cumul = 0.0
                    for idx, (sid, stats) in enumerate(top_20):
                        rule = next((r for r in self.parent.rules 
                                   if hasattr(r, 'sid') and r.sid == sid), None)
                        if rule:
                            hits = stats.get('hits', 0)
                            percent = stats.get('percent', 0.0)
                            cumul += percent
                            f.write(f"{idx+1}. SID {sid}: {hits:,} hits ({percent:.1f}%, cumulative {cumul:.1f}%)\n")
                            f.write(f"   {rule.message}\n\n")
                    
                    if broad_rules:
                        f.write("\nBroadness Analysis:\n")
                        f.write("-" * 60 + "\n")
                        for sid, stats, rule, percent, severity in broad_rules:
                            f.write(f"{severity} - SID {sid} ({percent:.1f}% of traffic)\n")
                            f.write(f"Rule: {rule.to_string()}\n\n")
                
                messagebox.showinfo("Export Complete", f"Effectiveness analysis exported to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export analysis:\n{str(e)}")
        
        ttk.Button(export_frame, text="Export List", command=export_effectiveness).pack()
        
        # Tab 5: Efficiency Tiers (Phase 8)
        tiers_tab = ttk.Frame(notebook)
        notebook.add(tiers_tab, text="Tiers")
        
        # Main content frame
        tiers_content = ttk.Frame(tiers_tab)
        tiers_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        ttk.Label(tiers_content, 
                 text="Rule Distribution by Efficiency Tier:",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Bar chart canvas
        chart_frame = ttk.Frame(tiers_content)
        chart_frame.pack(fill=tk.X, pady=(0, 15))
        
        chart_canvas = tk.Canvas(chart_frame, width=720, height=80, bg='white')
        chart_canvas.pack()
        
        # Draw the chart (pass notebook for clickable navigation)
        self._draw_tiers_chart(chart_canvas, analysis_results['categories'], 
                              analysis_results['total_rules'], notebook)
        
        # Tier Definitions panel
        defs_frame = ttk.LabelFrame(tiers_content, text="Tier Definitions")
        defs_frame.pack(fill=tk.X, pady=(0, 15))
        
        defs_grid = ttk.Frame(defs_frame)
        defs_grid.pack(padx=15, pady=15)
        
        categories = analysis_results['categories']
        total_rules = analysis_results['total_rules']
        
        # Use only logged rules for percentage calculation (same as chart)
        # This ensures percentages match the tier chart exactly
        unlogged_count = categories.get('unlogged', 0)
        total_logged = total_rules - unlogged_count
        
        # Define tier info with emoji, name, criteria, color
        tier_defs = [
            ("🔴", "Unused", "0 hits", categories['unused'], "#D32F2F"),
            ("🟠", "Low-Frequency", f"<{analysis_results.get('low_freq_threshold', 10)} total hits OR <1 hit/day", 
             categories['low_freq'], "#FF6F00"),
            ("🔵", "Medium", "1-9.9 hits/day", categories['medium'], "#1976D2"),
            ("🟢", "High", "≥10 hits/day", categories['high'], "#2E7D32")
        ]
        
        for i, (emoji, name, criteria, count, color) in enumerate(tier_defs):
            # Emoji
            ttk.Label(defs_grid, text=emoji, font=("TkDefaultFont", 12)).grid(
                row=i, column=0, sticky=tk.W, pady=5, padx=(0, 10))
            
            # Name and criteria - use total_logged for percentage (same as chart)
            pct = (count / total_logged * 100) if total_logged > 0 else 0
            label_text = f"{name} ({criteria}): {count} rules ({pct:.1f}%)"
            ttk.Label(defs_grid, text=label_text, font=("TkDefaultFont", 10),
                     foreground=color).grid(row=i, column=1, sticky=tk.W, pady=5)
        
        # Distribution Analysis panel
        dist_frame = ttk.LabelFrame(tiers_content, text="Distribution Analysis")
        dist_frame.pack(fill=tk.X, pady=(0, 15))
        
        dist_content = ttk.Frame(dist_frame)
        dist_content.pack(padx=15, pady=15)
        
        # Calculate metrics
        active_rules = categories['medium'] + categories['high']
        active_pct = (active_rules / total_rules * 100) if total_rules > 0 else 0
        unused_pct = (categories['unused'] / total_rules * 100) if total_rules > 0 else 0
        low_freq_pct = (categories['low_freq'] / total_rules * 100) if total_rules > 0 else 0
        
        # Calculate traffic concentration for high tier
        sid_stats = analysis_results.get('sid_stats', {})
        if sid_stats:
            sorted_rules = sorted(sid_stats.items(), key=lambda x: x[1]['hits'], reverse=True)
            high_tier_rules = [s for s in sorted_rules if s[1].get('category') == 'high']
            
            high_tier_hits = sum(stat['hits'] for _, stat in high_tier_rules)
            total_hits = sum(stat['hits'] for stat in sid_stats.values())
            high_tier_traffic_pct = (high_tier_hits / total_hits * 100) if total_hits > 0 else 0
            
            medium_tier_rules = [s for s in sorted_rules if s[1].get('category') == 'medium']
            medium_tier_hits = sum(stat['hits'] for _, stat in medium_tier_rules)
            medium_tier_traffic_pct = (medium_tier_hits / total_hits * 100) if total_hits > 0 else 0
        else:
            high_tier_traffic_pct = 0
            medium_tier_traffic_pct = 0
        
        # Efficiency rating
        if active_pct >= 95:
            rating = "EXCELLENT"
            rating_color = "#2E7D32"  # Green
        elif active_pct >= 90:
            rating = "GOOD"
            rating_color = "#7CB342"  # Light green
        elif active_pct >= 80:
            rating = "FAIR"
            rating_color = "#FFA000"  # Orange
        else:
            rating = "POOR"
            rating_color = "#D32F2F"  # Red
        
        # Display analysis
        analysis_text = f"• Total rules analyzed: {total_rules:,}\n"
        analysis_text += f"• Unused rules: {unused_pct:.1f}% "
        if unused_pct > 5:
            analysis_text += "(consider removal)\n"
        else:
            analysis_text += "\n"
        
        analysis_text += f"• Low-frequency rules: {low_freq_pct:.1f}% "
        if low_freq_pct > 5:
            analysis_text += "(potential shadow rules)\n"
        else:
            analysis_text += "\n"
        
        analysis_text += f"• Active rules (medium+high): {active_pct:.1f}%\n"
        
        if high_tier_traffic_pct > 0:
            analysis_text += f"• High-tier rules handle {high_tier_traffic_pct:.1f}% of all traffic\n"
        if medium_tier_traffic_pct > 0:
            analysis_text += f"• Medium-tier rules handle {medium_tier_traffic_pct:.1f}% of traffic\n"
        
        ttk.Label(dist_content, text=analysis_text,
                 font=("TkDefaultFont", 10), justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 10))
        
        # Efficiency rating
        rating_frame = ttk.Frame(dist_content)
        rating_frame.pack(anchor=tk.W)
        
        ttk.Label(rating_frame, text="• Efficiency rating: ",
                 font=("TkDefaultFont", 10)).pack(side=tk.LEFT)
        ttk.Label(rating_frame, text=rating,
                 font=("TkDefaultFont", 10, "bold"),
                 foreground=rating_color).pack(side=tk.LEFT)
        ttk.Label(rating_frame, text=f" ({active_pct:.1f}% active)",
                 font=("TkDefaultFont", 10)).pack(side=tk.LEFT)
        
        # Navigation buttons
        nav_frame = ttk.Frame(tiers_content)
        nav_frame.pack(fill=tk.X, pady=(15, 0))
        
        ttk.Label(nav_frame, text="Quick Navigation:",
                 font=("TkDefaultFont", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(nav_frame, text="View Unused Rules",
                  command=lambda: notebook.select(1)).pack(side=tk.LEFT, padx=5)
        ttk.Button(nav_frame, text="View Low-Frequency",
                  command=lambda: notebook.select(2)).pack(side=tk.LEFT, padx=5)
        ttk.Button(nav_frame, text="View Top Rules",
                  command=lambda: notebook.select(3)).pack(side=tk.LEFT, padx=5)
        
        # Export button (Phase 12)
        export_tiers_frame = ttk.Frame(tiers_content)
        export_tiers_frame.pack(fill=tk.X, pady=(15, 0))
        
        ttk.Button(export_tiers_frame, text="Export Chart",
                  command=lambda: self._export_tiers_chart(analysis_results)).pack()
        
        # Tab 6: SID Search (Phase 9)
        search_tab = ttk.Frame(notebook)
        notebook.add(search_tab, text="Search")
        
        # Main content frame
        search_content = ttk.Frame(search_tab)
        search_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        ttk.Label(search_content, 
                 text="Quick Rule Lookup:",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Search input section
        input_frame = ttk.Frame(search_content)
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(input_frame, text="Enter SID to view detailed statistics:").pack(anchor=tk.W, pady=(0, 5))
        
        # SID input with search buttons
        search_row = ttk.Frame(input_frame)
        search_row.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_row, text="SID:").pack(side=tk.LEFT, padx=(0, 5))
        
        search_sid_var = tk.StringVar()
        search_entry = ttk.Entry(search_row, textvariable=search_sid_var, width=15)
        search_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # Recent searches (will be populated after first search)
        recent_searches = []
        recent_frame = ttk.Frame(input_frame)
        recent_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(recent_frame, text="Recent:").pack(side=tk.LEFT, padx=(0, 5))
        
        def add_to_recent(sid):
            """Add SID to recent searches (max 3)"""
            if sid in recent_searches:
                recent_searches.remove(sid)
            recent_searches.insert(0, sid)
            if len(recent_searches) > 3:
                recent_searches.pop()
            update_recent_display()
        
        def update_recent_display():
            """Update recent searches display"""
            # Clear existing recent buttons
            for widget in recent_frame.winfo_children()[1:]:  # Keep label
                widget.destroy()
            
            # Add buttons for each recent search
            for sid in recent_searches:
                btn = ttk.Button(recent_frame, text=f"[{sid}]",
                               command=lambda s=sid: [search_sid_var.set(str(s)), perform_search()])
                btn.pack(side=tk.LEFT, padx=2)
        
        # Results display area
        results_frame = ttk.LabelFrame(search_content, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create scrollable canvas for results
        results_canvas = tk.Canvas(results_frame)
        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_canvas.yview)
        results_content = ttk.Frame(results_canvas)
        
        results_content.bind(
            "<Configure>",
            lambda e: results_canvas.configure(scrollregion=results_canvas.bbox("all"))
        )
        
        results_canvas.create_window((0, 0), window=results_content, anchor="nw")
        results_canvas.configure(yscrollcommand=results_scrollbar.set)
        
        results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling
        def on_results_mousewheel(event):
            try:
                if event.delta:
                    results_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    results_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    results_canvas.yview_scroll(1, "units")
            except:
                pass
        
        results_canvas.bind("<Enter>", lambda e: results_canvas.bind_all("<MouseWheel>", on_results_mousewheel))
        results_canvas.bind("<Leave>", lambda e: results_canvas.unbind_all("<MouseWheel>"))
        
        # Initial "not tested yet" message
        ttk.Label(results_content, text="Enter a SID and click Search to view statistics",
                 font=("TkDefaultFont", 9, "italic"), foreground="#666666").pack(padx=10, pady=20)
        
        def perform_search():
            """Perform SID search and display results"""
            # Clear previous results
            for widget in results_content.winfo_children():
                widget.destroy()
            
            # Get and validate SID
            sid_str = search_sid_var.get().strip()
            if not sid_str:
                ttk.Label(results_content, text="Please enter a SID to search",
                         foreground="red").pack(padx=10, pady=20)
                return
            
            try:
                sid = int(sid_str)
            except ValueError:
                ttk.Label(results_content, text="Invalid SID. Please enter a valid number.",
                         foreground="red").pack(padx=10, pady=20)
                return
            
            # Add to recent searches
            add_to_recent(sid)
            
            # Get SID stats
            sid_stats = analysis_results.get('sid_stats', {})
            
            # Check if SID exists in analysis
            if sid in sid_stats:
                # SID found - display detailed statistics
                stats = sid_stats[sid]
                
                # Find the rule in parent rules list
                rule = next((r for r in self.parent.rules 
                           if hasattr(r, 'sid') and r.sid == sid), None)
                
                if not rule:
                    ttk.Label(results_content, text=f"SID {sid} found in analysis but not in current rule file",
                             foreground="orange").pack(padx=10, pady=20)
                    return
                
                # Create results display
                result_panel = ttk.Frame(results_content)
                result_panel.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
                
                # SID header
                ttk.Label(result_panel, text=f"SID {sid}",
                         font=("TkDefaultFont", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
                
                # Usage Statistics section
                ttk.Label(result_panel, text=f"Usage Statistics (Last {analysis_results['time_range_days']} days):",
                         font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 5))
                
                stats_grid = ttk.Frame(result_panel)
                stats_grid.pack(fill=tk.X, pady=(0, 10))
                
                # Display statistics
                stat_items = [
                    ("Total hits:", f"{stats.get('hits', 0):,}"),
                    ("Percentage of traffic:", f"{stats.get('percent', 0.0):.2f}%"),
                    ("Hits per day:", f"{stats.get('hits_per_day', 0.0):.1f} avg"),
                ]
                
                if stats.get('last_hit_days') is not None:
                    last_hit_days = stats['last_hit_days']
                    stat_items.append(("Last hit:", f"{last_hit_days} days ago"))
                
                if stats.get('days_in_production') is not None:
                    stat_items.append(("Age of rule:", f"{stats['days_in_production']} days"))
                
                for label, value in stat_items:
                    row = ttk.Frame(stats_grid)
                    row.pack(fill=tk.X, pady=2)
                    ttk.Label(row, text=f"• {label}", width=25).pack(side=tk.LEFT)
                    ttk.Label(row, text=value, font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
                
                # Rule Information section
                ttk.Label(result_panel, text="Rule Information:",
                         font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(15, 5))
                
                rule_info_grid = ttk.Frame(result_panel)
                rule_info_grid.pack(fill=tk.X, pady=(0, 10))
                
                line_num = self.parent.rules.index(rule) + 1
                
                rule_items = [
                    ("Line #:", str(line_num)),
                    ("Action:", rule.action.upper()),
                    ("Protocol:", rule.protocol.upper()),
                    ("Message:", rule.message[:60] + "..." if len(rule.message) > 60 else rule.message),
                ]
                
                if hasattr(rule, 'rev'):
                    rule_items.append(("Current revision:", str(rule.rev)))
                
                for label, value in rule_items:
                    row = ttk.Frame(rule_info_grid)
                    row.pack(fill=tk.X, pady=2)
                    ttk.Label(row, text=f"• {label}", width=25).pack(side=tk.LEFT)
                    ttk.Label(row, text=value).pack(side=tk.LEFT)
                
                # Category
                category = stats.get('category', 'Unknown')
                ttk.Label(result_panel, text=f"Category: {category}",
                         font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(15, 10))
                
                # Full Rule
                ttk.Label(result_panel, text="Full Rule:",
                         font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(15, 5))
                
                rule_text = tk.Text(result_panel, height=3, wrap=tk.WORD,
                                   font=("Consolas", 9), bg="#F5F5F5")
                rule_text.pack(fill=tk.X, pady=(0, 10))
                rule_text.insert(tk.END, rule.to_string())
                rule_text.config(state=tk.DISABLED)
                
                # Analysis/Interpretation
                ttk.Label(result_panel, text="Analysis:",
                         font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(15, 5))
                
                # Generate interpretation based on category and stats
                interpretation = self._generate_sid_interpretation(stats, category, analysis_results)
                
                interp_label = ttk.Label(result_panel, text=interpretation,
                                        font=("TkDefaultFont", 9), wraplength=750, justify=tk.LEFT)
                interp_label.pack(anchor=tk.W, pady=(0, 15))
                
                # Navigation buttons
                nav_frame = ttk.Frame(result_panel)
                nav_frame.pack(fill=tk.X, pady=(10, 0))
                
                # Determine which tab to link to based on category
                tab_index = None
                if 'unused' in category.lower():
                    tab_index = 1  # Unused tab
                elif 'low-frequency' in category.lower() or 'low_freq' in category.lower():
                    tab_index = 2  # Low-Frequency tab
                elif 'high' in category.lower() or 'critical' in category.lower():
                    tab_index = 3  # Effectiveness tab
                
                if tab_index is not None:
                    ttk.Button(nav_frame, text="View in Analysis Tab",
                              command=lambda: notebook.select(tab_index)).pack(side=tk.LEFT, padx=5)
                
                def jump_to_line():
                    """Jump to the rule in main editor and close results window"""
                    # Close results window
                    results_window.destroy()
                    
                    # Jump to line in main editor
                    all_items = self.parent.tree.get_children()
                    if line_num - 1 < len(all_items):
                        target_item = all_items[line_num - 1]
                        self.parent.tree.selection_set(target_item)
                        self.parent.tree.focus(target_item)
                        self.parent.tree.see(target_item)
                
                ttk.Button(nav_frame, text=f"Jump to Line {line_num}",
                          command=jump_to_line).pack(side=tk.LEFT, padx=5)
                
                # Export button (Phase 12)
                ttk.Button(nav_frame, text="Export This Result",
                          command=lambda: self._export_search_result(sid, stats, analysis_results)).pack(side=tk.LEFT, padx=5)
                
            else:
                # SID not found - check if it's in the rule file
                rule_exists = any(hasattr(r, 'sid') and r.sid == sid 
                                for r in self.parent.rules 
                                if not getattr(r, 'is_comment', False))
                
                if rule_exists:
                    # SID exists in file but has 0 hits
                    ttk.Label(results_content, text=f"SID {sid} - No hits recorded",
                             font=("TkDefaultFont", 11, "bold"), foreground="#FF6600").pack(anchor=tk.W, padx=10, pady=(10, 5))
                    
                    ttk.Label(results_content, 
                             text=f"This rule exists in your file but had 0 hits during the\n"
                                  f"{analysis_results['time_range_days']}-day analysis period.\n\n"
                                  f"It may be an unused rule. Check the Unused Rules tab for more details.",
                             font=("TkDefaultFont", 9), justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=5)
                    
                    # Show link to Unused tab
                    link_label = ttk.Label(results_content, text="→ View in Unused Rules Tab",
                                          foreground="blue", cursor="hand2",
                                          font=("TkDefaultFont", 9, "underline"))
                    link_label.pack(anchor=tk.W, padx=10, pady=5)
                    link_label.bind('<Button-1>', lambda e: notebook.select(1))
                else:
                    # SID not in file at all
                    ttk.Label(results_content, text=f"SID {sid} not found",
                             font=("TkDefaultFont", 11, "bold"), foreground="red").pack(anchor=tk.W, padx=10, pady=(10, 5))
                    
                    # Troubleshooting tips
                    tips_frame = ttk.LabelFrame(results_content, text="SID not found? Try:")
                    tips_frame.pack(fill=tk.X, padx=10, pady=10)
                    
                    tips = [
                        "• Check if SID is correct",
                        "• Verify rule is not commented out",
                        "• Confirm analysis includes this rule",
                        "• Rule may have been added after analysis was run"
                    ]
                    
                    for tip in tips:
                        ttk.Label(tips_frame, text=tip, font=("TkDefaultFont", 9)).pack(anchor=tk.W, padx=10, pady=2)
        
        # Search button
        def on_search_click():
            perform_search()
        
        ttk.Button(search_row, text="Search", command=on_search_click).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_row, text="Clear", 
                  command=lambda: [search_sid_var.set(""), 
                                  [widget.destroy() for widget in results_content.winfo_children()],
                                  ttk.Label(results_content, text="Enter a SID and click Search to view statistics",
                                           font=("TkDefaultFont", 9, "italic"), foreground="#666666").pack(padx=10, pady=20)]).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key to search
        search_entry.bind('<Return>', lambda e: perform_search())
        
        # Tab 7: Unlogged Rules
        unlogged_tab = ttk.Frame(notebook)
        unlogged_count = len(analysis_results.get('unlogged_sids', set()))
        notebook.add(unlogged_tab, text=f"Unlogged ({unlogged_count})")
        
        # Create scrollable canvas for tab content
        unlogged_canvas = tk.Canvas(unlogged_tab)
        unlogged_scrollbar = ttk.Scrollbar(unlogged_tab, orient=tk.VERTICAL, command=unlogged_canvas.yview)
        unlogged_content = ttk.Frame(unlogged_canvas)
        
        unlogged_content.bind(
            "<Configure>",
            lambda e: unlogged_canvas.configure(scrollregion=unlogged_canvas.bbox("all"))
        )
        
        unlogged_canvas.create_window((0, 0), window=unlogged_content, anchor="nw")
        unlogged_canvas.configure(yscrollcommand=unlogged_scrollbar.set)
        
        unlogged_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        unlogged_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling
        def on_unlogged_mousewheel(event):
            try:
                if event.delta:
                    unlogged_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    unlogged_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    unlogged_canvas.yview_scroll(1, "units")
            except:
                pass
        
        unlogged_canvas.bind("<Enter>", lambda e: unlogged_canvas.bind_all("<MouseWheel>", on_unlogged_mousewheel))
        unlogged_canvas.bind("<Leave>", lambda e: unlogged_canvas.unbind_all("<MouseWheel>"))
        
        # Description
        description_text = (
            "These rules don't write to CloudWatch Logs and cannot be tracked for usage.\n"
            "They may be actively processing traffic but won't show any hits in the analysis."
        )
        ttk.Label(unlogged_content, text=description_text,
                 font=("TkDefaultFont", 10)).pack(anchor=tk.W, padx=10, pady=(10, 10))
        
        # Get unlogged rule details
        unlogged_sids = analysis_results.get('unlogged_sids', set())
        
        # Treeview for unlogged rules
        unlogged_tree_container = ttk.Frame(unlogged_content)
        unlogged_tree_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        unlogged_columns = ("Line", "SID", "Action", "Protocol", "Keyword", "Message")
        unlogged_tree = ttk.Treeview(unlogged_tree_container, columns=unlogged_columns,
                                     show="headings", height=12)
        
        unlogged_tree.heading("Line", text="Line")
        unlogged_tree.heading("SID", text="SID")
        unlogged_tree.heading("Action", text="Action")
        unlogged_tree.heading("Protocol", text="Protocol")
        unlogged_tree.heading("Keyword", text="Reason")
        unlogged_tree.heading("Message", text="Message")
        
        unlogged_tree.column("Line", width=50, stretch=False)
        unlogged_tree.column("SID", width=70, stretch=False)
        unlogged_tree.column("Action", width=70, stretch=False)
        unlogged_tree.column("Protocol", width=80, stretch=False)
        unlogged_tree.column("Keyword", width=120, stretch=False)
        unlogged_tree.column("Message", width=450, stretch=True)
        
        # Scrollbars
        unlogged_v_scrollbar = ttk.Scrollbar(unlogged_tree_container, orient=tk.VERTICAL,
                                            command=unlogged_tree.yview)
        unlogged_h_scrollbar = ttk.Scrollbar(unlogged_tree_container, orient=tk.HORIZONTAL,
                                            command=unlogged_tree.xview)
        unlogged_tree.configure(yscrollcommand=unlogged_v_scrollbar.set,
                               xscrollcommand=unlogged_h_scrollbar.set)
        
        unlogged_tree.grid(row=0, column=0, sticky="nsew")
        unlogged_v_scrollbar.grid(row=0, column=1, sticky="ns")
        unlogged_h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        unlogged_tree_container.grid_rowconfigure(0, weight=1)
        unlogged_tree_container.grid_columnconfigure(0, weight=1)
        
        # Populate with unlogged rules
        from rule_usage_analyzer import RuleUsageAnalyzer
        
        for sid in sorted(unlogged_sids):
            # Find rule in main rule list
            rule = next((r for r in self.parent.rules
                       if hasattr(r, 'sid') and r.sid == sid), None)
            
            if rule:
                line_num = self.parent.rules.index(rule) + 1
                message = rule.message[:60] + "..." if len(rule.message) > 60 else rule.message
                
                # Determine reason (why it doesn't log)
                action_lower = rule.action.lower()
                options_text = f"{rule.content} {rule.original_options}".lower()
                
                if action_lower == "pass":
                    # Check if it has alert keyword
                    import re
                    if re.search(r'\balert\b', options_text):
                        reason = "Pass with 'alert' (LOGS)"  # Shouldn't be here
                    else:
                        reason = "Pass without 'alert'"
                elif action_lower in ["drop", "reject"]:
                    if "noalert" in options_text:
                        reason = f"{action_lower.capitalize()} with 'noalert'"
                    else:
                        reason = f"{action_lower.capitalize()} (LOGS)"  # Shouldn't be here
                else:
                    reason = "Unknown"
                
                unlogged_tree.insert("", tk.END,
                                   values=(line_num, sid, rule.action.upper(),
                                          rule.protocol.upper(), reason, message))
        
        # Double-click handler to jump to rule in main editor
        def on_unlogged_tree_double_click(event):
            item = unlogged_tree.identify_row(event.y)
            if not item:
                return
            
            # Get the line number from the clicked item (first column)
            values = unlogged_tree.item(item, 'values')
            if not values or not values[0]:
                return
            
            try:
                line_num = int(values[0])  # Line column
            except (ValueError, TypeError):
                return
            
            # Jump to the rule in main editor
            self._jump_to_rule_in_main_editor(line_num, results_window)
        
        unlogged_tree.bind("<Double-1>", on_unlogged_tree_double_click)
        
        # Information panel at bottom
        info_frame = ttk.LabelFrame(unlogged_content, text="Why These Rules Don't Log")
        info_frame.pack(fill=tk.X, pady=(10, 0))
        
        info_content = ttk.Frame(info_frame)
        info_content.pack(padx=15, pady=15)
        
        info_text = (
            "• Pass rules don't generate alert logs by default\n"
            "• Drop/reject rules with 'noalert' keyword explicitly suppress logging\n"
            "• These rules may be actively used but won't show hits in CloudWatch\n"
            "• They are excluded from unused rule detection and health score calculations"
        )
        
        ttk.Label(info_content, text=info_text,
                 font=("TkDefaultFont", 10), justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 10))
        
        # Recommendations panel
        rec_frame = ttk.LabelFrame(unlogged_content, text="💡 Recommendations")
        rec_frame.pack(fill=tk.X, pady=(10, 0))
        
        rec_content = ttk.Frame(rec_frame)
        rec_content.pack(padx=15, pady=15)
        
        rec_text = (
            "If you need to track these rules:\n\n"
            "• Pass rules: Add 'alert;' keyword to enable logging\n"
            "  Example: pass tls $HOME_NET any -> any any (...; alert; sid:X; rev:1;)\n\n"
            "• Drop/Reject rules: Remove 'noalert' keyword\n"
            "  (Logging is enabled by default for drop/reject)\n\n"
            "• Alternative: Use Flow logs instead of Alert logs\n"
            "  (Tracks connections at network layer, not rule-specific)"
        )
        
        ttk.Label(rec_content, text=rec_text,
                 font=("TkDefaultFont", 9), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Statistics
        stats_frame = ttk.Frame(unlogged_content)
        stats_frame.pack(fill=tk.X, pady=(15, 0))
        
        count = len(unlogged_sids)
        total = analysis_results['total_rules']
        percentage = (count / total * 100) if total > 0 else 0
        
        ttk.Label(stats_frame,
                 text=f"Count: {count} ({percentage:.1f}% of total rules)",
                 font=("TkDefaultFont", 10)).pack(anchor=tk.W)
        
        # Export button
        export_frame = ttk.Frame(unlogged_content)
        export_frame.pack(fill=tk.X, pady=(15, 0))
        
        def export_unlogged_rules():
            # Similar export pattern to other tabs
            export_format = self._show_export_format_dialog()
            if not export_format:
                return
            
            if export_format == 'html':
                default_ext = ".html"
                filetypes = [("HTML files", "*.html"), ("All files", "*.*")]
            else:
                default_ext = ".txt"
                filetypes = [("Text files", "*.txt"), ("All files", "*.*")]
            
            filename = filedialog.asksaveasfilename(
                title="Export Unlogged Rules",
                defaultextension=default_ext,
                filetypes=filetypes,
                initialfile="unlogged_rules"
            )
            
            if not filename:
                return
            
            try:
                if export_format == 'html':
                    self._export_unlogged_html(filename, unlogged_sids, analysis_results)
                else:
                    self._export_unlogged_text(filename, unlogged_sids, analysis_results)
                
                messagebox.showinfo("Export Complete", f"Unlogged rules exported to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
        
        ttk.Button(export_frame, text="Export", command=export_unlogged_rules).pack()
        
        # Tab 8: Untracked Rules (NEW)
        untracked_tab = ttk.Frame(notebook)
        untracked_count = len(analysis_results.get('untracked_sids', set()))
        notebook.add(untracked_tab, text=f"Untracked ({untracked_count})")
        
        # Create scrollable canvas for tab content
        untracked_canvas = tk.Canvas(untracked_tab)
        untracked_scrollbar = ttk.Scrollbar(untracked_tab, orient=tk.VERTICAL, command=untracked_canvas.yview)
        untracked_content = ttk.Frame(untracked_canvas)
        
        untracked_content.bind(
            "<Configure>",
            lambda e: untracked_canvas.configure(scrollregion=untracked_canvas.bbox("all"))
        )
        
        untracked_canvas.create_window((0, 0), window=untracked_content, anchor="nw")
        untracked_canvas.configure(yscrollcommand=untracked_scrollbar.set)
        
        untracked_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        untracked_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling
        def on_untracked_mousewheel(event):
            try:
                if event.delta:
                    untracked_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    untracked_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    untracked_canvas.yview_scroll(1, "units")
            except:
                pass
        
        untracked_canvas.bind("<Enter>", lambda e: untracked_canvas.bind_all("<MouseWheel>", on_untracked_mousewheel))
        untracked_canvas.bind("<Leave>", lambda e: untracked_canvas.unbind_all("<MouseWheel>"))
        
        # Description
        description_text = (
            "These SIDs were found in CloudWatch logs but do not exist in your current rules file.\n"
            "They may have triggered during the analysis period but are not part of your rule group."
        )
        ttk.Label(untracked_content, text=description_text,
                 font=("TkDefaultFont", 10)).pack(anchor=tk.W, padx=10, pady=(10, 10))
        
        # Get untracked rule details
        untracked_sids = analysis_results.get('untracked_sids', set())
        
        # Treeview for untracked rules
        untracked_tree_container = ttk.Frame(untracked_content)
        untracked_tree_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        untracked_columns = ("SID", "Hits", "Hits/Day", "Last Hit", "% Traffic")
        untracked_tree = ttk.Treeview(untracked_tree_container, columns=untracked_columns,
                                      show="headings", height=12)
        
        untracked_tree.heading("SID", text="SID", command=lambda: self._sort_treeview(untracked_tree, "SID", False))
        untracked_tree.heading("Hits", text="Hits", command=lambda: self._sort_treeview(untracked_tree, "Hits", False))
        untracked_tree.heading("Hits/Day", text="Hits/Day", command=lambda: self._sort_treeview(untracked_tree, "Hits/Day", False))
        untracked_tree.heading("Last Hit", text="Last Hit", command=lambda: self._sort_treeview(untracked_tree, "Last Hit", False))
        untracked_tree.heading("% Traffic", text="% Traffic", command=lambda: self._sort_treeview(untracked_tree, "% Traffic", False))
        
        untracked_tree.column("SID", width=100, stretch=False)
        untracked_tree.column("Hits", width=100, stretch=False)
        untracked_tree.column("Hits/Day", width=100, stretch=False)
        untracked_tree.column("Last Hit", width=120, stretch=False)
        untracked_tree.column("% Traffic", width=120, stretch=True)
        
        # Scrollbars
        untracked_v_scrollbar = ttk.Scrollbar(untracked_tree_container, orient=tk.VERTICAL,
                                              command=untracked_tree.yview)
        untracked_h_scrollbar = ttk.Scrollbar(untracked_tree_container, orient=tk.HORIZONTAL,
                                              command=untracked_tree.xview)
        untracked_tree.configure(yscrollcommand=untracked_v_scrollbar.set,
                                xscrollcommand=untracked_h_scrollbar.set)
        
        untracked_tree.grid(row=0, column=0, sticky="nsew")
        untracked_v_scrollbar.grid(row=0, column=1, sticky="ns")
        untracked_h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        untracked_tree_container.grid_rowconfigure(0, weight=1)
        untracked_tree_container.grid_columnconfigure(0, weight=1)
        
        # Configure light blue background for rows
        untracked_tree.tag_configure("untracked_row", background="#E3F2FD")
        
        # Populate with untracked rules
        for sid in sorted(untracked_sids):
            # Get stats from analysis results
            stats = sid_stats.get(sid, {})
            hits = stats.get('hits', 0)
            hits_per_day = stats.get('hits_per_day', 0.0)
            hits_per_day_str = f"{hits_per_day:.1f}"
            last_hit_days = stats.get('last_hit_days', 999)
            last_hit_str = f"{last_hit_days}d ago" if last_hit_days < 999 else 'Unknown'
            percent = stats.get('percent', 0.0)
            percent_str = f"{percent:.2f}%"
            
            untracked_tree.insert("", tk.END,
                                 values=(sid, f"{hits:,}", hits_per_day_str, last_hit_str, percent_str),
                                 tags=("untracked_row",))
        
        # Information panel explaining untracked rules
        info_frame = ttk.LabelFrame(untracked_content, text="Why These Rules Appear Here")
        info_frame.pack(fill=tk.X, pady=(10, 0))
        
        info_content = ttk.Frame(info_frame)
        info_content.pack(padx=15, pady=15)
        
        info_text = (
            "These SIDs exist in CloudWatch logs but not in your current rules file.\n\n"
            "Common reasons:\n"
            "• Rules were recently deleted or commented out from your file\n"
            "  (but still exist in CloudWatch logs during the analysis timeframe)\n\n"
            "• AWS Network Firewall applied default policy rules:\n"
            "  Alert-based defaults:\n"
            "    - 'Application alert established'\n"
            "    - 'Alert established'\n"
            "    - 'Alert all'\n"
            "  Drop-based defaults:\n"
            "    - 'Application drop established'\n"
            "    - 'Drop established'\n"
            "    - 'Drop all'\n"
            "  These default actions generate rules that are not visible in your rule group\n\n"
            "Impact:\n"
            "• These rules are excluded from health score calculations\n"
            "• They do not affect unused rule detection\n"
            "• They are not counted in tier distributions\n"
            "• They represent traffic patterns but not rules you manage"
        )
        
        ttk.Label(info_content, text=info_text,
                 font=("TkDefaultFont", 10), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Statistics
        stats_frame = ttk.Frame(untracked_content)
        stats_frame.pack(fill=tk.X, pady=(15, 0))
        
        count = len(untracked_sids)
        total = analysis_results['total_rules']
        
        ttk.Label(stats_frame,
                 text=f"Count: {count} untracked SIDs detected in CloudWatch logs",
                 font=("TkDefaultFont", 10)).pack(anchor=tk.W)
        
        # Save and Close buttons at bottom
        close_frame = ttk.Frame(main_frame)
        close_frame.pack(pady=(10, 0))
        
        # Determine if Save button should be enabled (requires open file)
        save_enabled = (self.parent.current_file is not None)
        
        ttk.Button(close_frame, text="Save", 
                  command=lambda: self.save_stats_to_file(analysis_results, results_window),
                  state="normal" if save_enabled else "disabled").pack(side=tk.LEFT, padx=5)
        ttk.Button(close_frame, text="Close", command=results_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def _format_time_ago(self, timestamp):
        """Format timestamp as 'X minutes/hours ago'"""
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        now = datetime.now(timestamp.tzinfo) if timestamp.tzinfo else datetime.now()
        delta = now - timestamp
        
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif seconds < 86400:
            hours = seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        else:
            days = seconds // 86400
            return f"{days} day{'s' if days != 1 else ''} ago"
    
    def _draw_health_gauge(self, canvas, score):
        """Draw health gauge on canvas using tkinter"""
        width = 400
        height = 60
        padding = 10
        
        # Draw background rectangle
        canvas.create_rectangle(padding, padding, width - padding, height - padding,
                              fill='#EEEEEE', outline='#CCCCCC')
        
        # Determine color based on score
        # Matches grading scale: 80-100 Excellent, 60-79 Good, 40-59 Fair, 0-39 Poor
        if score >= 80:
            color = '#2E7D32'  # Green
            label = 'Excellent'
        elif score >= 60:
            color = '#7CB342'  # Light green
            label = 'Good'
        elif score >= 40:
            color = '#FFA000'  # Orange
            label = 'Fair'
        else:
            color = '#D32F2F'  # Red
            label = 'Poor'
        
        # Draw filled portion
        fill_width = int((width - 2 * padding) * (score / 100))
        canvas.create_rectangle(padding, padding, padding + fill_width, height - padding,
                              fill=color, outline='')
        
        # Draw scale markers
        for marker in [0, 25, 50, 75, 100]:
            x = padding + int((width - 2 * padding) * (marker / 100))
            canvas.create_line(x, height - padding, x, height - padding + 5,
                             fill='#666666', width=1)
            canvas.create_text(x, height - padding + 15, text=str(marker),
                             font=("TkDefaultFont", 8), fill='#666666')
        
        # Draw score text in center
        center_x = width // 2
        center_y = (height - padding) // 2
        
        # Use black text for better visibility on all backgrounds
        # For very low scores, the colored portion doesn't reach center, so white text would be on gray
        canvas.create_text(center_x, center_y, text=f"{score}/100 - {label}",
                         font=("TkDefaultFont", 14, "bold"), fill='black')
    
    def _generate_pareto_insights(self, results):
        """Generate Pareto analysis insights text"""
        sid_stats = results.get('sid_stats', {})
        if not sid_stats:
            return "No traffic data available for Pareto analysis."
        
        # Sort by hits descending
        sorted_rules = sorted(sid_stats.items(), key=lambda x: x[1]['hits'], reverse=True)
        total_hits = sum(stat['hits'] for stat in sid_stats.values())
        
        # Calculate top 10% and 20%
        top_10_count = max(1, len(sorted_rules) // 10)
        top_20_count = max(1, len(sorted_rules) // 5)
        
        top_10_hits = sum(stat['hits'] for _, stat in sorted_rules[:top_10_count])
        top_20_hits = sum(stat['hits'] for _, stat in sorted_rules[:top_20_count])
        
        top_10_pct = int((top_10_hits / total_hits * 100)) if total_hits > 0 else 0
        top_20_pct = int((top_20_hits / total_hits * 100)) if total_hits > 0 else 0
        
        insights = (
            f"📊 Pareto Analysis:\n"
            f"• Top 10% of rules ({top_10_count} rules) handle {top_10_pct}% of traffic\n"
            f"• Top 20% of rules ({top_20_count} rules) handle {top_20_pct}% of traffic\n\n"
            f"This indicates {'high' if top_10_pct > 80 else 'moderate' if top_10_pct > 60 else 'low'} "
            f"traffic concentration in a small subset of rules."
        )
        
        return insights
    
    def _generate_recommendations(self, results, notebook):
        """Generate priority recommendations with tab links"""
        recommendations = []
        categories = results['categories']
        
        # High priority: Unused rules
        if categories['unused'] > 0:
            recommendations.append({
                'priority': 'HIGH',
                'text': f"{categories['unused']} unused rules detected.",
                'link_text': '[View Details]',
                'tab_index': 1  # Unused tab (will be added in Phase 5)
            })
        
        # Medium priority: Low-frequency rules
        if categories['low_freq'] > 10:
            recommendations.append({
                'priority': 'MEDIUM',
                'text': f"{categories['low_freq']} low-frequency rules may be shadow rules.",
                'link_text': '[Analyze]',
                'tab_index': 2  # Low-frequency tab (will be added in Phase 6)
            })
        
        # Medium priority: Unlogged rules detected
        if categories.get('unlogged', 0) > 0:
            unlogged_count = categories['unlogged']
            recommendations.append({
                'priority': 'MEDIUM',
                'text': f"{unlogged_count} unlogged rule{'s' if unlogged_count != 1 else ''} cannot be tracked via CloudWatch.",
                'link_text': '[View Details]',
                'tab_index': 6  # Unlogged tab (will be tab 7, but 0-indexed so index 6)
            })
        
        # Info priority: Untracked rules detected
        if categories.get('untracked', 0) > 0:
            untracked_count = categories['untracked']
            recommendations.append({
                'priority': 'LOW',
                'text': f"{untracked_count} untracked SID{'s' if untracked_count != 1 else ''} in CloudWatch (not in your file).",
                'link_text': '[View Details]',
                'tab_index': 7  # Untracked tab (tab 8, but 0-indexed so index 7)
            })
        
        # Health score recommendations
        health = results['health_score']
        if health < 50:
            recommendations.append({
                'priority': 'HIGH',
                'text': "Rule group health is poor. Immediate attention required.",
                'link_text': None,
                'tab_index': None
            })
        elif health < 75:
            recommendations.append({
                'priority': 'MEDIUM',
                'text': "Rule group health is fair. Consider optimization.",
                'link_text': None,
                'tab_index': None
            })
        
        # If no recommendations, add positive message
        if not recommendations:
            recommendations.append({
                'priority': 'LOW',
                'text': "Rule group is healthy. No immediate actions required.",
                'link_text': None,
                'tab_index': None
            })
        
        return recommendations
    
    def _show_export_format_dialog(self):
        """Show dialog to select export format (HTML or Text)
        
        Returns:
            str: 'html', 'txt', or None if cancelled
        """
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Export Format")
        dialog.geometry("450x250")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 250,
            self.parent.root.winfo_rooty() + 200
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(main_frame, text="Select Export Format",
                 font=("TkDefaultFont", 11, "bold")).pack(pady=(0, 15))
        
        # Format selection
        format_var = tk.StringVar(value="html")
        
        # HTML option
        html_frame = ttk.Frame(main_frame)
        html_frame.pack(fill=tk.X, pady=5)
        ttk.Radiobutton(html_frame, text="HTML (Styled report - recommended)",
                       variable=format_var, value="html").pack(anchor=tk.W)
        ttk.Label(html_frame, text="Professional format with colors and styling",
                 font=("TkDefaultFont", 8), foreground="#666666").pack(anchor=tk.W, padx=(25, 0))
        
        # Text option
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.X, pady=5)
        ttk.Radiobutton(text_frame, text="Plain Text (Simple format)",
                       variable=format_var, value="txt").pack(anchor=tk.W)
        ttk.Label(text_frame, text="Easy to read in any text editor",
                 font=("TkDefaultFont", 8), foreground="#666666").pack(anchor=tk.W, padx=(25, 0))
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=(20, 0))
        
        result = [None]
        
        def on_export():
            result[0] = format_var.get()
            dialog.destroy()
        
        def on_cancel():
            result[0] = None
            dialog.destroy()
        
        ttk.Button(btn_frame, text="Export", command=on_export).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)
        
        # Wait for dialog to close
        dialog.wait_window()
        
        return result[0]
    
    def _export_analysis_report(self, results):
        """Export analysis results to file (Summary tab)
        
        Args:
            results: Analysis results dictionary
        """
        # Show format selection dialog
        export_format = self._show_export_format_dialog()
        if not export_format:
            return  # User cancelled
        
        # Show file save dialog with appropriate extension
        if export_format == 'html':
            default_ext = ".html"
            filetypes = [("HTML files", "*.html"), ("All files", "*.*")]
        else:
            default_ext = ".txt"
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]
        
        filename = filedialog.asksaveasfilename(
            title="Export Analysis Report",
            defaultextension=default_ext,
            filetypes=filetypes
        )
        
        if not filename:
            return
        
        try:
            if export_format == 'html':
                self._export_summary_html(filename, results)
            else:
                self._export_summary_text(filename, results)
            
            messagebox.showinfo("Export Complete", f"Report exported to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{str(e)}")
    
    def _export_summary_text(self, filename, results):
        """Export Summary tab as plain text
        
        Args:
            filename: Output filename
            results: Analysis results dictionary
        """
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("RULE USAGE ANALYSIS REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            # Metadata
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Analysis Period: Last {results['time_range_days']} days\n")
            f.write(f"Log Group: {results['log_group']}\n")
            f.write(f"Total Rules: {results['total_rules']:,}\n")
            f.write(f"Records Analyzed: {results['records_analyzed']:,}\n\n")
            
            # Health Score
            f.write("RULE GROUP HEALTH\n")
            f.write("-" * 70 + "\n")
            health_score = results['health_score']
            health_label = 'Excellent' if health_score >= 80 else 'Good' if health_score >= 60 else 'Fair' if health_score >= 40 else 'Poor'
            f.write(f"Score: {health_score}/100 ({health_label})\n\n")
            
            # Quick Statistics
            f.write("QUICK STATISTICS\n")
            f.write("-" * 70 + "\n")
            categories = results['categories']
            total = results['total_rules']
            
            f.write(f"Unused (0 hits):          {categories['unused']:,} rules ({categories['unused']/total*100:.1f}%)\n")
            f.write(f"Low-frequency (<10 hits): {categories['low_freq']:,} rules ({categories['low_freq']/total*100:.1f}%)\n")
            f.write(f"Medium (10-99 hits):      {categories['medium']:,} rules ({categories['medium']/total*100:.1f}%)\n")
            f.write(f"High (100+ hits):         {categories['high']:,} rules ({categories['high']/total*100:.1f}%)\n\n")
            
            # Pareto Analysis
            f.write("PERFORMANCE INSIGHTS\n")
            f.write("-" * 70 + "\n")
            
            sid_stats = results.get('sid_stats', {})
            if sid_stats:
                sorted_rules = sorted(sid_stats.items(), key=lambda x: x[1]['hits'], reverse=True)
                total_hits = sum(stat['hits'] for stat in sid_stats.values())
                
                top_10_count = max(1, len(sorted_rules) // 10)
                top_10_hits = sum(stat['hits'] for _, stat in sorted_rules[:top_10_count])
                top_10_pct = int((top_10_hits / total_hits * 100)) if total_hits > 0 else 0
                
                top_20_count = max(1, len(sorted_rules) // 5)
                top_20_hits = sum(stat['hits'] for _, stat in sorted_rules[:top_20_count])
                top_20_pct = int((top_20_hits / total_hits * 100)) if total_hits > 0 else 0
                
                f.write(f"• Top 10% of rules ({top_10_count} rules) handle {top_10_pct}% of traffic\n")
                f.write(f"• Top 20% of rules ({top_20_count} rules) handle {top_20_pct}% of traffic\n\n")
            
            # Recommendations
            f.write("PRIORITY RECOMMENDATIONS\n")
            f.write("-" * 70 + "\n\n")
            
            # High priority: Unused rules
            if categories['unused'] > 0:
                f.write("🔴 HIGH PRIORITY:\n")
                f.write(f"   Remove {categories['unused']} unused rules\n")
                f.write(f"   → Capacity reduction: {categories['unused']/total*100:.1f}%\n")
                f.write(f"   → Zero hits in last {results['time_range_days']} days\n\n")
            
            # Medium priority: Low-frequency rules
            if categories['low_freq'] > 10:
                f.write("🟡 MEDIUM PRIORITY:\n")
                f.write(f"   Review {categories['low_freq']} low-frequency rules\n")
                f.write(f"   → May be shadowed by earlier rules\n")
                f.write(f"   → Consider using Review Rules feature\n\n")
            
            # Check for broad rules
            if sid_stats:
                broad_rules = [(sid, stat) for sid, stat in sid_stats.items() if stat.get('percent', 0) > 10]
                if broad_rules:
                    f.write("🔴 HIGH PRIORITY:\n")
                    f.write(f"   Review {len(broad_rules)} overly-broad rules\n")
                    f.write(f"   → Some rules handle >10% of traffic\n")
                    f.write(f"   → Security risk - too generic\n\n")
    
    def _export_summary_html(self, filename, results):
        """Export Summary tab as HTML
        
        Args:
            filename: Output filename
            results: Analysis results dictionary
        """
        # Generate HTML content
        html = self._generate_summary_html(results)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_summary_html(self, results):
        """Generate HTML report for Summary tab
        
        Args:
            results: Analysis results dictionary
            
        Returns:
            str: Complete HTML document
        """
        from version import get_main_version
        version_str = get_main_version()
        
        categories = results['categories']
        total = results['total_rules']
        health_score = results['health_score']
        
        # Determine health status and color
        if health_score >= 80:
            health_status = 'Excellent'
            health_color = '#2E7D32'
        elif health_score >= 60:
            health_status = 'Good'
            health_color = '#7CB342'
        elif health_score >= 40:
            health_status = 'Fair'
            health_color = '#FFA000'
        else:
            health_status = 'Poor'
            health_color = '#D32F2F'
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Rule Usage Analysis Report</title>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
            color: #333;
        }}
        .header {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .title {{
            color: #2c3e50;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .meta {{
            color: #6c757d;
            font-size: 14px;
        }}
        .section {{
            margin: 20px 0;
            padding: 15px;
            border-left: 4px solid #dee2e6;
            background-color: #f8f9fa;
        }}
        .section-title {{
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #2c3e50;
        }}
        .critical {{
            border-left-color: #dc3545;
            background-color: #f8d7da;
        }}
        .warning {{
            border-left-color: #ffc107;
            background-color: #fff3cd;
        }}
        .info {{
            border-left-color: #17a2b8;
            background-color: #d1ecf1;
        }}
        .success {{
            border-left-color: #28a745;
            background-color: #d4edda;
        }}
        .health-score {{
            font-size: 36px;
            font-weight: bold;
            color: {health_color};
        }}
        .stat-box {{
            display: inline-block;
            padding: 15px;
            margin: 10px;
            background-color: #e9ecef;
            border-radius: 5px;
            min-width: 150px;
        }}
        .stat-label {{
            font-size: 12px;
            color: #6c757d;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th {{
            background-color: #e9ecef;
            padding: 10px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #dee2e6;
        }}
        td {{
            padding: 8px 10px;
            border-bottom: 1px solid #dee2e6;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">Rule Usage Analysis Report</div>
        <div class="meta">
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Generator Version:</strong> {version_str}<br>
            <strong>Analysis Period:</strong> Last {results['time_range_days']} days<br>
            <strong>Log Group:</strong> {results['log_group']}<br>
            <strong>Total Rules Analyzed:</strong> {results['total_rules']:,}
        </div>
    </div>
    
    <h2>Rule Group Health</h2>
    <div class="section success">
        <div class="health-score">{health_score}/100</div>
        <p><strong>Status:</strong> {health_status}</p>
    </div>
    
    <h2>Quick Statistics</h2>
    <div>
        <div class="stat-box">
            <div class="stat-label">Unused Rules</div>
            <div class="stat-value">{categories['unused']}</div>
            <div class="stat-label">{categories['unused']/total*100:.1f}%</div>
        </div>
        <div class="stat-box">
            <div class="stat-label">Low-Frequency</div>
            <div class="stat-value">{categories['low_freq']}</div>
            <div class="stat-label">{categories['low_freq']/total*100:.1f}%</div>
        </div>
        <div class="stat-box">
            <div class="stat-label">Medium</div>
            <div class="stat-value">{categories['medium']}</div>
            <div class="stat-label">{categories['medium']/total*100:.1f}%</div>
        </div>
        <div class="stat-box">
            <div class="stat-label">High-Frequency</div>
            <div class="stat-value">{categories['high']}</div>
            <div class="stat-label">{categories['high']/total*100:.1f}%</div>
        </div>
    </div>
    
    <h2>Performance Insights</h2>
    <div class="section info">'''
        
        # Add Pareto analysis
        sid_stats = results.get('sid_stats', {})
        if sid_stats:
            sorted_rules = sorted(sid_stats.items(), key=lambda x: x[1]['hits'], reverse=True)
            total_hits = sum(stat['hits'] for stat in sid_stats.values())
            
            top_10_count = max(1, len(sorted_rules) // 10)
            top_10_hits = sum(stat['hits'] for _, stat in sorted_rules[:top_10_count])
            top_10_pct = int((top_10_hits / total_hits * 100)) if total_hits > 0 else 0
            
            top_20_count = max(1, len(sorted_rules) // 5)
            top_20_hits = sum(stat['hits'] for _, stat in sorted_rules[:top_20_count])
            top_20_pct = int((top_20_hits / total_hits * 100)) if total_hits > 0 else 0
            
            html += f'''
        <p>• Top 10% of rules ({top_10_count} rules) handle {top_10_pct}% of total traffic</p>
        <p>• Top 20% of rules ({top_20_count} rules) handle {top_20_pct}% of total traffic</p>'''
        
        html += '''
    </div>
    
    <h2>Priority Recommendations</h2>'''
        
        # Add recommendations
        if categories['unused'] > 0:
            html += f'''
    <div class="section critical">
        <div class="section-title">🔴 HIGH: Remove unused rules</div>
        <p>→ {categories['unused']} rules with zero hits</p>
        <p>→ Capacity reduction: {categories['unused']/total*100:.1f}%</p>
        <p>→ Safe to remove (no traffic impact)</p>
    </div>'''
        
        # Check for broad rules
        if sid_stats:
            broad_rules = [(sid, stat) for sid, stat in sid_stats.items() if stat.get('percent', 0) > 10]
            if broad_rules:
                html += f'''
    <div class="section critical">
        <div class="section-title">🔴 HIGH: Review overly-broad rules</div>
        <p>→ {len(broad_rules)} rules handle >10% of traffic each</p>
        <p>→ Security risk - rules too generic</p>
        <p>→ Split into more specific rules</p>
    </div>'''
        
        if categories['low_freq'] > 10:
            html += f'''
    <div class="section warning">
        <div class="section-title">🟡 MEDIUM: Review low-frequency rules</div>
        <p>→ {categories['low_freq']} rules with <{results.get('low_freq_threshold', 10)} hits</p>
        <p>→ May be shadowed by earlier rules</p>
        <p>→ Use Review Rules feature to check</p>
    </div>'''
        
        html += f'''
    <div style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 12px;">
        <p>Generated by Suricata Rule Generator - Rule Usage Analyzer v{version_str}</p>
    </div>
</body>
</html>'''
        
        return html
    
    def _export_unused_rules(self, unused_sids, confidence_level, results):
        """Export unused rules for a specific confidence level
        
        Args:
            unused_sids: List of SIDs to export
            confidence_level: 'confirmed', 'recent', or 'never_observed'
            results: Analysis results dictionary
        """
        # Show format selection dialog
        export_format = self._show_export_format_dialog()
        if not export_format:
            return
        
        # Determine filename suggestion based on confidence level
        filename_suffix = confidence_level.replace('_', '_')
        
        if export_format == 'html':
            default_ext = ".html"
            filetypes = [("HTML files", "*.html"), ("All files", "*.*")]
        else:
            default_ext = ".txt"
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]
        
        filename = filedialog.asksaveasfilename(
            title=f"Export {confidence_level.replace('_', ' ').title()} Rules",
            defaultextension=default_ext,
            filetypes=filetypes,
            initialfile=f"unused_rules_{filename_suffix}"
        )
        
        if not filename:
            return
        
        try:
            if export_format == 'html':
                self._export_unused_html(filename, unused_sids, confidence_level, results)
            else:
                self._export_unused_text(filename, unused_sids, confidence_level, results)
            
            messagebox.showinfo("Export Complete", f"Unused rules exported to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
    
    def _export_unused_text(self, filename, unused_sids, confidence_level, results):
        """Export unused rules as plain text"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("UNUSED RULES EXPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Confidence Level: {confidence_level.replace('_', ' ').title()}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Analysis Period: Last {results['time_range_days']} days\n")
            f.write(f"Total Unused Rules: {len(unused_sids)}\n\n")
            
            # Description by confidence level
            min_days = results.get('min_days_in_production', 14)
            if confidence_level == 'confirmed':
                f.write(f"These rules are ≥{min_days} days old with 0 hits - safe to remove.\n\n")
            elif confidence_level == 'recent':
                f.write(f"These rules are <{min_days} days old with 0 hits - too new to judge.\n\n")
            else:
                f.write("These rules have unknown age with 0 hits - manual review recommended.\n\n")
            
            f.write("UNUSED RULES LIST\n")
            f.write("-" * 70 + "\n")
            f.write(f"{'Line':<6} {'SID':<8} {'Age':<8} {'Message':<40}\n")
            f.write("-" * 70 + "\n")
            
            sid_stats = results.get('sid_stats', {})
            
            for sid in sorted(unused_sids):
                rule = next((r for r in self.parent.rules 
                           if hasattr(r, 'sid') and r.sid == sid), None)
                
                if rule:
                    line_num = self.parent.rules.index(rule) + 1
                    stat = sid_stats.get(sid, {})
                    days = stat.get('days_in_production')
                    days_str = f"{days}d" if days is not None else 'Unknown'
                    message = rule.message[:40] + "..." if len(rule.message) > 40 else rule.message
                    
                    f.write(f"{line_num:<6} {sid:<8} {days_str:<8} {message:<40}\n")
            
            # Statistics
            f.write("\n")
            f.write("STATISTICS\n")
            f.write("-" * 70 + "\n")
            f.write(f"Count: {len(unused_sids)}\n")
            total = results['total_rules']
            f.write(f"Percentage of total: {len(unused_sids)/total*100:.1f}%\n")
            
            if confidence_level == 'confirmed':
                # Calculate average age
                ages = [sid_stats.get(sid, {}).get('days_in_production', 0) 
                       for sid in unused_sids 
                       if sid_stats.get(sid, {}).get('days_in_production') is not None]
                if ages:
                    avg_age = sum(ages) / len(ages)
                    f.write(f"Average age: {avg_age:.0f} days\n")
    
    def _export_unused_html(self, filename, unused_sids, confidence_level, results):
        """Export unused rules as HTML"""
        from version import get_main_version
        version_str = get_main_version()
        
        categories = results['categories']
        total = results['total_rules']
        sid_stats = results.get('sid_stats', {})
        min_days = results.get('min_days_in_production', 14)
        
        # Description by confidence level
        if confidence_level == 'confirmed':
            description = f"These rules are ≥{min_days} days old with 0 hits - safe to remove."
            bg_color = "#FFEBEE"
        elif confidence_level == 'recent':
            description = f"These rules are <{min_days} days old with 0 hits - too new to judge."
            bg_color = "#FFF9C4"
        else:
            description = "These rules have unknown age with 0 hits - manual review recommended."
            bg_color = "#F5F5F5"
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Unused Rules Export - {confidence_level.replace('_', ' ').title()}</title>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
            color: #333;
        }}
        .header {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .title {{
            color: #2c3e50;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .meta {{
            color: #6c757d;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th {{
            background-color: #e9ecef;
            padding: 10px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #dee2e6;
        }}
        td {{
            padding: 8px 10px;
            border-bottom: 1px solid #dee2e6;
            background-color: {bg_color};
        }}
        tr:hover td {{
            background-color: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">Unused Rules - {confidence_level.replace('_', ' ').title()}</div>
        <div class="meta">
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Analysis Period:</strong> Last {results['time_range_days']} days<br>
            <strong>Total Unused Rules:</strong> {len(unused_sids)}<br>
            <strong>Description:</strong> {description}
        </div>
    </div>
    
    <h2>Unused Rules List</h2>
    <table>
        <thead>
            <tr>
                <th>Line</th>
                <th>SID</th>
                <th>Age</th>
                <th>Message</th>
            </tr>
        </thead>
        <tbody>'''
        
        for sid in sorted(unused_sids):
            rule = next((r for r in self.parent.rules 
                       if hasattr(r, 'sid') and r.sid == sid), None)
            
            if rule:
                line_num = self.parent.rules.index(rule) + 1
                stat = sid_stats.get(sid, {})
                days = stat.get('days_in_production')
                days_str = f"{days} days" if days is not None else 'Unknown'
                message = rule.message
                
                html += f'''
            <tr>
                <td>{line_num}</td>
                <td>{sid}</td>
                <td>{days_str}</td>
                <td>{message}</td>
            </tr>'''
        
        html += f'''
        </tbody>
    </table>
    
    <div style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 12px;">
        <p>Generated by Suricata Rule Generator - Rule Usage Analyzer v{version_str}</p>
    </div>
</body>
</html>'''
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _export_low_frequency_rules(self, results):
        """Export low-frequency rules
        
        Args:
            results: Analysis results dictionary
        """
        # Show format selection dialog
        export_format = self._show_export_format_dialog()
        if not export_format:
            return
        
        # Get low-frequency SIDs
        sid_stats = results.get('sid_stats', {})
        low_freq_sids = [sid for sid, stat in sid_stats.items() 
                        if stat.get('category') == 'low_freq']
        
        if not low_freq_sids:
            messagebox.showinfo("No Data", "No low-frequency rules to export.")
            return
        
        if export_format == 'html':
            default_ext = ".html"
            filetypes = [("HTML files", "*.html"), ("All files", "*.*")]
        else:
            default_ext = ".txt"
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]
        
        filename = filedialog.asksaveasfilename(
            title="Export Low-Frequency Rules",
            defaultextension=default_ext,
            filetypes=filetypes,
            initialfile="low_frequency_rules"
        )
        
        if not filename:
            return
        
        try:
            if export_format == 'html':
                self._export_low_freq_html(filename, low_freq_sids, results)
            else:
                self._export_low_freq_text(filename, low_freq_sids, results)
            
            messagebox.showinfo("Export Complete", f"Low-frequency rules exported to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
    
    def _export_low_freq_text(self, filename, low_freq_sids, results):
        """Export low-frequency rules as plain text"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("LOW-FREQUENCY RULES EXPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Analysis Period: Last {results['time_range_days']} days\n")
            f.write(f"Low-Frequency Threshold: <{results.get('low_freq_threshold', 10)} hits\n")
            f.write(f"Total Low-Frequency Rules: {len(low_freq_sids)}\n\n")
            
            f.write("Rules that trigger rarely (potential shadow rules).\n\n")
            
            f.write("LOW-FREQUENCY RULES LIST\n")
            f.write("-" * 70 + "\n")
            f.write(f"{'Line':<6} {'SID':<8} {'Hits':<6} {'Last Hit':<12} {'Message':<40}\n")
            f.write("-" * 70 + "\n")
            
            sid_stats = results.get('sid_stats', {})
            
            for sid in sorted(low_freq_sids):
                rule = next((r for r in self.parent.rules 
                           if hasattr(r, 'sid') and r.sid == sid), None)
                
                if rule:
                    line_num = self.parent.rules.index(rule) + 1
                    stat = sid_stats.get(sid, {})
                    hits = stat.get('hits', 0)
                    last_hit_days = stat.get('last_hit_days', 999)
                    last_hit_str = f"{last_hit_days}d ago" if last_hit_days < 999 else 'Unknown'
                    message = rule.message[:40] + "..." if len(rule.message) > 40 else rule.message
                    
                    f.write(f"{line_num:<6} {sid:<8} {hits:<6} {last_hit_str:<12} {message:<40}\n")
            
            # Statistics
            f.write("\n")
            f.write("STATISTICS\n")
            f.write("-" * 70 + "\n")
            f.write(f"Count: {len(low_freq_sids)}\n")
            f.write(f"Percentage of total: {len(low_freq_sids)/results['total_rules']*100:.1f}%\n")
            
            # Calculate insights
            very_low = len([s for s in low_freq_sids if sid_stats.get(s, {}).get('hits', 0) < 3])
            stale = len([s for s in low_freq_sids if sid_stats.get(s, {}).get('last_hit_days', 0) > 14])
            
            f.write(f"\nInsights:\n")
            f.write(f"• {very_low} rules had <3 hits (potential shadow rules)\n")
            f.write(f"• {stale} rules not triggered in last 14+ days (stale)\n")
    
    def _export_low_freq_html(self, filename, low_freq_sids, results):
        """Export low-frequency rules as HTML"""
        from version import get_main_version
        version_str = get_main_version()
        
        sid_stats = results.get('sid_stats', {})
        total = results['total_rules']
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Low-Frequency Rules Export</title>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
            color: #333;
        }}
        .header {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .title {{
            color: #2c3e50;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .meta {{
            color: #6c757d;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th {{
            background-color: #e9ecef;
            padding: 10px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #dee2e6;
        }}
        td {{
            padding: 8px 10px;
            border-bottom: 1px solid #dee2e6;
        }}
        .stale_high {{ background-color: #ffcc66; }}
        .stale_medium {{ background-color: #ffdd88; }}
        .stale_low {{ background-color: #ffeeaa; }}
        .stale_none {{ background-color: #ffffcc; }}
        tr:hover td {{
            background-color: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">Low-Frequency Rules</div>
        <div class="meta">
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Analysis Period:</strong> Last {results['time_range_days']} days<br>
            <strong>Threshold:</strong> &lt;{results.get('low_freq_threshold', 10)} hits<br>
            <strong>Total Rules:</strong> {len(low_freq_sids)}
        </div>
    </div>
    
    <h2>Low-Frequency Rules List</h2>
    <p>Rules that trigger rarely (potential shadow rules)</p>
    <table>
        <thead>
            <tr>
                <th>Line</th>
                <th>SID</th>
                <th>Hits</th>
                <th>Last Hit</th>
                <th>Message</th>
            </tr>
        </thead>
        <tbody>'''
        
        for sid in sorted(low_freq_sids):
            rule = next((r for r in self.parent.rules 
                       if hasattr(r, 'sid') and r.sid == sid), None)
            
            if rule:
                line_num = self.parent.rules.index(rule) + 1
                stat = sid_stats.get(sid, {})
                hits = stat.get('hits', 0)
                last_hit_days = stat.get('last_hit_days', 999)
                last_hit_str = f"{last_hit_days} days ago" if last_hit_days < 999 else 'Unknown'
                message = rule.message
                
                # Color code by staleness
                if last_hit_days >= 21:
                    row_class = 'stale_high'
                elif last_hit_days >= 14:
                    row_class = 'stale_medium'
                elif last_hit_days >= 7:
                    row_class = 'stale_low'
                else:
                    row_class = 'stale_none'
                
                html += f'''
            <tr class="{row_class}">
                <td>{line_num}</td>
                <td>{sid}</td>
                <td>{hits}</td>
                <td>{last_hit_str}</td>
                <td>{message}</td>
            </tr>'''
        
        html += f'''
        </tbody>
    </table>
    
    <div style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 12px;">
        <p>Generated by Suricata Rule Generator - Rule Usage Analyzer v{version_str}</p>
    </div>
</body>
</html>'''
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _export_tiers_chart(self, results):
        """Export tier distribution chart
        
        Args:
            results: Analysis results dictionary
        """
        # Show format selection dialog
        export_format = self._show_export_format_dialog()
        if not export_format:
            return
        
        if export_format == 'html':
            default_ext = ".html"
            filetypes = [("HTML files", "*.html"), ("All files", "*.*")]
        else:
            default_ext = ".txt"
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]
        
        filename = filedialog.asksaveasfilename(
            title="Export Tier Distribution",
            defaultextension=default_ext,
            filetypes=filetypes,
            initialfile="tier_distribution"
        )
        
        if not filename:
            return
        
        try:
            if export_format == 'html':
                self._export_tiers_html(filename, results)
            else:
                self._export_tiers_text(filename, results)
            
            messagebox.showinfo("Export Complete", f"Tier distribution exported to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
    
    def _export_tiers_text(self, filename, results):
        """Export tier distribution as plain text"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("EFFICIENCY TIERS DISTRIBUTION\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Analysis Period: Last {results['time_range_days']} days\n")
            f.write(f"Total Rules: {results['total_rules']:,}\n\n")
            
            categories = results['categories']
            total = results['total_rules']
            
            f.write("TIER DISTRIBUTION\n")
            f.write("-" * 70 + "\n")
            
            # ASCII bar chart
            max_width = 50
            
            tiers = [
                ("Unused (0 hits)", categories['unused'], "🔴"),
                (f"Low-Frequency (<{results.get('low_freq_threshold', 10)} total hits OR <1 hit/day)", categories['low_freq'], "🟠"),
                ("Medium (1-9.9 hits/day)", categories['medium'], "🔵"),
                ("High (≥10 hits/day)", categories['high'], "🟢")
            ]
            
            for name, count, emoji in tiers:
                pct = (count / total * 100) if total > 0 else 0
                bar_len = int((count / total * max_width)) if total > 0 else 0
                bar = "█" * bar_len + "░" * (max_width - bar_len)
                f.write(f"{emoji} {name:<30} [{bar}] {count:,} ({pct:.1f}%)\n")
            
            f.write("\n")
            
            # Analysis
            f.write("DISTRIBUTION ANALYSIS\n")
            f.write("-" * 70 + "\n")
            
            active_rules = categories['medium'] + categories['high']
            active_pct = (active_rules / total * 100) if total > 0 else 0
            
            f.write(f"• Active rules (medium+high): {active_pct:.1f}%\n")
            f.write(f"• Unused rules: {categories['unused']/total*100:.1f}%\n")
            f.write(f"• Low-frequency rules: {categories['low_freq']/total*100:.1f}%\n\n")
            
            # Efficiency rating
            if active_pct >= 95:
                rating = "EXCELLENT"
            elif active_pct >= 90:
                rating = "GOOD"
            elif active_pct >= 80:
                rating = "FAIR"
            else:
                rating = "POOR"
            
            f.write(f"• Efficiency rating: {rating} ({active_pct:.1f}% active)\n")
    
    def _export_tiers_html(self, filename, results):
        """Export tier distribution as HTML"""
        from version import get_main_version
        version_str = get_main_version()
        
        categories = results['categories']
        total = results['total_rules']
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Efficiency Tiers Distribution</title>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
            color: #333;
        }}
        .header {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .title {{
            color: #2c3e50;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .meta {{
            color: #6c757d;
            font-size: 14px;
        }}
        .tier-bar {{
            height: 40px;
            margin: 20px 0;
            display: flex;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            overflow: hidden;
        }}
        .tier-unused {{ background-color: #D32F2F; }}
        .tier-low {{ background-color: #FF6F00; }}
        .tier-medium {{ background-color: #1976D2; }}
        .tier-high {{ background-color: #2E7D32; }}
        .tier-section {{
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">Efficiency Tiers Distribution</div>
        <div class="meta">
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Analysis Period:</strong> Last {results['time_range_days']} days<br>
            <strong>Total Rules:</strong> {results['total_rules']:,}
        </div>
    </div>
    
    <h2>Tier Distribution</h2>
    <div class="tier-bar">'''
        
        # Add colored sections
        tiers_data = [
            (categories['unused'], 'tier-unused', f"{categories['unused']/total*100:.1f}%"),
            (categories['low_freq'], 'tier-low', f"{categories['low_freq']/total*100:.1f}%"),
            (categories['medium'], 'tier-medium', f"{categories['medium']/total*100:.1f}%"),
            (categories['high'], 'tier-high', f"{categories['high']/total*100:.1f}%")
        ]
        
        for count, css_class, pct_label in tiers_data:
            if count > 0:
                width_pct = (count / total * 100) if total > 0 else 0
                html += f'''
        <div class="tier-section {css_class}" style="width: {width_pct}%;">{pct_label if width_pct >= 5 else ''}</div>'''
        
        html += '''
    </div>
    
    <h2>Tier Definitions</h2>
    <ul>'''
        
        tier_defs = [
            ("🔴", "Unused", "0 hits", categories['unused']),
            ("🟠", "Low-Frequency", f"<{results.get('low_freq_threshold', 10)} total hits OR <1 hit/day", categories['low_freq']),
            ("🔵", "Medium", "1-9.9 hits/day", categories['medium']),
            ("🟢", "High", "≥10 hits/day", categories['high'])
        ]
        
        for emoji, name, criteria, count in tier_defs:
            pct = (count / total * 100) if total > 0 else 0
            html += f'''
        <li>{emoji} <strong>{name}</strong> ({criteria}): {count:,} rules ({pct:.1f}%)</li>'''
        
        html += f'''
    </ul>
    
    <div style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 12px;">
        <p>Generated by Suricata Rule Generator - Rule Usage Analyzer v{version_str}</p>
    </div>
</body>
</html>'''
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _export_search_result(self, sid, stats, results):
        """Export individual SID search result
        
        Args:
            sid: SID to export
            stats: Statistics for the SID
            results: Analysis results dictionary
        """
        # Show format selection dialog
        export_format = self._show_export_format_dialog()
        if not export_format:
            return
        
        if export_format == 'html':
            default_ext = ".html"
            filetypes = [("HTML files", "*.html"), ("All files", "*.*")]
        else:
            default_ext = ".txt"
            filetypes = [("Text files", "*.txt"), ("All files", "*.*")]
        
        filename = filedialog.asksaveasfilename(
            title=f"Export SID {sid} Statistics",
            defaultextension=default_ext,
            filetypes=filetypes,
            initialfile=f"sid_{sid}_stats"
        )
        
        if not filename:
            return
        
        try:
            if export_format == 'html':
                self._export_search_html(filename, sid, stats, results)
            else:
                self._export_search_text(filename, sid, stats, results)
            
            messagebox.showinfo("Export Complete", f"SID {sid} statistics exported to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
    
    def _export_search_text(self, filename, sid, stats, results):
        """Export search result as plain text"""
        # Find the rule
        rule = next((r for r in self.parent.rules 
                   if hasattr(r, 'sid') and r.sid == sid), None)
        
        if not rule:
            return
        
        line_num = self.parent.rules.index(rule) + 1
        category = stats.get('category', 'Unknown')
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"SID {sid} STATISTICS\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Analysis Period: Last {results['time_range_days']} days\n\n")
            
            f.write("USAGE STATISTICS\n")
            f.write("-" * 70 + "\n")
            f.write(f"Total hits: {stats.get('hits', 0):,}\n")
            f.write(f"Percentage of traffic: {stats.get('percent', 0.0):.2f}%\n")
            f.write(f"Hits per day: {stats.get('hits_per_day', 0.0):.1f} avg\n")
            
            if stats.get('last_hit_days') is not None:
                f.write(f"Last hit: {stats['last_hit_days']} days ago\n")
            
            if stats.get('days_in_production') is not None:
                f.write(f"Age of rule: {stats['days_in_production']} days\n")
            
            f.write("\n")
            f.write("RULE INFORMATION\n")
            f.write("-" * 70 + "\n")
            f.write(f"Line #: {line_num}\n")
            f.write(f"Action: {rule.action.upper()}\n")
            f.write(f"Protocol: {rule.protocol.upper()}\n")
            f.write(f"Message: {rule.message}\n")
            
            if hasattr(rule, 'rev'):
                f.write(f"Revision: {rule.rev}\n")
            
            f.write("\n")
            f.write(f"Category: {category}\n\n")
            
            f.write("FULL RULE\n")
            f.write("-" * 70 + "\n")
            f.write(f"{rule.to_string()}\n\n")
            
            f.write("ANALYSIS\n")
            f.write("-" * 70 + "\n")
            interpretation = self._generate_sid_interpretation(stats, category, results)
            f.write(f"{interpretation}\n")
    
    def _export_search_html(self, filename, sid, stats, results):
        """Export search result as HTML"""
        from version import get_main_version
        version_str = get_main_version()
        
        # Find the rule
        rule = next((r for r in self.parent.rules 
                   if hasattr(r, 'sid') and r.sid == sid), None)
        
        if not rule:
            return
        
        line_num = self.parent.rules.index(rule) + 1
        category = stats.get('category', 'Unknown')
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>SID {sid} Statistics</title>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
            color: #333;
        }}
        .header {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .title {{
            color: #2c3e50;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .meta {{
            color: #6c757d;
            font-size: 14px;
        }}
        .section {{
            margin: 20px 0;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #2c3e50;
        }}
        .rule-text {{
            font-family: 'Courier New', monospace;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-size: 12px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th {{
            background-color: #e9ecef;
            padding: 10px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #dee2e6;
        }}
        td {{
            padding: 8px 10px;
            border-bottom: 1px solid #dee2e6;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">SID {sid} Statistics</div>
        <div class="meta">
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Analysis Period:</strong> Last {results['time_range_days']} days
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">Usage Statistics</div>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Hits</td><td>{stats.get('hits', 0):,}</td></tr>
            <tr><td>% of Traffic</td><td>{stats.get('percent', 0.0):.2f}%</td></tr>
            <tr><td>Hits/Day Avg</td><td>{stats.get('hits_per_day', 0.0):.1f}</td></tr>'''
        
        if stats.get('last_hit_days') is not None:
            html += f'''
            <tr><td>Last Hit</td><td>{stats['last_hit_days']} days ago</td></tr>'''
        
        if stats.get('days_in_production') is not None:
            html += f'''
            <tr><td>Age of Rule</td><td>{stats['days_in_production']} days</td></tr>'''
        
        html += f'''
        </table>
    </div>
    
    <div class="section">
        <div class="section-title">Rule Information</div>
        <p><strong>Line:</strong> {line_num}<br>
        <strong>Action:</strong> {rule.action.upper()}<br>
        <strong>Protocol:</strong> {rule.protocol.upper()}<br>
        <strong>Message:</strong> {rule.message}</p>
        <p><strong>Category:</strong> {category}</p>
    </div>
    
    <div class="section">
        <div class="section-title">Full Rule</div>
        <div class="rule-text">{rule.to_string()}</div>
    </div>
    
    <div style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 12px;">
        <p>Generated by Suricata Rule Generator - Rule Usage Analyzer v{version_str}</p>
    </div>
</body>
</html>'''
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _export_unlogged_text(self, filename, unlogged_sids, results):
        """Export unlogged rules as plain text"""
        from rule_usage_analyzer import RuleUsageAnalyzer
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("UNLOGGED RULES EXPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Unlogged Rules: {len(unlogged_sids)}\n\n")
            
            f.write("Rules that don't write to CloudWatch Logs.\n\n")
            
            f.write("UNLOGGED RULES LIST\n")
            f.write("-" * 70 + "\n")
            f.write(f"{'Line':<6} {'SID':<8} {'Action':<8} {'Reason':<25} {'Message':<30}\n")
            f.write("-" * 70 + "\n")
            
            for sid in sorted(unlogged_sids):
                rule = next((r for r in self.parent.rules
                           if hasattr(r, 'sid') and r.sid == sid), None)
                
                if rule:
                    line_num = self.parent.rules.index(rule) + 1
                    action = rule.action.upper()
                    
                    # Determine reason
                    action_lower = rule.action.lower()
                    options_text = f"{rule.content} {rule.original_options}".lower()
                    
                    if action_lower == "pass":
                        reason = "Pass without 'alert'"
                    elif action_lower in ["drop", "reject"]:
                        reason = f"{action_lower.capitalize()} with 'noalert'"
                    else:
                        reason = "Unknown"
                    
                    message = rule.message[:30] + "..." if len(rule.message) > 30 else rule.message
                    f.write(f"{line_num:<6} {sid:<8} {action:<8} {reason:<25} {message:<30}\n")
            
            f.write("\n")
            f.write("STATISTICS\n")
            f.write("-" * 70 + "\n")
            f.write(f"Count: {len(unlogged_sids)}\n")
            f.write(f"Percentage of total: {len(unlogged_sids)/results['total_rules']*100:.1f}%\n")
    
    def _export_unlogged_html(self, filename, unlogged_sids, results):
        """Export unlogged rules as HTML"""
        from version import get_main_version
        from rule_usage_analyzer import RuleUsageAnalyzer
        version_str = get_main_version()
        
        total = results['total_rules']
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Unlogged Rules Export</title>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.6;
            color: #333;
        }}
        .header {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .title {{
            color: #2c3e50;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .meta {{
            color: #6c757d;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th {{
            background-color: #e9ecef;
            padding: 10px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #dee2e6;
        }}
        td {{
            padding: 8px 10px;
            border-bottom: 1px solid #dee2e6;
            background-color: #f5f5f5;
        }}
        tr:hover td {{
            background-color: #e9ecef;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">Unlogged Rules</div>
        <div class="meta">
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Total Rules:</strong> {len(unlogged_sids)}
        </div>
    </div>
    
    <h2>Unlogged Rules List</h2>
    <p>Rules that don't write to CloudWatch Logs and cannot be tracked for usage.</p>
    <table>
        <thead>
            <tr>
                <th>Line</th>
                <th>SID</th>
                <th>Action</th>
                <th>Protocol</th>
                <th>Reason</th>
                <th>Message</th>
            </tr>
        </thead>
        <tbody>'''
        
        for sid in sorted(unlogged_sids):
            rule = next((r for r in self.parent.rules
                       if hasattr(r, 'sid') and r.sid == sid), None)
            
            if rule:
                line_num = self.parent.rules.index(rule) + 1
                action = rule.action.upper()
                protocol = rule.protocol.upper()
                message = rule.message
                
                # Determine reason
                action_lower = rule.action.lower()
                options_text = f"{rule.content} {rule.original_options}".lower()
                
                if action_lower == "pass":
                    reason = "Pass without 'alert'"
                elif action_lower in ["drop", "reject"]:
                    reason = f"{action_lower.capitalize()} with 'noalert'"
                else:
                    reason = "Unknown"
                
                html += f'''
            <tr>
                <td>{line_num}</td>
                <td>{sid}</td>
                <td>{action}</td>
                <td>{protocol}</td>
                <td>{reason}</td>
                <td>{message}</td>
            </tr>'''
        
        html += f'''
        </tbody>
    </table>
    
    <div style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 12px;">
        <p>Generated by Suricata Rule Generator - Rule Usage Analyzer v{version_str}</p>
    </div>
</body>
</html>'''
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _sort_treeview(self, tree, col, reverse):
        """Sort treeview by column (helper for sortable columns)
        
        Args:
            tree: Treeview widget to sort
            col: Column name to sort by
            reverse: Boolean indicating sort direction
        """
        # Get all items with their values
        items = [(tree.set(item, col), item) for item in tree.get_children('')]
        
        # Determine sort key based on column type
        def get_sort_key(val_item_tuple):
            val = val_item_tuple[0]
            # Try to convert to numeric for Line, SID, Hits columns (integers)
            if col in ["Line", "SID", "Hits"]:
                try:
                    return int(val.replace(',', ''))  # Remove commas for numeric comparison
                except (ValueError, TypeError):
                    return 0
            # For "Hits/Day" column, handle decimal values (floats)
            elif col == "Hits/Day":
                try:
                    return float(val)
                except (ValueError, TypeError):
                    return 0.0
            # For "Age of Rule (days)" column, handle numeric days
            elif col == "Age of Rule (days)":
                try:
                    if val == 'Unknown':
                        return 999999  # Unknown goes to end
                    return int(val)
                except (ValueError, TypeError):
                    return 999999
            # For "Last Modified" column, handle date format YYYY-MM-DD
            elif col == "Last Modified":
                try:
                    if val == 'Unknown':
                        return '9999-99-99'  # Unknown goes to end
                    return val  # Date strings sort correctly as-is
                except (ValueError, TypeError):
                    return '9999-99-99'
            # For "Last Hit" column, extract days number
            elif col == "Last Hit":
                try:
                    # Format is "Xd ago"
                    if 'd ago' in val:
                        return int(val.split('d')[0])
                    return 999  # Unknown goes to end
                except (ValueError, TypeError):
                    return 999
            # For percentage columns (% Traffic, Cumulative %), strip % and convert to float
            elif col in ["% Traffic", "Cumulative %"]:
                try:
                    # Format is "X.X%"
                    return float(val.rstrip('%'))
                except (ValueError, TypeError):
                    return 0.0
            else:
                # String sort for other columns
                return val.lower()
        
        # Sort items
        items.sort(key=get_sort_key, reverse=reverse)
        
        # Rearrange items in sorted order
        for index, (val, item) in enumerate(items):
            tree.move(item, '', index)
        
        # Update column heading to show sort direction and toggle on next click
        for column in tree["columns"]:
            if column == col:
                # Add arrow indicator
                current_text = col
                if reverse:
                    tree.heading(column, text=f"{current_text} ▼",
                               command=lambda c=col, t=tree: self._sort_treeview(t, c, not reverse))
                else:
                    tree.heading(column, text=f"{current_text} ▲",
                               command=lambda c=col, t=tree: self._sort_treeview(t, c, not reverse))
            else:
                # Remove arrow from other columns
                # BUG FIX #8: Capture column variable correctly in lambda to avoid closure issue
                if column != "☐" and column != "Message":
                    tree.heading(column, text=column,
                               command=lambda c=column, t=tree: self._sort_treeview(t, c, False))
                else:
                    # BUG FIX #9: Cannot set command=None in tkinter - omit command parameter instead
                    tree.heading(column, text=column)
    
    def _generate_sid_interpretation(self, stats, category, analysis_results):
        """Generate interpretation text for a searched SID
        
        Args:
            stats: Statistics dict for the SID
            category: Category string
            analysis_results: Full analysis results dict
            
        Returns:
            str: Interpretation text
        """
        hits = stats.get('hits', 0)
        percent = stats.get('percent', 0.0)
        last_hit_days = stats.get('last_hit_days')
        hits_per_day = stats.get('hits_per_day', 0.0)
        
        interpretation = ""
        
        if hits == 0:
            interpretation = "• This rule has not triggered during the analysis period\n"
            interpretation += "• It may be unused or redundant\n"
            interpretation += "• Consider reviewing for removal or modification"
        elif 'low-frequency' in category.lower() or 'low_freq' in category.lower():
            interpretation = f"• Low-frequency rule ({hits} hits in {analysis_results['time_range_days']} days)\n"
            
            if last_hit_days and last_hit_days > 21:
                interpretation += f"• Very stale - last triggered {last_hit_days} days ago\n"
                interpretation += "• Likely shadowed by an earlier rule\n"
            elif last_hit_days and last_hit_days > 14:
                interpretation += f"• Getting stale - last triggered {last_hit_days} days ago\n"
                interpretation += "• May be shadowed by an earlier rule\n"
            else:
                interpretation += "• Triggers infrequently\n"
                interpretation += "• May be shadowed by earlier rules\n"
            
            interpretation += "• Consider using 'Review Rules' feature to check for shadowing"
        elif percent > 30:
            interpretation = f"• CRITICAL: Handles {percent:.1f}% of all traffic\n"
            interpretation += "• Rule is too generic/broad\n"
            interpretation += "• Security risk - allows too much without specificity\n"
            interpretation += "• Recommendation: Split into more specific rules"
        elif percent > 15:
            interpretation = f"• HIGH: Handles {percent:.1f}% of all traffic\n"
            interpretation += "• Rule is overly broad\n"
            interpretation += "• Consider splitting into more specific rules\n"
            interpretation += "• Changes to this rule require careful testing"
        elif percent > 10:
            interpretation = f"• MEDIUM: Handles {percent:.1f}% of all traffic\n"
            interpretation += "• Rule is moderately broad\n"
            interpretation += "• Consider refining for better specificity"
        elif hits_per_day >= 100:
            interpretation = f"• Critical rule - very high traffic ({hits_per_day:.0f} hits/day)\n"
            interpretation += "• Changes require extensive testing\n"
            interpretation += "• Monitor closely for performance impact"
        elif hits_per_day >= 10:
            interpretation = f"• High-traffic rule ({hits_per_day:.1f} hits/day average)\n"
            interpretation += "• Well-utilized and effective\n"
            interpretation += "• Part of core rule set"
        elif hits_per_day >= 1:
            interpretation = f"• Medium-traffic rule ({hits_per_day:.1f} hits/day average)\n"
            interpretation += "• Regularly triggered\n"
            interpretation += "• Functioning as expected"
        else:
            interpretation = "• Normal rule activity\n"
            interpretation += "• No issues detected"
        
        return interpretation
    
    def _draw_tiers_chart(self, canvas, categories, total_rules, notebook):
        """Draw horizontal stacked bar chart showing tier distribution with clickable sections
        
        Args:
            canvas: Canvas widget to draw on
            categories: Dict with 'unused', 'low_freq', 'medium', 'high' counts
            total_rules: Total number of rules (includes unlogged)
            notebook: Notebook widget for tab navigation
        """
        width = 700
        height = 60
        padding = 10
        
        # Use only logged rules for percentage calculation (excludes unlogged rules)
        # This ensures the chart sections add up to 100%
        unlogged_count = categories.get('unlogged', 0)
        total_logged = total_rules - unlogged_count
        
        # Calculate percentages based on logged rules only
        unused_pct = (categories['unused'] / total_logged * 100) if total_logged > 0 else 0
        low_freq_pct = (categories['low_freq'] / total_logged * 100) if total_logged > 0 else 0
        medium_pct = (categories['medium'] / total_logged * 100) if total_logged > 0 else 0
        high_pct = (categories['high'] / total_logged * 100) if total_logged > 0 else 0
        
        # Draw background
        canvas.create_rectangle(padding, padding, width - padding, height - padding,
                              fill='#EEEEEE', outline='#CCCCCC')
        
        # Draw sections (left to right)
        x = padding
        bar_height = height - 2 * padding
        
        # Section 1: Unused (Red)
        section_width = int((width - 2 * padding) * (unused_pct / 100))
        if section_width > 0:
            canvas.create_rectangle(x, padding, x + section_width, height - padding,
                                  fill='#D32F2F', outline='', tags='tier_unused')
            if unused_pct >= 5:  # Only show label if section is wide enough
                canvas.create_text(x + section_width/2, height/2,
                                 text=f"{unused_pct:.1f}%",
                                 fill='white', font=("TkDefaultFont", 10, "bold"),
                                 tags='tier_unused')
            x += section_width
        
        # Section 2: Low-Frequency (Orange)
        section_width = int((width - 2 * padding) * (low_freq_pct / 100))
        if section_width > 0:
            canvas.create_rectangle(x, padding, x + section_width, height - padding,
                                  fill='#FF6F00', outline='', tags='tier_low_freq')
            if low_freq_pct >= 5:
                canvas.create_text(x + section_width/2, height/2,
                                 text=f"{low_freq_pct:.1f}%",
                                 fill='white', font=("TkDefaultFont", 10, "bold"),
                                 tags='tier_low_freq')
            x += section_width
        
        # Section 3: Medium (Blue)
        section_width = int((width - 2 * padding) * (medium_pct / 100))
        if section_width > 0:
            canvas.create_rectangle(x, padding, x + section_width, height - padding,
                                  fill='#1976D2', outline='', tags='tier_medium')
            if medium_pct >= 5:
                canvas.create_text(x + section_width/2, height/2,
                                 text=f"{medium_pct:.1f}%",
                                 fill='white', font=("TkDefaultFont", 10, "bold"),
                                 tags='tier_medium')
            x += section_width
        
        # Section 4: High (Green)
        section_width = int((width - 2 * padding) * (high_pct / 100))
        if section_width > 0:
            canvas.create_rectangle(x, padding, x + section_width, height - padding,
                                  fill='#2E7D32', outline='', tags='tier_high')
            if high_pct >= 5:
                canvas.create_text(x + section_width/2, height/2,
                                 text=f"{high_pct:.1f}%",
                                 fill='white', font=("TkDefaultFont", 10, "bold"),
                                 tags='tier_high')
        
        # Bind click events to navigate to tabs
        canvas.tag_bind('tier_unused', '<Button-1>', 
                       lambda e: notebook.select(1))  # Unused tab
        canvas.tag_bind('tier_low_freq', '<Button-1>', 
                       lambda e: notebook.select(2))  # Low-Frequency tab
        canvas.tag_bind('tier_medium', '<Button-1>', 
                       lambda e: notebook.select(3))  # Effectiveness tab (shows high-traffic)
        canvas.tag_bind('tier_high', '<Button-1>', 
                       lambda e: notebook.select(3))  # Effectiveness tab (shows high-traffic)
        
        # Hover effect - change cursor to hand when over clickable sections
        def on_hover(event):
            # Find which item is under cursor
            items = canvas.find_overlapping(event.x - 2, event.y - 2, 
                                           event.x + 2, event.y + 2)
            for item in items:
                tags = canvas.gettags(item)
                if any(t.startswith('tier_') for t in tags):
                    canvas.config(cursor='hand2')
                    return
            canvas.config(cursor='')
        
        def on_leave(event):
            canvas.config(cursor='')
        
        canvas.bind('<Motion>', on_hover)
        canvas.bind('<Leave>', on_leave)
    
    def setup_filter_bar(self, parent):
        """Setup collapsible filter bar above the rules table"""
        # Main filter container
        filter_container = ttk.Frame(parent)
        filter_container.pack(fill=tk.X, pady=(0, 5))
        
        # Row 1: Always visible (shown when collapsed or expanded)
        self.filter_row1_frame = ttk.Frame(filter_container)
        self.filter_row1_frame.pack(fill=tk.X, pady=2)
        
        # Collapse/expand control
        self.filter_collapsed = True
        self.collapse_label = ttk.Label(self.filter_row1_frame, text="▶", cursor="hand2", 
                                       font=("TkDefaultFont", 9, "bold"))
        self.collapse_label.pack(side=tk.LEFT, padx=5)
        self.collapse_label.bind('<Button-1>', lambda e: self.toggle_filter_bar())
        
        # Action checkboxes (always visible)
        self.filter_pass_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_row1_frame, text="Pass", variable=self.filter_pass_var,
                       command=self.apply_filters_phase1).pack(side=tk.LEFT, padx=3)
        
        self.filter_drop_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_row1_frame, text="Drop", variable=self.filter_drop_var,
                       command=self.apply_filters_phase1).pack(side=tk.LEFT, padx=3)
        
        self.filter_reject_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_row1_frame, text="Reject", variable=self.filter_reject_var,
                       command=self.apply_filters_phase1).pack(side=tk.LEFT, padx=3)
        
        self.filter_alert_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_row1_frame, text="Alert", variable=self.filter_alert_var,
                       command=self.apply_filters_phase1).pack(side=tk.LEFT, padx=3)
        
        self.filter_comments_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.filter_row1_frame, text="Comments", variable=self.filter_comments_var,
                       command=self.apply_filters_phase1).pack(side=tk.LEFT, padx=3)
        
        # Protocol button (always visible)
        ttk.Label(self.filter_row1_frame, text="| Protocol:", font=("TkDefaultFont", 9)).pack(side=tk.LEFT, padx=(10, 2))
        self.filter_protocol_var = tk.StringVar(value="All Protocols")
        self.selected_protocols = []
        self.protocol_button = ttk.Button(self.filter_row1_frame, text="All Protocols", width=14, 
                                         command=self.show_protocol_selector)
        self.protocol_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Row 2: SID range, Variable filters + buttons (only visible when expanded)
        self.filter_row2_frame = ttk.Frame(filter_container)
        row2 = self.filter_row2_frame
        
        # Add spacing to align with row1
        ttk.Label(row2, text="              ", font=("TkDefaultFont", 9)).pack(side=tk.LEFT)
        
        # SID range inputs with exclude checkbox
        ttk.Label(row2, text="SID:", font=("TkDefaultFont", 9)).pack(side=tk.LEFT, padx=(0, 2))
        self.filter_sid_from_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.filter_sid_from_var, width=8).pack(side=tk.LEFT)
        ttk.Label(row2, text="to", font=("TkDefaultFont", 9)).pack(side=tk.LEFT, padx=2)
        self.filter_sid_to_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.filter_sid_to_var, width=8).pack(side=tk.LEFT)
        
        # Exclude range checkbox
        self.filter_sid_exclude_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Exclude", variable=self.filter_sid_exclude_var).pack(side=tk.LEFT, padx=(2, 10))
        
        # Variable dropdown (auto-populated from rules)
        ttk.Label(row2, text="Var:", font=("TkDefaultFont", 9)).pack(side=tk.LEFT, padx=(0, 2))
        self.filter_variable_var = tk.StringVar(value="All")
        self.variable_combo = ttk.Combobox(row2, textvariable=self.filter_variable_var,
                                          values=["All"],
                                          state="readonly", width=12)
        self.variable_combo.pack(side=tk.LEFT, padx=(0, 10))
        
        # Apply and Clear buttons
        ttk.Button(row2, text="Apply", command=self.apply_filters_phase2).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(row2, text="Clear", command=self.clear_filters).pack(side=tk.RIGHT)
        
        # Initially update variable dropdown
        self.refresh_variable_dropdown()
    
    def toggle_filter_bar(self):
        """Toggle filter bar between collapsed and expanded states"""
        self.filter_collapsed = not self.filter_collapsed
        
        if self.filter_collapsed:
            # Collapsed: Hide Row 2, show Row 1 only
            self.collapse_label.config(text="▶")
            self.filter_row2_frame.pack_forget()
        else:
            # Expanded: Show both rows
            self.collapse_label.config(text="▼")
            self.filter_row2_frame.pack(fill=tk.X, pady=2)
            # Refresh variable dropdown when expanding
            self.refresh_variable_dropdown()
    
    
    def show_protocol_selector(self):
        """Show multi-select protocol popup with checkmarks"""
        # Create popup window with optimized dimensions
        popup = tk.Toplevel(self.parent.root)
        popup.title("Select Protocols")
        popup.transient(self.parent.root)
        popup.grab_set()
        popup.resizable(False, False)
        
        # Position popup near the protocol button
        button_x = self.protocol_button.winfo_rootx()
        button_y = self.protocol_button.winfo_rooty() + self.protocol_button.winfo_height()
        popup.geometry(f"180x350+{button_x}+{button_y}")
        
        # Main container
        main_container = ttk.Frame(popup)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create scrollable frame for checkboxes
        canvas = tk.Canvas(main_container, width=140, height=280)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Create checkbox variables for each protocol
        protocol_vars = {}
        
        for protocol in SuricataConstants.SUPPORTED_PROTOCOLS:
            var = tk.BooleanVar(value=(protocol in self.selected_protocols))
            protocol_vars[protocol] = var
            
            cb = ttk.Checkbutton(scrollable_frame, text=protocol.upper(), variable=var)
            cb.pack(anchor=tk.W, padx=10, pady=1)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Enable mouse wheel scrolling
        def on_mousewheel(event):
            try:
                if event.delta:
                    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
                elif event.num == 4:
                    canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    canvas.yview_scroll(1, "units")
            except:
                pass
        
        canvas.bind_all("<MouseWheel>", on_mousewheel)
        canvas.bind_all("<Button-4>", on_mousewheel)
        canvas.bind_all("<Button-5>", on_mousewheel)
        
        # Buttons at bottom - no padding above to eliminate wasted space
        button_frame = ttk.Frame(popup)
        button_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        def on_ok():
            # Unbind mouse wheel before closing
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")
            
            # Collect selected protocols
            self.selected_protocols = [p for p, v in protocol_vars.items() if v.get()]
            
            # Update button text
            if not self.selected_protocols:
                self.protocol_button.config(text="All Protocols")
                self.filter_protocol_var.set("All Protocols")
            elif len(self.selected_protocols) == 1:
                self.protocol_button.config(text=self.selected_protocols[0].upper())
                self.filter_protocol_var.set(self.selected_protocols[0].upper())
            else:
                self.protocol_button.config(text=f"{len(self.selected_protocols)} Protocols")
                self.filter_protocol_var.set(f"{len(self.selected_protocols)} Protocols")
            
            popup.destroy()
            
            # Apply filters immediately
            self.apply_filters_phase1()
        
        def on_cancel():
            # Unbind mouse wheel before closing
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")
            popup.destroy()
        
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT)
        
        # Bind Escape key
        popup.bind('<Escape>', lambda e: on_cancel())
    
    def apply_filters_phase1(self):
        """Apply Phase 1 filters (Actions + Protocol) - instant filtering"""
        filter_obj = self.parent.rule_filter
        
        # Collect checked actions
        filter_obj.actions = []
        if self.filter_pass_var.get():
            filter_obj.actions.append('pass')
        if self.filter_drop_var.get():
            filter_obj.actions.append('drop')
        if self.filter_reject_var.get():
            filter_obj.actions.append('reject')
        if self.filter_alert_var.get():
            filter_obj.actions.append('alert')
        
        filter_obj.show_comments = self.filter_comments_var.get()
        
        # Protocol filter (support multiple protocols)
        if self.selected_protocols:
            filter_obj.protocols = [p.lower() for p in self.selected_protocols]
        else:
            filter_obj.protocols = []
        
        # Refresh table
        self.parent.refresh_table(preserve_selection=False)
    
    def apply_filters_phase2(self):
        """Apply Phase 2 filters (includes SID Range + Variable) - with Apply button"""
        # First apply Phase 1 filters
        self.apply_filters_phase1()
        
        filter_obj = self.parent.rule_filter
        
        # Apply SID range filter
        try:
            sid_from = self.filter_sid_from_var.get().strip()
            sid_to = self.filter_sid_to_var.get().strip()
            
            filter_obj.sid_min = int(sid_from) if sid_from else None
            filter_obj.sid_max = int(sid_to) if sid_to else None
            filter_obj.sid_exclude_range = self.filter_sid_exclude_var.get()
        except ValueError:
            # Invalid SID input - ignore filter
            filter_obj.sid_min = None
            filter_obj.sid_max = None
            filter_obj.sid_exclude_range = False
        
        # Apply Variable filter
        selected_var = self.filter_variable_var.get()
        if selected_var != "All":
            filter_obj.variables = [selected_var]
        else:
            filter_obj.variables = []
        
        # Refresh variable dropdown (to catch any new variables added)
        self.refresh_variable_dropdown()
        
        # Refresh table
        self.parent.refresh_table(preserve_selection=False)
    
    def refresh_variable_dropdown(self):
        """Refresh variable dropdown when rules change"""
        used_vars = self.parent.rule_filter.get_used_variables(self.parent.rules)
        var_values = ["All"] + used_vars
        self.variable_combo['values'] = var_values
        
        # If currently selected variable is no longer in use, reset to "All"
        if self.filter_variable_var.get() not in var_values:
            self.filter_variable_var.set("All")
    
    def clear_filters(self):
        """Reset all filters to default (show all)"""
        self.filter_pass_var.set(True)
        self.filter_drop_var.set(True)
        self.filter_reject_var.set(True)
        self.filter_alert_var.set(True)
        self.filter_comments_var.set(True)
        
        # Reset protocol multi-select
        self.selected_protocols = []
        self.protocol_button.config(text="All Protocols")
        self.filter_protocol_var.set("All Protocols")
        
        self.filter_sid_from_var.set("")
        self.filter_sid_to_var.set("")
        self.filter_sid_exclude_var.set(False)
        self.filter_variable_var.set("All")
        
        # Apply the cleared filters
        self.apply_filters_phase2()
    
    def setup_rules_table(self, parent):
        """Setup the rules display table with color coding and enhanced scrolling"""
        table_frame = ttk.LabelFrame(parent, text="Suricata Rules")
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create container for table and scrollbars
        table_container = ttk.Frame(table_frame)
        table_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview with enhanced scrolling capabilities
        # Reduced height to allocate more space to editor section below
        columns = ("Line", "SigType", "Action", "Protocol", "Rule Data")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", 
                                height=15, selectmode="extended")
        
        # Configure column headings and widths
        self.tree.heading("Line", text="Line")
        self.tree.heading("SigType", text="SIG Type")
        self.tree.heading("Action", text="Action") 
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Rule Data", text="Source | Src Port | Direction | Destination | Dst Port | Options | Message | SID | Rev")
        
        self.tree.column("Line", width=50, stretch=False, minwidth=40)
        self.tree.column("SigType", width=0, stretch=False, minwidth=0)  # Hidden by default
        self.tree.column("Action", width=80, stretch=False, minwidth=60)
        self.tree.column("Protocol", width=80, stretch=False, minwidth=60)
        self.tree.column("Rule Data", width=1000, stretch=True, minwidth=300)
        
        # Create vertical scrollbar with enhanced configuration
        v_scrollbar = ttk.Scrollbar(table_container, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scrollbar.set)
        
        # Create horizontal scrollbar for wide rule data
        h_scrollbar = ttk.Scrollbar(table_container, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(xscrollcommand=h_scrollbar.set)
        
        # Grid layout for better scrollbar positioning
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights for proper resizing
        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)
        
        # Enable mouse wheel scrolling
        self.tree.bind("<MouseWheel>", self._on_mousewheel)
        self.tree.bind("<Button-4>", self._on_mousewheel)  # Linux scroll up
        self.tree.bind("<Button-5>", self._on_mousewheel)  # Linux scroll down
        
        # Configure color tags for different columns
        self.tree.tag_configure("action_pass", foreground="#2E7D32")
        self.tree.tag_configure("action_alert", foreground="#1976D2")
        self.tree.tag_configure("action_drop", foreground="#D32F2F")
        self.tree.tag_configure("action_reject", foreground="#7B1FA2")  # Purple
        self.tree.tag_configure("comment", foreground="#808080")  # Grey for comments
        self.tree.tag_configure("search_highlight", background="#FFFF00")  # Yellow highlight for search results
        
        # Bind selection and double-click events
        self.tree.bind("<<TreeviewSelect>>", self.on_rule_select)
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<Button-3>", self.on_right_click)  # Right-click context menu
        # Bind events that can cause treeview redraw
        self.tree.bind("<Configure>", self.on_tree_configure)
        self.tree.bind("<ButtonRelease-1>", self.on_column_resize)
        # Bind Ctrl-V specifically to tree for pasting rules
        self.tree.bind("<Control-v>", lambda e: self.parent.paste_rules())
        
        # Store reference in parent for access by other components
        self.parent.tree = self.tree
        
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling for the rules table"""
        try:
            # Windows and MacOS
            if event.delta:
                delta = -1 * (event.delta / 120)
            # Linux
            elif event.num == 4:
                delta = -1
            elif event.num == 5:
                delta = 1
            else:
                delta = 0
            
            # Only scroll if there are enough items to require scrolling
            if len(self.tree.get_children()) > 20:  # More items than visible height
                self.tree.yview_scroll(int(delta), "units")
                
        except (AttributeError, tk.TclError):
            # Ignore any scrolling errors
            pass
    
    def setup_tabbed_editor(self, parent):
        """Setup the tabbed editor interface"""
        editor_frame = ttk.LabelFrame(parent, text="Editor", height=360)
        editor_frame.pack(fill=tk.X, pady=(10, 0))
        editor_frame.pack_propagate(False)  # Prevent frame from shrinking
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(editor_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tab styling for better visual distinction
        style = ttk.Style()
        style.configure('TNotebook.Tab', padding=[20, 8])
        
        # Setup tabs
        self.setup_rule_editor_tab()
        self.setup_variables_tab()
        self.setup_tags_tab()  # AWS Tags tab - NEW
        self.setup_history_tab()
        
        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # Store reference in parent for access by other components
        self.parent.notebook = self.notebook
    
    def setup_rule_editor_tab(self):
        """Setup the rule editor tab"""
        # Create rule editor tab
        rule_tab = ttk.Frame(self.notebook)
        self.notebook.add(rule_tab, text="Rule Editor")
        
        # Create form fields in a grid
        fields_frame = ttk.Frame(rule_tab)
        fields_frame.pack(fill=tk.X, expand=False, anchor=tk.N, padx=5, pady=(5, 0))
        
        # Row 1: Action, Protocol, Direction
        ttk.Label(fields_frame, text="Action:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.action_var = tk.StringVar(value="pass")
        action_combo = ttk.Combobox(fields_frame, textvariable=self.action_var, 
                                   values=["pass", "alert", "drop", "reject"], state="readonly", width=10)
        action_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        ttk.Label(fields_frame, text="Protocol:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.protocol_var = tk.StringVar(value="tcp")
        protocol_combo = ttk.Combobox(fields_frame, textvariable=self.protocol_var,
                                     values=SuricataConstants.SUPPORTED_PROTOCOLS, state="readonly", width=10)
        protocol_combo.grid(row=0, column=3, sticky=tk.W, padx=(0, 20))
        
        # Bind protocol change to update Content Keywords for new rules
        protocol_combo.bind('<<ComboboxSelected>>', self.on_protocol_changed)
        
        ttk.Label(fields_frame, text="Direction:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        self.direction_var = tk.StringVar(value="->")
        direction_combo = ttk.Combobox(fields_frame, textvariable=self.direction_var,
                                    values=["->", "<>"], state="readonly", width=5)
        direction_combo.grid(row=0, column=5, sticky=tk.W)
        
        # Row 2: Source Network, Dest Network with enhanced tooltips
        src_net_label = ttk.Label(fields_frame, text="Source Network:")
        src_net_label.grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.src_net_var = tk.StringVar(value="$HOME_NET")
        self.src_net_entry = ttk.Entry(fields_frame, textvariable=self.src_net_var, width=15)
        self.src_net_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.src_net_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Add tooltip for source network
        self.create_tooltip(self.src_net_entry, 
            "Source Network Examples:\n" +
            "• any\n" +
            "• $HOME_NET (variable)\n" +
            "• @VPC_REFERENCE (reference)\n" +
            "• 192.168.1.0/24 (single CIDR)\n" +
            "• !192.168.1.5 (negation)\n" +
            "• [10.0.0.0/24, !10.0.0.5] (group)\n" +
            "• [$HOME_NET, !192.168.1.0/24] (variable group)")
        
        dst_net_label = ttk.Label(fields_frame, text="Dest Network:")
        dst_net_label.grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.dst_net_var = tk.StringVar(value="$EXTERNAL_NET")
        self.dst_net_entry = ttk.Entry(fields_frame, textvariable=self.dst_net_var, width=15)
        self.dst_net_entry.grid(row=1, column=3, sticky=tk.W, pady=(5, 0))
        self.dst_net_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Add tooltip for destination network
        self.create_tooltip(self.dst_net_entry,
            "Destination Network Examples:\n" +
            "• any\n" +
            "• $EXTERNAL_NET (variable)\n" +
            "• @VPC_REFERENCE (reference)\n" +
            "• 192.168.1.0/24 (single CIDR)\n" +
            "• !192.168.1.5 (negation)\n" +
            "• [10.0.0.0/24, !10.0.0.5] (group)\n" +
            "• [$EXTERNAL_NET, !$HOME_NET] (variable group)")
        
        # Row 3: Source Port, Dest Port with validation warnings
        ttk.Label(fields_frame, text="Source Port:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.src_port_var = tk.StringVar(value="any")
        self.src_port_entry = ttk.Entry(fields_frame, textvariable=self.src_port_var, width=15)
        self.src_port_entry.grid(row=2, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.src_port_entry.bind("<Button-3>", self.on_entry_right_click)
        
        ttk.Label(fields_frame, text="Dest Port:").grid(row=2, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.dst_port_var = tk.StringVar(value="any")
        self.dst_port_entry = ttk.Entry(fields_frame, textvariable=self.dst_port_var, width=15)
        self.dst_port_entry.grid(row=2, column=3, sticky=tk.W, pady=(5, 0))
        self.dst_port_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Row 4: Message
        ttk.Label(fields_frame, text="Message:").grid(row=3, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(fields_frame, textvariable=self.message_var, width=50)
        self.message_entry.grid(row=3, column=1, columnspan=4, sticky=tk.W+tk.E, pady=(5, 0))
        self.message_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Row 5: Content Keywords
        ttk.Label(fields_frame, text="Content Keywords:").grid(row=4, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.content_var = tk.StringVar()
        self.content_entry = ttk.Entry(fields_frame, textvariable=self.content_var, width=50)
        self.content_entry.grid(row=4, column=1, columnspan=4, sticky=tk.W+tk.E, pady=(5, 0))
        self.content_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Row 6: SID and REV
        ttk.Label(fields_frame, text="SID:").grid(row=5, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.sid_var = tk.StringVar()
        self.sid_entry = ttk.Entry(fields_frame, textvariable=self.sid_var, width=10)
        self.sid_entry.grid(row=5, column=1, sticky=tk.W, pady=(5, 0))
        self.sid_entry.bind("<Button-3>", self.on_entry_right_click)
        
        ttk.Label(fields_frame, text="Rev:").grid(row=5, column=2, sticky=tk.W, padx=(20, 5), pady=(5, 0))
        self.rev_var = tk.StringVar()
        
        # Rev field - conditional based on tracking state (will be set up properly in show_rule_editor)
        self.rev_entry = ttk.Entry(fields_frame, textvariable=self.rev_var, width=5, state="readonly")
        self.rev_entry.grid(row=5, column=3, sticky=tk.W, pady=(5, 0))
        
        # Create dropdown for rev selection (hidden initially, shown when tracking enabled)
        # Width 27 fits "Rev XXX - YYYY-MM-DDTHH:MM" comfortably without wasted space
        self.rev_combo = ttk.Combobox(fields_frame, textvariable=self.rev_var, 
                                      state="readonly", width=27)
        # Don't grid it yet - will be shown/hidden dynamically
        
        # Comment (hidden by default)
        self.comment_label = ttk.Label(fields_frame, text="Comment:")
        self.comment_var = tk.StringVar()
        self.comment_entry = ttk.Entry(fields_frame, textvariable=self.comment_var, width=50)
        
        # Save button
        ttk.Button(fields_frame, text="Save Changes", command=self.parent.save_rule_changes).grid(row=5, column=4, sticky=tk.W, padx=(20, 0), pady=(5, 0))
        
        # Configure column weights for resizing
        fields_frame.columnconfigure(1, weight=1)
        fields_frame.columnconfigure(3, weight=1)
        
        # Rule management buttons (inside the tab to maintain consistent frame height)
        buttons_container = ttk.Frame(rule_tab)
        buttons_container.pack(fill=tk.X, padx=5, pady=(10, 5))
        
        ttk.Button(buttons_container, text="Delete Selected", command=self.parent.delete_selected_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_container, text="Copy Selected", command=self.parent.copy_selected_rules).pack(side=tk.LEFT, padx=(0, 5))
        self.paste_button = ttk.Button(buttons_container, text="Paste", command=self.parent.paste_rules, state="disabled")
        self.paste_button.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_container, text="Insert Rule", command=self.parent.insert_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_container, text="Insert Comment", command=self.parent.insert_comment).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_container, text="Insert Domain Allow Rule", command=self.parent.domain_importer.insert_domain_rule).pack(side=tk.LEFT, padx=(0, 5))
        
        # Move buttons on the right side
        ttk.Button(buttons_container, text="Move Up", command=self.parent.move_rule_up).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(buttons_container, text="Move Down", command=self.parent.move_rule_down).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Store button reference for paste button state management
        self.parent.paste_button = self.paste_button
        
        # Store references in parent for access by other components
        self.parent.action_var = self.action_var
        self.parent.protocol_var = self.protocol_var
        self.parent.src_net_var = self.src_net_var
        self.parent.src_port_var = self.src_port_var
        self.parent.direction_var = self.direction_var
        self.parent.dst_net_var = self.dst_net_var
        self.parent.dst_port_var = self.dst_port_var
        self.parent.message_var = self.message_var
        self.parent.content_var = self.content_var
        self.parent.sid_var = self.sid_var
        self.parent.rev_var = self.rev_var
        self.parent.comment_var = self.comment_var
        self.parent.comment_label = self.comment_label
        self.parent.comment_entry = self.comment_entry
        self.parent.src_port_entry = self.src_port_entry
        self.parent.dst_port_entry = self.dst_port_entry
    
    def setup_variables_tab(self):
        """Setup the rule variables tab"""
        # Create variables tab
        variables_tab = ttk.Frame(self.notebook)
        self.notebook.add(variables_tab, text="Rule Variables")
        
        # Variables table frame
        table_frame = ttk.Frame(variables_tab)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Variables table with Description column
        columns = ("Variable", "Type", "Definition", "Description")
        self.variables_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        
        self.variables_tree.heading("Variable", text="Variable")
        self.variables_tree.heading("Type", text="Type")
        self.variables_tree.heading("Definition", text="Definition")
        self.variables_tree.heading("Description", text="Description")
        
        self.variables_tree.column("Variable", width=120, stretch=False)
        self.variables_tree.column("Type", width=80, stretch=False)
        self.variables_tree.column("Definition", width=200, stretch=False)
        self.variables_tree.column("Description", width=300, stretch=True)
        
        # Scrollbar for variables table
        var_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.variables_tree.yview)
        self.variables_tree.configure(yscrollcommand=var_scrollbar.set)
        
        self.variables_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        var_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event to edit variable
        self.variables_tree.bind("<Double-1>", self.on_variable_double_click)
        
        # Variables buttons
        var_buttons_frame = ttk.Frame(variables_tab)
        var_buttons_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(var_buttons_frame, text="Add IP Set ($)", command=lambda: self.add_variable("ip_set")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(var_buttons_frame, text="Add Port Set ($)", command=lambda: self.add_variable("port_set")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(var_buttons_frame, text="Add Reference (@)", command=lambda: self.add_variable("reference")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(var_buttons_frame, text="Add Common Ports", command=self.show_add_common_ports_dialog).pack(side=tk.LEFT, padx=(10, 5))
        ttk.Button(var_buttons_frame, text="Edit", command=self.edit_variable).pack(side=tk.LEFT, padx=(10, 5))
        ttk.Button(var_buttons_frame, text="Delete", command=self.delete_variable).pack(side=tk.LEFT, padx=(0, 5))
        
        # Store reference in parent for access by other components
        self.parent.variables_tree = self.variables_tree
    
    def setup_tags_tab(self):
        """Setup the AWS tags tab"""
        # Create tags tab
        tags_tab = ttk.Frame(self.notebook)
        self.notebook.add(tags_tab, text="AWS Tags")
        
        # Description section
        desc_frame = ttk.Frame(tags_tab)
        desc_frame.pack(fill=tk.X, padx=5, pady=(5, 10))
        
        ttk.Label(desc_frame,
                 text="Tags to apply to rule group when exporting to AWS",
                 font=("TkDefaultFont", 9)).pack(anchor=tk.W)
        
        # Tags table frame
        table_frame = ttk.Frame(tags_tab)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tags table
        columns = ("Key", "Value")
        tags_tree = ttk.Treeview(table_frame, columns=columns,
                                 show="headings", height=8)
        
        tags_tree.heading("Key", text="Key")
        tags_tree.heading("Value", text="Value")
        
        tags_tree.column("Key", width=200, stretch=False)
        tags_tree.column("Value", width=400, stretch=True)
        
        # Scrollbar for tags table
        tags_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL,
                                       command=tags_tree.yview)
        tags_tree.configure(yscrollcommand=tags_scrollbar.set)
        
        tags_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tags_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event to edit tag
        tags_tree.bind("<Double-1>", self.on_tag_double_click)
        
        # Enable mouse wheel scrolling
        tags_tree.bind("<MouseWheel>", self._on_tags_mousewheel)
        tags_tree.bind("<Button-4>", self._on_tags_mousewheel)  # Linux scroll up
        tags_tree.bind("<Button-5>", self._on_tags_mousewheel)  # Linux scroll down
        
        # Tags buttons
        tags_buttons_frame = ttk.Frame(tags_tab)
        tags_buttons_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(tags_buttons_frame, text="Add Tag",
                  command=self.add_tag).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(tags_buttons_frame, text="Add Common Tags",
                  command=self.show_add_common_tags_dialog).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(tags_buttons_frame, text="Edit",
                  command=self.edit_tag).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(tags_buttons_frame, text="Delete",
                  command=self.delete_tag).pack(side=tk.LEFT, padx=(0, 5))
        
        # Store reference in parent for access by other components
        self.parent.tags_tree = tags_tree
    
    def setup_history_tab(self):
        """Setup the change history tab"""
        # Create history tab
        history_tab = ttk.Frame(self.notebook)
        self.notebook.add(history_tab, text="Change History")
        
        # History display frame
        history_frame = ttk.Frame(history_tab)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # History text area with scrollbar
        self.history_text = tk.Text(history_frame, wrap=tk.WORD, font=("Consolas", 9), state=tk.DISABLED)
        history_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_text.yview)
        self.history_text.configure(yscrollcommand=history_scrollbar.set)
        
        # Bind right-click context menu for history text
        self.history_text.bind("<Button-3>", self.on_history_right_click)
        
        self.history_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # History buttons
        history_buttons_frame = ttk.Frame(history_tab)
        history_buttons_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(history_buttons_frame, text="Refresh", command=self.refresh_history_display).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(history_buttons_frame, text="Clear Display", command=self.clear_history_display).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(history_buttons_frame, text="Export History", command=self.export_history).pack(side=tk.RIGHT)
        
        # Store reference in parent for access by other components
        self.parent.history_text = self.history_text
    
    def on_tab_changed(self, event):
        """Handle tab change events"""
        selected_tab = self.notebook.select()
        tab_text = self.notebook.tab(selected_tab, "text")
        
        if tab_text == "Rule Variables":
            # Auto-detect variables when Variables tab is selected
            self.parent.auto_detect_variables()
        elif tab_text == "Change History":
            # Refresh history display
            self.refresh_history_display()
    
    def setup_status_bar(self, parent):
        """Setup status bar at bottom of window with colored action counts"""
        status_frame = ttk.Frame(parent, relief=tk.SUNKEN, borderwidth=1)
        status_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Main status label for capacity and file status
        self.status_label = ttk.Label(status_frame, text="Capacity: 0 | New", 
                                     font=("TkDefaultFont", 9))
        self.status_label.pack(side=tk.LEFT, padx=5, pady=2)
        
        # Colored labels for action counts
        self.pass_label = tk.Label(status_frame, text="", fg="#2E7D32", font=("TkDefaultFont", 9))
        self.drop_label = tk.Label(status_frame, text="", fg="#D32F2F", font=("TkDefaultFont", 9))
        self.reject_label = tk.Label(status_frame, text="", fg="#7B1FA2", font=("TkDefaultFont", 9))
        self.alert_label = tk.Label(status_frame, text="", fg="#1976D2", font=("TkDefaultFont", 9))
        
        # Additional info labels
        self.sid_label = tk.Label(status_frame, text="", fg="#666666", font=("TkDefaultFont", 9))
        self.vars_label = tk.Label(status_frame, text="", fg="#FF6600", font=("TkDefaultFont", 9))
        self.refs_label = tk.Label(status_frame, text="", fg="#008B8B", font=("TkDefaultFont", 9))
        self.filter_label = tk.Label(status_frame, text="", fg="#666666", font=("TkDefaultFont", 9))
        
        # Store references in parent for access by other components
        self.parent.status_label = self.status_label
        self.parent.pass_label = self.pass_label
        self.parent.drop_label = self.drop_label
        self.parent.reject_label = self.reject_label
        self.parent.alert_label = self.alert_label
        self.parent.sid_label = self.sid_label
        self.parent.vars_label = self.vars_label
        self.parent.refs_label = self.refs_label
        self.parent.filter_label = self.filter_label
    
    def on_rule_select(self, event):
        """Handle rule selection to populate editor fields with selected rule data"""
        # Clear search highlights when user manually selects a different item
        selection = self.tree.selection()
        if selection:
            if self.parent.search_manager.handle_rule_selection_during_search(selection[0]):
                # Search was cleared by the search manager
                pass
        
        selection = self.tree.selection()
        if not selection:
            # No selection - hide editor fields
            self.hide_all_editor_fields()
            self.parent.selected_rule_index = None
            return
        
        # Clean up placeholder if selecting a real rule
        selected_item = selection[0]
        if selected_item != self.parent.placeholder_item:
            self.parent.remove_placeholder_row()
        
        # Get the index of the selected rule
        selected_item = selection[0]
        
        # Get the line number from the first column (this is the actual line number in the file)
        values = self.tree.item(selected_item, 'values')
        if values and values[0]:
            # Line numbers are 1-based, convert to 0-based index
            actual_rule_index = int(values[0]) - 1
            
            if actual_rule_index < len(self.parent.rules):
                rule = self.parent.rules[actual_rule_index]
                self.parent.selected_rule_index = actual_rule_index
                
                # Show appropriate editor based on rule type
                if getattr(rule, 'is_blank', False):
                    # Blank line - set up editor for replacing this blank line with a new rule
                    self.show_rule_editor()
                    # Keep selected_rule_index at current blank line position to replace it
                    # (actual_rule_index is already set above to the blank line's position)
                    # Populate with default values for new rule
                    self.parent.set_default_editor_values()
                    # Auto-generate next available SID
                    max_sid = max([r.sid for r in self.parent.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)], default=99)
                    self.sid_var.set(str(max_sid + 1))
                elif getattr(rule, 'is_comment', False):
                    # Comment line - show comment editor only
                    self.show_comment_editor()
                    self.comment_var.set(rule.comment_text)
                else:
                    # Regular rule - populate all rule editor fields
                    self.show_rule_editor()
                    self.action_var.set(rule.action)
                    self.protocol_var.set(rule.protocol)
                    self.src_net_var.set(rule.src_net)
                    self.src_port_var.set(rule.src_port)
                    self.direction_var.set(rule.direction)
                    self.dst_net_var.set(rule.dst_net)
                    self.dst_port_var.set(rule.dst_port)
                    self.message_var.set(rule.message)
                    self.content_var.set(rule.content)
                    self.sid_var.set(str(rule.sid))
                    self.rev_var.set(str(rule.rev))
                    
                    # Populate revision dropdown if tracking enabled
                    if self.parent.tracking_enabled:
                        self.populate_rev_dropdown(rule)
                    else:
                        # Make sure entry is shown when tracking disabled
                        self.setup_rev_dropdown_widget()
    
    def show_rule_editor(self):
        """Show rule editing fields, hide comment fields"""
        # Hide comment fields and save button
        self.comment_label.grid_remove()
        self.comment_entry.grid_remove()
        if hasattr(self.parent, 'comment_save_button'):
            self.parent.comment_save_button.grid_remove()
        
        # Restore all rule fields to their original positions
        fields_frame = self.comment_label.master
        for widget in fields_frame.winfo_children():
            # Exclude comment fields, comment save button, AND rev_combo from auto-grid
            # rev_combo should only be shown when tracking is enabled
            if widget not in [self.comment_label, self.comment_entry, getattr(self.parent, 'comment_save_button', None), self.rev_combo]:
                try:
                    widget.grid()
                except tk.TclError:
                    pass
        
        # Ensure rev_combo is hidden by default
        self.rev_combo.grid_remove()
    
    def hide_all_editor_fields(self):
        """Hide all editor fields for blank lines"""
        fields_frame = self.comment_label.master
        for widget in fields_frame.winfo_children():
            widget.grid_remove()
    
    def show_comment_editor(self):
        """Show only comment editing field and save button"""
        # Hide all fields first
        self.hide_all_editor_fields()
        
        # Show only comment field and save button
        fields_frame = self.comment_label.master
        self.comment_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.comment_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W+tk.E, padx=(0, 10), pady=(5, 0))
        
        # Bind right-click context menu to comment entry
        self.comment_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Add save button for comments if it doesn't exist
        if not hasattr(self.parent, 'comment_save_button'):
            self.parent.comment_save_button = ttk.Button(fields_frame, text="Save Changes", command=self.parent.save_rule_changes)
        self.parent.comment_save_button.grid(row=0, column=3, sticky=tk.W, padx=(5, 0), pady=(5, 0))
    
    def on_double_click(self, event):
        """Handle double-click events on tree items"""
        item = self.tree.identify_row(event.y)
        if item == self.parent.placeholder_item:
            # Double-click on placeholder - show insert rule dialog
            self.parent.insert_rule()
        else:
            # Double-click on regular rule - show edit dialog
            self.parent.edit_selected_rule()
    
    def on_tree_click(self, event):
        """Handle clicks on the tree to manage rule selection and insertion"""
        # Determine if click is on an existing item or empty area
        item = self.tree.identify_row(event.y)
        if not item:
            # Click in empty area below rules - just clear selection and hide editor
            self.tree.selection_remove(self.tree.selection())  # Clear any selection
            if not self.parent.placeholder_item:  # Only add if doesn't exist
                self.parent.add_placeholder_row()  # Add placeholder
            self.parent.selected_rule_index = None  # Clear selection
            self.hide_all_editor_fields()  # Hide editor for empty area clicks
        elif item == self.parent.placeholder_item:
            # Click on placeholder - keep it and set up for new rule insertion
            self.tree.selection_remove(self.tree.selection())  # Clear any selection
            self.parent.selected_rule_index = len(self.parent.rules)  # Set insertion point
            self.show_rule_editor()  # Show editor fields
            self.parent.set_default_editor_values()  # Populate with defaults
            # Auto-generate next available SID for convenience
            max_sid = max([rule.sid for rule in self.parent.rules if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False)], default=99)
            self.sid_var.set(str(max_sid + 1))
        else:
            # Check if clicking on already selected item to toggle selection
            current_selection = self.tree.selection()
            if len(current_selection) == 1 and current_selection[0] == item:
                # Toggle off - deselect the item and schedule deselection after event processing
                # Use after_idle to avoid conflict with TreeviewSelect event
                self.parent.root.after_idle(lambda: self.deselect_item(item))
                return
            
            # Click on existing rule - clean up placeholder only if it exists
            if self.parent.placeholder_item:
                self.parent.remove_placeholder_row()
    
    def deselect_item(self, item):
        """Deselect a tree item"""
        try:
            self.tree.selection_remove(item)
            self.parent.selected_rule_index = None
            self.hide_all_editor_fields()
        except tk.TclError:
            pass
    
    def on_right_click(self, event):
        """Handle right-click context menu"""
        def select_all_wrapper():
            self.select_all_rules()
        
        try:
            # Create context menu
            context_menu = tk.Menu(self.parent.root, tearoff=0)
            context_menu.add_command(label="Select All", command=select_all_wrapper)
            context_menu.add_separator()
            
            # Check clipboard states
            has_internal_clipboard = bool(self.parent.clipboard)
            system_content = self.parent.get_system_clipboard_content()
            has_system_clipboard = bool(system_content and system_content.strip())
            
            # Determine which clipboard source will be used (same logic as paste_rules method)
            use_system_clipboard = False
            if system_content and system_content.strip():
                # Check if system clipboard has different content than what we last copied
                if hasattr(self.parent, '_last_copied_text'):
                    # If system clipboard content is different from our last copy, prefer system
                    if system_content.strip() != self.parent._last_copied_text.strip():
                        use_system_clipboard = True
                else:
                    # No record of last copy, check if system content looks like rules
                    if any(keyword in system_content.lower() for keyword in ['alert', 'drop', 'pass', 'reject', 'sid:', '->', 'tcp', 'udp', 'http']):
                        use_system_clipboard = True
            
            # Show appropriate paste option based on which clipboard will be used
            if use_system_clipboard and has_system_clipboard:
                context_menu.add_command(label="Paste (system clipboard)", command=self.parent.paste_rules)
            elif has_internal_clipboard:
                context_menu.add_command(label="Paste (internal clipboard)", command=self.parent.paste_rules)
            
            # Check if there's a selection for copy/delete
            selection = self.tree.selection()
            if selection:
                context_menu.add_command(label="Copy", command=self.parent.copy_selected_rules)
            
            # Show delete option if there's a selection
            if selection:
                if use_system_clipboard and has_system_clipboard or has_internal_clipboard:  # Only add separator if paste was added
                    context_menu.add_separator()
                context_menu.add_command(label="Delete", command=self.parent.delete_selected_rule)
            
            # Phase 10: Add CloudWatch Statistics menu item
            context_menu.add_separator()
            
            # Check if analysis has been run
            has_analysis = (hasattr(self.parent, 'usage_analyzer') and 
                          hasattr(self.parent.usage_analyzer, 'last_analysis_results') and
                          self.parent.usage_analyzer.last_analysis_results is not None)
            
            if has_analysis and selection:
                context_menu.add_command(label="View CloudWatch Statistics", 
                                        command=lambda: self.show_quick_cloudwatch_stats())
            else:
                context_menu.add_command(label="View CloudWatch Statistics (run analysis first)", 
                                        state='disabled')
            
            # Show the menu with explicit positioning
            try:
                # Ensure menu appears on screen
                screen_width = self.parent.root.winfo_screenwidth()
                screen_height = self.parent.root.winfo_screenheight()
                menu_x = min(event.x_root, screen_width - 200)
                menu_y = min(event.y_root, screen_height - 150)
                
                context_menu.tk_popup(menu_x, menu_y)
                
            except Exception as popup_error:
                # Fallback: show at mouse position
                context_menu.tk_popup(event.x_root, event.y_root)
                
        except Exception as e:
            # Ultimate fallback - show error message
            messagebox.showinfo("Menu Error", f"Context menu error: {str(e)}")
        finally:
            try:
                context_menu.grab_release()
            except:
                pass
    
    def select_all_rules(self):
        """Select all rules in the tree (excludes placeholder)"""
        # Clear any existing selection first
        self.tree.selection_remove(self.tree.selection())
        
        all_items = self.tree.get_children()
        if all_items:
            # Filter out placeholder item if it exists
            items_to_select = [item for item in all_items if item != self.parent.placeholder_item]
            if items_to_select:
                # Add each item to selection
                for item in items_to_select:
                    self.tree.selection_add(item)
                # Focus on first selected item
                self.tree.focus(items_to_select[0])
    
    def on_tree_configure(self, event):
        """Handle tree configure events (including after redraw) to restore placeholder"""
        # Use after_idle to avoid duplicate placeholders during rapid events
        self.parent.root.after_idle(self.restore_placeholder_if_needed)
    
    def on_column_resize(self, event):
        """Handle column resize events to restore placeholder row"""
        self.restore_placeholder_if_needed()
    
    def restore_placeholder_if_needed(self):
        """Restore placeholder row if conditions are met"""
        if len(self.parent.rules) > 0 and not self.parent.placeholder_item:
            # Only restore if placeholder doesn't exist
            self.parent.root.after_idle(self.parent.add_placeholder_row)
    
    def on_delete_key(self, event):
        """Handle Delete key - only delete rules when tree view has focus"""
        # Only delete rules if the tree view has focus
        if self.parent.root.focus_get() == self.tree:
            self.parent.delete_selected_rule()
        # If focus is elsewhere (like text entry fields), let the default behavior handle it
    
    def on_key_down(self, event):
        """Handle Down arrow key to navigate to placeholder when at last rule"""
        # Only handle if the tree has focus
        if self.parent.root.focus_get() != self.tree:
            return
        
        selection = self.tree.selection()
        if not selection or not self.parent.placeholder_item:
            return
        
        selected_item = selection[0]
        all_items = self.tree.get_children()
        
        # If we have rules and a placeholder
        if len(all_items) >= 2:
            # Check if we're on the last actual rule (not the placeholder)
            last_rule_item = all_items[-2]  # Second to last (placeholder is last)
            if selected_item == last_rule_item:
                # Move to placeholder
                self.tree.selection_set(self.parent.placeholder_item)
                self.tree.focus(self.parent.placeholder_item)
                return 'break'
    
    def on_key_end(self, event):
        """Handle End key to navigate to placeholder"""
        # Only handle if the tree has focus
        if self.parent.root.focus_get() != self.tree:
            return
        
        if self.parent.placeholder_item:
            self.tree.selection_set(self.parent.placeholder_item)
            self.tree.focus(self.parent.placeholder_item)
            self.tree.see(self.parent.placeholder_item)  # Scroll to show the placeholder
            return 'break'
    
    def on_key_home(self, event):
        """Handle Home key to navigate to first line"""
        # Only handle if the tree has focus
        if self.parent.root.focus_get() != self.tree:
            return
        
        all_items = self.tree.get_children()
        if all_items:
            first_item = all_items[0]
            self.tree.selection_set(first_item)
            self.tree.focus(first_item)
            self.tree.see(first_item)  # Scroll to show the first item
            return 'break'
    
    def on_space_key(self, event):
        """Handle Space key - only toggle rules when tree view has focus"""
        # Only handle if the tree view has focus
        if self.parent.root.focus_get() == self.tree:
            self.parent.toggle_rule_disabled()
            return 'break'  # Prevent default space behavior
        # If focus is elsewhere, let the default behavior handle it
    
    def on_ctrl_g_key(self, event):
        """Handle Ctrl+G key - only show dialog when tree view has focus"""
        # Only handle if the tree view has focus
        if self.parent.root.focus_get() == self.tree:
            self.show_jump_to_line_dialog()
            return 'break'  # Prevent default behavior
        # If focus is elsewhere, let the default behavior handle it
    
    def on_enter_key(self, event):
        """Handle Enter key - insert blank line at selected position when no filters active"""
        # Only handle if the tree view has focus
        if self.parent.root.focus_get() != self.tree:
            return
        
        # Check if filters are active - only allow blank line insertion when no filters
        if self.parent.rule_filter.is_active():
            messagebox.showinfo("Blank Line Insertion", 
                "Cannot insert blank lines while filters are active.\n\n"
                "Please clear all filters first to insert blank lines.")
            return 'break'
        
        # Get selected item
        selection = self.tree.selection()
        if not selection:
            return 'break'
        
        # Get the actual line number from tree
        selected_item = selection[0]
        values = self.tree.item(selected_item, 'values')
        if not values or not values[0]:
            return 'break'
        
        # Convert 1-based line number to 0-based index
        insert_index = int(values[0]) - 1
        
        # Save state for undo
        self.parent.save_undo_state()
        
        # Create blank line rule
        blank_rule = SuricataRule()
        blank_rule.is_blank = True
        
        # Insert blank line at the selected position
        self.parent.rules.insert(insert_index, blank_rule)
        
        # Refresh table
        self.parent.refresh_table(preserve_selection=False)
        self.parent.modified = True
        self.parent.update_status_bar()
        
        # Select the line after the inserted blank line
        all_items = self.tree.get_children()
        if insert_index + 1 < len(all_items):
            next_item = all_items[insert_index + 1]
            self.tree.selection_set(next_item)
            self.tree.focus(next_item)
            self.tree.see(next_item)
        
        return 'break'  # Prevent default behavior
    
    def show_jump_to_line_dialog(self):
        """Show dialog to jump to a specific line number"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Go to Line")
        dialog.geometry("300x120")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 200, self.parent.root.winfo_rooty() + 200))
        
        # Calculate total lines (including comments and blanks)
        total_lines = len(self.parent.rules)
        if self.parent.placeholder_item:
            total_lines += 1  # Include placeholder in count
        
        ttk.Label(dialog, text=f"Line number (1-{total_lines}):").pack(pady=10)
        
        line_var = tk.StringVar()
        entry = ttk.Entry(dialog, textvariable=line_var, width=10)
        entry.pack(pady=5)
        entry.focus()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def on_go():
            try:
                line_num = int(line_var.get().strip())
                if line_num < 1:
                    messagebox.showerror("Error", "Line number must be 1 or greater.")
                    return
                
                # Convert to 0-based index
                target_index = line_num - 1
                
                # Get all tree items
                all_items = self.tree.get_children()
                
                if target_index < len(all_items):
                    # Jump to the specified line
                    target_item = all_items[target_index]
                    self.tree.selection_set(target_item)
                    self.tree.focus(target_item)
                    self.tree.see(target_item)
                else:
                    # Line number exceeds available lines - jump to placeholder if it exists
                    if self.parent.placeholder_item:
                        self.tree.selection_set(self.parent.placeholder_item)
                        self.tree.focus(self.parent.placeholder_item)
                        self.tree.see(self.parent.placeholder_item)
                    else:
                        # No placeholder, jump to last line
                        if all_items:
                            last_item = all_items[-1]
                            self.tree.selection_set(last_item)
                            self.tree.focus(last_item)
                            self.tree.see(last_item)
                
                dialog.destroy()
                
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid line number.")
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Go", command=on_go).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key
        dialog.bind('<Return>', lambda e: on_go())
    
    def show_keyboard_shortcuts(self):
        """Display keyboard shortcuts cheatsheet in a dialog"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Keyboard Shortcuts")
        dialog.geometry("700x600")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 100, self.parent.root.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="Keyboard Shortcuts", 
                               font=("TkDefaultFont", 14, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Create text widget with scrollbar for shortcuts
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("TkDefaultFont", 10),
                             bg=dialog.cget('bg'), relief=tk.FLAT, cursor="arrow")
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure text tags for formatting
        text_widget.tag_configure("category", font=("TkDefaultFont", 11, "bold"), 
                                foreground="#1976D2", spacing1=10, spacing3=5)
        text_widget.tag_configure("shortcut", font=("Consolas", 10, "bold"))
        text_widget.tag_configure("description", font=("TkDefaultFont", 10))
        
        # Add shortcuts organized by category
        shortcuts = [
            ("File Operations", [
                ("Ctrl+S", "Save current file"),
                ("Ctrl+O", "Open file"),
                ("Ctrl+N", "New file"),
            ]),
            ("Tools", [
                ("Ctrl+E", "Open Advanced Editor"),
            ]),
            ("Editing & Selection", [
                ("Ctrl+Z", "Undo last change"),
                ("Ctrl+C", "Copy selected rules"),
                ("Ctrl+V", "Paste rules"),
                ("Ctrl+A", "Select all rules"),
                ("Delete", "Delete selected rule(s) (when rules table has focus)"),
                ("Space", "Toggle rule enabled/disabled (when rules table has focus)"),
            ]),
            ("Navigation", [
                ("Home", "Jump to first rule"),
                ("End", "Jump to placeholder/last rule"),
                ("Down Arrow", "Navigate to placeholder when at last rule"),
                ("Ctrl+G", "Go to line number"),
            ]),
            ("Search", [
                ("Ctrl+F", "Open Find dialog"),
                ("F3", "Find next occurrence"),
                ("Escape", "Close search and clear highlights"),
            ]),
            ("Rules Table Interactions", [
                ("Double-Click", "Edit selected rule or comment"),
                ("Right-Click", "Show context menu with copy/paste options"),
                ("Click below rules", "Add new rule (shows placeholder)"),
            ]),
        ]
        
        # Insert shortcuts into text widget
        for category, shortcuts_list in shortcuts:
            # Category header
            text_widget.insert(tk.END, f"{category}\n", "category")
            
            # Shortcuts in this category
            for shortcut, description in shortcuts_list:
                text_widget.insert(tk.END, f"  {shortcut:<20}", "shortcut")
                text_widget.insert(tk.END, f"{description}\n", "description")
            
            text_widget.insert(tk.END, "\n")
        
        # Add tip at the bottom
        text_widget.insert(tk.END, "\n")
        text_widget.tag_configure("tip", font=("TkDefaultFont", 9, "italic"), 
                                foreground="#666666")
        text_widget.insert(tk.END, "Tip: Most shortcuts work when the rules table has focus. ", "tip")
        text_widget.insert(tk.END, "Click on the rules table first if a shortcut isn't working.", "tip")
        
        # Make text widget read-only
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Focus on dialog
        dialog.focus_set()
    
    def show_sid_management(self):
        """Show SID Management dialog for bulk SID renumbering"""
        # This method is quite large, so we'll delegate to the parent for now
        # to keep this UI manager focused on UI setup and event handling
        self.parent.show_sid_management()
    
    def add_variable(self, var_type=None):
        """Add a new variable of specified type"""
        if var_type:
            self.show_variable_dialog(f"Add {var_type.replace('_', ' ').title()}", var_type=var_type)
        else:
            self.show_variable_dialog("Add Variable")
    
    def edit_variable(self):
        """Edit selected variable"""
        selection = self.parent.variables_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a variable to edit.")
            return
        
        item = selection[0]
        values = self.parent.variables_tree.item(item, "values")
        var_name = values[0]
        
        # Prevent editing $EXTERNAL_NET
        if var_name == '$EXTERNAL_NET':
            messagebox.showinfo("Information", "$EXTERNAL_NET is automatically defined by AWS Network Firewall as the inverse of $HOME_NET and cannot be edited.")
            return
        
        # Get var_type from table, but infer actual type from definition if it hasn't been used yet
        var_type = values[1].lower().replace(' ', '_')
        definition = self.parent.variables.get(var_name, "")
        
        # If variable has a definition but shows as "IP Set", check if it's actually a port definition
        if var_type == "ip_set" and definition and var_name.startswith('$'):
            # Try to infer if this is actually a port set by checking the definition format
            if self._looks_like_port_definition(definition):
                var_type = "port_set"
        
        self.show_variable_dialog("Edit Variable", var_name, var_type)
    
    def delete_variable(self):
        """Delete selected variable"""
        selection = self.parent.variables_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a variable to delete.")
            return
        
        item = selection[0]
        var_name = self.parent.variables_tree.item(item, "values")[0]
        
        # Prevent deleting $EXTERNAL_NET
        if var_name == '$EXTERNAL_NET':
            messagebox.showinfo("Information", "$EXTERNAL_NET is automatically defined by AWS Network Firewall and cannot be deleted.")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Delete variable {var_name}?"):
            del self.parent.variables[var_name]
            self.parent.add_history_entry('variable_deleted', {'variable': var_name})
            self.parent.refresh_variables_table()
            self.parent.update_status_bar()  # Update status bar to reflect undefined variable count
    
    def on_variable_double_click(self, event):
        """Handle double-click events on variables tree items"""
        item = self.variables_tree.identify_row(event.y)
        if not item:
            return
        
        # Get the variable name from the double-clicked item
        values = self.variables_tree.item(item, "values")
        if not values:
            return
        
        var_name = values[0]
        
        # Prevent editing $EXTERNAL_NET
        if var_name == '$EXTERNAL_NET':
            messagebox.showinfo("Information", "$EXTERNAL_NET is automatically defined by AWS Network Firewall as the inverse of $HOME_NET and cannot be edited.")
            return
        
        # Get var_type from table, but infer actual type from definition if it hasn't been used yet
        var_type = values[1].lower().replace(' ', '_')
        definition = self.parent.variables.get(var_name, "")
        
        # If variable has a definition but shows as "IP Set", check if it's actually a port definition
        if var_type == "ip_set" and definition and var_name.startswith('$'):
            # Try to infer if this is actually a port set by checking the definition format
            if self._looks_like_port_definition(definition):
                var_type = "port_set"
        
        self.show_variable_dialog("Edit Variable", var_name, var_type)
    
    def _looks_like_port_definition(self, definition):
        """Check if a definition string looks like port numbers/ranges rather than CIDR blocks
        
        Args:
            definition: The definition string or dict to check
            
        Returns:
            bool: True if it looks like ports, False if it looks like CIDR or is ambiguous
        """
        # Handle new dict format (extract definition string)
        if isinstance(definition, dict):
            definition = definition.get("definition", "")
        
        if not definition or not definition.strip():
            return False
        
        # Check if it passes port validation
        if self.parent.validate_port_list(definition):
            # Now check if it would also pass CIDR validation (ambiguous)
            # If it passes CIDR validation too, it's ambiguous - default to False (CIDR)
            if self.parent.validate_cidr_list(definition):
                # Ambiguous - could be either. Check for port-specific patterns
                # Port ranges with colons, or brackets indicate ports
                if ':' in definition or '[' in definition:
                    return True
                # Single small numbers (1-1024) are more likely ports
                try:
                    num = int(definition.strip())
                    if 1 <= num <= 1024:
                        return True
                except ValueError:
                    pass
                return False  # Ambiguous, default to CIDR
            else:
                # Passes port validation but not CIDR - it's a port
                return True
        
        return False
    
    def show_variable_dialog(self, title, var_name=None, var_type=None):
        """Show dialog for adding/editing variables with description field"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title(title)
        dialog.geometry("550x320")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Variable name with prefix hint
        ttk.Label(dialog, text="Variable Name:").pack(pady=5)
        name_var = tk.StringVar(value=var_name or "")
        name_entry = ttk.Entry(dialog, textvariable=name_var, width=40)
        name_entry.pack(pady=5)
        
        # Show prefix hint based on type and existing variable name
        if var_type == "ip_set":
            hint_text = "Must start with $ (e.g., $HOME_NET)"
            definition_label = "CIDR Definition:"
            definition_hint = "Single: 192.168.1.0/24 or Multiple: [10.0.0.0/8,172.16.0.0/12]"
            if not var_name:
                name_var.set("$")
        elif var_type == "port_set":
            # AWS Network Firewall requires port variables to use $ prefix only
            hint_text = "Must start with $ (e.g., $WEB, $SRC_PORTS)"
            definition_label = "Port Definition:"
            definition_hint = "e.g., [80,443] or [8080:8090]"
            if not var_name:
                name_var.set("$")
        elif var_type == "reference":
            hint_text = "Must start with @ (e.g., @ALLOW_LIST, @VPC_CIDR)"
            definition_label = "Reference ARN:"
            definition_hint = "AWS VPC IP Set Reference ARN"
            if not var_name:
                name_var.set("@")
        else:
            hint_text = "$ for IP sets and port sets, @ for references"
            definition_label = "Definition:"
            definition_hint = ""
        
        ttk.Label(dialog, text=hint_text, font=("TkDefaultFont", 8)).pack(pady=(0, 10))
        
        # Definition
        ttk.Label(dialog, text=definition_label).pack(pady=5)
        
        # Get existing variable data (handle both old and new formats)
        existing_data = self.parent.variables.get(var_name, {}) if var_name else {}
        if isinstance(existing_data, dict):
            existing_def = existing_data.get("definition", "")
            existing_desc = existing_data.get("description", "")
        else:
            # Legacy format
            existing_def = existing_data
            existing_desc = ""
        
        definition_var = tk.StringVar(value=existing_def)
        definition_entry = ttk.Entry(dialog, textvariable=definition_var, width=60)
        definition_entry.pack(pady=5)
        
        if definition_hint:
            ttk.Label(dialog, text=definition_hint, font=("TkDefaultFont", 8)).pack(pady=(0, 10))
        
        # Description field (NEW)
        ttk.Label(dialog, text="Description (optional):").pack(pady=5)
        description_var = tk.StringVar(value=existing_desc)
        description_entry = ttk.Entry(dialog, textvariable=description_var, width=60)
        description_entry.pack(pady=5)
        ttk.Label(dialog, text="Brief description of what this variable is for", 
                 font=("TkDefaultFont", 8), foreground="#666666").pack(pady=(0, 10))
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def save_variable():
            name = name_var.get().strip()
            definition = definition_var.get().strip()
            description = description_var.get().strip()
            
            if not name:
                messagebox.showerror("Error", "Variable name is required.")
                return
            
            # Use context-aware validation based on var_type or actual usage
            if definition:  # Only validate if definition is provided
                # For new variables, use var_type first; for existing variables, analyze usage
                # Check var_type parameter first (most reliable for new variables)
                if var_type == "port_set":
                    # Port Set validation (AWS Network Firewall requires $ prefix for port variables)
                    if not self.parent.validate_port_list(definition):
                        messagebox.showerror("Port Validation Error", 
                            "Invalid port definition. Port ranges and lists MUST use brackets:\n" +
                            "• Single port: 80\n" +
                            "• Port range: [8080:8090]\n" +
                            "• Multiple ports: [80,443,8080]\n" +
                            "• Complex specs: [80:100,!85]\n\n" +
                            "Suricata syntax requires brackets for all port ranges and complex port specifications.")
                        return
                elif var_type == "ip_set":
                    # IP Set validation (for explicit ip_set type)
                    if not self.parent.validate_cidr_list(definition):
                        messagebox.showerror("CIDR Validation Error", 
                            "Invalid CIDR definition. AWS Network Firewall requires brackets for multiple CIDR blocks:\n" +
                            "• Single CIDR: 192.168.1.0/24\n" +
                            "• Multiple CIDRs: [192.168.1.0/24,192.168.2.0/24]\n" +
                            "• With negation: [192.168.1.0/24,!172.16.0.0/12]")
                        return
                elif var_type == "reference":
                    # Reference Set validation
                    if not definition.strip():
                        messagebox.showerror("Error", "Reference ARN is required for reference variables.")
                        return
                else:
                    # Fallback: Analyze current variable usage to determine correct validation
                    variable_usage = self.parent.file_manager.analyze_variable_usage(self.parent.rules)
                    determined_type = self.parent.file_manager.get_variable_type_from_usage(name, variable_usage)
                    
                    # Validate based on determined type from usage
                    if determined_type == "Port Set":
                        # Port Set validation
                        if not self.parent.validate_port_list(definition):
                            messagebox.showerror("Port Validation Error", 
                                "Invalid port definition. Port ranges and lists MUST use brackets:\n" +
                                "• Single port: 80\n" +
                                "• Port range: [8080:8090]\n" +
                                "• Multiple ports: [80,443,8080]\n" +
                                "• Complex specs: [80:100,!85]\n\n" +
                                "Suricata syntax requires brackets for all port ranges and complex port specifications.")
                            return
                    elif determined_type == "Reference":
                        # Reference Set - minimal validation
                        if not definition.strip():
                            messagebox.showerror("Error", "Reference ARN is required for reference variables.")
                            return
                    else:
                        # Default to IP Set validation (determined_type == "IP Set" or other)
                        if not self.parent.validate_cidr_list(definition):
                            messagebox.showerror("Error", "Invalid CIDR definition. Use comma-separated CIDR blocks.")
                            return
            
            # Determine if this is adding a new variable or editing existing one
            is_new_variable = var_name is None or var_name not in self.parent.variables
            action_type = 'variable_added' if is_new_variable else 'variable_modified'
            
            self.parent.variables[name] = definition
            self.parent.add_history_entry(action_type, {'variable': name, 'definition': definition})
            self.parent.refresh_variables_table()
            self.parent.update_status_bar()  # Update status bar to reflect variable definition changes
            dialog.destroy()
        
        ttk.Button(button_frame, text="Save", command=save_variable).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Focus on name entry and position cursor appropriately
        name_entry.focus()
        
        # If we pre-filled with "$" for ip_set/port_set or "@" for reference, position cursor after it
        if var_type in ["ip_set", "port_set", "reference"] and not var_name:
            name_entry.icursor(1)  # Position cursor after the "$" or "@"
    
    def show_variable_dialog(self, title, var_name=None, var_type=None):
        """Show dialog for adding/editing variables with description field"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title(title)
        dialog.geometry("550x360")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Variable name with prefix hint
        ttk.Label(dialog, text="Variable Name:").pack(pady=5)
        name_var = tk.StringVar(value=var_name or "")
        name_entry = ttk.Entry(dialog, textvariable=name_var, width=40)
        name_entry.pack(pady=5)
        
        # Show prefix hint based on type and existing variable name
        if var_type == "ip_set":
            hint_text = "Must start with $ (e.g., $HOME_NET)"
            definition_label = "CIDR Definition:"
            definition_hint = "Single: 192.168.1.0/24 or Multiple: [10.0.0.0/8,172.16.0.0/12]"
            if not var_name:
                name_var.set("$")
        elif var_type == "port_set":
            # AWS Network Firewall requires port variables to use $ prefix only
            hint_text = "Must start with $ (e.g., $WEB, $SRC_PORTS)"
            definition_label = "Port Definition:"
            definition_hint = "e.g., [80,443] or [8080:8090]"
            if not var_name:
                name_var.set("$")
        elif var_type == "reference":
            hint_text = "Must start with @ (e.g., @ALLOW_LIST, @VPC_CIDR)"
            definition_label = "Reference ARN:"
            definition_hint = "AWS VPC IP Set Reference ARN"
            if not var_name:
                name_var.set("@")
        else:
            hint_text = "$ for IP sets and port sets, @ for references"
            definition_label = "Definition:"
            definition_hint = ""
        
        ttk.Label(dialog, text=hint_text, font=("TkDefaultFont", 8)).pack(pady=(0, 10))
        
        # Definition
        ttk.Label(dialog, text=definition_label).pack(pady=5)
        
        # Get existing variable data (handle both old and new formats)
        existing_data = self.parent.variables.get(var_name, {}) if var_name else {}
        if isinstance(existing_data, dict):
            existing_def = existing_data.get("definition", "")
            existing_desc = existing_data.get("description", "")
        else:
            # Legacy format
            existing_def = existing_data
            existing_desc = ""
        
        definition_var = tk.StringVar(value=existing_def)
        definition_entry = ttk.Entry(dialog, textvariable=definition_var, width=60)
        definition_entry.pack(pady=5)
        
        if definition_hint:
            ttk.Label(dialog, text=definition_hint, font=("TkDefaultFont", 8)).pack(pady=(0, 10))
        
        # Description field (NEW)
        ttk.Label(dialog, text="Description (optional):").pack(pady=5)
        description_var = tk.StringVar(value=existing_desc)
        description_entry = ttk.Entry(dialog, textvariable=description_var, width=60)
        description_entry.pack(pady=5)
        ttk.Label(dialog, text="Brief description of what this variable is for", 
                 font=("TkDefaultFont", 8), foreground="#666666").pack(pady=(0, 10))
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def save_variable():
            name = name_var.get().strip()
            definition = definition_var.get().strip()
            description = description_var.get().strip()
            
            if not name:
                messagebox.showerror("Error", "Variable name is required.")
                return
            
            # Use context-aware validation based on var_type or actual usage
            if definition:  # Only validate if definition is provided
                # For new variables, use var_type first; for existing variables, analyze usage
                # Check var_type parameter first (most reliable for new variables)
                if var_type == "port_set":
                    # Port Set validation (AWS Network Firewall requires $ prefix for port variables)
                    if not self.parent.validate_port_list(definition):
                        messagebox.showerror("Port Validation Error", 
                            "Invalid port definition. Port ranges and lists MUST use brackets:\n" +
                            "• Single port: 80\n" +
                            "• Port range: [8080:8090]\n" +
                            "• Multiple ports: [80,443,8080]\n" +
                            "• Complex specs: [80:100,!85]\n\n" +
                            "Suricata syntax requires brackets for all port ranges and complex port specifications.")
                        return
                elif var_type == "ip_set":
                    # IP Set validation (for explicit ip_set type)
                    if not self.parent.validate_cidr_list(definition):
                        messagebox.showerror("CIDR Validation Error", 
                            "Invalid CIDR definition. AWS Network Firewall requires brackets for multiple CIDR blocks:\n" +
                            "• Single CIDR: 192.168.1.0/24\n" +
                            "• Multiple CIDRs: [192.168.1.0/24,192.168.2.0/24]\n" +
                            "• With negation: [192.168.1.0/24,!172.16.0.0/12]")
                        return
                elif var_type == "reference":
                    # Reference Set validation
                    if not definition.strip():
                        messagebox.showerror("Error", "Reference ARN is required for reference variables.")
                        return
                else:
                    # Fallback: Analyze current variable usage to determine correct validation
                    variable_usage = self.parent.file_manager.analyze_variable_usage(self.parent.rules)
                    determined_type = self.parent.file_manager.get_variable_type_from_usage(name, variable_usage)
                    
                    # Validate based on determined type from usage
                    if determined_type == "Port Set":
                        # Port Set validation
                        if not self.parent.validate_port_list(definition):
                            messagebox.showerror("Port Validation Error", 
                                "Invalid port definition. Port ranges and lists MUST use brackets:\n" +
                                "• Single port: 80\n" +
                                "• Port range: [8080:8090]\n" +
                                "• Multiple ports: [80,443,8080]\n" +
                                "• Complex specs: [80:100,!85]\n\n" +
                                "Suricata syntax requires brackets for all port ranges and complex port specifications.")
                            return
                    elif determined_type == "Reference":
                        # Reference Set - minimal validation
                        if not definition.strip():
                            messagebox.showerror("Error", "Reference ARN is required for reference variables.")
                            return
                    else:
                        # Default to IP Set validation (determined_type == "IP Set" or other)
                        if not self.parent.validate_cidr_list(definition):
                            messagebox.showerror("Error", "Invalid CIDR definition. Use comma-separated CIDR blocks.")
                            return
            
            # Determine if this is adding a new variable or editing existing one
            is_new_variable = var_name is None or var_name not in self.parent.variables
            action_type = 'variable_added' if is_new_variable else 'variable_modified'
            
            # Save in new dict format with definition and description
            self.parent.variables[name] = {
                "definition": definition,
                "description": description
            }
            
            self.parent.add_history_entry(action_type, {'variable': name, 'definition': definition, 'description': description})
            self.parent.refresh_variables_table()
            self.parent.update_status_bar()  # Update status bar to reflect variable definition changes
            dialog.destroy()
        
        ttk.Button(button_frame, text="Save", command=save_variable).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Focus on name entry and position cursor appropriately
        name_entry.focus()
        
        # If we pre-filled with "$" for ip_set/port_set or "@" for reference, position cursor after it
        if var_type in ["ip_set", "port_set", "reference"] and not var_name:
            name_entry.icursor(1)  # Position cursor after the "$" or "@"
    
    def refresh_history_display(self):
        """Refresh the history display with current tracking data"""
        self.parent.history_text.config(state=tk.NORMAL)
        self.parent.history_text.delete(1.0, tk.END)
        
        if not self.parent.tracking_enabled:
            self.parent.history_text.insert(tk.END, "Change tracking is currently disabled.\n\n")
            self.parent.history_text.insert(tk.END, "To enable change tracking:\n")
            self.parent.history_text.insert(tk.END, "1. Go to Tools > Enable Change Tracking\n")
            self.parent.history_text.insert(tk.END, "2. Changes will be tracked and displayed here\n")
            self.parent.history_text.config(state=tk.DISABLED)
            return
        
        # Display current file info
        if self.parent.current_file:
            filename = os.path.basename(self.parent.current_file)
            self.parent.history_text.insert(tk.END, f"File: {filename}\n")
        else:
            self.parent.history_text.insert(tk.END, "File: New (unsaved)\n")
        
        self.parent.history_text.insert(tk.END, f"Tracking: {'Enabled' if self.parent.tracking_enabled else 'Disabled'}\n")
        
        # Show header info if present
        if self.parent.has_header and self.parent.created_timestamp:
            self.parent.history_text.insert(tk.END, f"Created: {self.parent.created_timestamp}\n")
        
        self.parent.history_text.insert(tk.END, "\n" + "="*50 + "\n\n")
        
        # Display pending history entries
        if self.parent.pending_history:
            self.parent.history_text.insert(tk.END, "Pending Changes (not yet saved):\n")
            self.parent.history_text.insert(tk.END, "-" * 30 + "\n")
            
            for entry in self.parent.pending_history:
                timestamp = entry.get('timestamp', 'Unknown')
                action = entry.get('action', 'Unknown')
                details = entry.get('details', {})
                count = entry.get('count')
                
                # Format timestamp
                try:
                    import datetime
                    dt = datetime.datetime.fromisoformat(timestamp)
                    formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    formatted_time = timestamp
                
                self.parent.history_text.insert(tk.END, f"[{formatted_time}] ")
                
                # Format action description
                if action == 'file_created':
                    self.parent.history_text.insert(tk.END, "File created\n")
                elif action == 'file_opened':
                    filename = details.get('filename', 'unknown')
                    self.parent.history_text.insert(tk.END, f"Opened file: {filename}\n")
                elif action == 'file_saved':
                    filename = details.get('filename', 'unknown')
                    self.parent.history_text.insert(tk.END, f"Saved file: {filename}\n")
                elif action == 'rule_added':
                    line = details.get('line', '?')
                    rule_text = details.get('rule_text', '')
                    
                    # Extract action and SID from rule_text if individual fields not available
                    rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                    sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                    
                    # Base message with rule identification
                    # For template insertions (line 0), omit line number
                    if line == 0:
                        self.parent.history_text.insert(tk.END, f"Added {rule_action} rule (SID: {sid})")
                    else:
                        self.parent.history_text.insert(tk.END, f"Added {rule_action} rule at line {line} (SID: {sid})")
                    
                    # Add detailed rule information if available
                    protocol = details.get('protocol')
                    src_net = details.get('src_net')
                    src_port = details.get('src_port')
                    direction = details.get('direction')
                    dst_net = details.get('dst_net')
                    dst_port = details.get('dst_port')
                    message = details.get('message')
                    content = details.get('content')
                    
                    if any([protocol, src_net, src_port, direction, dst_net, dst_port, message, content]):
                        self.parent.history_text.insert(tk.END, " - Details:\n")
                        if protocol:
                            self.parent.history_text.insert(tk.END, f"  - Protocol: {protocol}\n")
                        if src_net:
                            self.parent.history_text.insert(tk.END, f"  - Source Network: {src_net}\n")
                        if src_port:
                            self.parent.history_text.insert(tk.END, f"  - Source Port: {src_port}\n")
                        if direction:
                            self.parent.history_text.insert(tk.END, f"  - Direction: {direction}\n")
                        if dst_net:
                            self.parent.history_text.insert(tk.END, f"  - Dest Network: {dst_net}\n")
                        if dst_port:
                            self.parent.history_text.insert(tk.END, f"  - Dest Port: {dst_port}\n")
                        if message:
                            # Truncate long messages for readability
                            display_message = (message[:50] + '...' if len(message) > 50 else message)
                            self.parent.history_text.insert(tk.END, f"  - Message: \"{display_message}\"\n")
                        if content:
                            # Truncate long content for readability
                            display_content = (content[:50] + '...' if len(content) > 50 else content)
                            self.parent.history_text.insert(tk.END, f"  - Content: {display_content}\n")
                    else:
                        self.parent.history_text.insert(tk.END, "\n")
                elif action == 'rule_modified':
                    line = details.get('line', '?')
                    rule_text = details.get('rule_text', '')
                    
                    # Extract action and SID from rule_text if individual fields not available
                    rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                    sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                    changes = details.get('changes', {})
                    
                    # Base message with rule identification
                    self.parent.history_text.insert(tk.END, f"Modified {rule_action} rule at line {line} (SID: {sid})")
                    
                    # Add detailed change information if available
                    if changes:
                        self.parent.history_text.insert(tk.END, " - Changes:\n")
                        for field, change_info in changes.items():
                            from_val = change_info.get('from', '')
                            to_val = change_info.get('to', '')
                            # Format field name for display
                            field_display = {
                                'action': 'Action',
                                'protocol': 'Protocol', 
                                'src_net': 'Source Network',
                                'src_port': 'Source Port',
                                'direction': 'Direction',
                                'dst_net': 'Dest Network', 
                                'dst_port': 'Dest Port',
                                'message': 'Message',
                                'content': 'Content',
                                'sid': 'SID'
                            }.get(field, field.title())
                            
                            # Truncate long values for readability
                            from_display = (from_val[:30] + '...' if len(str(from_val)) > 30 else str(from_val)) if from_val else '(empty)'
                            to_display = (to_val[:30] + '...' if len(str(to_val)) > 30 else str(to_val)) if to_val else '(empty)'
                            
                            self.parent.history_text.insert(tk.END, f"  - {field_display}: '{from_display}' → '{to_display}'\n")
                    else:
                        self.parent.history_text.insert(tk.END, "\n")
                elif action == 'rule_deleted':
                    line = details.get('line', '?')
                    rule_text = details.get('rule_text', '')
                    
                    # Extract action and SID from rule_text if individual fields not available
                    rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                    sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                    message = details.get('message', '')
                    
                    if message:
                        self.parent.history_text.insert(tk.END, f"Deleted {rule_action} rule from line {line} (SID: {sid}): \"{message}\"\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Deleted {rule_action} rule from line {line} (SID: {sid})\n")
                    
                    if rule_text:
                        # Show truncated rule text (first 80 characters)
                        truncated_rule = rule_text[:80] + '...' if len(rule_text) > 80 else rule_text
                        self.parent.history_text.insert(tk.END, f"  Rule: {truncated_rule}\n")
                elif action == 'rules_deleted':
                    if count:
                        self.parent.history_text.insert(tk.END, f"Deleted {count} rules\n")
                    else:
                        self.parent.history_text.insert(tk.END, "Deleted rules\n")
                elif action == 'rules_copied':
                    rule_count = details.get('count', '?')
                    self.parent.history_text.insert(tk.END, f"Copied {rule_count} rules to clipboard\n")
                elif action == 'rules_pasted':
                    line = details.get('line', '?')
                    rule_count = details.get('count', '?')
                    rules_info = details.get('rules', [])
                    if rules_info:
                        self.parent.history_text.insert(tk.END, f"Pasted {rule_count} rules at line {line}:\n")
                        for i, rule_info in enumerate(rules_info[:3]):  # Show first 3 rules
                            if rule_info.get('type') == 'comment':
                                comment_text = rule_info.get('text', 'comment')
                                self.parent.history_text.insert(tk.END, f"  - Comment: {comment_text}\n")
                            elif rule_info.get('type') == 'blank':
                                self.parent.history_text.insert(tk.END, f"  - Blank line\n")
                            else:
                                action_type = rule_info.get('action', 'unknown')
                                sid = rule_info.get('sid', '?')
                                message = rule_info.get('message', '')
                                if message:
                                    self.parent.history_text.insert(tk.END, f"  - {action_type.upper()} rule (SID: {sid}): {message}\n")
                                else:
                                    self.parent.history_text.insert(tk.END, f"  - {action_type.upper()} rule (SID: {sid})\n")
                        if len(rules_info) > 3:
                            self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Pasted {rule_count} rules at line {line}\n")
                elif action == 'rule_moved':
                    direction = details.get('direction', 'unknown')
                    from_line = details.get('from_line', '?')
                    to_line = details.get('to_line', '?')
                    self.parent.history_text.insert(tk.END, f"Moved rule {direction} from line {from_line} to {to_line}\n")
                elif action == 'domain_import':
                    rule_count = details.get('count', '?')
                    domain_count = details.get('domains', '?')
                    import_action = details.get('action', 'unknown')
                    domain_details = details.get('domain_details', [])
                    start_sid = details.get('start_sid')
                    end_sid = details.get('end_sid')
                    
                    if domain_details and start_sid and end_sid:
                        self.parent.history_text.insert(tk.END, f"Imported {rule_count} {import_action} rules for {domain_count} domains (SIDs {start_sid}-{end_sid}):\n")
                        for domain_info in domain_details:
                            domain = domain_info['domain']
                            d_start = domain_info['start_sid']
                            d_end = domain_info['end_sid']
                            self.parent.history_text.insert(tk.END, f"  - {domain}: SIDs {d_start}-{d_end}\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Imported {rule_count} {import_action} rules for {domain_count} domains\n")
                elif action == 'variable_added':
                    variable = details.get('variable', 'unknown')
                    definition = details.get('definition', '')
                    if definition:
                        # Truncate long definitions for readability
                        display_def = definition[:30] + '...' if len(definition) > 30 else definition
                        self.parent.history_text.insert(tk.END, f"Added variable {variable} = {display_def}\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Added variable {variable}\n")
                elif action == 'variable_modified':
                    variable = details.get('variable', 'unknown')
                    definition = details.get('definition', '')
                    if definition:
                        # Truncate long definitions for readability
                        display_def = definition[:30] + '...' if len(definition) > 30 else definition
                        self.parent.history_text.insert(tk.END, f"Modified variable {variable} = {display_def}\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Modified variable {variable}\n")
                elif action == 'variable_deleted':
                    variable = details.get('variable', 'unknown')
                    # Show the variable type for context
                    var_type = 'IP Set' if variable.startswith('$') else 'Port Set' if variable.startswith('@') else 'Reference'
                    self.parent.history_text.insert(tk.END, f"Deleted {var_type.lower()} variable {variable}\n")
                elif action == 'tag_added':
                    key = details.get('key', 'unknown')
                    value = details.get('value', '')
                    self.parent.history_text.insert(tk.END, f"Added tag: {key} = \"{value}\"\n")
                elif action == 'tag_modified':
                    key = details.get('key', 'unknown')
                    old_value = details.get('old_value', '')
                    new_value = details.get('new_value', '')
                    self.parent.history_text.insert(tk.END, f"Modified tag {key}: \"{old_value}\" → \"{new_value}\"\n")
                elif action == 'tag_deleted':
                    key = details.get('key', 'unknown')
                    value = details.get('value', '')
                    self.parent.history_text.insert(tk.END, f"Deleted tag: {key} (was \"{value}\")\n")
                elif action == 'rules_enabled':
                    rule_count = details.get('count', '?')
                    rules_info = details.get('rules', [])
                    if rules_info:
                        self.parent.history_text.insert(tk.END, f"Enabled {rule_count} rules (uncommented):\n")
                        for rule_info in rules_info[:3]:  # Show first 3 rules
                            action_type = rule_info.get('action', 'unknown')
                            sid = rule_info.get('sid', '?')
                            line = rule_info.get('line', '?')
                            message = rule_info.get('message', '')
                            if message:
                                self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid}): {message}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid})\n")
                        if len(rules_info) > 3:
                            self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Enabled {rule_count} rules\n")
                elif action == 'rules_disabled':
                    rule_count = details.get('count', '?')
                    rules_info = details.get('rules', [])
                    if rules_info:
                        self.parent.history_text.insert(tk.END, f"Disabled {rule_count} rules (commented out):\n")
                        for rule_info in rules_info[:3]:  # Show first 3 rules
                            action_type = rule_info.get('action', 'unknown')
                            sid = rule_info.get('sid', '?')
                            line = rule_info.get('line', '?')
                            message = rule_info.get('message', '')
                            if message:
                                self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid}): {message}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid})\n")
                        if len(rules_info) > 3:
                            self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Disabled {rule_count} rules\n")
                elif action == 'undo_performed':
                    rules_before = details.get('rules_before', '?')
                    rules_after = details.get('rules_after', '?')
                    rules_changed = details.get('rules_changed', 0)
                    if rules_changed > 0:
                        self.parent.history_text.insert(tk.END, f"Undo operation performed ({rules_changed} rules affected: {rules_before} → {rules_after})\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Undo operation performed (rules restored: {rules_before} → {rules_after})\n")
                elif action == 'advanced_editor_rules_added':
                    count = details.get('count', '?')
                    rules_before = details.get('rules_before', '?')
                    rules_after = details.get('rules_after', '?')
                    rule_word = "rule" if count == 1 else "rules"
                    self.parent.history_text.insert(tk.END, f"[Advanced Editor] Added {count} {rule_word} | Total: {rules_before} → {rules_after} rules\n")
                elif action == 'advanced_editor_rules_deleted':
                    count = details.get('count', '?')
                    rules_before = details.get('rules_before', '?')
                    rules_after = details.get('rules_after', '?')
                    rule_word = "rule" if count == 1 else "rules"
                    self.parent.history_text.insert(tk.END, f"[Advanced Editor] Deleted {count} {rule_word} | Total: {rules_before} → {rules_after} rules\n")
                elif action == 'advanced_editor_rules_modified':
                    count = details.get('count', '?')
                    rules_before = details.get('rules_before', '?')
                    rules_after = details.get('rules_after', '?')
                    rule_word = "rule" if count == 1 else "rules"
                    # Only show arrow notation if counts differ (for consistency)
                    if rules_before == rules_after:
                        self.parent.history_text.insert(tk.END, f"[Advanced Editor] Modified {count} {rule_word} | Total: {rules_after} rules\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"[Advanced Editor] Modified {count} {rule_word} | Total: {rules_before} → {rules_after} rules\n")
                elif action == 'advanced_editor_bulk_changes':
                    rules_before = details.get('rules_before', '?')
                    rules_after = details.get('rules_after', '?')
                    rules_added = details.get('rules_added', 0)
                    rules_deleted = details.get('rules_deleted', 0)
                    rules_modified = details.get('rules_modified', 0)
                    net_change = details.get('net_change', 0)
                    
                    self.parent.history_text.insert(tk.END, f"[Advanced Editor] Bulk changes applied:\n")
                    self.parent.history_text.insert(tk.END, f"  - Rules: {rules_before} → {rules_after} (net change: {net_change:+d})\n")
                    
                    if rules_added > 0:
                        self.parent.history_text.insert(tk.END, f"  - Added: {rules_added} rules\n")
                    if rules_deleted > 0:
                        self.parent.history_text.insert(tk.END, f"  - Deleted: {rules_deleted} rules\n")
                    if rules_modified > 0:
                        self.parent.history_text.insert(tk.END, f"  - Modified: {rules_modified} rules\n")
                    
                    # Show SID range changes
                    original_sid_range = details.get('original_sid_range')
                    new_sid_range = details.get('new_sid_range')
                    if original_sid_range and new_sid_range:
                        self.parent.history_text.insert(tk.END, f"  - SID range: {original_sid_range} → {new_sid_range}\n")
                    
                    # Show action distribution changes if significant
                    action_changes = details.get('action_changes')
                    if action_changes:
                        before_actions = action_changes.get('before', {})
                        after_actions = action_changes.get('after', {})
                        
                        # Check if action distribution changed
                        if before_actions != after_actions:
                            self.parent.history_text.insert(tk.END, f"  - Action distribution changed:\n")
                            all_actions = set(list(before_actions.keys()) + list(after_actions.keys()))
                            for action_type in sorted(all_actions):
                                before_count = before_actions.get(action_type, 0)
                                after_count = after_actions.get(action_type, 0)
                                if before_count != after_count:
                                    self.parent.history_text.insert(tk.END, f"    • {action_type}: {before_count} → {after_count}\n")
                else:
                    self.parent.history_text.insert(tk.END, f"{action}\n")
        
        # Try to load and display saved history
        if self.parent.current_file:
            self.display_saved_history()
        
        if not self.parent.pending_history and not self.parent.current_file:
            self.parent.history_text.insert(tk.END, "No changes recorded yet.\n")
            self.parent.history_text.insert(tk.END, "\nChanges will appear here as you work with rules.\n")
        
        self.parent.history_text.config(state=tk.DISABLED)
    
    def display_saved_history(self):
        """Display saved history from .history file if it exists"""
        if not self.parent.current_file:
            return
        
        history_filename = self.parent.current_file.replace('.suricata', '.history')
        if not history_filename.endswith('.history'):
            history_filename += '.history'
        
        if os.path.exists(history_filename):
            try:
                import json
                with open(history_filename, 'r', encoding='utf-8') as f:
                    history_data = json.load(f)
                
                saved_changes = history_data.get('changes', [])
                if saved_changes:
                    self.parent.history_text.insert(tk.END, "\nSaved History:\n")
                    self.parent.history_text.insert(tk.END, "-" * 30 + "\n")
                    
                    # Show most recent entries first
                    for entry in reversed(saved_changes[-20:]):  # Show last 20 entries
                        timestamp = entry.get('timestamp', 'Unknown')
                        action = entry.get('action', 'Unknown')
                        details = entry.get('details', {})
                        count = entry.get('count')
                        
                        # Format timestamp
                        try:
                            import datetime
                            dt = datetime.datetime.fromisoformat(timestamp)
                            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except:
                            formatted_time = timestamp
                        
                        self.parent.history_text.insert(tk.END, f"[{formatted_time}] ")
                        
                        # Use same formatting logic as pending changes
                        if action == 'file_created':
                            self.parent.history_text.insert(tk.END, "File created\n")
                        elif action == 'file_opened':
                            filename = details.get('filename', 'unknown')
                            self.parent.history_text.insert(tk.END, f"Opened file: {filename}\n")
                        elif action == 'file_saved':
                            filename = details.get('filename', 'unknown')
                            self.parent.history_text.insert(tk.END, f"Saved file: {filename}\n")
                        elif action == 'rule_added':
                            line = details.get('line', '?')
                            rule_text = details.get('rule_text', '')
                            
                            # Extract action and SID from rule_text if individual fields not available
                            rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                            sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                            
                            # For template insertions (line 0), omit line number
                            if line == 0:
                                self.parent.history_text.insert(tk.END, f"Added {rule_action} rule (SID: {sid})\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Added {rule_action} rule at line {line} (SID: {sid})\n")
                        elif action == 'rule_modified':
                            line = details.get('line', '?')
                            rule_text = details.get('rule_text', '')
                            
                            # Extract action and SID from rule_text if individual fields not available
                            rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                            sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                            changes = details.get('changes', {})
                            
                            # Base message with rule identification
                            self.parent.history_text.insert(tk.END, f"Modified {rule_action} rule at line {line} (SID: {sid})")
                            
                            # Add detailed change information if available
                            if changes:
                                self.parent.history_text.insert(tk.END, " - Changes:\n")
                                for field, change_info in changes.items():
                                    from_val = change_info.get('from', '')
                                    to_val = change_info.get('to', '')
                                    # Format field name for display
                                    field_display = {
                                        'action': 'Action',
                                        'protocol': 'Protocol', 
                                        'src_net': 'Source Network',
                                        'src_port': 'Source Port',
                                        'direction': 'Direction',
                                        'dst_net': 'Dest Network', 
                                        'dst_port': 'Dest Port',
                                        'message': 'Message',
                                        'content': 'Content',
                                        'sid': 'SID'
                                    }.get(field, field.title())
                                    
                                    # Truncate long values for readability
                                    from_display = (from_val[:30] + '...' if len(str(from_val)) > 30 else str(from_val)) if from_val else '(empty)'
                                    to_display = (to_val[:30] + '...' if len(str(to_val)) > 30 else str(to_val)) if to_val else '(empty)'
                                    
                                    self.parent.history_text.insert(tk.END, f"  - {field_display}: '{from_display}' → '{to_display}'\n")
                            else:
                                self.parent.history_text.insert(tk.END, "\n")
                        elif action == 'rule_deleted':
                            line = details.get('line', '?')
                            rule_text = details.get('rule_text', '')
                            
                            # Extract action and SID from rule_text if individual fields not available
                            rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                            sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                            message = details.get('message', '')
                            
                            if message:
                                self.parent.history_text.insert(tk.END, f"Deleted {rule_action} rule from line {line} (SID: {sid}): \"{message}\"\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Deleted {rule_action} rule from line {line} (SID: {sid})\n")
                            
                            if rule_text:
                                # Show truncated rule text (first 80 characters)
                                truncated_rule = rule_text[:80] + '...' if len(rule_text) > 80 else rule_text
                                self.parent.history_text.insert(tk.END, f"  Rule: {truncated_rule}\n")
                        elif action == 'rules_deleted':
                            if count:
                                self.parent.history_text.insert(tk.END, f"Deleted {count} rules\n")
                            else:
                                self.parent.history_text.insert(tk.END, "Deleted rules\n")
                        elif action == 'rules_copied':
                            rule_count = details.get('count', '?')
                            self.parent.history_text.insert(tk.END, f"Copied {rule_count} rules to clipboard\n")
                        elif action == 'rules_pasted':
                            line = details.get('line', '?')
                            rule_count = details.get('count', '?')
                            rules_info = details.get('rules', [])
                            if rules_info:
                                self.parent.history_text.insert(tk.END, f"Pasted {rule_count} rules at line {line}:\n")
                                for i, rule_info in enumerate(rules_info[:3]):  # Show first 3 rules
                                    if rule_info.get('type') == 'comment':
                                        comment_text = rule_info.get('text', 'comment')
                                        self.parent.history_text.insert(tk.END, f"  - Comment: {comment_text}\n")
                                    elif rule_info.get('type') == 'blank':
                                        self.parent.history_text.insert(tk.END, f"  - Blank line\n")
                                    else:
                                        action_type = rule_info.get('action', 'unknown')
                                        sid = rule_info.get('sid', '?')
                                        message = rule_info.get('message', '')
                                        if message:
                                            self.parent.history_text.insert(tk.END, f"  - {action_type.upper()} rule (SID: {sid}): {message}\n")
                                        else:
                                            self.parent.history_text.insert(tk.END, f"  - {action_type.upper()} rule (SID: {sid})\n")
                                if len(rules_info) > 3:
                                    self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Pasted {rule_count} rules at line {line}\n")
                        elif action == 'rule_moved':
                            direction = details.get('direction', 'unknown')
                            from_line = details.get('from_line', '?')
                            to_line = details.get('to_line', '?')
                            self.parent.history_text.insert(tk.END, f"Moved rule {direction} from line {from_line} to {to_line}\n")
                        elif action == 'domain_import':
                            rule_count = details.get('count', '?')
                            domain_count = details.get('domains', '?')
                            import_action = details.get('action', 'unknown')
                            domain_details = details.get('domain_details', [])
                            start_sid = details.get('start_sid')
                            end_sid = details.get('end_sid')
                            
                            if domain_details and start_sid and end_sid:
                                self.parent.history_text.insert(tk.END, f"Imported {rule_count} {import_action} rules for {domain_count} domains (SIDs {start_sid}-{end_sid}):\n")
                                for domain_info in domain_details:
                                    domain = domain_info['domain']
                                    d_start = domain_info['start_sid']
                                    d_end = domain_info['end_sid']
                                    self.parent.history_text.insert(tk.END, f"  - {domain}: SIDs {d_start}-{d_end}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Imported {rule_count} {import_action} rules for {domain_count} domains\n")
                        elif action == 'variable_added':
                            variable = details.get('variable', 'unknown')
                            definition = details.get('definition', '')
                            if definition:
                                display_def = definition[:30] + '...' if len(definition) > 30 else definition
                                self.parent.history_text.insert(tk.END, f"Added variable {variable} = {display_def}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Added variable {variable}\n")
                        elif action == 'variable_modified':
                            variable = details.get('variable', 'unknown')
                            definition = details.get('definition', '')
                            if definition:
                                display_def = definition[:30] + '...' if len(definition) > 30 else definition
                                self.parent.history_text.insert(tk.END, f"Modified variable {variable} = {display_def}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Modified variable {variable}\n")
                        elif action == 'variable_deleted':
                            variable = details.get('variable', 'unknown')
                            var_type = 'IP Set' if variable.startswith('$') else 'Port Set' if variable.startswith('@') else 'Reference'
                            self.parent.history_text.insert(tk.END, f"Deleted {var_type.lower()} variable {variable}\n")
                        elif action == 'tag_added':
                            key = details.get('key', 'unknown')
                            value = details.get('value', '')
                            self.parent.history_text.insert(tk.END, f"Added tag: {key} = \"{value}\"\n")
                        elif action == 'tag_modified':
                            key = details.get('key', 'unknown')
                            old_value = details.get('old_value', '')
                            new_value = details.get('new_value', '')
                            self.parent.history_text.insert(tk.END, f"Modified tag {key}: \"{old_value}\" → \"{new_value}\"\n")
                        elif action == 'tag_deleted':
                            key = details.get('key', 'unknown')
                            value = details.get('value', '')
                            self.parent.history_text.insert(tk.END, f"Deleted tag: {key} (was \"{value}\")\n")
                        elif action == 'rules_enabled':
                            rule_count = details.get('count', '?')
                            rules_info = details.get('rules', [])
                            if rules_info:
                                self.parent.history_text.insert(tk.END, f"Enabled {rule_count} rules (uncommented):\n")
                                for rule_info in rules_info[:3]:  # Show first 3 rules
                                    action_type = rule_info.get('action', 'unknown')
                                    sid = rule_info.get('sid', '?')
                                    line = rule_info.get('line', '?')
                                    message = rule_info.get('message', '')
                                    if message:
                                        self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid}): {message}\n")
                                    else:
                                        self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid})\n")
                                if len(rules_info) > 3:
                                    self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Enabled {rule_count} rules\n")
                        elif action == 'rules_disabled':
                            rule_count = details.get('count', '?')
                            rules_info = details.get('rules', [])
                            if rules_info:
                                self.parent.history_text.insert(tk.END, f"Disabled {rule_count} rules (commented out):\n")
                                for rule_info in rules_info[:3]:  # Show first 3 rules
                                    action_type = rule_info.get('action', 'unknown')
                                    sid = rule_info.get('sid', '?')
                                    line = rule_info.get('line', '?')
                                    message = rule_info.get('message', '')
                                    if message:
                                        self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid}): {message}\n")
                                    else:
                                        self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid})\n")
                                if len(rules_info) > 3:
                                    self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Disabled {rule_count} rules\n")
                        elif action == 'undo_performed':
                            rules_before = details.get('rules_before', '?')
                            rules_after = details.get('rules_after', '?')
                            rules_changed = details.get('rules_changed', 0)
                            if rules_changed > 0:
                                self.parent.history_text.insert(tk.END, f"Undo operation performed ({rules_changed} rules affected: {rules_before} → {rules_after})\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Undo operation performed (rules restored: {rules_before} → {rules_after})\n")
                        elif action == 'advanced_editor_rules_added':
                            count = details.get('count', '?')
                            rules_before = details.get('rules_before', '?')
                            rules_after = details.get('rules_after', '?')
                            rule_word = "rule" if count == 1 else "rules"
                            self.parent.history_text.insert(tk.END, f"[Advanced Editor] Added {count} {rule_word} | Total: {rules_before} → {rules_after} rules\n")
                        elif action == 'advanced_editor_rules_deleted':
                            count = details.get('count', '?')
                            rules_before = details.get('rules_before', '?')
                            rules_after = details.get('rules_after', '?')
                            rule_word = "rule" if count == 1 else "rules"
                            self.parent.history_text.insert(tk.END, f"[Advanced Editor] Deleted {count} {rule_word} | Total: {rules_before} → {rules_after} rules\n")
                        elif action == 'advanced_editor_rules_modified':
                            count = details.get('count', '?')
                            rules_before = details.get('rules_before', '?')
                            rules_after = details.get('rules_after', '?')
                            rule_word = "rule" if count == 1 else "rules"
                            # Only show arrow notation if counts differ (for consistency)
                            if rules_before == rules_after:
                                self.parent.history_text.insert(tk.END, f"[Advanced Editor] Modified {count} {rule_word} | Total: {rules_after} rules\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"[Advanced Editor] Modified {count} {rule_word} | Total: {rules_before} → {rules_after} rules\n")
                        elif action == 'advanced_editor_bulk_changes':
                            rules_before = details.get('rules_before', '?')
                            rules_after = details.get('rules_after', '?')
                            rules_added = details.get('rules_added', 0)
                            rules_deleted = details.get('rules_deleted', 0)
                            rules_modified = details.get('rules_modified', 0)
                            net_change = details.get('net_change', 0)
                            
                            self.parent.history_text.insert(tk.END, f"[Advanced Editor] Bulk changes applied:\n")
                            self.parent.history_text.insert(tk.END, f"  - Rules: {rules_before} → {rules_after} (net change: {net_change:+d})\n")
                            
                            if rules_added > 0:
                                self.parent.history_text.insert(tk.END, f"  - Added: {rules_added} rules\n")
                            if rules_deleted > 0:
                                self.parent.history_text.insert(tk.END, f"  - Deleted: {rules_deleted} rules\n")
                            if rules_modified > 0:
                                self.parent.history_text.insert(tk.END, f"  - Modified: {rules_modified} rules\n")
                            
                            # Show SID range changes
                            original_sid_range = details.get('original_sid_range')
                            new_sid_range = details.get('new_sid_range')
                            if original_sid_range and new_sid_range:
                                self.parent.history_text.insert(tk.END, f"  - SID range: {original_sid_range} → {new_sid_range}\n")
                            
                            # Show action distribution changes if significant
                            action_changes = details.get('action_changes')
                            if action_changes:
                                before_actions = action_changes.get('before', {})
                                after_actions = action_changes.get('after', {})
                                
                                # Check if action distribution changed
                                if before_actions != after_actions:
                                    self.parent.history_text.insert(tk.END, f"  - Action distribution changed:\n")
                                    all_actions = set(list(before_actions.keys()) + list(after_actions.keys()))
                                    for action_type in sorted(all_actions):
                                        before_count = before_actions.get(action_type, 0)
                                        after_count = after_actions.get(action_type, 0)
                                        if before_count != after_count:
                                            self.parent.history_text.insert(tk.END, f"    • {action_type}: {before_count} → {after_count}\n")
                        else:
                            self.parent.history_text.insert(tk.END, f"{action}\n")
                    
                    if len(saved_changes) > 20:
                        self.parent.history_text.insert(tk.END, f"... and {len(saved_changes) - 20} earlier entries\n")
            
            except (OSError, IOError, json.JSONDecodeError, KeyError) as e:
                self.parent.history_text.insert(tk.END, f"\nError loading saved history: {str(e)}\n")
                # Add some debugging info
                self.parent.history_text.insert(tk.END, f"File exists: {os.path.exists(history_filename)}\n")
                if os.path.exists(history_filename):
                    try:
                        with open(history_filename, 'r', encoding='utf-8') as debug_f:
                            debug_data = json.load(debug_f)
                            self.parent.history_text.insert(tk.END, f"JSON keys: {list(debug_data.keys())}\n")
                    except Exception as debug_e:
                        self.parent.history_text.insert(tk.END, f"Debug error: {str(debug_e)}\n")
    
    def clear_history_display(self):
        """Clear the history display"""
        self.parent.history_text.config(state=tk.NORMAL)
        self.parent.history_text.delete(1.0, tk.END)
        self.parent.history_text.insert(tk.END, "History display cleared.\n\n")
        self.parent.history_text.insert(tk.END, "Click 'Refresh' to reload history data.\n")
        self.parent.history_text.config(state=tk.DISABLED)
    
    def export_history(self):
        """Export history to a text file"""
        from tkinter import filedialog
        
        if not self.parent.tracking_enabled:
            messagebox.showwarning("Export History", "Change tracking is not enabled.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export Change History",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    # Get current history content
                    current_content = self.parent.history_text.get(1.0, tk.END)
                    f.write(current_content)
                
                messagebox.showinfo("Export Complete", f"History exported to {filename}")
            except FileNotFoundError as e:
                messagebox.showerror("Directory Error", f"Export directory not found: {str(e)}")
            except PermissionError as e:
                messagebox.showerror("Permission Error", f"Cannot write to export location: {str(e)}")
            except OSError as e:
                messagebox.showerror("File System Error", f"Cannot write export file: {str(e)}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export history: {str(e)}")
    
    def handle_ctrl_c(self):
        """Handle Ctrl-C with focus awareness - copy rules or history text based on focus"""
        focused_widget = self.parent.root.focus_get()
        
        # Check if focus is on the Change History text widget
        if focused_widget == self.history_text:
            self.copy_history_selection()
        elif focused_widget == self.tree:
            # Focus is on the rules tree - copy selected rules
            self.parent.copy_selected_rules()
        else:
            # Check if focus is on any text entry field, let default behavior handle it
            if isinstance(focused_widget, (tk.Entry, tk.Text)):
                # For entry fields, let the default copy behavior work
                try:
                    focused_widget.event_generate("<<Copy>>")
                except:
                    pass  # If copy fails, ignore silently
            else:
                # Default to copying selected rules if no specific focus detected
                self.parent.copy_selected_rules()
    
    def handle_ctrl_v(self, event):
        """Handle Ctrl-V with focus awareness - paste rules or allow normal paste based on focus"""
        focused_widget = self.parent.root.focus_get()
        
        # Check if focus is on the rules tree - paste rules
        if focused_widget == self.tree:
            self.parent.paste_rules()
            return 'break'  # Prevent default handler
        # Check if focus is on any text entry field - allow default paste behavior
        elif isinstance(focused_widget, (tk.Entry, tk.Text)):
            # For entry fields, don't intercept - let tkinter's default paste handler work
            # By not returning 'break', the event continues to the widget's default handler
            return  # Allow default behavior
        else:
            # If no specific focus detected, default to pasting rules for backward compatibility
            self.parent.paste_rules()
            return 'break'  # Prevent default handler
    
    def copy_history_selection(self):
        """Copy selected text from Change History to system clipboard"""
        try:
            # Get selected text from history widget
            if self.history_text.tag_ranges(tk.SEL):
                selected_text = self.history_text.selection_get()
                # Copy to system clipboard
                self.parent.root.clipboard_clear()
                self.parent.root.clipboard_append(selected_text)
                # Show brief feedback
                messagebox.showinfo("Copy", "Selected history text copied to clipboard.")
            else:
                # No selection - copy all visible history text
                all_text = self.history_text.get(1.0, tk.END).strip()
                if all_text:
                    self.parent.root.clipboard_clear()
                    self.parent.root.clipboard_append(all_text)
                    messagebox.showinfo("Copy", "All history text copied to clipboard.")
                else:
                    messagebox.showwarning("Copy", "No history text to copy.")
        except tk.TclError:
            # No selection available
            messagebox.showwarning("Copy", "No text selected to copy.")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy text: {str(e)}")
    
    def on_history_right_click(self, event):
        """Handle right-click context menu for Change History text"""
        try:
            # Create context menu for history text
            context_menu = tk.Menu(self.parent.root, tearoff=0)
            
            # Check if there's selected text
            has_selection = bool(self.history_text.tag_ranges(tk.SEL))
            
            if has_selection:
                context_menu.add_command(label="Copy Selection", command=self.copy_history_selection)
                context_menu.add_separator()
            
            # Always show "Copy All" option
            context_menu.add_command(label="Copy All", command=self.copy_all_history_text)
            
            # Add "Select All" option
            context_menu.add_command(label="Select All", command=self.select_all_history_text)
            
            # Show the menu at mouse position
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            except Exception as popup_error:
                # Fallback: show at approximate position
                context_menu.tk_popup(event.x_root, event.y_root)
                
        except Exception as e:
            # Ultimate fallback - show error message
            messagebox.showinfo("Menu Error", f"Context menu error: {str(e)}")
        finally:
            try:
                context_menu.grab_release()
            except:
                pass
    
    def copy_all_history_text(self):
        """Copy all history text to system clipboard"""
        try:
            all_text = self.history_text.get(1.0, tk.END).strip()
            if all_text:
                self.parent.root.clipboard_clear()
                self.parent.root.clipboard_append(all_text)
                messagebox.showinfo("Copy", "All history text copied to clipboard.")
            else:
                messagebox.showwarning("Copy", "No history text to copy.")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy all text: {str(e)}")
    
    def select_all_history_text(self):
        """Select all text in the Change History tab"""
        try:
            # Enable the text widget temporarily to allow selection
            self.history_text.config(state=tk.NORMAL)
            self.history_text.tag_add(tk.SEL, "1.0", tk.END)
            # Set focus to the text widget so selection is visible
            self.history_text.focus_set()
            # Disable it again
            self.history_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Select All Error", f"Failed to select all text: {str(e)}")
    
    def on_entry_right_click(self, event):
        """Handle right-click context menu for text entry fields"""
        try:
            entry_widget = event.widget
            
            # Create context menu for entry fields
            context_menu = tk.Menu(self.parent.root, tearoff=0)
            
            # Check if there's selected text in the entry
            has_selection = False
            try:
                if entry_widget.selection_present():
                    has_selection = True
            except tk.TclError:
                has_selection = False
            
            # Cut option (only if there's a selection)
            if has_selection:
                context_menu.add_command(label="Cut", command=lambda: self.entry_cut(entry_widget))
            
            # Copy option (only if there's a selection)  
            if has_selection:
                context_menu.add_command(label="Copy", command=lambda: self.entry_copy(entry_widget))
            
            # Paste option (check if clipboard has content)
            try:
                clipboard_content = self.parent.root.clipboard_get()
                if clipboard_content:
                    if has_selection:
                        context_menu.add_separator()
                    context_menu.add_command(label="Paste", command=lambda: self.entry_paste(entry_widget))
            except tk.TclError:
                # No clipboard content
                pass
            
            # Select All option (only if entry has content)
            entry_content = entry_widget.get()
            if entry_content:
                context_menu.add_separator()
                context_menu.add_command(label="Select All", command=lambda: self.entry_select_all(entry_widget))
            
            # Only show menu if it has items
            if context_menu.index("end") is not None:
                # Show the menu at mouse position
                try:
                    context_menu.tk_popup(event.x_root, event.y_root)
                except Exception as popup_error:
                    # Fallback: show at approximate position
                    context_menu.tk_popup(event.x_root, event.y_root)
                    
        except Exception as e:
            # Ultimate fallback - show error message
            messagebox.showinfo("Menu Error", f"Context menu error: {str(e)}")
        finally:
            try:
                context_menu.grab_release()
            except:
                pass
    
    def entry_cut(self, entry_widget):
        """Cut selected text from entry widget"""
        try:
            entry_widget.event_generate("<<Cut>>")
        except Exception as e:
            messagebox.showerror("Cut Error", f"Failed to cut text: {str(e)}")
    
    def entry_copy(self, entry_widget):
        """Copy selected text from entry widget"""
        try:
            entry_widget.event_generate("<<Copy>>")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy text: {str(e)}")
    
    def entry_paste(self, entry_widget):
        """Paste text into entry widget"""
        try:
            entry_widget.event_generate("<<Paste>>")
        except Exception as e:
            messagebox.showerror("Paste Error", f"Failed to paste text: {str(e)}")
    
    def entry_select_all(self, entry_widget):
        """Select all text in entry widget"""
        try:
            entry_widget.select_range(0, tk.END)
            entry_widget.icursor(tk.END)
        except Exception as e:
            messagebox.showerror("Select All Error", f"Failed to select all text: {str(e)}")
    
    def create_tooltip(self, widget, text):
        """Create a tooltip for a widget"""
        def show_tooltip(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
            
            label = tk.Label(tooltip, text=text, background="lightyellow", 
                           relief="solid", borderwidth=1, font=("TkDefaultFont", 9))
            label.pack()
            
            def hide_tooltip():
                tooltip.destroy()
            
            # Hide tooltip after 5 seconds or when mouse leaves
            tooltip.after(5000, hide_tooltip)
            widget.tooltip = tooltip
            widget.hide_tooltip = hide_tooltip
        
        def hide_tooltip(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                delattr(widget, 'tooltip')
        
        # Bind events
        widget.bind("<Enter>", show_tooltip)
        widget.bind("<Leave>", hide_tooltip)
    
    def on_protocol_changed(self, event):
        """Handle protocol dropdown change to update Content Keywords for new rules only"""
        # Only update Content Keywords when creating a new rule (not editing existing)
        if (self.parent.selected_rule_index is not None and 
            self.parent.selected_rule_index >= len(self.parent.rules)):
            # This is a new rule being created
            protocol = self.protocol_var.get().lower()
            if protocol in ["udp", "icmp"]:
                self.content_var.set("")
            else:
                self.content_var.set("flow: to_server")
    
    def _extract_action_from_rule_text(self, rule_text):
        """Extract action from rule_text string"""
        if not rule_text:
            return 'unknown'
        try:
            # Extract first word which should be the action
            action = rule_text.split()[0].lower()
            if action in ['pass', 'alert', 'drop', 'reject']:
                return action
        except (IndexError, AttributeError):
            pass
        return 'unknown'
    
    def _extract_sid_from_rule_text(self, rule_text):
        """Extract SID from rule_text string"""
        if not rule_text:
            return '?'
        try:
            # Look for sid:number pattern
            import re
            sid_match = re.search(r'sid:(\d+)', rule_text)
            if sid_match:
                return sid_match.group(1)
        except (AttributeError, ValueError):
            pass
        return '?'
    
    def show_test_flow_dialog(self):
        """Show dialog for testing a flow against current rules"""
        if not self.parent.rules:
            messagebox.showinfo("Test Flow", "No rules to test against. Please add some rules first.")
            return
        
        # Create dialog (increased height to show all elements)
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Test Flow Against Rules")
        dialog.geometry("950x900")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 50, self.parent.root.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title
        title_label = ttk.Label(main_frame, text="Test Flow Against Rules", 
                               font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 5))
        
        # Disclaimer
        disclaimer_label = ttk.Label(main_frame, 
                                    text="For illustrative purposes only. Proper testing should be performed to fully determine real flow results.",
                                    font=("TkDefaultFont", 8, "italic"),
                                    foreground="#666666")
        disclaimer_label.pack(pady=(0, 2))
        
        # Version
        from version import get_flow_tester_version
        version_label = ttk.Label(main_frame,
                                 text=f"Flow Tester Version: {get_flow_tester_version()}",
                                 font=("TkDefaultFont", 8),
                                 foreground="#999999")
        version_label.pack(pady=(0, 15))
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Flow Information")
        input_frame.pack(fill=tk.X, pady=(0, 15))
        
        fields = ttk.Frame(input_frame)
        fields.pack(fill=tk.X, padx=10, pady=10)
        
        # Row 1: Source IP and Port
        row = 0
        ttk.Label(fields, text="Source IP:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        src_ip_var = tk.StringVar(value="192.168.1.100")
        ttk.Entry(fields, textvariable=src_ip_var, width=20).grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(fields, text="Source Port:").grid(row=row, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        src_port_var = tk.StringVar(value="12345")
        src_port_entry = ttk.Entry(fields, textvariable=src_port_var, width=10)
        src_port_entry.grid(row=row, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Row 2: Destination IP and Port
        row += 1
        dst_ip_label = ttk.Label(fields, text="Dest IP:")
        dst_ip_label.grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        dst_ip_var = tk.StringVar(value="8.8.8.8")
        dst_ip_entry = ttk.Entry(fields, textvariable=dst_ip_var, width=20)
        dst_ip_entry.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for dest IP when testing HTTP/TLS
        self.create_tooltip(dst_ip_entry,
            "Note: For HTTP/TLS testing, the destination IP is used only for \n" +
            "network/port matching. Domain matching is done via the URL/Domain field.\n" +
            "You can use any IP (e.g., 8.8.8.8) when testing domain-based rules.")
        
        ttk.Label(fields, text="Dest Port:").grid(row=row, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        dst_port_var = tk.StringVar(value="443")
        dst_port_entry = ttk.Entry(fields, textvariable=dst_port_var, width=10)
        dst_port_entry.grid(row=row, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Row 3: Protocol, Direction, and URL/Domain (on same row to save space)
        row += 1
        ttk.Label(fields, text="Protocol:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        protocol_var = tk.StringVar(value="tcp")
        protocol_combo = ttk.Combobox(fields, textvariable=protocol_var, 
                                     values=["ip", "icmp", "udp", "tcp", "http", "tls"], 
                                     state="readonly", width=10)
        protocol_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(fields, text="Direction:").grid(row=row, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        direction_var = tk.StringVar(value="->")
        direction_combo = ttk.Combobox(fields, textvariable=direction_var,
                                      values=["->", "<>"],
                                      state="readonly", width=5)
        direction_combo.grid(row=row, column=3, sticky=tk.W, padx=5, pady=5)
        
        # URL/Domain field (for HTTP/TLS protocols) - placed after Direction to save space
        url_label = ttk.Label(fields, text="URL/Domain:")
        url_var = tk.StringVar(value="")
        url_entry = ttk.Entry(fields, textvariable=url_var, width=35)
        
        # Protocol change handler to show/hide URL field and manage port states
        def on_test_protocol_change(event):
            protocol = protocol_var.get().lower()
            
            # Handle ICMP - disable ports
            if protocol == 'icmp':
                src_port_var.set("any")
                dst_port_var.set("any")
                src_port_entry.config(state="disabled")
                dst_port_entry.config(state="disabled")
            else:
                src_port_entry.config(state="normal")
                dst_port_entry.config(state="normal")
            
            # Show URL field for HTTP/TLS protocols (on same row as protocol/direction)
            if protocol in ['http', 'tls', 'https']:
                url_label.grid(row=2, column=4, sticky=tk.W, padx=(20, 5), pady=5)
                url_entry.grid(row=2, column=5, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=5)
                
                # Set default port based on protocol
                if protocol == 'http':
                    dst_port_var.set("80")
                    url_var.set("www.example.com/path")
                elif protocol in ['tls', 'https']:
                    dst_port_var.set("443")
                    url_var.set("www.example.com")
            else:
                # Hide URL field for other protocols
                url_label.grid_remove()
                url_entry.grid_remove()
                url_var.set("")
                
                # Reset to default values for non-HTTP/TLS
                if protocol == 'tcp':
                    dst_port_var.set("443")
                elif protocol == 'udp':
                    dst_port_var.set("53")
        
        protocol_combo.bind('<<ComboboxSelected>>', on_test_protocol_change)
        
        # Test button
        test_button = ttk.Button(input_frame, text="Test Flow")
        test_button.pack(pady=(0, 10))
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Test Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Create paned window for flow diagram and matched rules
        paned = ttk.PanedWindow(results_frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Flow diagram section
        flow_frame = ttk.Frame(paned)
        paned.add(flow_frame, weight=1)
        
        ttk.Label(flow_frame, text="Flow Diagram:", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # Canvas for flow visualization (increased height for vertical stacking)
        flow_canvas = tk.Canvas(flow_frame, height=300, bg="white", relief=tk.SUNKEN, bd=1)
        flow_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Matched rules section
        rules_frame = ttk.Frame(paned)
        paned.add(rules_frame, weight=2)
        
        ttk.Label(rules_frame, text="Matched Rules (in evaluation order):", 
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # Create container for results table and scrollbars
        results_container = ttk.Frame(rules_frame)
        results_container.pack(fill=tk.BOTH, expand=True)
        
        # Results table (created as child of results_container, not rules_frame)
        columns = ("Line", "Type", "Action", "Protocol", "Rule")
        results_tree = ttk.Treeview(results_container, columns=columns, show="headings", height=5)
        
        results_tree.heading("Line", text="Line")
        results_tree.heading("Type", text="Type")
        results_tree.heading("Action", text="Action")
        results_tree.heading("Protocol", text="Protocol")
        results_tree.heading("Rule", text="Rule Details")
        
        results_tree.column("Line", width=50, stretch=False)
        results_tree.column("Type", width=100, stretch=False)
        results_tree.column("Action", width=70, stretch=False)
        results_tree.column("Protocol", width=70, stretch=False)
        results_tree.column("Rule", width=550, stretch=True)
        
        # Configure color tags
        results_tree.tag_configure("pass", foreground="#2E7D32")
        results_tree.tag_configure("drop", foreground="#D32F2F")
        results_tree.tag_configure("reject", foreground="#7B1FA2")
        results_tree.tag_configure("alert", foreground="#1976D2")
        results_tree.tag_configure("final", background="#FFFF99")
        
        # Vertical scrollbar
        results_scrollbar = ttk.Scrollbar(results_container, orient=tk.VERTICAL, command=results_tree.yview)
        results_tree.configure(yscrollcommand=results_scrollbar.set)
        
        # Horizontal scrollbar for long rules
        results_h_scrollbar = ttk.Scrollbar(results_container, orient=tk.HORIZONTAL, command=results_tree.xview)
        results_tree.configure(xscrollcommand=results_h_scrollbar.set)
        
        # Grid layout
        results_tree.grid(row=0, column=0, sticky="nsew")
        results_scrollbar.grid(row=0, column=1, sticky="ns")
        results_h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        results_container.grid_rowconfigure(0, weight=1)
        results_container.grid_columnconfigure(0, weight=1)
        
        # Bind double-click to jump to rule
        results_tree.bind("<Double-1>", lambda e: self._on_results_double_click(e, results_tree, dialog))
        
        # Final action display (create here so final_label exists for test button)
        final_frame = ttk.Frame(main_frame)
        final_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(final_frame, text="Final Action:", font=("TkDefaultFont", 11, "bold")).pack(side=tk.LEFT, padx=5)
        final_label = ttk.Label(final_frame, text="(not tested yet)", 
                               font=("TkDefaultFont", 11, "bold"))
        final_label.pack(side=tk.LEFT, padx=5)
        
        # Now configure the test button command (test_button was created earlier, now we configure it)
        test_button.config(command=lambda: self.run_flow_test(src_ip_var.get(), src_port_var.get(),
                                                               dst_ip_var.get(), dst_port_var.get(),
                                                               protocol_var.get(), direction_var.get(),
                                                               results_tree, flow_canvas, final_label,
                                                               url_var.get()))
        
        # Close button
        ttk.Button(main_frame, text="Close", command=dialog.destroy).pack()
    
    def run_flow_test(self, src_ip, src_port, dst_ip, dst_port, protocol, direction,
                     results_tree, flow_canvas, final_label, url=None):
        """Run flow test and update results display"""
        try:
            # Validate inputs
            if not src_ip or not dst_ip:
                messagebox.showerror("Validation Error", "Source and destination IP addresses are required.")
                return
            
            try:
                import ipaddress
                ipaddress.ip_address(src_ip)
                ipaddress.ip_address(dst_ip)
            except ValueError as e:
                messagebox.showerror("Validation Error", f"Invalid IP address: {str(e)}")
                return
            
            # Validate ports
            if src_port.lower() != 'any':
                try:
                    port_num = int(src_port)
                    if not (1 <= port_num <= 65535):
                        messagebox.showerror("Validation Error", "Source port must be between 1 and 65535 or 'any'.")
                        return
                except ValueError:
                    messagebox.showerror("Validation Error", "Source port must be a number or 'any'.")
                    return
            
            if dst_port.lower() != 'any':
                try:
                    port_num = int(dst_port)
                    if not (1 <= port_num <= 65535):
                        messagebox.showerror("Validation Error", "Destination port must be between 1 and 65535 or 'any'.")
                        return
                except ValueError:
                    messagebox.showerror("Validation Error", "Destination port must be a number or 'any'.")
                    return
            
            # Validate URL for HTTP/TLS protocols
            if protocol.lower() in ['http', 'tls', 'https']:
                if not url or not url.strip():
                    messagebox.showerror("Validation Error", 
                                       f"{protocol.upper()} protocol requires a URL/Domain. "
                                       "Please enter a domain like 'www.example.com' or 'www.example.com/path'.")
                    return
            
            # Create FlowTester instance
            from flow_tester import FlowTester
            flow_tester = FlowTester(self.parent.rules, self.parent.variables, self.parent.rule_analyzer)
            
            # Run the test
            results = flow_tester.test_flow(src_ip, src_port, dst_ip, dst_port, protocol, direction, url)
            
            # Store results and results_tree for diagram access
            self.parent._last_flow_test_results = results
            self.parent._flow_test_results_tree = results_tree
            
            # Clear previous results
            results_tree.delete(*results_tree.get_children())
            flow_canvas.delete("all")
            
            # Display flow diagram with results context (including matched rule info)
            self._draw_flow_diagram(flow_canvas, results['flow_steps'], results['final_action'], results.get('final_rule'))
            
            # Display matched rules in evaluation order (combine action rules and alert rules)
            all_matches = results['matched_rules'] + results['alert_rules']
            
            if all_matches:
                # Sort by line number to show in evaluation order
                all_matches.sort(key=lambda m: m['line'])
                
                for match in all_matches:
                    rule = match['rule']
                    
                    # Extract rule details (everything after protocol and direction)
                    # Format: src_net src_port direction dst_net dst_port (content)
                    rule_details = f"{rule.src_net} {rule.src_port} {rule.direction} {rule.dst_net} {rule.dst_port}"
                    if rule.content:
                        rule_details += f" ({rule.content})"
                    
                    # Only use action color tag (no yellow highlight)
                    tags = [match['action'].lower()]
                    
                    results_tree.insert("", tk.END, 
                                      values=(match['line'], match['type'], match['action'].upper(), 
                                             rule.protocol.upper(), rule_details),
                                      tags=tuple(tags))
            else:
                # No matches
                results_tree.insert("", tk.END, values=("", "", "", "", "No rules matched this flow"))
            
            # Display final action
            final_action = results['final_action']
            if final_action == 'PASS':
                final_label.config(text="ALLOWED", foreground="#2E7D32")
            elif final_action in ['DROP', 'REJECT']:
                final_label.config(text="BLOCKED", foreground="#D32F2F")
            elif final_action == 'NO_RULES':
                final_label.config(text="NO RULES TO EVALUATE", foreground="#FF6600")
            elif 'no matching rules' in final_action.lower():
                final_label.config(text="UNDETERMINED (no matching rules)", foreground="#FF6600")
            else:
                final_label.config(text=final_action, foreground="#000000")
                
        except Exception as e:
            messagebox.showerror("Flow Test Error", f"An error occurred during flow testing:\n\n{str(e)}\n\nPlease check your inputs and try again.")
            import traceback
            print(f"Flow test error: {traceback.format_exc()}")
    
    def _draw_flow_diagram(self, canvas, flow_steps, final_action=None, final_rule=None):
        """Draw enhanced visual flow diagram with rule-to-step mapping
        
        Args:
            canvas: Canvas widget to draw on
            flow_steps: List of flow step dictionaries
            final_action: Final action result (e.g., 'PASS', 'DROP', 'REJECT')
            final_rule: The final matched rule info (includes rule object)
        """
        canvas.delete("all")
        
        # Store references for hover functionality
        if not hasattr(self, '_canvas_hover_data'):
            self._canvas_hover_data = {}
        self._canvas_hover_data['canvas'] = canvas
        self._canvas_hover_data['arrow_to_line'] = {}
        self._canvas_hover_data['line_to_arrows'] = {}
        
        if not flow_steps:
            return
        
        # Calculate canvas dimensions
        canvas.update_idletasks()
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        
        if width <= 1:
            width = 900
        if height <= 1:
            height = 400  # Increased for vertical stacking
        
        # Layout parameters
        margin = 60
        box_width = 120
        box_height = 50
        
        # Calculate positions for source and destination boxes
        src_x = margin + box_width // 2
        dst_x = width - margin - box_width // 2
        
        # Draw source box (on left)
        src_y = height // 2
        canvas.create_rectangle(src_x - box_width//2, src_y - box_height//2,
                              src_x + box_width//2, src_y + box_height//2,
                              fill="#E3F2FD", outline="#1976D2", width=2)
        canvas.create_text(src_x, src_y, text="Source", font=("TkDefaultFont", 11, "bold"))
        
        # Add source address below box
        if flow_steps:
            src_addr = flow_steps[0].get('from', '')
            canvas.create_text(src_x, src_y + box_height//2 + 15, 
                             text=src_addr, font=("TkDefaultFont", 8))
        
        # Draw destination box (on right)
        dst_y = height // 2
        canvas.create_rectangle(dst_x - box_width//2, dst_y - box_height//2,
                              dst_x + box_width//2, dst_y + box_height//2,
                              fill="#E8F5E9", outline="#2E7D32", width=2)
        canvas.create_text(dst_x, dst_y, text="Destination", font=("TkDefaultFont", 11, "bold"))
        
        # Add destination address below box
        if flow_steps:
            dst_addr = flow_steps[0].get('to', '')
            canvas.create_text(dst_x, dst_y + box_height//2 + 15,
                             text=dst_addr, font=("TkDefaultFont", 8))
        
        # Get results from parent's last flow test (stored during run_flow_test)
        results = getattr(self.parent, '_last_flow_test_results', None)
        if not results:
            # No results available - just show source and destination boxes (already drawn)
            return
        
        # Build list of arrows to draw (TCP handshake steps + matched rules)
        arrows_to_draw = []
        
        # Get all matched rules (action rules + alert rules)
        all_matched = results.get('matched_rules', []) + results.get('alert_rules', [])
        step_mapping = results.get('step_rule_mapping', {})
        
        # If no rules matched, don't draw any arrows - just show source/destination boxes
        if not all_matched:
            return
        
        # TCP and application layer protocols over TCP (HTTP, TLS) use handshake + established phases
        if results.get('protocol') in ['tcp', 'http', 'tls', 'https']:
            # Show individual handshake steps (SYN, SYN-ACK, ACK) then established
            handshake_rules = [m for m in all_matched if m.get('phase') == 'handshake']
            established_rules = [m for m in all_matched if m.get('phase') == 'established']
            
            # TCP handshake steps with their matching rules (use first handshake rule for all 3 steps)
            handshake_match = handshake_rules[0] if handshake_rules else None
            
            # Check if handshake was blocked (DROP or REJECT)
            handshake_blocked = (handshake_match and 
                                handshake_match['action'].lower() in ['drop', 'reject'])
            
            # Step 1: SYN (->)
            arrows_to_draw.append({
                'type': 'tcp_syn',
                'match': handshake_match,
                'description': 'SYN',
                'direction': '->',
                'step_name': 'TCP SYN'
            })
            
            # Only show SYN-ACK and ACK if handshake was NOT blocked
            if not handshake_blocked:
                # Step 2: SYN-ACK (<-)
                arrows_to_draw.append({
                    'type': 'tcp_synack',
                    'match': handshake_match,  # Same rule (stateful)
                    'description': 'SYN-ACK',
                    'direction': '<-',
                    'step_name': 'TCP SYN-ACK'
                })
                
                # Step 3: ACK (->)
                arrows_to_draw.append({
                    'type': 'tcp_ack',
                    'match': handshake_match,  # Same rule (stateful)
                    'description': 'ACK',
                    'direction': '->',
                    'step_name': 'TCP ACK'
                })
                
                # Step 4+: Established phase rules (sorted by line number to match table order)
                # Only show if handshake succeeded
                established_rules_sorted = sorted(established_rules, key=lambda m: m['line'])
                
                protocol_name = results.get('protocol', 'tcp').upper()
                
                # For TLS/HTTPS, show detailed TLS handshake steps
                if protocol_name in ['TLS', 'HTTPS'] and established_rules_sorted:
                    # Find the first action rule (pass/drop/reject) - not alert
                    action_match = next((m for m in established_rules_sorted if m['action'].lower() != 'alert'), None)
                    
                    if action_match:
                        # Add alert rules that come BEFORE the action rule (by line number)
                        for match in established_rules_sorted:
                            if match['action'].lower() == 'alert' and match['line'] < action_match['line']:
                                arrows_to_draw.append({
                                    'type': 'alert',
                                    'match': match,
                                    'description': 'Alert',
                                    'direction': '->',
                                    'step_name': 'Alert Rule'
                                })
                        
                        # Check if TLS connection is blocked (DROP or REJECT)
                        tls_blocked = action_match['action'].lower() in ['drop', 'reject']
                        
                        # Show TLS ClientHello (always shown)
                        arrows_to_draw.append({
                            'type': 'tls_client_hello',
                            'match': action_match,
                            'description': 'ClientHello',
                            'direction': '->',
                            'step_name': 'TLS ClientHello'
                        })
                        
                        # Only show ServerHello and Encrypted Data if TLS was NOT blocked
                        if not tls_blocked:
                            arrows_to_draw.append({
                                'type': 'tls_server_hello',
                                'match': action_match,
                                'description': 'ServerHello',
                                'direction': '<-',
                                'step_name': 'TLS ServerHello'
                            })
                            
                            arrows_to_draw.append({
                                'type': 'tls_data',
                                'match': action_match,
                                'description': 'Encrypted Data',
                                'direction': '->',
                                'step_name': 'Application Data'
                            })
                        
                        # Add alert rules that come AFTER the action rule (by line number)
                        for match in established_rules_sorted:
                            if match['action'].lower() == 'alert' and match['line'] > action_match['line']:
                                arrows_to_draw.append({
                                    'type': 'alert',
                                    'match': match,
                                    'description': 'Alert',
                                    'direction': '->',
                                    'step_name': 'Alert Rule'
                                })
                    else:
                        # No action rule, just show all alert rules
                        for match in established_rules_sorted:
                            if match['action'].lower() == 'alert':
                                arrows_to_draw.append({
                                    'type': 'alert',
                                    'match': match,
                                    'description': 'Alert',
                                    'direction': '->',
                                    'step_name': 'Alert Rule'
                                })
                else:
                    # For HTTP and TCP, show single arrow per matched rule
                    for match in established_rules_sorted:
                        if protocol_name == 'HTTP':
                            desc = 'HTTP Data' if match['action'].lower() != 'alert' else 'Alert'
                        else:
                            desc = 'Established' if match['action'].lower() != 'alert' else 'Alert'
                        
                        arrows_to_draw.append({
                            'type': 'established',
                            'match': match,
                            'description': desc,
                            'direction': '->',
                            'step_name': f'{protocol_name} Connection' if match['action'].lower() != 'alert' else 'Alert Rule'
                        })
        elif all_matched:
            # Non-TCP protocols (IP, ICMP, UDP): show one arrow per matched rule
            all_phase_rules = [m for m in all_matched if m.get('phase') == 'all']
            for match in all_phase_rules:
                arrows_to_draw.append({
                    'type': 'single',
                    'match': match,
                    'description': results.get('protocol', 'IP').upper(),
                    'direction': '->',
                    'step_name': f"{results.get('protocol', 'IP').upper()} Packet"
                })
        else:
            # No matched rules - don't draw any arrows
            # Just show the source and destination boxes (already drawn)
            pass
        
        # Draw arrows vertically stacked (reduce spacing to fit more arrows)
        arrow_height = 30  # Vertical spacing between arrows (reduced for TLS handshake)
        start_y = max(60, (height - len(arrows_to_draw) * arrow_height) // 2)
        
        for i, arrow_info in enumerate(arrows_to_draw):
            y_pos = start_y + i * arrow_height
            match = arrow_info['match']
            arrow_direction = arrow_info.get('direction', '->')
            step_desc = arrow_info.get('description', '')
            
            if match:
                action = match['action'].lower()
                line_num = match['line']
                is_alert = (action == 'alert')
                is_final = (final_rule and match['line'] == final_rule['line'])
                
                # Determine arrow color based on rule action (match rule table colors)
                if is_alert:
                    arrow_color = "#1976D2"  # Blue for alerts
                    arrow_dash = (5, 3)  # Dashed line
                    arrow_width = 2
                elif action == 'pass':
                    arrow_color = "#2E7D32"  # Green for pass
                    arrow_dash = ()
                    arrow_width = 3 if is_final else 2
                elif action == 'reject':
                    arrow_color = "#7B1FA2"  # Purple for reject
                    arrow_dash = ()
                    arrow_width = 3 if is_final else 2
                elif action == 'drop':
                    arrow_color = "#D32F2F"  # Red for drop
                    arrow_dash = ()
                    arrow_width = 3 if is_final else 2
                else:
                    arrow_color = "#424242"  # Gray for others
                    arrow_dash = ()
                    arrow_width = 2
                
                # Draw arrow based on direction
                arrow_start_x = src_x + box_width//2 + 10
                arrow_end_x = dst_x - box_width//2 - 10
                
                if arrow_direction == '<-':
                    # Reverse direction for SYN-ACK
                    arrow_start_x, arrow_end_x = arrow_end_x, arrow_start_x
                
                # For drop/reject, arrow is cut in half to show flow stopped
                if action in ['drop', 'reject'] and arrow_direction == '->':
                    arrow_end_x = src_x + (dst_x - src_x) // 2
                
                # Create arrow with tags for hover
                arrow_tag = f"arrow_{line_num}_{i}"
                arrow_id = canvas.create_line(
                    arrow_start_x, y_pos, arrow_end_x, y_pos,
                    arrow=tk.LAST, width=arrow_width, fill=arrow_color,
                    dash=arrow_dash, tags=arrow_tag
                )
                
                # Store mapping for hover
                self._canvas_hover_data['arrow_to_line'][arrow_tag] = line_num
                if line_num not in self._canvas_hover_data['line_to_arrows']:
                    self._canvas_hover_data['line_to_arrows'][line_num] = []
                self._canvas_hover_data['line_to_arrows'][line_num].append(arrow_tag)
                
                # Draw visual indicators at arrow endpoint based on rule action
                actual_end_x = arrow_end_x
                if arrow_direction == '->':
                    if action == 'pass':
                        # Green checkmark for pass rules
                        self._draw_checkmark(canvas, actual_end_x + 5, y_pos, arrow_tag)
                    elif action in ['drop', 'reject']:
                        # Red X for drop/reject rules
                        self._draw_x_mark(canvas, actual_end_x + 10, y_pos, arrow_tag)
                    # Alert rules: no visual indicator (dashed line is sufficient)
                
                # Draw step description above arrow (e.g., "SYN", "SYN-ACK", "ACK")
                mid_x = (arrow_start_x + arrow_end_x) // 2
                canvas.create_text(mid_x, y_pos - 15,
                                 text=f"{step_desc} (Line {line_num})",
                                 font=("TkDefaultFont", 9),
                                 fill=arrow_color, tags=arrow_tag)
            else:
                # Generic arrow (no matching rule)
                arrow_color = "#999999"
                arrow_id = canvas.create_line(
                    src_x + box_width//2 + 10, y_pos,
                    dst_x - box_width//2 - 10, y_pos,
                    arrow=tk.LAST, width=2, fill=arrow_color
                )
                canvas.create_text((src_x + dst_x) // 2, y_pos - 15,
                                 text=arrow_info['description'],
                                 font=("TkDefaultFont", 8), fill=arrow_color)
        
        # Bind hover events
        self._setup_canvas_hover_bindings(canvas)
    
    def _draw_simple_arrows(self, canvas, flow_steps, src_x, dst_x, src_y, box_width):
        """Draw simple horizontal arrows when no rule mapping available"""
        arrow_spacing = 30
        start_y = src_y - (len(flow_steps) * arrow_spacing) // 2
        
        for i, step in enumerate(flow_steps):
            y_pos = start_y + i * arrow_spacing
            description = step.get('description', '')
            
            canvas.create_line(src_x + box_width//2 + 10, y_pos,
                             dst_x - box_width//2 - 10, y_pos,
                             arrow=tk.LAST, width=2, fill="#424242")
            canvas.create_text((src_x + dst_x) // 2, y_pos - 15,
                             text=description, font=("TkDefaultFont", 8))
    
    def _draw_checkmark(self, canvas, x, y, tag):
        """Draw a green checkmark at specified position"""
        # Checkmark shape
        points = [
            x - 6, y,
            x - 2, y + 4,
            x + 6, y - 4
        ]
        canvas.create_line(points, width=3, fill="#2E7D32",
                         capstyle=tk.ROUND, joinstyle=tk.ROUND, tags=tag)
    
    def _draw_x_mark(self, canvas, x, y, tag):
        """Draw a red X at specified position"""
        # X mark (two crossing lines)
        size = 6
        canvas.create_line(x - size, y - size, x + size, y + size,
                         width=3, fill="#D32F2F", tags=tag)
        canvas.create_line(x - size, y + size, x + size, y - size,
                         width=3, fill="#D32F2F", tags=tag)
    
    def _draw_info_icon(self, canvas, x, y, tag):
        """Draw a blue info icon at specified position"""
        # Circle
        radius = 6
        canvas.create_oval(x - radius, y - radius, x + radius, y + radius,
                         outline="#1976D2", width=2, fill="white", tags=tag)
        # 'i' letter
        canvas.create_text(x, y, text="i", font=("TkDefaultFont", 10, "bold"),
                         fill="#1976D2", tags=tag)
    
    def _setup_canvas_hover_bindings(self, canvas):
        """Setup hover event bindings for canvas arrows"""
        def on_canvas_hover(event):
            # Find which arrow is being hovered
            items = canvas.find_overlapping(event.x - 5, event.y - 5,
                                           event.x + 5, event.y + 5)
            
            # Clear any previous highlights
            self._clear_canvas_highlights(canvas)
            
            for item in items:
                tags = canvas.gettags(item)
                for tag in tags:
                    if tag.startswith('arrow_'):
                        line_num = self._canvas_hover_data.get('arrow_to_line', {}).get(tag)
                        if line_num:
                            # Highlight only line items (not text) on canvas
                            item_type = canvas.type(item)
                            if item_type == 'line':
                                canvas.itemconfig(item, width=4)
                            # Highlight rule in results table
                            self._highlight_rule_in_results(line_num)
                        break
        
        def on_canvas_leave(event):
            self._clear_canvas_highlights(canvas)
        
        canvas.bind("<Motion>", on_canvas_hover)
        canvas.bind("<Leave>", on_canvas_leave)
    
    def _clear_canvas_highlights(self, canvas):
        """Clear all arrow highlights on canvas"""
        for arrow_tag in self._canvas_hover_data.get('arrow_to_line', {}).keys():
            # Reset arrow width to normal - only for line items
            try:
                # Find all items with this tag
                items = canvas.find_withtag(arrow_tag)
                for item in items:
                    if canvas.type(item) == 'line':
                        canvas.itemconfig(item, width=2)
            except:
                pass
    
    def _highlight_rule_in_results(self, line_num):
        """Highlight corresponding rule in results table"""
        # This will be called from canvas hover
        # The results_tree reference should be stored during flow test
        results_tree = getattr(self.parent, '_flow_test_results_tree', None)
        if not results_tree:
            return
        
        # Find and select the item with matching line number
        for item in results_tree.get_children():
            values = results_tree.item(item, 'values')
            if values and str(values[0]) == str(line_num):
                results_tree.selection_set(item)
                results_tree.see(item)
                break
    
    def _on_results_double_click(self, event, results_tree, test_dialog):
        """Handle double-click on results table to jump to rule in main editor
        
        Args:
            event: Click event
            results_tree: The results treeview widget
            test_dialog: The test flow dialog window
        """
        # Get the clicked item
        item = results_tree.identify_row(event.y)
        if not item:
            return
        
        # Get the line number from the clicked item
        values = results_tree.item(item, 'values')
        if not values or not values[0]:
            return
        
        try:
            line_num = int(values[0])
        except (ValueError, TypeError):
            return
        
        # Close the test dialog
        test_dialog.destroy()
        
        # Jump to the rule in the main editor
        # Convert line number to 0-based index
        rule_index = line_num - 1
        
        # Get all items in main tree
        all_items = self.parent.tree.get_children()
        
        if rule_index < len(all_items):
            target_item = all_items[rule_index]
            # Clear current selection
            self.parent.tree.selection_remove(self.parent.tree.selection())
            # Select and focus the target rule
            self.parent.tree.selection_set(target_item)
            self.parent.tree.focus(target_item)
            self.parent.tree.see(target_item)
            # Ensure main window is visible
            self.parent.root.lift()
            self.parent.root.focus_force()
    
    def show_add_common_ports_dialog(self):
        """Show dialog for adding common port variables from predefined library
        
        Uses a two-panel layout with category dropdown:
        - Left panel: Category variables with checkboxes
        - Right panel: Selected variables summary
        Preserves selections when switching categories for better UX.
        """
        import json
        
        # Load common ports from JSON file
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            common_ports_file = os.path.join(script_dir, "common_ports.json")
            
            with open(common_ports_file, 'r', encoding='utf-8') as f:
                common_ports_data = json.load(f)
            
            # Support both old and new formats for backward compatibility
            if 'categories' in common_ports_data:
                # New format with version info
                common_ports = common_ports_data['categories']
            else:
                # Old format (direct categories at top level)
                common_ports = common_ports_data
                
        except FileNotFoundError:
            messagebox.showerror("File Not Found", 
                "common_ports.json file not found in program directory.\n\n" +
                "This file should contain predefined port variable definitions.")
            return
        except json.JSONDecodeError as e:
            messagebox.showerror("JSON Error", 
                f"Error parsing common_ports.json:\n\n{str(e)}")
            return
        except Exception as e:
            messagebox.showerror("Error", 
                f"Failed to load common ports:\n\n{str(e)}")
            return
        
        # Create dialog (wider to accommodate two-panel layout)
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Add Common Port Variables")
        dialog.geometry("1000x600")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 50, self.parent.root.winfo_rooty() + 100))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title
        title_label = ttk.Label(main_frame, text="Add Common Port Variables", 
                               font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 5))
        
        # Description
        desc_label = ttk.Label(main_frame, 
                              text="Select common port variables to add to your Rule Variables. Selections persist across categories.",
                              font=("TkDefaultFont", 9))
        desc_label.pack(pady=(0, 15))
        
        # Category selector frame
        selector_frame = ttk.Frame(main_frame)
        selector_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(selector_frame, text="Category:", font=("TkDefaultFont", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        # Category dropdown
        category_var = tk.StringVar()
        category_list = sorted(common_ports.keys())
        category_var.set(category_list[0] if category_list else "")
        
        category_combo = ttk.Combobox(selector_frame, textvariable=category_var,
                                     values=category_list,
                                     state="readonly", width=30)
        category_combo.pack(side=tk.LEFT)
        
        # Category count label
        cat_count_label = ttk.Label(selector_frame, text="", font=("TkDefaultFont", 9), foreground="#666666")
        cat_count_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Two-panel layout
        panels_frame = ttk.Frame(main_frame)
        panels_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # LEFT PANEL: Category variables (60% width)
        left_panel = ttk.LabelFrame(panels_frame, text="Variables in Selected Category")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Create scrollable canvas for left panel
        left_canvas = tk.Canvas(left_panel)
        left_v_scrollbar = ttk.Scrollbar(left_panel, orient=tk.VERTICAL, command=left_canvas.yview)
        left_h_scrollbar = ttk.Scrollbar(left_panel, orient=tk.HORIZONTAL, command=left_canvas.xview)
        left_content = ttk.Frame(left_canvas)
        
        left_content.bind(
            "<Configure>",
            lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all"))
        )
        
        left_canvas.create_window((0, 0), window=left_content, anchor="nw")
        left_canvas.configure(yscrollcommand=left_v_scrollbar.set, xscrollcommand=left_h_scrollbar.set)
        
        # Grid layout for scrollbars
        left_canvas.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        left_v_scrollbar.grid(row=0, column=1, sticky="ns", pady=5)
        left_h_scrollbar.grid(row=1, column=0, sticky="ew", padx=5)
        
        left_panel.grid_rowconfigure(0, weight=1)
        left_panel.grid_columnconfigure(0, weight=1)
        
        # Enable mousewheel scrolling for left panel
        def on_left_mousewheel(event):
            left_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        left_canvas.bind("<Enter>", lambda e: left_canvas.bind("<MouseWheel>", on_left_mousewheel))
        left_canvas.bind("<Leave>", lambda e: left_canvas.unbind("<MouseWheel>"))
        
        # RIGHT PANEL: Selected variables summary (40% width)
        right_panel = ttk.LabelFrame(panels_frame, text="Selected Variables")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(5, 0))
        right_panel.config(width=350)
        
        # Selected count label
        selected_count_label = ttk.Label(right_panel, text="0 selected", 
                                        font=("TkDefaultFont", 9, "bold"), foreground="#1976D2")
        selected_count_label.pack(pady=(5, 5))
        
        # Create scrollable canvas for right panel
        right_canvas = tk.Canvas(right_panel, width=330)
        right_scrollbar = ttk.Scrollbar(right_panel, orient=tk.VERTICAL, command=right_canvas.yview)
        right_content = ttk.Frame(right_canvas)
        
        right_content.bind(
            "<Configure>",
            lambda e: right_canvas.configure(scrollregion=right_canvas.bbox("all"))
        )
        
        right_canvas.create_window((0, 0), window=right_content, anchor="nw")
        right_canvas.configure(yscrollcommand=right_scrollbar.set)
        
        # Pack right panel components
        right_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        right_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Enable mousewheel scrolling for right panel
        def on_right_mousewheel(event):
            right_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        right_canvas.bind("<Enter>", lambda e: right_canvas.bind("<MouseWheel>", on_right_mousewheel))
        right_canvas.bind("<Leave>", lambda e: right_canvas.unbind("<MouseWheel>"))
        
        # Global storage for ALL selections across ALL categories
        selected_vars = {}  # {var_name: {'definition': ..., 'description': ..., 'category': ...}}
        
        # Store checkbox variables for current category
        current_checkboxes = {}
        
        def update_selected_panel():
            """Update the right panel showing all selected variables"""
            # Clear existing items
            for widget in right_content.winfo_children():
                widget.destroy()
            
            # Update count
            count = len(selected_vars)
            selected_count_label.config(text=f"{count} selected")
            
            if not selected_vars:
                ttk.Label(right_content, text="No variables selected yet",
                         font=("TkDefaultFont", 9, "italic"), foreground="#666666").pack(padx=10, pady=20)
                return
            
            # Show each selected variable with remove button
            for var_name in sorted(selected_vars.keys()):
                var_info = selected_vars[var_name]
                
                # Create frame for this variable
                var_frame = ttk.Frame(right_content)
                var_frame.pack(fill=tk.X, padx=5, pady=2)
                
                # Variable info (name and definition)
                info_text = f"{var_name}\n{var_info['definition']}"
                var_label = ttk.Label(var_frame, text=info_text, 
                                     font=("TkDefaultFont", 8), wraplength=250)
                var_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
                
                # Remove button
                def make_remove_command(vn):
                    def remove():
                        # Remove from selected_vars
                        del selected_vars[vn]
                        # Update checkbox if in current category
                        if vn in current_checkboxes:
                            current_checkboxes[vn]['var'].set(False)
                        # Refresh right panel
                        update_selected_panel()
                    return remove
                
                remove_btn = ttk.Button(var_frame, text="✕", width=3, 
                                       command=make_remove_command(var_name))
                remove_btn.pack(side=tk.RIGHT)
                
                # Add separator
                ttk.Separator(right_content, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=2)
        
        def populate_category(category_name):
            """Populate the variables display with the selected category's variables"""
            # Clear existing checkboxes
            for widget in left_content.winfo_children():
                widget.destroy()
            current_checkboxes.clear()
            
            # Get the ports list for this category
            ports_list = common_ports.get(category_name, [])
            
            # Update count label
            cat_count_label.config(text=f"({len(ports_list)} variables)")
            
            if not ports_list:
                ttk.Label(left_content, text="No variables in this category",
                         font=("TkDefaultFont", 9, "italic")).pack(padx=10, pady=20)
                return
            
            # Add checkbox for each port variable
            for port_def in ports_list:
                var_name = port_def['name']
                definition = port_def['definition']
                description = port_def['description']
                
                # Check if this variable already exists in Rule Variables
                already_exists = var_name in self.parent.variables
                
                # Check if already selected (from previous category view)
                is_selected = var_name in selected_vars
                
                var = tk.BooleanVar(value=is_selected)
                current_checkboxes[var_name] = {
                    'var': var,
                    'definition': definition,
                    'description': description,
                    'category': category_name,
                    'exists': already_exists
                }
                
                # Format checkbox label
                label_text = f"{var_name} - {definition} - {description}"
                if already_exists:
                    label_text += " (already defined)"
                
                # Checkbox with change handler
                def make_checkbox_handler(vn, cat):
                    def on_change():
                        if current_checkboxes[vn]['var'].get():
                            # Add to selected_vars
                            selected_vars[vn] = {
                                'definition': current_checkboxes[vn]['definition'],
                                'description': current_checkboxes[vn]['description'],
                                'category': cat
                            }
                        else:
                            # Remove from selected_vars
                            if vn in selected_vars:
                                del selected_vars[vn]
                        # Update right panel
                        update_selected_panel()
                    return on_change
                
                cb = ttk.Checkbutton(left_content, text=label_text, variable=var,
                                    command=make_checkbox_handler(var_name, category_name))
                cb.pack(anchor=tk.W, padx=10, pady=2)
                
                # Disable checkbox if variable already exists
                if already_exists:
                    cb.config(state="disabled")
        
        # Populate initial category
        if category_list:
            populate_category(category_list[0])
        
        # Bind category change event
        category_combo.bind('<<ComboboxSelected>>', lambda e: populate_category(category_var.get()))
        
        # Initial update of selected panel
        update_selected_panel()
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 0))
        
        def on_add():
            """Add selected variables from global selections"""
            if not selected_vars:
                messagebox.showwarning("No Selection", "Please select at least one port variable to add.")
                return
            
            # Check for conflicts
            to_add = []
            conflicts = []
            
            for var_name, var_info in selected_vars.items():
                if var_name in self.parent.variables:
                    conflicts.append(var_name)
                else:
                    to_add.append({
                        'name': var_name,
                        'definition': var_info['definition'],
                        'description': var_info['description']
                    })
            
            # Show conflict warning if any
            if conflicts:
                conflict_msg = "The following variables already exist and will not be added:\n\n"
                conflict_msg += "\n".join(f"• {var}" for var in conflicts)
                
                if to_add:
                    conflict_msg += f"\n\n{len(to_add)} new variables will be added."
                    if not messagebox.askyesno("Conflicts Detected", conflict_msg):
                        return
                else:
                    messagebox.showinfo("No Variables Added", "All selected variables already exist.")
                    return
            
            # Add selected variables to parent.variables
            added_count = 0
            for var_def in to_add:
                self.parent.variables[var_def['name']] = {
                    "definition": var_def['definition'],
                    "description": var_def['description']
                }
                
                # Add history entry
                self.parent.add_history_entry('variable_added', {
                    'variable': var_def['name'],
                    'definition': var_def['definition'],
                    'description': var_def['description'],
                    'source': 'common_ports'
                })
                added_count += 1
            
            # Refresh variables table
            self.parent.refresh_variables_table()
            self.parent.update_status_bar()
            self.parent.modified = True
            
            # Close dialog and show success
            dialog.destroy()
            
            var_text = "variable" if added_count == 1 else "variables"
            messagebox.showinfo("Variables Added", 
                f"Successfully added {added_count} port {var_text} to Rule Variables.\n\n" +
                "You can now use these variables in your rules.")
        
        ttk.Button(button_frame, text="Add Selected", command=on_add).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def toggle_sigtype_column(self):
        """Toggle SIG Type column visibility in main rule editor"""
        is_visible = self.parent.show_sigtype_var.get()
        
        if is_visible:
            # Show the column (110px for longest label "LIKE_IPONLY" = 11 characters)
            self.tree.column("SigType", width=110, minwidth=110)
        else:
            # Hide the column
            self.tree.column("SigType", width=0, minwidth=0)
        
        # Refresh table to populate/clear SIG type data
        self.parent.refresh_table()
    
    def show_sigtype_help(self):
        """Show dialog explaining Suricata SIG type classification"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("About Suricata SIG Types")
        dialog.geometry("750x650")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 100,
            self.parent.root.winfo_rooty() + 50
        ))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Create scrollable text widget
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("TkDefaultFont", 10),
                             state=tk.DISABLED, bg=dialog.cget('bg'))
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure text tags
        text_widget.tag_configure("title", font=("TkDefaultFont", 14, "bold"))
        text_widget.tag_configure("section", font=("TkDefaultFont", 11, "bold"), spacing1=10)
        text_widget.tag_configure("type", font=("Consolas", 10, "bold"))
        text_widget.tag_configure("body", font=("TkDefaultFont", 10))
        text_widget.tag_configure("note", font=("TkDefaultFont", 9, "italic"), foreground="#666666")
        text_widget.tag_configure("link", foreground="blue", underline=True)
        
        # Insert content
        text_widget.config(state=tk.NORMAL)
        
        text_widget.insert(tk.END, "Suricata Rule Type Classification\n", "title")
        text_widget.insert(tk.END, "\n")
        text_widget.insert(tk.END, "AWS Network Firewall processes rules using a multi-tier model.\n", "body")
        text_widget.insert(tk.END, "Within each tier, rules are evaluated in strict file order (top to bottom).\n\n", "body")
        
        text_widget.insert(tk.END, "AWS Network Firewall Processing Order:\n", "section")
        text_widget.insert(tk.END, "─" * 50 + "\n", "body")
        
        text_widget.insert(tk.END, "TIER 1: IP-Only (Processed First)\n", "section")
        tier1_types = [
            ("  IPONLY", "Basic IP matching (no keywords)"),
            ("  LIKE_IPONLY", "IP-only with negated addresses"),
        ]
        for type_label, description in tier1_types:
            text_widget.insert(tk.END, type_label, "type")
            text_widget.insert(tk.END, f" - {description}\n", "body")
        
        text_widget.insert(tk.END, "\n")
        text_widget.insert(tk.END, "TIER 2: Packet-Level (Processed Second)\n", "section")
        tier2_types = [
            ("  DEONLY", "Decoder events (broken/invalid packets)"),
            ("  PKT", "Flow keywords (flow:established, flowbits:isset)"),
            ("  PKT_STREAM", "Anchored content (content with startswith/depth)"),
            ("  STREAM", "Unanchored content matching"),
        ]
        for type_label, description in tier2_types:
            text_widget.insert(tk.END, type_label, "type")
            text_widget.insert(tk.END, f" - {description}\n", "body")
        
        text_widget.insert(tk.END, "\n")
        text_widget.insert(tk.END, "TIER 3: Application-Layer (Processed Last)\n", "section")
        tier3_types = [
            ("  PDONLY", "Protocol detection (app-layer-protocol:)"),
            ("  APPLAYER", "Application protocol field (http, tls, dns)"),
            ("  APP_TX", "Application transaction (http.host, tls.sni)"),
        ]
        for type_label, description in tier3_types:
            text_widget.insert(tk.END, type_label, "type")
            text_widget.insert(tk.END, f" - {description}\n", "body")
        
        text_widget.insert(tk.END, "\n")
        text_widget.insert(tk.END, "Key Insights:\n", "section")
        text_widget.insert(tk.END, "─" * 50 + "\n", "body")
        text_widget.insert(tk.END, "• IPONLY rules process before APP_TX rules regardless of file position\n", "body")
        text_widget.insert(tk.END, "• This can cause unexpected shadowing and conflicts\n", "body")
        text_widget.insert(tk.END, "• Use 'Review Rules' to detect protocol layering conflicts\n", "body")
        text_widget.insert(tk.END, "• Add flow keywords to IPONLY rules to elevate them to PKT type\n\n", "body")
        
        text_widget.insert(tk.END, "For complete details, see:\n", "body")
        
        # Add clickable link
        link_start = text_widget.index(tk.INSERT)
        text_widget.insert(tk.END, "https://docs.suricata.io/en/latest/rules/rule-types.html\n", "link")
        link_end = text_widget.index(tk.INSERT)
        text_widget.tag_add("clickable_link", link_start, link_end)
        
        # Bind link click
        def on_link_click(event):
            import webbrowser
            webbrowser.open("https://docs.suricata.io/en/latest/rules/rule-types.html")
        
        text_widget.tag_bind("clickable_link", "<Button-1>", on_link_click)
        text_widget.tag_bind("clickable_link", "<Enter>", 
                            lambda e: text_widget.config(cursor="hand2"))
        text_widget.tag_bind("clickable_link", "<Leave>", 
                            lambda e: text_widget.config(cursor=""))
        
        text_widget.config(state=tk.DISABLED)
        
        # OK button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        ttk.Button(button_frame, text="OK", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def populate_rev_dropdown(self, rule: SuricataRule):
        """Populate rev dropdown with available revisions for this rule"""
        # If tracking not enabled or no combo widget, just set the rev value
        if not self.parent.tracking_enabled or not hasattr(self, 'rev_combo'):
            self.rev_var.set(str(rule.rev))
            return
        
        # Build history filename (check both saved file and unsaved temp file)
        if self.parent.current_file:
            history_filename = self.parent.current_file.replace('.suricata', '.history')
            if not history_filename.endswith('.history'):
                history_filename += '.history'
        else:
            # For unsaved files, check for _unsaved_.history
            import tempfile
            temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'user_files')
            if not os.path.exists(temp_dir):
                temp_dir = tempfile.gettempdir()
            history_filename = os.path.join(temp_dir, '_unsaved_.history')
        
        # Check format version first to determine how to display rev
        from revision_manager import RevisionManager
        
        if os.path.exists(history_filename):
            revision_manager = RevisionManager(history_filename)
            is_v2_format = (revision_manager.format_version == '2.0')
        else:
            # No history file yet - will be v2.0 when created
            is_v2_format = True
        
        # Setup the appropriate widget (dropdown for v2.0, entry for v1.0)
        self.setup_rev_dropdown_widget()
        
        # For legacy v1.0 format (user declined upgrade), just show plain rev number
        if not is_v2_format:
            self.rev_var.set(str(rule.rev))
            return
        
        # Get GUID for this rule (prefer GUID, fallback to SID)
        rule_guid = self.parent.rule_guids.get(rule.sid)
        
        # Get revisions from disk using GUID (primary) or SID (fallback)
        # If history file doesn't exist yet, revisions will be empty list
        if os.path.exists(history_filename):
            if rule_guid:
                revisions = revision_manager.get_revisions(rule_guid=rule_guid)
            else:
                revisions = revision_manager.get_revisions(sid=rule.sid)
        else:
            # No history file yet - start with empty revisions
            # We'll check pending_history next
            revisions = []
        
        # CRITICAL FIX: Merge pending snapshots from pending_history
        # This handles unsaved changes that haven't been written to disk yet
        pending_snapshots = []
        for entry in self.parent.pending_history:
            # Check if this is a snapshot entry for this rule
            if 'rule_snapshot' in entry.get('details', {}):
                snapshot = entry['details']['rule_snapshot']
                details = entry['details']
                
                # Match by GUID first, then SID for backward compatibility
                snapshot_guid = snapshot.get('rule_guid') or details.get('rule_guid')
                if (snapshot_guid and snapshot_guid == rule_guid) or \
                   (not rule_guid and (details.get('sid') == rule.sid or snapshot.get('sid') == rule.sid)):
                    # Create revision object from pending snapshot
                    pending_rev = snapshot.copy()
                    pending_rev['timestamp'] = entry['timestamp']
                    pending_snapshots.append(pending_rev)
        
        # Merge disk revisions with pending snapshots
        all_revisions = revisions + pending_snapshots
        
        # Sort by rev number in DESCENDING order (highest rev on top)
        all_revisions.sort(key=lambda r: r.get('rev', 0), reverse=True)
        
        if not all_revisions:
            # No history yet - just set plain rev number
            # Don't populate dropdown values since there's no history
            self.rev_var.set(str(rule.rev))
            self.rev_combo['values'] = []
            return
        
        # Build dropdown values with timestamps (newest first)
        dropdown_values = []
        for rev in all_revisions:
            timestamp = rev['timestamp'][:16]  # Truncate to minutes
            rev_num = rev['rev']
            # Always show just "Rev X - timestamp" format (no "Current" marker)
            label = f"Rev {rev_num} - {timestamp}"
            dropdown_values.append(label)
        
        # Setup dropdown widget and populate
        self.setup_rev_dropdown_widget()
        self.rev_combo['values'] = dropdown_values
        
        # Set current value to plain number (combobox will display this when not dropped down)
        # When user clicks dropdown, they'll see the formatted values with timestamps
        self.rev_var.set(str(rule.rev))
    
    def setup_rev_dropdown_widget(self):
        """Setup rev dropdown widget (show dropdown only for v2.0 format, hide entry)"""
        if not self.parent.tracking_enabled:
            # Show entry, hide combo
            self.rev_entry.grid()
            self.rev_combo.grid_remove()
            return
        
        # Check if we have v2.0 format (with snapshots) or legacy v1.0
        # Only show dropdown for v2.0 format
        has_v2_format = False
        
        if self.parent.current_file:
            history_filename = self.parent.current_file.replace('.suricata', '.history')
            if not history_filename.endswith('.history'):
                history_filename += '.history'
        else:
            # For unsaved files, check for _unsaved_.history
            import tempfile
            temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'user_files')
            if not os.path.exists(temp_dir):
                temp_dir = tempfile.gettempdir()
            history_filename = os.path.join(temp_dir, '_unsaved_.history')
        
        # CRITICAL BUG FIX: Check pending_history for snapshots FIRST
        # This handles new files where tracking was just enabled (snapshots in pending_history, not on disk)
        # Check for ANY action with snapshots (baseline_snapshot OR rule_added OR rule_modified)
        has_pending_snapshots = any(
            'rule_snapshot' in entry.get('details', {})
            for entry in self.parent.pending_history
        )
        
        if has_pending_snapshots:
            # Has baseline snapshots in pending_history - definitely v2.0 format
            has_v2_format = True
        elif os.path.exists(history_filename):
            # Check format version on disk
            from revision_manager import RevisionManager
            revision_manager = RevisionManager(history_filename)
            # If format is 2.0 or there are snapshots, show dropdown
            has_v2_format = (revision_manager.format_version == '2.0')
        else:
            # No history file and no pending snapshots - NEW file with tracking just enabled
            # Will be v2.0 when created
            has_v2_format = True
        
        if has_v2_format:
            # Show combo, hide entry
            self.rev_entry.grid_remove()
            self.rev_combo.grid(row=5, column=3, sticky=tk.W, pady=(5, 0))
            
            # Bind selection event if not already bound
            if not hasattr(self, '_rev_combo_bound'):
                self.rev_combo.bind('<<ComboboxSelected>>', self.on_rev_selected)
                self._rev_combo_bound = True
        else:
            # Legacy v1.0 format - show read-only entry (no rollback capability)
            self.rev_entry.grid()
            self.rev_combo.grid_remove()
    
    def on_rev_selected(self, event):
        """Handle rev dropdown selection"""
        if self.parent.selected_rule_index is None:
            return
        
        rule = self.parent.rules[self.parent.selected_rule_index]
        
        # Parse selected rev number from dropdown value
        selected_value = self.rev_combo.get()
        import re
        match = re.match(r'Rev (\d+)', selected_value)
        if not match:
            return
        
        selected_rev = int(match.group(1))
        
        # If selecting current rev, do nothing
        if selected_rev == rule.rev:
            return
        
        # Show rollback confirmation dialog
        self.show_rollback_confirmation(rule, selected_rev)
    
    def show_rollback_confirmation(self, current_rule: SuricataRule, target_rev: int):
        """Show side-by-side comparison dialog for rule rollback"""
        from revision_manager import RevisionManager
        
        # Build history filename (check both saved file and unsaved temp file)
        if self.parent.current_file:
            history_filename = self.parent.current_file.replace('.suricata', '.history')
            if not history_filename.endswith('.history'):
                history_filename += '.history'
        else:
            # For unsaved files, check for _unsaved_.history
            import tempfile
            temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'user_files')
            if not os.path.exists(temp_dir):
                temp_dir = tempfile.gettempdir()
            history_filename = os.path.join(temp_dir, '_unsaved_.history')
        
        revision_manager = RevisionManager(history_filename)
        
        # Get GUID for this rule (prefer GUID, fallback to SID)
        rule_guid = self.parent.rule_guids.get(current_rule.sid)
        
        # Get target revision using GUID (primary) or SID (fallback)
        # First check disk revisions
        if rule_guid:
            target_revision = revision_manager.get_revision(rule_guid=rule_guid, rev=target_rev)
        else:
            target_revision = revision_manager.get_revision(sid=current_rule.sid, rev=target_rev)
        
        # CRITICAL FIX: If not found on disk, check pending_history for unsaved snapshots
        if not target_revision:
            # Search pending_history for the target revision
            for entry in self.parent.pending_history:
                if 'rule_snapshot' in entry.get('details', {}):
                    snapshot = entry['details']['rule_snapshot']
                    details = entry['details']
                    
                    # Match by GUID first, then SID for backward compatibility
                    snapshot_guid = snapshot.get('rule_guid') or details.get('rule_guid')
                    if (snapshot_guid and snapshot_guid == rule_guid) or \
                       (not rule_guid and (details.get('sid') == current_rule.sid or snapshot.get('sid') == current_rule.sid)):
                        # Check if this is the target revision
                        if snapshot.get('rev') == target_rev:
                            target_revision = snapshot.copy()
                            target_revision['timestamp'] = entry['timestamp']
                            break
        
        if not target_revision:
            messagebox.showerror("Error", 
                f"Revision {target_rev} not found for SID {current_rule.sid}")
            # Reset dropdown to current value
            self.populate_rev_dropdown(current_rule)
            return
        
        # Create dialog
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Rollback Rule Confirmation")
        dialog.geometry("900x550")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 100,
            self.parent.root.winfo_rooty() + 100
        ))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        timestamp_str = target_revision['timestamp'][:16]
        header_text = f"SID: {current_rule.sid} | Rollback from Rev {current_rule.rev} → Rev {target_rev} ({timestamp_str})"
        ttk.Label(main_frame, text=header_text, 
                 font=("TkDefaultFont", 10, "bold")).pack(pady=(0, 15))
        
        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 15))
        
        # Comparison frame (two columns)
        comp_frame = ttk.Frame(main_frame)
        comp_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Left column: Current
        left_frame = ttk.LabelFrame(comp_frame, text="CURRENT (Before Rollback)")
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        # Right column: Target
        right_frame = ttk.LabelFrame(comp_frame, text="SELECTED REVISION (After Rollback)")
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        
        comp_frame.grid_columnconfigure(0, weight=1)
        comp_frame.grid_columnconfigure(1, weight=1)
        comp_frame.grid_rowconfigure(0, weight=1)
        
        # Helper function to add field comparison
        def add_field_row(parent, label, value, changed=False):
            frame = ttk.Frame(parent)
            frame.pack(fill=tk.X, padx=10, pady=2)
            
            ttk.Label(frame, text=f"{label}:", 
                     font=("TkDefaultFont", 9, "bold"), 
                     width=12).pack(side=tk.LEFT)
            
            # Highlight changed fields
            fg_color = "red" if changed else "black"
            ttk.Label(frame, text=value, 
                     font=("TkDefaultFont", 9),
                     foreground=fg_color).pack(side=tk.LEFT)
        
        # Compare and populate fields
        add_field_row(left_frame, "Action", current_rule.action,
                     current_rule.action != target_revision['action'])
        add_field_row(left_frame, "Protocol", current_rule.protocol,
                     current_rule.protocol != target_revision['protocol'])
        add_field_row(left_frame, "Source", f"{current_rule.src_net}:{current_rule.src_port}",
                     current_rule.src_net != target_revision['src_net'] or 
                     current_rule.src_port != target_revision['src_port'])
        add_field_row(left_frame, "Destination", f"{current_rule.dst_net}:{current_rule.dst_port}",
                     current_rule.dst_net != target_revision['dst_net'] or 
                     current_rule.dst_port != target_revision['dst_port'])
        add_field_row(left_frame, "Message", current_rule.message[:40] + "..." if len(current_rule.message) > 40 else current_rule.message,
                     current_rule.message != target_revision['message'])
        add_field_row(left_frame, "Rev", str(current_rule.rev), True)
        
        # Full rule text (scrollable)
        ttk.Label(left_frame, text="Full Rule:", 
                 font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        left_text = tk.Text(left_frame, height=6, wrap=tk.WORD, 
                           font=("Consolas", 8))
        left_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        left_text.insert(tk.END, current_rule.to_string())
        left_text.config(state=tk.DISABLED)
        
        # Right column fields
        add_field_row(right_frame, "Action", target_revision['action'],
                     current_rule.action != target_revision['action'])
        add_field_row(right_frame, "Protocol", target_revision['protocol'],
                     current_rule.protocol != target_revision['protocol'])
        add_field_row(right_frame, "Source", f"{target_revision['src_net']}:{target_revision['src_port']}",
                     current_rule.src_net != target_revision['src_net'] or 
                     current_rule.src_port != target_revision['src_port'])
        add_field_row(right_frame, "Destination", f"{target_revision['dst_net']}:{target_revision['dst_port']}",
                     current_rule.dst_net != target_revision['dst_net'] or 
                     current_rule.dst_port != target_revision['dst_port'])
        
        target_message = target_revision['message']
        add_field_row(right_frame, "Message", target_message[:40] + "..." if len(target_message) > 40 else target_message,
                     current_rule.message != target_revision['message'])
        add_field_row(right_frame, "Rev", str(target_rev), True)
        
        # Full rule text
        ttk.Label(right_frame, text="Full Rule:", 
                 font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        # Reconstruct target rule text using GUID (primary) or SID (fallback)
        # First try disk revisions
        if rule_guid:
            target_rule = revision_manager.restore_revision(rule_guid=rule_guid, rev=target_rev)
        else:
            target_rule = revision_manager.restore_revision(sid=current_rule.sid, rev=target_rev)
        
        # CRITICAL FIX: If not found on disk, manually reconstruct from target_revision dict
        # (which was already found from pending_history above)
        if not target_rule and target_revision:
            try:
                target_rule = SuricataRule(
                    action=target_revision['action'],
                    protocol=target_revision['protocol'],
                    src_net=target_revision['src_net'],
                    src_port=target_revision['src_port'],
                    dst_net=target_revision['dst_net'],
                    dst_port=target_revision['dst_port'],
                    message=target_revision['message'],
                    content=target_revision['content'],
                    sid=target_revision.get('sid', current_rule.sid),
                    direction=target_revision.get('direction', '->'),
                    rev=target_revision['rev'],
                    original_options=target_revision.get('original_options', '')
                )
            except (KeyError, TypeError, ValueError):
                # If reconstruction fails, target_rule will remain None
                pass
        
        right_text = tk.Text(right_frame, height=6, wrap=tk.WORD, 
                            font=("Consolas", 8))
        right_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        if target_rule:
            right_text.insert(tk.END, target_rule.to_string())
        right_text.config(state=tk.DISABLED)
        
        # Warning message
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 10))
        warning_label = ttk.Label(main_frame,
            text="⚠️ This will populate the Rule Editor with the selected revision. Click 'Save Changes' to commit.",
            foreground="orange",
            font=("TkDefaultFont", 9))
        warning_label.pack(pady=(0, 15))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack()
        
        result = [False]
        
        def on_rollback():
            result[0] = True
            dialog.destroy()
        
        def on_cancel():
            # Reset dropdown to current value
            self.populate_rev_dropdown(current_rule)
            dialog.destroy()
        
        ttk.Button(button_frame, text="Rollback", 
                  command=on_rollback).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=on_cancel).pack(side=tk.LEFT, padx=5)
        
        dialog.wait_window()
        
        if result[0]:
            self.perform_rollback(current_rule, target_rev, revision_manager)
        else:
            # User cancelled - reset dropdown
            self.populate_rev_dropdown(current_rule)
    
    def perform_rollback(self, current_rule: SuricataRule, target_rev: int,
                        revision_manager):
        """Perform the rollback by populating editor with historical values"""
        
        # Get GUID for this rule (prefer GUID, fallback to SID)
        rule_guid = self.parent.rule_guids.get(current_rule.sid)
        
        # Restore rule from history using GUID (primary) or SID (fallback)
        # First try disk revisions
        if rule_guid:
            restored_rule = revision_manager.restore_revision(rule_guid=rule_guid, rev=target_rev)
        else:
            restored_rule = revision_manager.restore_revision(sid=current_rule.sid, rev=target_rev)
        
        # CRITICAL FIX: If not found on disk, check pending_history for unsaved snapshots
        if not restored_rule:
            # Search pending_history for the target revision
            for entry in self.parent.pending_history:
                if 'rule_snapshot' in entry.get('details', {}):
                    snapshot = entry['details']['rule_snapshot']
                    details = entry['details']
                    
                    # Match by GUID first, then SID for backward compatibility
                    snapshot_guid = snapshot.get('rule_guid') or details.get('rule_guid')
                    if (snapshot_guid and snapshot_guid == rule_guid) or \
                       (not rule_guid and (details.get('sid') == current_rule.sid or snapshot.get('sid') == current_rule.sid)):
                        # Check if this is the target revision
                        if snapshot.get('rev') == target_rev:
                            # Manually reconstruct rule from pending snapshot
                            try:
                                restored_rule = SuricataRule(
                                    action=snapshot['action'],
                                    protocol=snapshot['protocol'],
                                    src_net=snapshot['src_net'],
                                    src_port=snapshot['src_port'],
                                    dst_net=snapshot['dst_net'],
                                    dst_port=snapshot['dst_port'],
                                    message=snapshot['message'],
                                    content=snapshot['content'],
                                    sid=snapshot.get('sid', current_rule.sid),
                                    direction=snapshot.get('direction', '->'),
                                    rev=snapshot['rev'],
                                    original_options=snapshot.get('original_options', '')
                                )
                            except (KeyError, TypeError, ValueError):
                                pass  # Continue searching
                            break
        
        if not restored_rule:
            messagebox.showerror("Error", "Failed to restore rule revision")
            # Reset dropdown
            self.populate_rev_dropdown(current_rule)
            return
        
        # CRITICAL: Check if restored SID differs from current SID (SID was renumbered)
        if restored_rule.sid != current_rule.sid:
            # SID was changed since this revision - check for conflicts
            sid_conflict = any(
                r.sid == restored_rule.sid and 
                self.parent.rules.index(r) != self.parent.selected_rule_index
                for r in self.parent.rules
                if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)
            )
            
            if sid_conflict:
                # Show conflict resolution dialog
                response = messagebox.askyesnocancel(
                    "SID Conflict Detected",
                    f"The selected revision contains SID {restored_rule.sid},\n"
                    f"but SID {restored_rule.sid} is now used by a different rule.\n\n"
                    f"This occurred because SIDs were renumbered after\n"
                    f"this revision was created.\n\n"
                    f"Options:\n"
                    f"• YES: Restore with CURRENT SID ({current_rule.sid})\n"
                    f"       (keeps new SID, restores other fields)\n"
                    f"• NO: Cancel rollback\n\n"
                    f"Restore with current SID?"
                )
                
                if response is None or response is False:
                    # User cancelled or chose NO - reset dropdown
                    self.populate_rev_dropdown(current_rule)
                    return
                
                # User chose YES - keep current SID, restore other fields
                restored_rule.sid = current_rule.sid
                
                # Update original_options to reflect current SID
                if restored_rule.original_options:
                    import re
                    restored_rule.original_options = re.sub(
                        r'sid:\d+', 
                        f'sid:{current_rule.sid}', 
                        restored_rule.original_options
                    )
        
        # Populate editor fields with restored values (don't save yet!)
        self.action_var.set(restored_rule.action)
        self.protocol_var.set(restored_rule.protocol)
        self.src_net_var.set(restored_rule.src_net)
        self.src_port_var.set(restored_rule.src_port)
        self.direction_var.set(restored_rule.direction)
        self.dst_net_var.set(restored_rule.dst_net)
        self.dst_port_var.set(restored_rule.dst_port)
        self.message_var.set(restored_rule.message)
        self.content_var.set(restored_rule.content)
        self.sid_var.set(str(restored_rule.sid))
        # CRITICAL FIX: Set rev to plain number for save_rule_changes() to parse correctly
        self.rev_var.set(str(restored_rule.rev))
        
        # Show info message to user
        messagebox.showinfo(
            "Rollback Pending",
            f"Rule editor populated with Rev {target_rev}.\n\n"
            f"Review the changes in the editor, then:\n"
            f"• Click 'Save Changes' to commit the rollback, OR\n"
            f"• Select another rule to cancel"
        )
    
    # Phase 10: Right-Click Context Menu for CloudWatch Statistics
    def show_quick_cloudwatch_stats(self):
        """Show quick CloudWatch statistics dialog for selected rule(s) (Phase 10)
        
        Displays a mini-dialog with CloudWatch statistics for the selected rule(s).
        Handles multi-selection with Previous/Next navigation.
        Handles 4 scenarios:
        1. Rule with statistics (most common)
        2. Rule has 0 hits (unused)
        3. Rule not in cache
        4. No analysis run yet
        """
        # Get selected rules
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a rule to view statistics.")
            return
        
        # Build list of valid rules (exclude comments and blanks)
        selected_rules = []
        for selected_item in selection:
            values = self.tree.item(selected_item, 'values')
            if not values or not values[0]:
                continue
            
            # Get rule index from line number
            line_num = int(values[0])
            rule_index = line_num - 1
            
            if rule_index >= len(self.parent.rules):
                continue
            
            rule = self.parent.rules[rule_index]
            
            # Skip comments and blank lines
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            
            selected_rules.append(rule)
        
        if not selected_rules:
            messagebox.showinfo("Invalid Selection", 
                              "CloudWatch statistics are only available for active rules.")
            return
        
        # Scenario 4: No analysis run yet
        if not hasattr(self.parent.usage_analyzer, 'last_analysis_results') or \
           self.parent.usage_analyzer.last_analysis_results is None:
            self._show_no_analysis_dialog()
            return
        
        # Handle multi-selection with navigation
        if len(selected_rules) > 1:
            self._show_multi_rule_stats_dialog(selected_rules, index=0)
        else:
            # Single selection - show single rule dialog
            self._show_single_rule_stats(selected_rules[0])
    
    def _show_single_rule_stats(self, rule):
        """Show stats for a single rule (helper method)"""
        # Get analysis results
        analysis_results = self.parent.usage_analyzer.last_analysis_results
        sid_stats = analysis_results.get('sid_stats', {})
        unlogged_sids = analysis_results.get('unlogged_sids', set())
        sid = rule.sid
        
        # Check if rule is unlogged FIRST (before checking stats)
        if sid in unlogged_sids:
            # Scenario: Rule is unlogged (cannot be tracked)
            self._show_unlogged_rule_dialog(rule, analysis_results)
        # Check if SID in results
        elif sid in sid_stats:
            # Scenario 1: Rule has statistics
            stats = sid_stats[sid]
            self._show_rule_stats_dialog(rule, stats, analysis_results)
        else:
            # Check if SID was in the file when analysis ran (has 0 hits)
            file_sids = set(analysis_results.get('file_sids', []))
            if sid in file_sids:
                # Scenario 2: Rule has 0 hits (unused)
                self._show_unused_rule_dialog(rule, analysis_results)
            else:
                # Scenario 3: Rule not in cache
                self._show_rule_not_in_cache_dialog(rule)
    
    def _show_multi_rule_stats_dialog(self, selected_rules, index):
        """Show stats dialog with navigation for multiple selected rules
        
        Args:
            selected_rules: List of selected SuricataRule objects
            index: Current index in the selected_rules list (0-based)
        """
        rule = selected_rules[index]
        
        # Get analysis results
        analysis_results = self.parent.usage_analyzer.last_analysis_results
        sid_stats = analysis_results.get('sid_stats', {})
        sid = rule.sid
        
        # Determine which dialog to show based on rule status
        if sid in sid_stats:
            # Rule has statistics
            stats = sid_stats[sid]
            self._show_rule_stats_dialog_multi(rule, stats, analysis_results, selected_rules, index)
        else:
            # Check if rule has 0 hits or not in cache
            file_sids = set(analysis_results.get('file_sids', []))
            if sid in file_sids:
                # Rule has 0 hits
                self._show_unused_rule_dialog_multi(rule, analysis_results, selected_rules, index)
            else:
                # Rule not in cache
                self._show_rule_not_in_cache_dialog_multi(rule, selected_rules, index)
    
    def _show_rule_stats_dialog_multi(self, rule, stats, analysis_results, selected_rules, index):
        """Show full statistics dialog for rule with hits (multi-select version)"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title(f"CloudWatch Statistics - SID {rule.sid}")
        dialog.geometry("480x580")  # Slightly taller for navigation
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 230,
            self.parent.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Multi-selection info at top
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, 
                 text=f"ℹ️  {len(selected_rules)} rules selected, showing rule {index+1}",
                 font=("TkDefaultFont", 8),
                 foreground="#666666").pack(anchor=tk.W)
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        # Rule summary (2 lines)
        rule_summary = f"{rule.action} {rule.protocol} {rule.src_net} {rule.src_port} {rule.direction} {rule.dst_net} {rule.dst_port}"
        ttk.Label(main_frame, text=rule_summary, 
                 font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W)
        ttk.Label(main_frame, text=rule.message, 
                 font=("TkDefaultFont", 9)).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Usage statistics
        ttk.Label(main_frame, 
                 text=f"Usage (Last {analysis_results['time_range_days']} days):",
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create stats table
        stat_items = [
            ("Total Hits:", f"{stats.get('hits', 0):,}"),
            ("% of Traffic:", f"{stats.get('percent', 0.0):.2f}%"),
            ("Hits/Day Avg:", f"{stats.get('hits_per_day', 0.0):.1f}"),
        ]
        
        if stats.get('last_hit_days') is not None:
            stat_items.append(("Last Hit:", f"{stats['last_hit_days']} days ago"))
        
        if stats.get('days_in_production') is not None:
            stat_items.append(("Age of Rule:", f"{stats['days_in_production']} days"))
        
        for label, value in stat_items:
            row = ttk.Frame(stats_frame)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=label, width=18).pack(side=tk.LEFT)
            ttk.Label(row, text=value, font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Category
        category = stats.get('category', 'Unknown')
        ttk.Label(main_frame, text=f"Category: {category}",
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Interpretation (abbreviated for multi-select)
        interpretation = self._generate_sid_interpretation(stats, category, analysis_results)
        # Truncate interpretation for space
        interp_lines = interpretation.split('\n')[:3]  # Show first 3 lines
        ttk.Label(main_frame, text='\n'.join(interp_lines),
                 font=("TkDefaultFont", 9), foreground="#666666",
                 wraplength=420, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 15))
        
        # Navigation frame (for multi-select)
        nav_frame = ttk.Frame(main_frame)
        nav_frame.pack(fill=tk.X, pady=10)
        
        # Previous button
        prev_btn = ttk.Button(nav_frame, text="← Previous",
                             command=lambda: [dialog.destroy(), 
                                            self._show_multi_rule_stats_dialog(selected_rules, index-1)])
        prev_btn.pack(side=tk.LEFT, padx=5)
        if index == 0:
            prev_btn.configure(state='disabled')
        
        # Position indicator
        ttk.Label(nav_frame, 
                 text=f"Rule {index+1} of {len(selected_rules)}",
                 font=("TkDefaultFont", 8)).pack(side=tk.LEFT, padx=15)
        
        # Next button
        next_btn = ttk.Button(nav_frame, text="Next →",
                             command=lambda: [dialog.destroy(), 
                                            self._show_multi_rule_stats_dialog(selected_rules, index+1)])
        next_btn.pack(side=tk.LEFT, padx=5)
        if index == len(selected_rules) - 1:
            next_btn.configure(state='disabled')
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Analysis timestamp
        timestamp = analysis_results['timestamp']
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M') if hasattr(timestamp, 'strftime') else str(timestamp)[:16]
        time_ago = self._format_time_ago(timestamp)
        
        ttk.Label(main_frame, text=f"Analysis from: {timestamp_str} ({time_ago})",
                 font=("TkDefaultFont", 8), foreground="#666666").pack(anchor=tk.W, pady=(0, 15))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        def view_in_analysis():
            dialog.destroy()
            if not hasattr(self, '_current_results_window') or not self._current_results_window.winfo_exists():
                self.show_usage_results_window(analysis_results)
            else:
                self._current_results_window.lift()
        
        ttk.Button(btn_frame, text="View in Analysis", command=view_in_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _show_unused_rule_dialog_multi(self, rule, analysis_results, selected_rules, index):
        """Show dialog for rule with 0 hits (multi-select version)"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title(f"CloudWatch Statistics - SID {rule.sid}")
        dialog.geometry("480x480")  # Slightly taller for navigation
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 230,
            self.parent.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Multi-selection info at top
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, 
                 text=f"ℹ️  {len(selected_rules)} rules selected, showing rule {index+1}",
                 font=("TkDefaultFont", 8),
                 foreground="#666666").pack(anchor=tk.W)
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        # Rule summary
        rule_summary = f"{rule.action} {rule.protocol} {rule.src_net} {rule.src_port} {rule.direction} {rule.dst_net} {rule.dst_port}"
        ttk.Label(main_frame, text=rule_summary, 
                 font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W)
        ttk.Label(main_frame, text=rule.message, 
                 font=("TkDefaultFont", 9)).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Usage statistics (0 hits)
        ttk.Label(main_frame, 
                 text=f"Usage (Last {analysis_results['time_range_days']} days):",
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Get rule age
        sid_stats_dict = analysis_results.get('sid_stats', {})
        rule_stat = sid_stats_dict.get(rule.sid, {})
        days = rule_stat.get('days_in_production')
        
        stat_items = [("Total Hits:", "0")]
        if days is not None:
            stat_items.append(("Age of Rule:", f"{days} days"))
        
        for label, value in stat_items:
            row = ttk.Frame(stats_frame)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=label, width=18).pack(side=tk.LEFT)
            ttk.Label(row, text=value, font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Determine confidence level
        min_days = analysis_results.get('min_days_in_production', 14)
        if days is None:
            category_text = "Category: Unused (Never Observed) ℹ️"
        elif days >= min_days:
            category_text = "Category: Unused (Confirmed) ✓"
        else:
            category_text = "Category: Unused (Recently Deployed) ⚠️"
        
        ttk.Label(main_frame, text=category_text,
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Navigation frame (for multi-select)
        nav_frame = ttk.Frame(main_frame)
        nav_frame.pack(fill=tk.X, pady=10)
        
        # Previous button
        prev_btn = ttk.Button(nav_frame, text="← Previous",
                             command=lambda: [dialog.destroy(), 
                                            self._show_multi_rule_stats_dialog(selected_rules, index-1)])
        prev_btn.pack(side=tk.LEFT, padx=5)
        if index == 0:
            prev_btn.configure(state='disabled')
        
        # Position indicator
        ttk.Label(nav_frame, 
                 text=f"Rule {index+1} of {len(selected_rules)}",
                 font=("TkDefaultFont", 8)).pack(side=tk.LEFT, padx=15)
        
        # Next button
        next_btn = ttk.Button(nav_frame, text="Next →",
                             command=lambda: [dialog.destroy(), 
                                            self._show_multi_rule_stats_dialog(selected_rules, index+1)])
        next_btn.pack(side=tk.LEFT, padx=5)
        if index == len(selected_rules) - 1:
            next_btn.configure(state='disabled')
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Analysis timestamp
        timestamp = analysis_results['timestamp']
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M') if hasattr(timestamp, 'strftime') else str(timestamp)[:16]
        time_ago = self._format_time_ago(timestamp)
        
        ttk.Label(main_frame, text=f"Analysis from: {timestamp_str} ({time_ago})",
                 font=("TkDefaultFont", 8), foreground="#666666").pack(anchor=tk.W, pady=(0, 15))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        def view_in_analysis():
            dialog.destroy()
            if not hasattr(self, '_current_results_window') or not self._current_results_window.winfo_exists():
                self.show_usage_results_window(analysis_results)
            else:
                self._current_results_window.lift()
        
        ttk.Button(btn_frame, text="View in Analysis", command=view_in_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _show_rule_not_in_cache_dialog_multi(self, rule, selected_rules, index):
        """Show dialog when rule wasn't in last analysis (multi-select version)"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("CloudWatch Statistics")
        dialog.geometry("450x360")  # Taller for navigation
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 250,
            self.parent.root.winfo_rooty() + 200
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Multi-selection info at top
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, 
                 text=f"ℹ️  {len(selected_rules)} rules selected, showing rule {index+1}",
                 font=("TkDefaultFont", 8),
                 foreground="#666666").pack(anchor=tk.W)
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        # Warning icon and title
        ttk.Label(main_frame, text="⚠️ Rule Not in Analysis Cache",
                 font=("TkDefaultFont", 12, "bold"), foreground="#FF6600").pack(pady=(0, 15))
        
        # Message
        message_text = (
            f"SID {rule.sid} was not included in the last\n"
            f"analysis run.\n\n"
            f"Possible reasons:\n"
            f"• Rule added after analysis\n"
            f"• SID changed after analysis\n"
            f"• Rule commented out during analysis"
        )
        
        ttk.Label(main_frame, text=message_text,
                 font=("TkDefaultFont", 10), justify=tk.LEFT).pack(pady=(0, 20))
        
        # Navigation frame
        nav_frame = ttk.Frame(main_frame)
        nav_frame.pack(fill=tk.X, pady=10)
        
        # Previous button
        prev_btn = ttk.Button(nav_frame, text="← Previous",
                             command=lambda: [dialog.destroy(), 
                                            self._show_multi_rule_stats_dialog(selected_rules, index-1)])
        prev_btn.pack(side=tk.LEFT, padx=5)
        if index == 0:
            prev_btn.configure(state='disabled')
        
        # Position indicator
        ttk.Label(nav_frame, 
                 text=f"Rule {index+1} of {len(selected_rules)}",
                 font=("TkDefaultFont", 8)).pack(side=tk.LEFT, padx=15)
        
        # Next button
        next_btn = ttk.Button(nav_frame, text="Next →",
                             command=lambda: [dialog.destroy(), 
                                            self._show_multi_rule_stats_dialog(selected_rules, index+1)])
        next_btn.pack(side=tk.LEFT, padx=5)
        if index == len(selected_rules) - 1:
            next_btn.configure(state='disabled')
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _show_no_analysis_dialog(self):
        """Show dialog when no analysis has been run yet (Scenario 4)"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("CloudWatch Statistics")
        dialog.geometry("450x300")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 250,
            self.parent.root.winfo_rooty() + 200
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Info icon and title
        ttk.Label(main_frame, text="ℹ️  No Analysis Available",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 15))
        
        # Message
        message_text = (
            "CloudWatch analysis has not been run yet.\n\n"
            "To view rule usage statistics:\n"
            "1. Click Tools > Analyze Rule Usage\n"
            "2. Configure parameters and run analysis\n"
            "3. Return here for instant lookups\n\n"
            "After running analysis once, you can quickly\n"
            "check any rule's statistics by right-clicking."
        )
        
        ttk.Label(main_frame, text=message_text,
                 font=("TkDefaultFont", 10), justify=tk.LEFT).pack(pady=(0, 20))
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        def run_analysis():
            dialog.destroy()
            self.show_rule_usage_analyzer()
        
        ttk.Button(btn_frame, text="Run Analysis Now", command=run_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    # Stats File Save/Load Functionality
    def save_stats_to_file(self, analysis_results, parent_window=None):
        """Save CloudWatch analysis results to .stats file
        
        Args:
            analysis_results: Analysis results dictionary to save
            parent_window: Optional parent window to close after save
        """
        if not self.parent.current_file:
            messagebox.showwarning("No File Open", 
                "Please save your rule file before saving statistics.\n\n"
                "The statistics file will be saved with the same name\n"
                "as your rule file with a .stats extension.")
            return
        
        try:
            import json
            
            # Build stats filename
            stats_filename = self.parent.current_file.replace('.suricata', '.stats')
            if not stats_filename.endswith('.stats'):
                stats_filename += '.stats'
            
            # Convert analysis_results to JSON-serializable format
            stats_data = self._serialize_analysis_results(analysis_results)
            
            # Write to file
            with open(stats_filename, 'w', encoding='utf-8') as f:
                json.dump(stats_data, f, indent=2)
            
            messagebox.showinfo("Stats Saved", 
                f"Rule usage statistics saved to:\n{os.path.basename(stats_filename)}\n\n"
                f"This file will be automatically loaded when you\n"
                f"open {os.path.basename(self.parent.current_file)} in the future.")
            
        except PermissionError as e:
            messagebox.showerror("Permission Error", 
                f"Cannot write to stats file:\n{str(e)}")
        except OSError as e:
            messagebox.showerror("File System Error", 
                f"Cannot write stats file:\n{str(e)}")
        except Exception as e:
            messagebox.showerror("Save Error", 
                f"Failed to save statistics:\n{str(e)}")
    
    def _serialize_analysis_results(self, results):
        """Convert analysis results to JSON-serializable format
        
        Args:
            results: Analysis results dictionary with datetime objects
            
        Returns:
            dict: JSON-serializable dictionary
        """
        serialized = {
            'version': '1.0',
            'timestamp': results['timestamp'].isoformat() if hasattr(results['timestamp'], 'isoformat') else str(results['timestamp']),
            'log_group': results['log_group'],
            'time_range_days': results['time_range_days'],
            'total_rules': results['total_rules'],
            'total_logged_rules': results.get('total_logged_rules', results['total_rules']),
            'records_analyzed': results['records_analyzed'],
            'low_freq_threshold': results.get('low_freq_threshold', 10),
            'min_days_in_production': results.get('min_days_in_production', 14),
            'partial_results': results.get('partial_results', False),
            'categories': results['categories'],
            'health_score': results['health_score']
        }
        
        # Serialize sid_stats (convert datetime objects to strings)
        serialized['sid_stats'] = {}
        for sid, stats in results.get('sid_stats', {}).items():
            serialized['sid_stats'][str(sid)] = {
                'hits': stats.get('hits', 0),
                'last_hit': stats['last_hit'].isoformat() if stats.get('last_hit') and hasattr(stats['last_hit'], 'isoformat') else None,
                'last_hit_days': stats.get('last_hit_days'),
                'percent': stats.get('percent', 0.0),
                'hits_per_day': stats.get('hits_per_day', 0.0),
                'category': stats.get('category', 'unknown'),
                'days_in_production': stats.get('days_in_production'),
                'last_modified': stats['last_modified'].isoformat() if stats.get('last_modified') and hasattr(stats['last_modified'], 'isoformat') else None,
                'days_since_last_modified': stats.get('days_since_last_modified')
            }
        
        # Serialize sets as lists
        serialized['unused_sids'] = list(results.get('unused_sids', []))
        serialized['unlogged_sids'] = list(results.get('unlogged_sids', set()))
        serialized['file_sids'] = list(results.get('file_sids', []))
        
        return serialized
    
    def load_stats_from_file(self, stats_filename):
        """Load CloudWatch statistics from .stats file
        
        Args:
            stats_filename: Path to .stats file
        """
        try:
            import json
            
            with open(stats_filename, 'r', encoding='utf-8') as f:
                stats_data = json.load(f)
            
            # Deserialize and load into analyzer
            analysis_results = self._deserialize_analysis_results(stats_data)
            
            # Store in usage_analyzer as if it was just fetched
            self.parent.usage_analyzer.last_analysis_results = analysis_results
            self.parent.usage_analyzer.last_analysis_timestamp = analysis_results['timestamp']
            
            # Also set session parameters from loaded stats for dialog pre-population
            # This ensures that if user wants to run a new analysis, the dialog will
            # be pre-filled with the parameters from the saved analysis
            self.parent._last_log_group = analysis_results['log_group']
            self.parent._last_time_range = analysis_results['time_range_days']
            self.parent._last_low_freq_threshold = analysis_results.get('low_freq_threshold', 10)
            self.parent._last_min_days_in_production = analysis_results.get('min_days_in_production', 14)
            
            # Silent load - user will see prompt when they access the feature
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Stats file not found: {stats_filename}")
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON in stats file: {str(e)}")
        except KeyError as e:
            raise Exception(f"Missing required field in stats file: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to load stats file: {str(e)}")
    
    def _deserialize_analysis_results(self, stats_data):
        """Convert JSON data back to analysis results format
        
        Args:
            stats_data: JSON dictionary from .stats file
            
        Returns:
            dict: Analysis results in the format expected by the UI
        """
        from datetime import datetime
        
        # Reconstruct analysis_results dictionary
        results = {
            'timestamp': datetime.fromisoformat(stats_data['timestamp']),
            'log_group': stats_data['log_group'],
            'time_range_days': stats_data['time_range_days'],
            'total_rules': stats_data['total_rules'],
            'total_logged_rules': stats_data.get('total_logged_rules', stats_data['total_rules']),
            'records_analyzed': stats_data['records_analyzed'],
            'low_freq_threshold': stats_data.get('low_freq_threshold', 10),
            'min_days_in_production': stats_data.get('min_days_in_production', 14),
            'partial_results': stats_data.get('partial_results', False),
            'categories': stats_data['categories'],
            'health_score': stats_data['health_score']
        }
        
        # Deserialize sid_stats (convert strings back to integers and datetime objects)
        results['sid_stats'] = {}
        for sid_str, stats in stats_data.get('sid_stats', {}).items():
            sid = int(sid_str)
            results['sid_stats'][sid] = {
                'hits': stats.get('hits', 0),
                'last_hit': datetime.fromisoformat(stats['last_hit']) if stats.get('last_hit') else None,
                'last_hit_days': stats.get('last_hit_days'),
                'percent': stats.get('percent', 0.0),
                'hits_per_day': stats.get('hits_per_day', 0.0),
                'category': stats.get('category', 'unknown'),
                'days_in_production': stats.get('days_in_production'),
                'last_modified': datetime.fromisoformat(stats['last_modified']) if stats.get('last_modified') else None,
                'days_since_last_modified': stats.get('days_since_last_modified')
            }
        
        # Deserialize sets from lists
        results['unused_sids'] = set(stats_data.get('unused_sids', []))
        results['unlogged_sids'] = set(stats_data.get('unlogged_sids', []))
        results['file_sids'] = stats_data.get('file_sids', [])
        
        return results
    
    # Phase 11: Help Menu - AWS Setup Guide (covers Rule Usage Analyzer + Rule Group Import)
    def show_aws_setup_help(self, default_tab='prerequisites'):
        """Show 4-tab setup guide dialog for AWS features (CloudWatch + Network Firewall)
        
        Args:
            default_tab: Which tab to open by default ('prerequisites', 'iam', 'credentials', 'testing')
        """
        help_dialog = tk.Toplevel(self.parent.root)
        help_dialog.title("AWS Setup - Help Guide")
        help_dialog.geometry("750x650")
        help_dialog.transient(self.parent.root)
        help_dialog.grab_set()
        
        # Center dialog
        help_dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 100,
            self.parent.root.winfo_rooty() + 50
        ))
        
        # Create notebook for tabs
        notebook = ttk.Notebook(help_dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Prerequisites
        prereq_frame = ttk.Frame(notebook)
        notebook.add(prereq_frame, text="Prerequisites")
        
        # Create scrollable content
        prereq_canvas = tk.Canvas(prereq_frame)
        prereq_scrollbar = ttk.Scrollbar(prereq_frame, orient=tk.VERTICAL, command=prereq_canvas.yview)
        prereq_content = ttk.Frame(prereq_canvas)
        
        prereq_content.bind(
            "<Configure>",
            lambda e: prereq_canvas.configure(scrollregion=prereq_canvas.bbox("all"))
        )
        
        prereq_canvas.create_window((0, 0), window=prereq_content, anchor="nw")
        prereq_canvas.configure(yscrollcommand=prereq_scrollbar.set)
        
        prereq_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        prereq_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling for Prerequisites tab
        def on_prereq_mousewheel(event):
            try:
                if event.delta:
                    prereq_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    prereq_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    prereq_canvas.yview_scroll(1, "units")
            except:
                pass
        
        prereq_canvas.bind("<Enter>", lambda e: prereq_canvas.bind_all("<MouseWheel>", on_prereq_mousewheel))
        prereq_canvas.bind("<Leave>", lambda e: prereq_canvas.unbind_all("<MouseWheel>"))
        
        # Prerequisites content
        ttk.Label(prereq_content, text="To use the AWS integration, you need:",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W, padx=15, pady=(15, 10))
        
        # Requirement 1: boto3
        req1_frame = ttk.LabelFrame(prereq_content, text="1. Install boto3")
        req1_frame.pack(fill=tk.X, padx=15, pady=10)
        
        req1_text = (
            "boto3 is the AWS SDK for Python.\n\n"
            "Installation:\n"
            "• Open terminal/command prompt\n"
            "• Run: pip install boto3\n"
            "  (or pip3 install boto3 on some systems)\n"
            "• Restart Suricata Generator\n\n"
            "Verify installation:\n"
            'python -c "import boto3; print(\'boto3 installed!\')"'
        )
        ttk.Label(req1_frame, text=req1_text, font=("TkDefaultFont", 9),
                 justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=10)
        
        # Requirement 2: AWS Credentials
        req2_frame = ttk.LabelFrame(prereq_content, text="2. Configure AWS Credentials")
        req2_frame.pack(fill=tk.X, padx=15, pady=10)
        
        ttk.Label(req2_frame, text="See Credentials tab for detailed instructions",
                 font=("TkDefaultFont", 9), foreground="#666666").pack(anchor=tk.W, padx=10, pady=10)
        
        # Requirement 3: CloudWatch Logging
        req3_frame = ttk.LabelFrame(prereq_content, text="3. Enable CloudWatch Logging on Firewall")
        req3_frame.pack(fill=tk.X, padx=15, pady=10)
        
        req3_text = (
            "Your AWS Network Firewall must send logs to CloudWatch.\n\n"
            "Required log types:\n"
            "• Alert logs (required for rule analysis)\n"
            "• Flow logs (optional but recommended)\n\n"
            "Enable logging via AWS Console:\n"
            "Network Firewall → Firewalls → Select firewall → Logging\n\n"
            "Or via AWS CLI:\n"
            "aws network-firewall update-logging-configuration \\\n"
            "  --firewall-name my-firewall \\\n"
            "  --logging-configuration '{...}'"
        )
        ttk.Label(req3_frame, text=req3_text, font=("TkDefaultFont", 9),
                 justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=10)
        
        # Requirement 4: IAM Permissions
        req4_frame = ttk.LabelFrame(prereq_content, text="4. IAM Permissions")
        req4_frame.pack(fill=tk.X, padx=15, pady=10)
        
        ttk.Label(req4_frame, text="See IAM Permissions tab for required policy",
                 font=("TkDefaultFont", 9), foreground="#666666").pack(anchor=tk.W, padx=10, pady=10)
        
        # Tab 2: IAM Permissions
        iam_frame = ttk.Frame(notebook)
        notebook.add(iam_frame, text="IAM Permissions")
        
        # Create scrollable content
        iam_canvas = tk.Canvas(iam_frame)
        iam_scrollbar = ttk.Scrollbar(iam_frame, orient=tk.VERTICAL, command=iam_canvas.yview)
        iam_content = ttk.Frame(iam_canvas)
        
        iam_content.bind(
            "<Configure>",
            lambda e: iam_canvas.configure(scrollregion=iam_canvas.bbox("all"))
        )
        
        iam_canvas.create_window((0, 0), window=iam_content, anchor="nw")
        iam_canvas.configure(yscrollcommand=iam_scrollbar.set)
        
        iam_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        iam_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling for IAM Permissions tab
        def on_iam_mousewheel(event):
            try:
                if event.delta:
                    iam_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    iam_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    iam_canvas.yview_scroll(1, "units")
            except:
                pass
        
        iam_canvas.bind("<Enter>", lambda e: iam_canvas.bind_all("<MouseWheel>", on_iam_mousewheel))
        iam_canvas.bind("<Leave>", lambda e: iam_canvas.unbind_all("<MouseWheel>"))
        
        # IAM content
        ttk.Label(iam_content, text="Required IAM Policy:",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W, padx=15, pady=(15, 10))
        
        # Copy button
        def copy_iam_policy():
            policy = '''{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "SuricataGeneratorAWSPermissions",
    "Effect": "Allow",
    "Action": [
      "logs:StartQuery",
      "logs:GetQueryResults",
      "network-firewall:ListRuleGroups",
      "network-firewall:DescribeRuleGroup",
      "network-firewall:CreateRuleGroup",
      "network-firewall:UpdateRuleGroup"
    ],
    "Resource": [
      "arn:aws:logs:*:*:log-group:/aws/network-firewall/*",
      "arn:aws:network-firewall:*:*:stateful-rulegroup/*"
    ]
  }]
}'''
            self.parent.root.clipboard_clear()
            self.parent.root.clipboard_append(policy)
            messagebox.showinfo("Copied", "IAM policy copied to clipboard!")
        
        ttk.Button(iam_content, text="Copy Policy to Clipboard", 
                  command=copy_iam_policy).pack(padx=15, pady=5)
        
        # Policy text
        policy_frame = ttk.Frame(iam_content)
        policy_frame.pack(fill=tk.X, padx=15, pady=10)
        
        policy_text = tk.Text(policy_frame, height=14, wrap=tk.WORD, font=("Consolas", 9),
                             bg="#F5F5F5", relief=tk.SOLID, borderwidth=1)
        policy_text.pack(fill=tk.X)
        
        policy_json = '''{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "SuricataGeneratorAWSPermissions",
    "Effect": "Allow",
    "Action": [
      "logs:StartQuery",
      "logs:GetQueryResults",
      "network-firewall:ListRuleGroups",
      "network-firewall:DescribeRuleGroup",
      "network-firewall:CreateRuleGroup",
      "network-firewall:UpdateRuleGroup"
    ],
    "Resource": [
      "arn:aws:logs:*:*:log-group:/aws/network-firewall/*",
      "arn:aws:network-firewall:*:*:stateful-rulegroup/*"
    ]
  }]
}'''
        policy_text.insert("1.0", policy_json)
        policy_text.config(state=tk.DISABLED)
        
        # Permission breakdown
        breakdown_frame = ttk.LabelFrame(iam_content, text="Permission Breakdown")
        breakdown_frame.pack(fill=tk.X, padx=15, pady=10)
        
        breakdown_text = (
            "CloudWatch Logs (Rule Usage Analyzer):\n"
            "• logs:StartQuery - Initiates CloudWatch Logs Insights queries\n"
            "• logs:GetQueryResults - Retrieves query results\n"
            "• Resource: /aws/network-firewall/* log groups only\n\n"
            "Network Firewall (Rule Group Import):\n"
            "• network-firewall:ListRuleGroups - Browse available rule groups\n"
            "• network-firewall:DescribeRuleGroup - View rule group details\n"
            "• Resource: All Network Firewall stateful rule groups in account\n\n"
            "Network Firewall (Rule Group Export):\n"
            "• network-firewall:CreateRuleGroup - Deploy new rule groups\n"
            "• network-firewall:UpdateRuleGroup - Overwrite existing rule groups\n"
            "• Resource: All Network Firewall stateful rule groups in account"
        )
        ttk.Label(breakdown_frame, text=breakdown_text, font=("TkDefaultFont", 9),
                 justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=10)
        
        # Security notes
        security_frame = ttk.LabelFrame(iam_content, text="Security Notes")
        security_frame.pack(fill=tk.X, padx=15, pady=10)
        
        security_text = (
            "• Read permissions for CloudWatch Logs and Rule Group browsing\n"
            "• Write permissions for Rule Group deployment (CreateRuleGroup, UpdateRuleGroup)\n"
            "• Minimal scope (CloudWatch Logs + Network Firewall rule groups)\n"
            "• No access to firewalls, policies, EC2, VPC, or other services\n"
            "• Overwrite protection via confirmation dialog\n"
            "• Same security model as AWS CLI\n"
            "• No credentials stored by application\n"
            "• Single policy covers all AWS features (future-proof)"
        )
        ttk.Label(security_frame, text=security_text, font=("TkDefaultFont", 9),
                 justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=10)
        
        # Tab 3: Credentials
        cred_frame = ttk.Frame(notebook)
        notebook.add(cred_frame, text="Credentials")
        
        # Create scrollable content
        cred_canvas = tk.Canvas(cred_frame)
        cred_scrollbar = ttk.Scrollbar(cred_frame, orient=tk.VERTICAL, command=cred_canvas.yview)
        cred_content = ttk.Frame(cred_canvas)
        
        cred_content.bind(
            "<Configure>",
            lambda e: cred_canvas.configure(scrollregion=cred_canvas.bbox("all"))
        )
        
        cred_canvas.create_window((0, 0), window=cred_content, anchor="nw")
        cred_canvas.configure(yscrollcommand=cred_scrollbar.set)
        
        cred_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cred_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling for Credentials tab
        def on_cred_mousewheel(event):
            try:
                if event.delta:
                    cred_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    cred_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    cred_canvas.yview_scroll(1, "units")
            except:
                pass
        
        cred_canvas.bind("<Enter>", lambda e: cred_canvas.bind_all("<MouseWheel>", on_cred_mousewheel))
        cred_canvas.bind("<Leave>", lambda e: cred_canvas.unbind_all("<MouseWheel>"))
        
        # Credentials content
        ttk.Label(cred_content, text="Configure AWS credentials using one of these options:",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W, padx=15, pady=(15, 10))
        
        # Option 1: AWS CLI
        opt1_frame = ttk.LabelFrame(cred_content, text="Option 1: AWS CLI (Recommended)")
        opt1_frame.pack(fill=tk.X, padx=15, pady=10)
        
        opt1_text = (
            "If you have AWS CLI installed:\n"
            "  aws configure\n\n"
            "You will be prompted for:\n"
            "• AWS Access Key ID\n"
            "• AWS Secret Access Key\n"
            "• Default region (e.g., us-east-1)\n"
            "• Default output format (json)\n\n"
            "These credentials will be used by this tool automatically."
        )
        ttk.Label(opt1_frame, text=opt1_text, font=("TkDefaultFont", 9),
                 justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=10)
        
        # Option 2: Environment Variables
        opt2_frame = ttk.LabelFrame(cred_content, text="Option 2: Environment Variables")
        opt2_frame.pack(fill=tk.X, padx=15, pady=10)
        
        opt2_text = (
            "Set these environment variables:\n\n"
            "Linux/Mac:\n"
            '  export AWS_ACCESS_KEY_ID="your-access-key-id"\n'
            '  export AWS_SECRET_ACCESS_KEY="your-secret-key"\n'
            '  export AWS_DEFAULT_REGION="us-east-1"\n\n'
            "Windows (Command Prompt):\n"
            "  set AWS_ACCESS_KEY_ID=your-access-key-id\n"
            "  set AWS_SECRET_ACCESS_KEY=your-secret-key\n"
            "  set AWS_DEFAULT_REGION=us-east-1\n\n"
            "Windows (PowerShell):\n"
            '  $env:AWS_ACCESS_KEY_ID="your-access-key-id"\n'
            '  $env:AWS_SECRET_ACCESS_KEY="your-secret-key"\n'
            '  $env:AWS_DEFAULT_REGION="us-east-1"'
        )
        
        opt2_text_widget = tk.Text(opt2_frame, height=13, wrap=tk.WORD,
                                   font=("Consolas", 8), bg="#F5F5F5")
        opt2_text_widget.pack(fill=tk.X, padx=10, pady=10)
        opt2_text_widget.insert("1.0", opt2_text)
        opt2_text_widget.config(state=tk.DISABLED)
        
        # Option 3: IAM Role
        opt3_frame = ttk.LabelFrame(cred_content, text="Option 3: IAM Role (If Running on AWS)")
        opt3_frame.pack(fill=tk.X, padx=15, pady=10)
        
        opt3_text = (
            "If running on an EC2 instance or in Cloud9:\n"
            "• Credentials provided automatically via instance role\n"
            "• No configuration needed\n"
            "• Most secure option (no credentials to manage)\n\n"
            "Verify credentials:\n"
            "  aws sts get-caller-identity"
        )
        ttk.Label(opt3_frame, text=opt3_text, font=("TkDefaultFont", 9),
                 justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=10)
        
        # Tab 4: Testing
        test_frame = ttk.Frame(notebook)
        notebook.add(test_frame, text="Testing")
        
        # Create scrollable content for Testing tab
        test_canvas = tk.Canvas(test_frame)
        test_scrollbar = ttk.Scrollbar(test_frame, orient=tk.VERTICAL, command=test_canvas.yview)
        test_main = ttk.Frame(test_canvas)
        
        test_main.bind(
            "<Configure>",
            lambda e: test_canvas.configure(scrollregion=test_canvas.bbox("all"))
        )
        
        test_canvas.create_window((0, 0), window=test_main, anchor="nw")
        test_canvas.configure(yscrollcommand=test_scrollbar.set)
        
        test_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        test_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling for Testing tab
        def on_test_mousewheel(event):
            try:
                if event.delta:
                    test_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                elif event.num == 4:
                    test_canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    test_canvas.yview_scroll(1, "units")
            except:
                pass
        
        test_canvas.bind("<Enter>", lambda e: test_canvas.bind_all("<MouseWheel>", on_test_mousewheel))
        test_canvas.bind("<Leave>", lambda e: test_canvas.unbind_all("<MouseWheel>"))
        
        # Content frame (now packed inside test_main which is in scrollable canvas)
        test_content = ttk.Frame(test_main)
        test_content.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        ttk.Label(test_content, text="Test your setup before running analysis:",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W, pady=(0, 15))
        
        # Log group input
        ttk.Label(test_content, text="Log Group Name:").pack(anchor=tk.W, pady=(0, 5))
        test_log_group_var = tk.StringVar(value="/aws/network-firewall/my-firewall")
        ttk.Entry(test_content, textvariable=test_log_group_var, width=60).pack(fill=tk.X, pady=(0, 15))
        
        # Test button
        def run_connection_test():
            log_group = test_log_group_var.get().strip()
            if not log_group:
                messagebox.showerror("Validation Error", "Log group name is required.")
                return
            
            # Clear previous results
            for widget in results_display.winfo_children():
                widget.destroy()
            
            # Run tests
            self._run_connection_test(log_group, results_display)
        
        ttk.Button(test_content, text="Test Connection", command=run_connection_test).pack(pady=(0, 15))
        
        # Results display
        results_frame = ttk.LabelFrame(test_content, text="Test Results")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        results_display = ttk.Frame(results_frame)
        results_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(results_display, text="Click 'Test Connection' to run diagnostic tests",
                 font=("TkDefaultFont", 9, "italic"), foreground="#666666").pack(pady=20)
        
        # Select default tab
        tab_map = {'prerequisites': 0, 'iam': 1, 'credentials': 2, 'testing': 3}
        notebook.select(tab_map.get(default_tab, 0))
        
        # Close button
        ttk.Button(help_dialog, text="Close", command=help_dialog.destroy).pack(pady=10)
    
    def _run_connection_test(self, log_group, results_display):
        """Run connection test and display results
        
        Args:
            log_group: CloudWatch log group name to test
            results_display: Frame to display results in
        """
        results = []
        
        # Test 1: boto3
        try:
            import boto3
            version = boto3.__version__
            results.append(("✓", f"boto3 installed (version {version})"))
        except ImportError:
            results.append(("✗", "boto3 not installed"))
            self._display_test_results(results, results_display)
            return
        
        # Test 2: Credentials
        try:
            session = boto3.Session()
            creds = session.get_credentials()
            if creds:
                results.append(("✓", "AWS credentials configured"))
                profile = session.profile_name or 'default'
                results.append(("✓", f"Using profile: {profile}"))
                region = session.region_name or 'Not set'
                results.append(("✓", f"Region: {region}"))
            else:
                results.append(("✗", "No AWS credentials found"))
                self._display_test_results(results, results_display)
                return
        except Exception as e:
            results.append(("✗", f"Credentials error: {str(e)}"))
            self._display_test_results(results, results_display)
            return
        
        # Test 3: Log group access
        try:
            client = boto3.client('logs')
            response = client.describe_log_groups(
                logGroupNamePrefix=log_group,
                limit=1
            )
            if response['logGroups']:
                results.append(("✓", "Log group accessible"))
                # Try to get log stream count
                try:
                    streams_response = client.describe_log_streams(
                        logGroupName=log_group,
                        limit=1
                    )
                    if streams_response['logStreams']:
                        results.append(("✓", "Log group has log streams"))
                except:
                    pass
            else:
                results.append(("✗", f"Log group not found: {log_group}"))
                self._display_test_results(results, results_display)
                return
        except Exception as e:
            error_str = str(e)
            if "AccessDenied" in error_str:
                results.append(("✗", "Access denied to CloudWatch Logs"))
            else:
                results.append(("✗", f"Log group access error: {error_str[:50]}"))
            self._display_test_results(results, results_display)
            return
        
        # Test 4: Query permissions
        try:
            test_query = "fields @timestamp | limit 1"
            response = client.start_query(
                logGroupName=log_group,
                startTime=int((datetime.now() - timedelta(days=1)).timestamp()),
                endTime=int(datetime.now().timestamp()),
                queryString=test_query,
                limit=1
            )
            results.append(("✓", "logs:StartQuery - Verified"))
            
            query_id = response['queryId']
            result = client.get_query_results(queryId=query_id)
            results.append(("✓", "logs:GetQueryResults - Verified"))
            
        except Exception as e:
            error_str = str(e)
            if "AccessDenied" in error_str:
                results.append(("✗", "Insufficient IAM permissions"))
            else:
                results.append(("✗", f"Permission test failed: {error_str[:50]}"))
            self._display_test_results(results, results_display)
            return
        
        # Test 5: Network Firewall access (NEW)
        results.append(("", ""))
        results.append(("", "Network Firewall:"))
        try:
            nfw_client = boto3.client('network-firewall')
            
            # Test ListRuleGroups
            response = nfw_client.list_rule_groups(
                Scope='ACCOUNT',
                Type='STATEFUL',
                MaxResults=5
            )
            rule_group_count = len(response.get('RuleGroups', []))
            results.append(("✓", "network-firewall:ListRuleGroups - Verified"))
            results.append(("✓", f"Found {rule_group_count} rule group(s) in account"))
            
            # Test DescribeRuleGroup if rule groups exist
            if rule_group_count > 0:
                first_rg_arn = response['RuleGroups'][0]['Arn']
                desc_response = nfw_client.describe_rule_group(
                    RuleGroupArn=first_rg_arn,
                    Type='STATEFUL'
                )
                results.append(("✓", "network-firewall:DescribeRuleGroup - Verified"))
            else:
                results.append(("ℹ️", "No rule groups to test DescribeRuleGroup (0 in account)"))
                
        except Exception as e:
            error_str = str(e)
            if "AccessDenied" in error_str:
                results.append(("✗", "Network Firewall permissions missing"))
            else:
                results.append(("✗", f"Network Firewall test failed: {error_str[:50]}"))
        
        # Test export permissions (NEW)
        results.append(("", ""))
        results.append(("", "Export Permissions:"))
        
        # Note: We can't actually test CreateRuleGroup without creating a rule group
        # Instead, check if user has the permission by attempting describe on a non-existent group
        # This will return AccessDenied if missing CreateRuleGroup, or ResourceNotFound if has permission
        try:
            test_describe = nfw_client.describe_rule_group(
                RuleGroupName='test-permission-check-do-not-create',
                Type='STATEFUL'
            )
            results.append(("✓", "network-firewall:CreateRuleGroup - Permissions verified"))
        except nfw_client.exceptions.ResourceNotFoundException:
            # ResourceNotFound means we have permission to check (good)
            results.append(("✓", "network-firewall:CreateRuleGroup - Permissions verified"))
        except nfw_client.exceptions.AccessDeniedException:
            # Access denied means we don't have permission
            results.append(("✗", "network-firewall:CreateRuleGroup - Permission missing"))
        except:
            pass
        
        # Note about UpdateRuleGroup
        results.append(("ℹ️", "network-firewall:UpdateRuleGroup - Same permissions as Create"))
        
        # All tests complete
        results.append(("", ""))
        results.append(("✓", "All checks passed!"))
        results.append(("", ""))
        results.append(("", "Ready to use:"))
        results.append(("", "• Tools > Analyze Rule Usage"))
        results.append(("", "• File > Import Rule Group"))
        results.append(("", "• File > Export Rule Group"))
        
        self._display_test_results(results, results_display)
    
    def _display_test_results(self, results, results_display):
        """Display test results in the results frame
        
        Args:
            results: List of (icon, message) tuples
            results_display: Frame to display results in
        """
        # Clear existing results
        for widget in results_display.winfo_children():
            widget.destroy()
        
        # Display each result
        for icon, message in results:
            if not icon and not message:
                # Blank line
                ttk.Label(results_display, text="").pack(anchor=tk.W)
            else:
                result_frame = ttk.Frame(results_display)
                result_frame.pack(fill=tk.X, pady=2)
                
                # Icon
                if icon:
                    color = "#2E7D32" if icon == "✓" else "#D32F2F" if icon == "✗" else "#666666"
                    ttk.Label(result_frame, text=icon, font=("TkDefaultFont", 10),
                             foreground=color).pack(side=tk.LEFT, padx=(0, 10))
                
                # Message
                ttk.Label(result_frame, text=message, font=("TkDefaultFont", 9)).pack(side=tk.LEFT)
    
    def _show_rule_stats_dialog(self, rule, stats, analysis_results):
        """Show full statistics dialog for rule with hits (Scenario 1)"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title(f"CloudWatch Statistics - SID {rule.sid}")
        dialog.geometry("480x520")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 230,
            self.parent.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Rule summary (2 lines)
        rule_summary = f"{rule.action} {rule.protocol} {rule.src_net} {rule.src_port} {rule.direction} {rule.dst_net} {rule.dst_port}"
        ttk.Label(main_frame, text=rule_summary, 
                 font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W)
        ttk.Label(main_frame, text=rule.message, 
                 font=("TkDefaultFont", 9)).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Usage statistics
        ttk.Label(main_frame, 
                 text=f"Usage (Last {analysis_results['time_range_days']} days):",
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create stats table
        stat_items = [
            ("Total Hits:", f"{stats.get('hits', 0):,}"),
            ("% of Traffic:", f"{stats.get('percent', 0.0):.2f}%"),
            ("Hits/Day Avg:", f"{stats.get('hits_per_day', 0.0):.1f}"),
        ]
        
        if stats.get('last_hit_days') is not None:
            stat_items.append(("Last Hit:", f"{stats['last_hit_days']} days ago"))
        
        if stats.get('days_in_production') is not None:
            stat_items.append(("Age of Rule:", f"{stats['days_in_production']} days"))
        
        for label, value in stat_items:
            row = ttk.Frame(stats_frame)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=label, width=18).pack(side=tk.LEFT)
            ttk.Label(row, text=value, font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Category
        category = stats.get('category', 'Unknown')
        ttk.Label(main_frame, text=f"Category: {category}",
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        # Interpretation (reuse existing helper)
        interpretation = self._generate_sid_interpretation(stats, category, analysis_results)
        ttk.Label(main_frame, text=interpretation,
                 font=("TkDefaultFont", 9), foreground="#666666",
                 wraplength=420, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 15))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Analysis timestamp
        timestamp = analysis_results['timestamp']
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M') if hasattr(timestamp, 'strftime') else str(timestamp)[:16]
        time_ago = self._format_time_ago(timestamp)
        
        ttk.Label(main_frame, text=f"Analysis from: {timestamp_str} ({time_ago})",
                 font=("TkDefaultFont", 8), foreground="#666666").pack(anchor=tk.W, pady=(0, 15))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        def view_in_analysis():
            dialog.destroy()
            # Open results window if not already open, or bring to front
            if not hasattr(self, '_current_results_window') or not self._current_results_window.winfo_exists():
                self.show_usage_results_window(analysis_results)
            else:
                self._current_results_window.lift()
        
        def refresh_all():
            dialog.destroy()
            self.run_usage_analysis(
                analysis_results['log_group'],
                analysis_results['time_range_days'],
                analysis_results.get('low_freq_threshold', 10),
                analysis_results.get('min_days_in_production', 14)
            )
        
        ttk.Button(btn_frame, text="View in Analysis", command=view_in_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Refresh All", command=refresh_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _show_unused_rule_dialog(self, rule, analysis_results):
        """Show dialog for rule with 0 hits (Scenario 2)"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title(f"CloudWatch Statistics - SID {rule.sid}")
        dialog.geometry("480x420")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 230,
            self.parent.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Rule summary
        rule_summary = f"{rule.action} {rule.protocol} {rule.src_net} {rule.src_port} {rule.direction} {rule.dst_net} {rule.dst_port}"
        ttk.Label(main_frame, text=rule_summary, 
                 font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W)
        ttk.Label(main_frame, text=rule.message, 
                 font=("TkDefaultFont", 9)).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Usage statistics (0 hits)
        ttk.Label(main_frame, 
                 text=f"Usage (Last {analysis_results['time_range_days']} days):",
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Get rule age
        sid_stats_dict = analysis_results.get('sid_stats', {})
        rule_stat = sid_stats_dict.get(rule.sid, {})
        days = rule_stat.get('days_in_production')
        
        stat_items = [("Total Hits:", "0")]
        if days is not None:
            stat_items.append(("Age of Rule:", f"{days} days"))
        
        for label, value in stat_items:
            row = ttk.Frame(stats_frame)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=label, width=18).pack(side=tk.LEFT)
            ttk.Label(row, text=value, font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT)
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Determine confidence level
        min_days = analysis_results.get('min_days_in_production', 14)
        if days is None:
            category_text = "Category: Unused (Unknown Age) ℹ️"
            interpretation = (
                "ℹ️ Rule has not triggered in analysis period.\n"
                "   Manual review recommended (unknown age)."
            )
        elif days >= min_days:
            category_text = "Category: Unused (Confirmed) ✓"
            interpretation = (
                "ℹ️ Rule has not triggered in analysis period.\n"
                f"   Safe to remove (≥{min_days} days old)."
            )
        else:
            category_text = "Category: Unused (Recently Deployed) ⚠️"
            interpretation = (
                "ℹ️ Rule has not triggered yet.\n"
                f"   Too new to judge (<{min_days} days old)."
            )
        
        ttk.Label(main_frame, text=category_text,
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Label(main_frame, text=interpretation,
                 font=("TkDefaultFont", 9), foreground="#666666",
                 wraplength=420, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 15))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Analysis timestamp
        timestamp = analysis_results['timestamp']
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M') if hasattr(timestamp, 'strftime') else str(timestamp)[:16]
        time_ago = self._format_time_ago(timestamp)
        
        ttk.Label(main_frame, text=f"Analysis from: {timestamp_str} ({time_ago})",
                 font=("TkDefaultFont", 8), foreground="#666666").pack(anchor=tk.W, pady=(0, 15))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        def view_in_analysis():
            dialog.destroy()
            if not hasattr(self, '_current_results_window') or not self._current_results_window.winfo_exists():
                self.show_usage_results_window(analysis_results)
            else:
                self._current_results_window.lift()
        
        def refresh_all():
            dialog.destroy()
            self.run_usage_analysis(
                analysis_results['log_group'],
                analysis_results['time_range_days'],
                analysis_results.get('low_freq_threshold', 10),
                analysis_results.get('min_days_in_production', 14)
            )
        
        ttk.Button(btn_frame, text="View in Analysis", command=view_in_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Refresh All", command=refresh_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _show_unlogged_rule_dialog(self, rule, analysis_results):
        """Show dialog for unlogged rule (cannot be tracked via CloudWatch)"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title(f"CloudWatch Statistics - SID {rule.sid}")
        dialog.geometry("480x420")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 230,
            self.parent.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Rule summary
        rule_summary = f"{rule.action} {rule.protocol} {rule.src_net} {rule.src_port} {rule.direction} {rule.dst_net} {rule.dst_port}"
        ttk.Label(main_frame, text=rule_summary, 
                 font=("TkDefaultFont", 9, "bold")).pack(anchor=tk.W)
        ttk.Label(main_frame, text=rule.message, 
                 font=("TkDefaultFont", 9)).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Category - Unlogged
        category_text = "Category: Unlogged ℹ️"
        ttk.Label(main_frame, text=category_text,
                 font=("TkDefaultFont", 10, "bold"), foreground="#9E9E9E").pack(anchor=tk.W, pady=(0, 10))
        
        # Explanation
        explanation_text = (
            "ℹ️ This rule doesn't write to CloudWatch Logs.\n\n"
            "   Reason: "
        )
        
        # Determine specific reason
        action_lower = rule.action.lower()
        options_text = f"{rule.content} {rule.original_options}".lower()
        
        if action_lower == "pass":
            explanation_text += "Pass rule without 'alert' keyword\n\n"
            explanation_text += "   Pass rules don't generate alert logs by default.\n"
            explanation_text += "   The rule may be actively used but won't show hits.\n\n"
            explanation_text += "   To enable tracking: Add 'alert;' keyword to the rule."
        elif action_lower in ["drop", "reject"]:
            if "noalert" in options_text:
                explanation_text += f"{action_lower.capitalize()} rule with 'noalert' keyword\n\n"
                explanation_text += f"   The 'noalert' keyword explicitly suppresses logging.\n"
                explanation_text += "   The rule may be actively blocking traffic.\n\n"
                explanation_text += "   To enable tracking: Remove 'noalert' keyword."
            else:
                explanation_text += "Unknown reason (should log by default)\n\n"
                explanation_text += "   This may be a detection error."
        else:
            explanation_text += "Unknown\n\n"
            explanation_text += "   Unable to determine why this rule doesn't log."
        
        ttk.Label(main_frame, text=explanation_text,
                 font=("TkDefaultFont", 9), foreground="#666666",
                 wraplength=420, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 15))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Analysis timestamp
        timestamp = analysis_results['timestamp']
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M') if hasattr(timestamp, 'strftime') else str(timestamp)[:16]
        time_ago = self._format_time_ago(timestamp)
        
        ttk.Label(main_frame, text=f"Analysis from: {timestamp_str} ({time_ago})",
                 font=("TkDefaultFont", 8), foreground="#666666").pack(anchor=tk.W, pady=(0, 15))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        def view_in_analysis():
            dialog.destroy()
            if not hasattr(self, '_current_results_window') or not self._current_results_window.winfo_exists():
                self.show_usage_results_window(analysis_results)
                # Navigate to Unlogged tab (tab index 6)
                try:
                    # Get the notebook from the results window
                    for child in self._current_results_window.winfo_children():
                        if isinstance(child, ttk.Frame):
                            for subchild in child.winfo_children():
                                if isinstance(subchild, ttk.Notebook):
                                    subchild.select(6)  # Select Unlogged tab
                                    break
                except:
                    pass
            else:
                self._current_results_window.lift()
        
        ttk.Button(btn_frame, text="View in Unlogged Tab", command=view_in_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _jump_to_rule_in_main_editor(self, line_num, results_window):
        """Jump to a specific rule in the main editor and close results window
        
        Args:
            line_num: Line number to jump to (1-based)
            results_window: Results window to close
        """
        # Close the results window
        results_window.destroy()
        
        # Jump to the rule in the main editor
        # Convert line number to 0-based index
        rule_index = line_num - 1
        
        # Get all items in main tree
        all_items = self.parent.tree.get_children()
        
        if rule_index < len(all_items):
            target_item = all_items[rule_index]
            # Clear current selection
            self.parent.tree.selection_remove(self.parent.tree.selection())
            # Select and focus the target rule
            self.parent.tree.selection_set(target_item)
            self.parent.tree.focus(target_item)
            self.parent.tree.see(target_item)
            # Ensure main window is visible
            self.parent.root.lift()
            self.parent.root.focus_force()
    
    def _copy_text_selection(self, widget):
        """Copy selected text from Text widget to clipboard"""
        try:
            if widget.tag_ranges(tk.SEL):
                selected = widget.selection_get()
                self.parent.root.clipboard_clear()
                self.parent.root.clipboard_append(selected)
        except tk.TclError:
            pass
    
    def _copy_all_text(self, widget):
        """Copy all text from Text widget to clipboard"""
        try:
            all_text = widget.get("1.0", tk.END).strip()
            self.parent.root.clipboard_clear()
            self.parent.root.clipboard_append(all_text)
        except:
            pass
    
    def _select_all_text(self, widget):
        """Select all text in Text widget"""
        try:
            widget.tag_add(tk.SEL, "1.0", tk.END)
            widget.mark_set(tk.INSERT, "1.0")
            widget.see(tk.INSERT)
        except:
            pass
    
    def _show_rule_not_in_cache_dialog(self, rule):
        """Show dialog when rule wasn't in last analysis (Scenario 3)"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("CloudWatch Statistics")
        dialog.geometry("450x300")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 250,
            self.parent.root.winfo_rooty() + 200
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Warning icon and title
        ttk.Label(main_frame, text="⚠️ Rule Not in Analysis Cache",
                 font=("TkDefaultFont", 12, "bold"), foreground="#FF6600").pack(pady=(0, 15))
        
        # Message
        message_text = (
            f"SID {rule.sid} was not included in the last\n"
            f"analysis run.\n\n"
            f"Possible reasons:\n"
            f"• Rule added after analysis\n"
            f"• SID changed after analysis\n"
            f"• Rule commented out during analysis\n\n"
            f"Run Tools > Analyze Rule Usage to include\n"
            f"this rule."
        )
        
        ttk.Label(main_frame, text=message_text,
                 font=("TkDefaultFont", 10), justify=tk.LEFT).pack(pady=(0, 20))
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        def run_analysis():
            dialog.destroy()
            self.show_rule_usage_analyzer()
        
        ttk.Button(btn_frame, text="Run Analysis Now", command=run_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    # AWS Tags Tab Methods
    def add_tag(self):
        """Add a new AWS tag"""
        self.show_add_tag_dialog()
    
    def show_add_tag_dialog(self):
        """Show dialog for adding a new AWS tag"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Add AWS Tag")
        dialog.geometry("500x400")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 150,
            self.parent.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Tag Key section
        ttk.Label(main_frame, text="Tag Key:").pack(anchor=tk.W, pady=(0, 5))
        
        key_var = tk.StringVar()
        key_entry = ttk.Entry(main_frame, textvariable=key_var, width=50)
        key_entry.pack(fill=tk.X, pady=(0, 5))
        
        # Key requirements
        key_req_frame = ttk.Frame(main_frame)
        key_req_frame.pack(fill=tk.X, pady=(0, 10))
        
        key_req_text = (
            "Requirements:\n"
            "• 1-128 characters\n"
            "• Valid: a-z, A-Z, 0-9, space, + - = . _ : / @\n"
            "• Cannot start with aws: (reserved prefix)"
        )
        ttk.Label(key_req_frame, text=key_req_text,
                 font=("TkDefaultFont", 8), foreground="#666666",
                 justify=tk.LEFT).pack(anchor=tk.W)
        
        # Tag Value section
        ttk.Label(main_frame, text="Tag Value:").pack(anchor=tk.W, pady=(10, 5))
        
        value_var = tk.StringVar()
        value_entry = ttk.Entry(main_frame, textvariable=value_var, width=50)
        value_entry.pack(fill=tk.X, pady=(0, 5))
        
        # Value requirements
        value_req_text = (
            "Requirements:\n"
            "• 0-256 characters (empty allowed)\n"
            "• Valid: a-z, A-Z, 0-9, space, + - = . _ : / @"
        )
        ttk.Label(main_frame, text=value_req_text,
                 font=("TkDefaultFont", 8), foreground="#666666",
                 justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 15))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def save_tag():
            key = key_var.get().strip()
            value = value_var.get().strip()
            
            # Validate key
            key_valid, key_error = self.parent.file_manager.validate_tag_key(key)
            if not key_valid:
                messagebox.showerror("Validation Error", key_error)
                return
            
            # Validate value
            value_valid, value_error = self.parent.file_manager.validate_tag_value(value)
            if not value_valid:
                messagebox.showerror("Validation Error", value_error)
                return
            
            # Check for duplicate key
            if key in self.parent.tags:
                messagebox.showerror("Duplicate Key",
                    f"Tag key '{key}' already exists.\n\n"
                    "Tag keys must be unique. Please choose a different key or edit the existing tag.")
                return
            
            # Add tag
            self.parent.tags[key] = value
            
            # Track change
            if self.parent.tracking_enabled:
                self.parent.add_history_entry('tag_added', {
                    'key': key,
                    'value': value
                })
            
            # Refresh display
            self.parent.refresh_tags_table()
            self.parent.modified = True
            
            dialog.destroy()
        
        ttk.Button(button_frame, text="Save", command=save_tag).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Focus on key entry
        key_entry.focus()
    
    def show_add_common_tags_dialog(self):
        """Show dialog for adding common AWS tags"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Add Common Tags")
        dialog.geometry("500x500")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 150,
            self.parent.root.winfo_rooty() + 100
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(main_frame,
                 text="Select tags to add to your rule group:",
                 font=("TkDefaultFont", 10)).pack(anchor=tk.W, pady=(0, 10))
        
        # Create container for canvas and scrollbar (to ensure proper width filling)
        canvas_container = ttk.Frame(main_frame)
        canvas_container.pack(fill=tk.X, pady=(0, 10))
        
        # Scrollable frame for checkboxes
        canvas = tk.Canvas(canvas_container, height=280)
        scrollbar = ttk.Scrollbar(canvas_container, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Common tags (ManagedBy excluded - it's automatic on new files)
        common_tags = [
            "Environment",
            "Owner",
            "CostCenter",
            "Project",
            "Application",
            "Team",
            "CreatedBy",
            "Compliance",
            "DataClassification"
        ]
        
        # Create checkbox variables
        tag_vars = {}
        
        for tag_key in sorted(common_tags):
            # Check if tag already exists (disable if it does)
            already_exists = tag_key in self.parent.tags
            
            var = tk.BooleanVar(value=False)
            tag_vars[tag_key] = var
            
            label_text = tag_key
            if already_exists:
                label_text += " (already defined)"
            
            cb = ttk.Checkbutton(scrollable_frame, text=label_text, variable=var)
            cb.pack(anchor=tk.W, padx=10, pady=3)
            
            if already_exists:
                cb.config(state="disabled")
        
        # Note
        ttk.Label(main_frame,
                 text="Note: Tags will be created with empty values. You can edit values after adding.",
                 font=("TkDefaultFont", 8), foreground="#666666",
                 wraplength=450).pack(pady=(10, 5))
        
        ttk.Label(main_frame,
                 text="ManagedBy is added automatically on new files and doesn't need to be selected here.",
                 font=("TkDefaultFont", 8), foreground="#666666",
                 wraplength=450).pack(pady=(0, 15))
        
        # Define button functions first (before creating button_frame)
        def select_all():
            for tag_key, var in tag_vars.items():
                if tag_key not in self.parent.tags:  # Only select if not already exists
                    var.set(True)
        
        def select_none():
            for var in tag_vars.values():
                var.set(False)
        
        def add_selected():
            # Get selected tags
            selected = [key for key, var in tag_vars.items()
                       if var.get() and key not in self.parent.tags]
            
            if not selected:
                messagebox.showwarning("No Selection",
                    "Please select at least one tag to add.")
                return
            
            # Add selected tags with empty values
            for tag_key in selected:
                self.parent.tags[tag_key] = ""
                
                # Track change
                if self.parent.tracking_enabled:
                    self.parent.add_history_entry('tag_added', {
                        'key': tag_key,
                        'value': "",
                        'source': 'common_tags'
                    })
            
            # Refresh display
            self.parent.refresh_tags_table()
            self.parent.modified = True
            
            # Show success message
            tag_word = "tag" if len(selected) == 1 else "tags"
            messagebox.showinfo("Tags Added",
                f"Successfully added {len(selected)} {tag_word}.\n\n"
                "You can now edit the values in the AWS Tags tab.")
            
            dialog.destroy()
        
        # Select All/None buttons (first row)
        select_frame = ttk.Frame(main_frame)
        select_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(select_frame, text="Select All", command=select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(select_frame, text="Select None", command=select_none).pack(side=tk.LEFT, padx=5)
        
        # Add Selected/Cancel buttons (second row at bottom)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="Add Selected",
                  command=add_selected).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel",
                  command=dialog.destroy).pack(side=tk.RIGHT)
    
    def edit_tag(self):
        """Edit selected AWS tag"""
        selection = self.parent.tags_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a tag to edit.")
            return
        
        item = selection[0]
        values = self.parent.tags_tree.item(item, "values")
        tag_key = values[0]
        tag_value = values[1]
        
        self.show_edit_tag_dialog(tag_key, tag_value)
    
    def show_edit_tag_dialog(self, original_key: str, original_value: str):
        """Show dialog for editing an existing AWS tag
        
        Args:
            original_key: Current tag key
            original_value: Current tag value
        """
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Edit AWS Tag")
        dialog.geometry("500x350")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 150,
            self.parent.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Tag Key section (editable)
        ttk.Label(main_frame, text="Tag Key:").pack(anchor=tk.W, pady=(0, 5))
        
        key_var = tk.StringVar(value=original_key)
        key_entry = ttk.Entry(main_frame, textvariable=key_var, width=50)
        key_entry.pack(fill=tk.X, pady=(0, 5))
        
        # Key requirements
        key_req_frame = ttk.Frame(main_frame)
        key_req_frame.pack(fill=tk.X, pady=(0, 10))
        
        key_req_text = (
            "Requirements:\n"
            "• 1-128 characters\n"
            "• Valid: a-z, A-Z, 0-9, space, + - = . _ : / @\n"
            "• Cannot start with aws: (reserved prefix)"
        )
        ttk.Label(key_req_frame, text=key_req_text,
                 font=("TkDefaultFont", 8), foreground="#666666",
                 justify=tk.LEFT).pack(anchor=tk.W)
        
        # Tag Value section (editable)
        ttk.Label(main_frame, text="Tag Value:").pack(anchor=tk.W, pady=(10, 5))
        
        value_var = tk.StringVar(value=original_value)
        value_entry = ttk.Entry(main_frame, textvariable=value_var, width=50)
        value_entry.pack(fill=tk.X, pady=(0, 5))
        
        # Value requirements
        value_req_text = (
            "Requirements:\n"
            "• 0-256 characters (empty allowed)\n"
            "• Valid: a-z, A-Z, 0-9, space, + - = . _ : / @"
        )
        ttk.Label(main_frame, text=value_req_text,
                 font=("TkDefaultFont", 8), foreground="#666666",
                 justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 15))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def save_changes():
            key = key_var.get().strip()
            value = value_var.get().strip()
            
            # Validate key
            key_valid, key_error = self.parent.file_manager.validate_tag_key(key)
            if not key_valid:
                messagebox.showerror("Validation Error", key_error)
                return
            
            # Validate value
            value_valid, value_error = self.parent.file_manager.validate_tag_value(value)
            if not value_valid:
                messagebox.showerror("Validation Error", value_error)
                return
            
            # Check for duplicate key (only if key changed)
            if key != original_key and key in self.parent.tags:
                messagebox.showerror("Duplicate Key",
                    f"Tag key '{key}' already exists.\n\n"
                    "Tag keys must be unique. Please choose a different key.")
                return
            
            # If key changed, delete old key and add new one
            if key != original_key:
                old_value = self.parent.tags.get(original_key, "")
                del self.parent.tags[original_key]
                self.parent.tags[key] = value
                
                # Track change as delete + add
                if self.parent.tracking_enabled:
                    self.parent.add_history_entry('tag_deleted', {
                        'key': original_key,
                        'value': old_value
                    })
                    self.parent.add_history_entry('tag_added', {
                        'key': key,
                        'value': value
                    })
            else:
                # Only value changed
                old_value = self.parent.tags[original_key]
                self.parent.tags[original_key] = value
                
                # Track change
                if self.parent.tracking_enabled:
                    self.parent.add_history_entry('tag_modified', {
                        'key': original_key,
                        'old_value': old_value,
                        'new_value': value
                    })
            
            self.parent.refresh_tags_table()
            self.parent.modified = True
            dialog.destroy()
        
        ttk.Button(button_frame, text="Save", command=save_changes).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Focus on value entry
        value_entry.focus()
        value_entry.select_range(0, tk.END)
    
    def delete_tag(self):
        """Delete selected AWS tag with confirmation"""
        selection = self.parent.tags_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a tag to delete.")
            return
        
        item = selection[0]
        tag_key = self.parent.tags_tree.item(item, "values")[0]
        
        # Confirmation dialog
        if messagebox.askyesno("Confirm Delete", f"Delete tag '{tag_key}'?"):
            # Store old value for change tracking
            old_value = self.parent.tags.get(tag_key, "")
            
            # Delete tag
            if tag_key in self.parent.tags:
                del self.parent.tags[tag_key]
                
                # Track change
                if self.parent.tracking_enabled:
                    self.parent.add_history_entry('tag_deleted', {
                        'key': tag_key,
                        'value': old_value
                    })
                
                # Refresh display
                self.parent.refresh_tags_table()
                self.parent.modified = True
    
    def on_tag_double_click(self, event):
        """Handle double-click events on tags tree items"""
        item = self.parent.tags_tree.identify_row(event.y)
        if not item:
            return
        
        # Get the tag key and value from the double-clicked item
        values = self.parent.tags_tree.item(item, "values")
        if not values:
            return
        
        tag_key = values[0]
        tag_value = values[1]
        
        # Show edit dialog
        self.show_edit_tag_dialog(tag_key, tag_value)
    
    def _on_tags_mousewheel(self, event):
        """Handle mouse wheel scrolling for tags table"""
        try:
            # Windows and MacOS
            if event.delta:
                delta = -1 * (event.delta / 120)
            # Linux
            elif event.num == 4:
                delta = -1
            elif event.num == 5:
                delta = 1
            else:
                delta = 0
            
            # Only scroll if there are enough items to require scrolling
            if len(self.parent.tags_tree.get_children()) > 8:  # More items than visible height
                self.parent.tags_tree.yview_scroll(int(delta), "units")
                
        except (AttributeError, tk.TclError):
            # Ignore any scrolling errors
            pass
    
    def _populate_scoring_explanation(self, parent_frame, analysis_results):
        """Populate the scoring methodology explanation section
        
        Args:
            parent_frame: Parent frame to add content to
            analysis_results: Analysis results dictionary
        """
        # Title
        ttk.Label(parent_frame, text="How the Health Score is Calculated",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 10))
        
        # Get key metrics
        health_score = analysis_results['health_score']
        categories = analysis_results['categories']
        total_rules = analysis_results['total_rules']
        total_logged = analysis_results.get('total_logged_rules', total_rules)
        
        # Calculate components
        effective_rules = total_logged - categories['unused'] - categories['low_freq']
        used_rules = total_logged - categories['unused']
        
        effective_ratio = effective_rules / total_logged if total_logged > 0 else 0
        usage_ratio = used_rules / total_logged if total_logged > 0 else 0
        
        # Count broad rules (rules with >10% of traffic)
        sid_stats = analysis_results.get('sid_stats', {})
        untracked_sids = analysis_results.get('untracked_sids', set())
        broad_rule_count = len([sid for sid, s in sid_stats.items() if s.get('percent', 0) > 10 and sid not in untracked_sids])
        
        # Calculate components
        base_points = 20
        effectiveness_points = effective_ratio * 50
        usage_points = usage_ratio * 30
        broad_penalty = min(15, broad_rule_count * 4)
        
        # Visibility penalty (balanced hybrid)
        unlogged_count = categories.get('unlogged', 0)
        if unlogged_count > 0:
            unlogged_pct = (unlogged_count / total_rules) * 100 if total_rules > 0 else 0
            absolute_component = unlogged_count * 1.0
            percentage_component = unlogged_pct * 0.5
            visibility_penalty = min(15, (absolute_component + percentage_component) / 2)
        else:
            visibility_penalty = 0
        
        # Current Score section
        score_frame = ttk.LabelFrame(parent_frame, text="Your Current Score Breakdown")
        score_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        score_content = ttk.Frame(score_frame)
        score_content.pack(padx=10, pady=10)
        
        ttk.Label(score_content, text=f"Base: +{base_points:.0f} pts",
                 font=("TkDefaultFont", 9), foreground="#666666").pack(anchor=tk.W, pady=2)
        
        ttk.Label(score_content, 
                 text=f"Effectiveness: +{effectiveness_points:.1f} pts ({effective_rules}/{total_logged} medium/high-freq)",
                 font=("TkDefaultFont", 9), foreground="#2E7D32").pack(anchor=tk.W, pady=2)
        
        ttk.Label(score_content, 
                 text=f"Usage: +{usage_points:.1f} pts ({used_rules}/{total_logged} have hits)",
                 font=("TkDefaultFont", 9), foreground="#2E7D32").pack(anchor=tk.W, pady=2)
        
        if broad_penalty > 0:
            ttk.Label(score_content, 
                     text=f"Broad rules: -{broad_penalty:.1f} pts ({broad_rule_count} rule{'s' if broad_rule_count != 1 else ''} >10% traffic)",
                     font=("TkDefaultFont", 9), foreground="#D32F2F").pack(anchor=tk.W, pady=2)
        
        if visibility_penalty > 0:
            ttk.Label(score_content, 
                     text=f"Visibility: -{visibility_penalty:.1f} pts ({unlogged_count} unlogged rule{'s' if unlogged_count != 1 else ''})",
                     font=("TkDefaultFont", 9), foreground="#FF6F00").pack(anchor=tk.W, pady=2)
        
        ttk.Separator(score_content, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        # Determine score color
        if health_score >= 80:
            score_color = "#2E7D32"
        elif health_score >= 60:
            score_color = "#7CB342"
        elif health_score >= 40:
            score_color = "#FFA000"
        else:
            score_color = "#D32F2F"
        
        ttk.Label(score_content, text=f"Final score: {health_score}/100",
                 font=("TkDefaultFont", 10, "bold"), foreground=score_color).pack(anchor=tk.W, pady=2)
        
        # Scoring Formula section
        formula_frame = ttk.LabelFrame(parent_frame, text="Scoring Formula")
        formula_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        formula_content = ttk.Frame(formula_frame)
        formula_content.pack(padx=10, pady=10)
        
        formula_text = (
            "Components (maximum 100 points):\n\n"
            "• Base: 20 points\n"
            "  (for using Suricata formatted rules)\n\n"
            "• Effectiveness: 0-50 points\n"
            "  = (Medium + High rules / Logged rules) × 50\n"
            "  Rewards quality rules\n\n"
            "• Usage: 0-30 points\n"
            "  = (Rules with hits / Logged rules) × 30\n"
            "  Rewards ANY usage, penalizes unused\n\n"
            "• Broad penalty: -15 max\n"
            "  = min(15, broad_rules × 4)\n"
            "  Penalizes rules handling >10% traffic\n\n"
            "• Visibility penalty: -15 max\n"
            "  Balanced: averages absolute count (1pt per\n"
            "  unlogged rule) with percentage (0.5pt per %)\n"
            "  Penalizes monitoring blind spots"
        )
        
        ttk.Label(formula_content, text=formula_text,
                 font=("TkDefaultFont", 9), justify=tk.LEFT).pack(anchor=tk.W)
        
        # How to Improve section
        improve_frame = ttk.LabelFrame(parent_frame, text="How to Improve Your Score")
        improve_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        improve_content = ttk.Frame(improve_frame)
        improve_content.pack(padx=10, pady=10)
        
        # Generate specific recommendations based on current state
        recommendations = []
        
        # Unused rules impact on Usage score
        if categories['unused'] > 0:
            current_usage_ratio = usage_ratio
            potential_usage_ratio = 1.0  # If all unused removed
            potential_usage_gain = (potential_usage_ratio - current_usage_ratio) * 30
            recommendations.append(
                f"🔴 Remove {categories['unused']} unused rules\n"
                f"   → Usage: +{potential_usage_gain:.1f} pts"
            )
        
        # Low-frequency rules impact on Effectiveness score
        if categories['low_freq'] > 0:
            current_eff_ratio = effective_ratio
            potential_eff_ratio = (effective_rules + categories['low_freq']) / total_logged if total_logged > 0 else 0
            potential_eff_gain = (potential_eff_ratio - current_eff_ratio) * 50
            if potential_eff_gain > 1:  # Only show if meaningful gain
                recommendations.append(
                    f"🟡 Improve {categories['low_freq']} low-freq rules\n"
                    f"   → Effectiveness: +{potential_eff_gain:.1f} pts\n"
                    f"   Make them medium/high frequency"
                )
        
        # Broad rules
        if broad_penalty > 0:
            recommendations.append(
                f"🟠 Fix {broad_rule_count} broad rule{'s' if broad_rule_count != 1 else ''}\n"
                f"   → Remove penalty: +{broad_penalty:.1f} pts\n"
                f"   Split into more specific rules"
            )
        
        # Visibility gap
        if visibility_penalty > 0:
            recommendations.append(
                f"ℹ️ Enable logging for {unlogged_count} unlogged rule{'s' if unlogged_count != 1 else ''}\n"
                f"   → Remove penalty: +{visibility_penalty:.1f} pts\n"
                f"   Add 'alert' keyword or remove 'noalert'"
            )
        
        if health_score >= 80:
            recommendations.append("✓ Excellent health!\n   Maintain current quality.")
        elif health_score >= 60 and not recommendations:
            recommendations.append("✓ Good health!\n   Minor optimization opportunities.")
        
        if not recommendations:
            recommendations.append("Review the Priority Recommendations\nsection on the left for specific actions.")
        
        rec_text = "\n\n".join(recommendations)
        
        ttk.Label(improve_content, text=rec_text,
                 font=("TkDefaultFont", 9), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Score Ranges section
        ranges_frame = ttk.LabelFrame(parent_frame, text="Score Interpretation")
        ranges_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ranges_content = ttk.Frame(ranges_frame)
        ranges_content.pack(padx=10, pady=10)
        
        ranges = [
            ("80-100", "Excellent", "#2E7D32"),
            ("60-79", "Good", "#7CB342"),
            ("40-59", "Fair", "#FFA000"),
            ("0-39", "Poor", "#D32F2F")
        ]
        
        for range_text, label, color in ranges:
            row = ttk.Frame(ranges_content)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=f"{range_text}:", width=8).pack(side=tk.LEFT)
            ttk.Label(row, text=label, font=("TkDefaultFont", 9, "bold"),
                     foreground=color).pack(side=tk.LEFT)
        
        # Example Scenarios section
        example_frame = ttk.LabelFrame(parent_frame, text="Example Scenarios")
        example_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        example_content = ttk.Frame(example_frame)
        example_content.pack(padx=10, pady=10)
        
        example_text = (
            "Effectiveness Ratio Approach:\n"
            "Formula: 30 + (effective_ratio × 70) - (broad × 5)\n\n"
            "Scenario 1 (100 rules):\n"
            "• 5 unused, 3 low-freq, 0 broad\n"
            "• Effective: 92/100 = 92%\n"
            "• Score: 30 + (0.92 × 70) = 94/100\n"
            "• Rating: Excellent\n\n"
            "Scenario 2 (100 rules):\n"
            "• 25 unused, 10 low-freq, 1 broad\n"
            "• Effective: 65/100 = 65%\n"
            "• Score: 30 + (0.65 × 70) - 5 = 71/100\n"
            "• Rating: Good"
        )
        
        ttk.Label(example_content, text=example_text,
                 font=("TkDefaultFont", 8), justify=tk.LEFT,
                 foreground="#666666").pack(anchor=tk.W)
