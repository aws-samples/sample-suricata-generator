"""
Traffic Analyzer UI - User Interface for Traffic Analysis

Provides dialogs and results windows for:
1. Configuration (log group, time range, region)
2. Progress tracking during analysis
3. Results display (3-tab window)

Author: Suricata Generator Team
Created: 2026-01-25
"""

import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# Check for required dependencies
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    from src.aws.traffic_analyzer import TrafficAnalyzer
    from src.aws.aws_service_detector import AWSServiceDetector
    HAS_ANALYZER = True
except ImportError:
    HAS_ANALYZER = False


class TrafficAnalyzerUI:
    """UI manager for Traffic Analysis & VPC Endpoints feature"""
    
    def __init__(self, parent_app):
        """Initialize UI manager
        
        Args:
            parent_app: Reference to main SuricataRuleGenerator instance
        """
        self.parent = parent_app
        self.last_analysis_results = None
        
        # Session-based preferences (not persisted to disk)
        self._last_log_group = "/aws/network-firewall/my-firewall"
        self._last_alert_log_group = None  # Optional - no default value
        self._last_time_range = 30
        self._last_region = None
        self._last_start_date = None  # For custom date range
        self._last_end_date = None    # For custom date range
        
        # Tooltip window reference
        self._tooltip_window = None
    
    def _create_tooltip(self, widget, text):
        """Create a tooltip for a widget
        
        Args:
            widget: The widget to attach the tooltip to
            text: The tooltip text to display
        """
        def on_enter(event):
            # Destroy any existing tooltip first to prevent multiple tooltips
            if self._tooltip_window:
                try:
                    self._tooltip_window.destroy()
                except:
                    pass
                self._tooltip_window = None
            
            # Create tooltip window
            self._tooltip_window = tk.Toplevel()
            self._tooltip_window.wm_overrideredirect(True)
            self._tooltip_window.wm_attributes("-topmost", True)
            
            # Position tooltip near cursor
            x = event.x_root + 10
            y = event.y_root + 10
            self._tooltip_window.wm_geometry(f"+{x}+{y}")
            
            # Create tooltip content with styled background
            frame = ttk.Frame(self._tooltip_window, relief=tk.SOLID, borderwidth=1)
            frame.pack()
            
            label = ttk.Label(frame, text=text, justify=tk.LEFT,
                            background="#ffffe0", foreground="#000000",
                            relief=tk.FLAT, borderwidth=0, padding=5,
                            wraplength=350, font=("TkDefaultFont", 9))
            label.pack()
        
        def on_leave(event):
            # Destroy tooltip window
            if self._tooltip_window:
                try:
                    self._tooltip_window.destroy()
                except:
                    pass
                self._tooltip_window = None
        
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)
    
    def show_config_dialog(self, skip_cache_check=False):
        """Show configuration dialog for traffic analysis
        
        Args:
            skip_cache_check: If True, skip checking for cached data (used by Refresh button)
        """
        # Check for cached traffic analysis data first (unless skipped by Refresh)
        if not skip_cache_check and hasattr(self.parent, 'current_file') and self.parent.current_file:
            # Derive .stats file path from current rule file
            rule_file = self.parent.current_file
            stats_file = rule_file.rsplit('.', 1)[0] + '.stats'
            
            # Check if cached results exist
            try:
                from src.aws.traffic_analyzer import TrafficAnalyzer
                if TrafficAnalyzer.has_cached_results(stats_file):
                    # Ask user if they want to use cached data
                    cached_results = TrafficAnalyzer.load_results(stats_file)
                    if cached_results:
                        timestamp = cached_results['metadata']['timestamp']
                        days_ago = (datetime.now() - timestamp).days
                        time_ago_str = f"{days_ago} days ago" if days_ago > 0 else "today"
                        
                        response = messagebox.askyesnocancel(
                            "Cached Traffic Analysis Found",
                            f"Found cached traffic analysis from {time_ago_str} "
                            f"({timestamp.strftime('%Y-%m-%d %H:%M')}).\n\n"
                            f"Would you like to:\n"
                            f"• Yes: Load cached data (instant, no CloudWatch charges)\n"
                            f"• No: Run new analysis (fresh data, CloudWatch charges apply)\n"
                            f"• Cancel: Return to main window",
                            icon='question'
                        )
                        
                        if response is None:  # Cancel
                            return
                        elif response:  # Yes - load cached
                            self.last_analysis_results = cached_results
                            self._show_results_window(cached_results)
                            return
                        # If No, continue to show config dialog for new analysis
            except:
                pass  # If anything fails, just continue to config dialog
        
        # Check dependencies
        if not HAS_BOTO3:
            response = messagebox.askyesno(
                "boto3 Required",
                "Traffic Analysis requires the 'boto3' library.\n\n"
                "Would you like to see installation instructions?"
            )
            if response:
                self._show_boto3_install_help()
            return
        
        if not HAS_ANALYZER:
            response = messagebox.askyesno(
                "Dependencies Required",
                "Traffic Analysis requires additional libraries:\n"
                "• intervaltree (fast IP lookups)\n"
                "• requests (AWS IP ranges download)\n\n"
                "Would you like to see installation instructions?"
            )
            if response:
                self._show_install_help()
            return
        
        # Create configuration dialog
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Analyze Traffic Costs")
        dialog.geometry("650x900")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 150,
            self.parent.root.winfo_rooty() + 100
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(main_frame, text="Traffic Analysis & VPC Endpoint Optimization",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 5))
        
        # Description
        desc_text = (
            "Analyze traffic patterns and identify cost optimization\n"
            "opportunities from AWS Network Firewall logs"
        )
        ttk.Label(main_frame, text=desc_text,
                 font=("TkDefaultFont", 9)).pack(pady=(0, 15))
        
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 15))
        
        # Get default region
        default_region = self._last_region
        if not default_region:
            try:
                default_region = self.parent.aws_session.get_default_region()
            except:
                default_region = 'us-east-1'
        
        # Region selector
        region_frame = ttk.LabelFrame(main_frame, text="Firewall Region")
        region_frame.pack(fill=tk.X, pady=(0, 15))
        
        region_content = ttk.Frame(region_frame)
        region_content.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(region_content, text="Region:").pack(side=tk.LEFT, padx=(0, 5))
        
        # All AWS standard commercial regions (matches Import/Export features)
        aws_regions = [
            # US Regions
            'us-east-1',      # US East (N. Virginia)
            'us-east-2',      # US East (Ohio)
            'us-west-1',      # US West (N. California)
            'us-west-2',      # US West (Oregon)
            # Canada Regions
            'ca-central-1',   # Canada (Central)
            'ca-west-1',      # Canada (Calgary)
            # Europe Regions
            'eu-west-1',      # Europe (Ireland)
            'eu-west-2',      # Europe (London)
            'eu-west-3',      # Europe (Paris)
            'eu-central-1',   # Europe (Frankfurt)
            'eu-central-2',   # Europe (Zurich)
            'eu-north-1',     # Europe (Stockholm)
            'eu-south-1',     # Europe (Milan)
            'eu-south-2',     # Europe (Spain)
            # Asia Pacific Regions
            'ap-south-1',     # Asia Pacific (Mumbai)
            'ap-south-2',     # Asia Pacific (Hyderabad)
            'ap-southeast-1', # Asia Pacific (Singapore)
            'ap-southeast-2', # Asia Pacific (Sydney)
            'ap-southeast-3', # Asia Pacific (Jakarta)
            'ap-southeast-4', # Asia Pacific (Melbourne)
            'ap-northeast-1', # Asia Pacific (Tokyo)
            'ap-northeast-2', # Asia Pacific (Seoul)
            'ap-northeast-3', # Asia Pacific (Osaka)
            'ap-east-1',      # Asia Pacific (Hong Kong)
            # South America Regions
            'sa-east-1',      # South America (São Paulo)
            # Middle East Regions
            'me-south-1',     # Middle East (Bahrain)
            'me-central-1',   # Middle East (UAE)
            # Africa Regions
            'af-south-1',     # Africa (Cape Town)
            # Israel Regions
            'il-central-1',   # Israel (Tel Aviv)
        ]
        
        region_var = tk.StringVar(value=default_region)
        region_combo = ttk.Combobox(region_content, textvariable=region_var,
                                   values=aws_regions, state="readonly", width=20)
        region_combo.pack(side=tk.LEFT)
        
        # Log group
        log_frame = ttk.LabelFrame(main_frame, text="CloudWatch Logs Configuration")
        log_frame.pack(fill=tk.X, pady=(0, 15))
        
        log_content = ttk.Frame(log_frame)
        log_content.pack(fill=tk.X, padx=10, pady=10)
        
        # Flow log group with dropdown
        ttk.Label(log_content, text="Flow Log Group:").pack(anchor=tk.W, pady=(0, 5))
        log_group_var = tk.StringVar(value=self._last_log_group)
        flow_combo = ttk.Combobox(log_content, textvariable=log_group_var, width=48)
        flow_combo.pack(fill=tk.X, pady=(0, 10))
        
        # Alert log group with dropdown (optional)
        ttk.Label(log_content, text="Alert Log Group (Optional):").pack(anchor=tk.W, pady=(0, 5))
        alert_log_group_var = tk.StringVar(value=getattr(self, '_last_alert_log_group', '') if self._last_alert_log_group else '')
        alert_combo = ttk.Combobox(log_content, textvariable=alert_log_group_var, width=48)
        alert_combo.pack(fill=tk.X, pady=(0, 8))
        
        # Status label for log group loading
        load_status = ttk.Label(log_content, text="", font=("TkDefaultFont", 8))
        load_status.pack(anchor=tk.W, pady=(0, 8))
        
        def load_log_groups(event=None):
            """Load available CloudWatch log groups for selected region
            
            Args:
                event: Optional event from combobox selection (not used)
            """
            region = region_var.get()
            load_status.config(text="Loading log groups...", foreground="#666666")
            dialog.update()
            
            try:
                logs_client = self.parent.aws_session.get_client('logs', region_name=region)
                
                # Query for log groups with pagination
                log_groups = []
                paginator = logs_client.get_paginator('describe_log_groups')
                
                for page in paginator.paginate():
                    for log_group in page.get('logGroups', []):
                        log_groups.append(log_group['logGroupName'])
                    
                    # Limit to first 100 log groups for performance
                    if len(log_groups) >= 100:
                        break
                
                if log_groups:
                    # Sort log groups alphabetically
                    log_groups.sort()
                    
                    # Update comboboxes
                    flow_combo['values'] = log_groups
                    alert_combo['values'] = log_groups
                    
                    load_status.config(
                        text=f"✓ Loaded {len(log_groups)} log groups",
                        foreground="#2E7D32"
                    )
                else:
                    load_status.config(
                        text="⚠️ No log groups found in this region",
                        foreground="#FF6600"
                    )
            except Exception as e:
                error_msg = str(e)
                if "NoCredentials" in error_msg:
                    load_status.config(
                        text="⚠️ AWS credentials not configured",
                        foreground="#D32F2F"
                    )
                elif "AccessDenied" in error_msg:
                    load_status.config(
                        text="⚠️ No permission to list log groups",
                        foreground="#D32F2F"
                    )
                else:
                    load_status.config(
                        text=f"⚠️ Error: {error_msg[:50]}...",
                        foreground="#D32F2F"
                    )
        
        # Bind region selector to automatically load log groups when changed
        region_combo.bind('<<ComboboxSelected>>', load_log_groups)
        
        # Auto-load on dialog open
        dialog.after(200, load_log_groups)
        
        # Help text for log group selection
        help_text = (
            "💡 Flow log group is REQUIRED. Alert log group is OPTIONAL.\n"
            "Flow logs contain traffic data. Alert logs contain HTTP/TLS hostnames.\n"
            "Without alert logs, all traffic will show as '(No hostname)'.\n"
            "Log groups will automatically refresh when you change the region."
        )
        help_label = ttk.Label(log_content, text=help_text,
                              font=("TkDefaultFont", 8), foreground="#666666",
                              justify=tk.LEFT)
        help_label.pack(anchor=tk.W)
        
        # Time range
        time_frame = ttk.LabelFrame(main_frame, text="Analysis Time Range")
        time_frame.pack(fill=tk.X, pady=(0, 15))
        
        time_content = ttk.Frame(time_frame)
        time_content.pack(fill=tk.X, padx=10, pady=10)
        
        time_var = tk.IntVar(value=self._last_time_range if self._last_time_range in [7, 15, 30, 60, 90] else 30)
        ttk.Radiobutton(time_content, text="Last 7 days (Quick analysis)",
                       variable=time_var, value=7).pack(anchor=tk.W)
        ttk.Radiobutton(time_content, text="Last 15 days (Two-week trends)",
                       variable=time_var, value=15).pack(anchor=tk.W)
        ttk.Radiobutton(time_content, text="Last 30 days (Monthly patterns - RECOMMENDED)",
                       variable=time_var, value=30).pack(anchor=tk.W)
        ttk.Radiobutton(time_content, text="Last 60 days (Extended analysis)",
                       variable=time_var, value=60).pack(anchor=tk.W)
        ttk.Radiobutton(time_content, text="Last 90 days (Long-term patterns)",
                       variable=time_var, value=90).pack(anchor=tk.W)
        ttk.Radiobutton(time_content, text="Custom date range",
                       variable=time_var, value=0).pack(anchor=tk.W, pady=(5, 0))
        
        # Custom date range fields (initially disabled)
        custom_frame = ttk.Frame(time_content)
        custom_frame.pack(fill=tk.X, padx=(20, 0), pady=(5, 0))
        
        # Try to import tkcalendar for date picker, fall back to simple entry if not available
        try:
            from tkcalendar import DateEntry
            HAS_TKCALENDAR = True
        except ImportError:
            HAS_TKCALENDAR = False
        
        # Start date
        start_frame = ttk.Frame(custom_frame)
        start_frame.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(start_frame, text="Start Date:").pack(side=tk.LEFT, padx=(0, 5))
        
        # Use last custom dates if available, otherwise default to 30 days ago
        if self._last_start_date and self._last_end_date:
            default_start = datetime.combine(self._last_start_date, datetime.min.time())
            default_end = datetime.combine(self._last_end_date, datetime.min.time())
        else:
            default_start = datetime.now() - timedelta(days=30)
            default_end = datetime.now()
        
        if HAS_TKCALENDAR:
            start_date_entry = DateEntry(start_frame, width=12, background='darkblue',
                                         foreground='white', borderwidth=2,
                                         date_pattern='yyyy-mm-dd',
                                         year=default_start.year, month=default_start.month, day=default_start.day)
            start_date_entry.pack(side=tk.LEFT)
        else:
            start_date_var = tk.StringVar(value=default_start.strftime('%Y-%m-%d'))
            start_date_entry = ttk.Entry(start_frame, textvariable=start_date_var, width=12)
            start_date_entry.pack(side=tk.LEFT)
        
        # End date
        end_frame = ttk.Frame(custom_frame)
        end_frame.pack(side=tk.LEFT)
        ttk.Label(end_frame, text="End Date:").pack(side=tk.LEFT, padx=(0, 5))
        
        if HAS_TKCALENDAR:
            end_date_entry = DateEntry(end_frame, width=12, background='darkblue',
                                       foreground='white', borderwidth=2,
                                       date_pattern='yyyy-mm-dd',
                                       year=default_end.year, month=default_end.month, day=default_end.day)
            end_date_entry.pack(side=tk.LEFT)
        else:
            end_date_var = tk.StringVar(value=default_end.strftime('%Y-%m-%d'))
            end_date_entry = ttk.Entry(end_frame, textvariable=end_date_var, width=12)
            end_date_entry.pack(side=tk.LEFT)
        
        # Enable/disable custom date fields based on radio selection
        def update_custom_date_state(*args):
            if time_var.get() == 0:  # Custom range selected
                start_date_entry.config(state='normal')
                end_date_entry.config(state='normal')
            else:
                start_date_entry.config(state='disabled')
                end_date_entry.config(state='disabled')
        
        time_var.trace_add('write', update_custom_date_state)
        update_custom_date_state()  # Set initial state
        
        # Cost warning
        warning_frame = ttk.LabelFrame(main_frame, text="⚠️  CloudWatch Logs Query Costs")
        warning_frame.pack(fill=tk.X, pady=(0, 15))
        
        warning_text = (
            "CloudWatch Logs Insights charges per GB scanned: $0.005/GB in\n"
            "many regions (including us-east-1/us-east-2), up to $0.009/GB in others.\n\n"
            "Estimated Cost:\n"
            "• 7 days: ~$0.15 - $0.50 per analysis\n"
            "• 30 days: ~$0.50 - $2.00 per analysis\n\n"
            "💡 Tip: Start with 7-day analysis to minimize costs"
        )
        ttk.Label(warning_frame, text=warning_text,
                 font=("TkDefaultFont", 8), foreground="#FF6600",
                 justify=tk.LEFT).pack(padx=10, pady=10)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def on_analyze():
            log_group = log_group_var.get().strip()
            alert_log_group = alert_log_group_var.get().strip()
            
            if not log_group:
                messagebox.showerror("Validation Error", "Flow log group name is required.")
                return
            
            # Alert log group is optional - if not provided, analysis will run without hostname enrichment
            if not alert_log_group:
                alert_log_group = None
            
            days_value = time_var.get()
            
            # Handle custom date range
            if days_value == 0:  # Custom range selected
                try:
                    if HAS_TKCALENDAR:
                        start_date = start_date_entry.get_date()  # Returns datetime.date
                        end_date = end_date_entry.get_date()
                    else:
                        # Parse from string format YYYY-MM-DD
                        start_str = start_date_var.get()
                        end_str = end_date_var.get()
                        start_date = datetime.strptime(start_str, '%Y-%m-%d').date()
                        end_date = datetime.strptime(end_str, '%Y-%m-%d').date()
                    
                    # Validate: start must not be after end (same date is allowed for single-day analysis)
                    if start_date > end_date:
                        messagebox.showerror("Invalid Date Range", 
                                           "Start date cannot be after end date.")
                        return
                    
                    # Validate: end date can't be in future
                    if end_date > datetime.now().date():
                        messagebox.showwarning("Future Date", 
                                             "End date is in the future. Using today instead.")
                        end_date = datetime.now().date()
                    
                    # Save preferences (including custom dates for session)
                    self._last_log_group = log_group
                    self._last_alert_log_group = alert_log_group
                    self._last_time_range = 0  # Indicate custom range
                    self._last_region = region_var.get()
                    self._last_start_date = start_date  # Save for session
                    self._last_end_date = end_date      # Save for session
                    
                    dialog.destroy()
                    
                    # Run with custom dates
                    self._run_analysis(log_group, alert_log_group, None, region_var.get(), 
                                     start_date=start_date, end_date=end_date)
                    
                except ValueError as e:
                    messagebox.showerror("Invalid Date Format", 
                                       f"Please use YYYY-MM-DD format.\nError: {str(e)}")
                    return
            else:
                # Save preferences
                self._last_log_group = log_group
                self._last_alert_log_group = alert_log_group
                self._last_time_range = days_value
                self._last_region = region_var.get()
                
                dialog.destroy()
                
                # Run with preset range
                self._run_analysis(log_group, alert_log_group, days_value, region_var.get())
        
        ttk.Button(button_frame, text="Help", command=self._show_help).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Analyze", command=on_analyze).pack(side=tk.RIGHT, padx=(0, 5))
    
    def _run_analysis(self, log_group: str, alert_log_group: str, days: Optional[int], region: str,
                     start_date=None, end_date=None):
        """Run traffic analysis with progress dialog
        
        Args:
            log_group: CloudWatch flow log group name
            alert_log_group: CloudWatch alert log group name
            days: Number of days to analyze (None if using custom dates)
            region: AWS region
            start_date: Optional custom start date
            end_date: Optional custom end date
        """
        # Create progress dialog
        progress_dialog = tk.Toplevel(self.parent.root)
        progress_dialog.title("Analyzing Network Traffic...")
        progress_dialog.geometry("560x280")
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
        status_label = ttk.Label(main_frame, text="Initializing...",
                                font=("TkDefaultFont", 10))
        status_label.pack(pady=(0, 10))
        
        # Progress bar
        progress_bar = ttk.Progressbar(main_frame, mode='indeterminate', length=510)
        progress_bar.pack(pady=10)
        progress_bar.start(10)
        
        # Persistent progress line (e.g. "Flow logs: chunk 4 of 18 (22%)").
        # Updated only on structured chunk events, so it is NOT overwritten by the
        # per-poll "Query running... (Ns)" detail updates and stays readable.
        progress_line_label = ttk.Label(main_frame, text="",
                                        font=("TkDefaultFont", 9, "bold"))
        progress_line_label.pack(pady=(0, 3))
        
        # Details label
        details_label = ttk.Label(main_frame, text="Starting analysis...", wraplength=510)
        details_label.pack(pady=5)
        
        # Elapsed time label
        elapsed_label = ttk.Label(main_frame, text="Elapsed time: 0s")
        elapsed_label.pack(pady=5)
        
        # Cancel button
        cancel_flag = [False]
        analyzer_ref = [None]
        
        def on_cancel():
            cancel_flag[0] = True
            if analyzer_ref[0]:
                analyzer_ref[0].cancel_analysis()
            progress_dialog.destroy()
        
        ttk.Button(main_frame, text="Cancel", command=on_cancel).pack(pady=(10, 0))
        # Closing the dialog with the window's X behaves like Cancel (the analysis
        # runs in the background, so it must be told to stop).
        progress_dialog.protocol("WM_DELETE_WINDOW", on_cancel)
        
        # Track start time
        start_time = datetime.now()
        throttle_retries = [0]
        
        # Update elapsed time
        def update_elapsed():
            if not cancel_flag[0]:
                try:
                    elapsed = int((datetime.now() - start_time).total_seconds())
                    text = f"Elapsed time: {elapsed}s"
                    if throttle_retries[0]:
                        text += f"   |   Throttled requests retried: {throttle_retries[0]:,}"
                    elapsed_label.config(text=text)
                    progress_dialog.after(1000, update_elapsed)
                except tk.TclError:
                    pass  # dialog already closed
        
        update_elapsed()
        
        # The analysis runs on a background thread so the application stays
        # responsive. The worker never touches tkinter: it posts progress updates
        # and its final outcome to this queue, and the UI thread drains the queue
        # on a timer (poll_events) and renders them.
        events = queue.Queue()
        bar_state = {'determinate': False, 'value': 0.0}
        
        def render(update: Dict):
            stage = update.get('stage', 'Processing')
            status = update.get('status', '')
            step = update.get('step')
            step_total = update.get('step_total')
            
            if step and step_total:
                status_label.config(
                    text=f"Step {step} of {step_total}: {update.get('step_name') or stage}"
                )
            else:
                status_label.config(text=f"{stage}...")
            details_label.config(text=status)
            
            if 'throttle_retries' in update:
                throttle_retries[0] = update['throttle_retries']
            
            # One determinate bar for the WHOLE run, driven by overall_percent.
            # It never moves backwards, so it does not fill up and restart for
            # each step.
            overall = update.get('overall_percent')
            if overall is not None:
                if not bar_state['determinate']:
                    try:
                        progress_bar.stop()  # halt the indeterminate marquee
                    except Exception:
                        pass
                    progress_bar.config(mode='determinate', maximum=100)
                    bar_state['determinate'] = True
                bar_state['value'] = max(bar_state['value'], overall)
                progress_bar['value'] = bar_state['value']
            
            # Persistent progress line: overall percentage plus, during a chunked
            # query step (flow breakdown, alert hostnames), the chunk count. Not
            # overwritten by per-poll details; cleared when the step changes.
            chunk_total = update.get('chunk_total')
            if chunk_total:
                chunk_current = update.get('chunk_current', 0)
                pct = (chunk_current / chunk_total * 100.0) if chunk_total else 0.0
                label = update.get('chunk_label', 'Flow logs')
                bar_state['chunk_text'] = (
                    f"{label}: chunk {chunk_current:,} of {chunk_total:,} ({pct:.0f}%)"
                )
                bar_state['chunk_step'] = step
            elif step and step != bar_state.get('chunk_step'):
                bar_state.pop('chunk_text', None)
            parts = []
            if bar_state['determinate']:
                parts.append(f"Overall: {bar_state['value']:.0f}%")
            if bar_state.get('chunk_text'):
                parts.append(bar_state['chunk_text'])
            progress_line_label.config(text="   |   ".join(parts))
        
        def finish():
            try:
                progress_dialog.destroy()
            except tk.TclError:
                pass
        
        def poll_events():
            if cancel_flag[0]:
                return  # dialog closed; the worker stops on its own
            outcome = None
            try:
                for _ in range(500):  # bounded per tick so the UI stays responsive
                    kind, payload = events.get_nowait()
                    if kind == 'progress':
                        try:
                            render(payload)
                        except tk.TclError:
                            return  # dialog closed
                        except Exception:
                            pass  # a bad progress update must not stop the run
                    else:
                        outcome = (kind, payload)
                        break
            except queue.Empty:
                pass
            
            if outcome is None:
                try:
                    progress_dialog.after(150, poll_events)
                except tk.TclError:
                    pass
                return
            
            kind, payload = outcome
            finish()
            if kind == 'error':
                self._handle_analysis_error(payload)
                return
            if cancel_flag[0] or payload is None:
                return
            # Store results and show them
            self.last_analysis_results = payload
            self._show_results_window(payload)
        
        def worker():
            try:
                # Create analyzer with either days or custom dates
                if start_date and end_date:
                    analyzer = TrafficAnalyzer(log_group, region, alert_log_group=alert_log_group,
                                             start_date=start_date, end_date=end_date,
                                             aws_session=self.parent.aws_session)
                else:
                    analyzer = TrafficAnalyzer(log_group, region, days, alert_log_group,
                                             aws_session=self.parent.aws_session)
                analyzer_ref[0] = analyzer
                if cancel_flag[0]:
                    analyzer.cancel_analysis()  # cancelled while starting up
                
                results = analyzer.analyze(lambda update: events.put(('progress', update)))
                events.put(('done', results))
            except Exception as e:
                events.put(('error', e))
        
        threading.Thread(target=worker, name='traffic-analysis', daemon=True).start()
        progress_dialog.after(150, poll_events)
    
    def _sort_tree_column(self, tree: ttk.Treeview, column: str, reverse: bool):
        """Sort tree view by column
        
        Args:
            tree: Treeview widget to sort
            column: Column name to sort by
            reverse: Sort in reverse order
        """
        # Get all items with their column values
        items = []
        for item_id in tree.get_children():
            col_value = tree.set(item_id, column)
            
            # Try to convert to number for numeric sorting
            try:
                # Remove $ and , for numeric columns
                numeric_val = col_value.replace('$', '').replace(',', '')
                sort_key = float(numeric_val)
                is_numeric = True
            except (ValueError, AttributeError):
                sort_key = col_value.lower() if col_value else ''
                is_numeric = False
            
            items.append((is_numeric, sort_key, item_id))
        
        # Sort items - numeric first, then strings, or reverse if needed
        items.sort(key=lambda x: (not x[0] if reverse else x[0], x[1]), reverse=reverse)
        
        # Rearrange items in tree
        for index, (_, _, item_id) in enumerate(items):
            tree.move(item_id, '', index)
        
        # Update column header to show sort direction
        for col in tree['columns']:
            header_text = tree.heading(col)['text']
            # Remove existing sort indicators
            header_text = header_text.replace(' ▲', '').replace(' ▼', '')
            
            if col == column:
                # Add sort indicator
                header_text += ' ▼' if reverse else ' ▲'
            
            # Update header with command for next sort
            tree.heading(col, text=header_text,
                        command=lambda c=col: self._sort_tree_column(tree, c, not reverse if c == column else False))
    
    def _show_results_window(self, results: Dict[str, Any]):
        """Show results window with 3 tabs
        
        Args:
            results: Analysis results dictionary
        """
        # Store results for drill-down access
        self.current_results = results
        
        # Extract and store region-specific firewall pricing rate for consistent use
        metadata = results['metadata']
        total_gb = metadata['total_gb']
        total_cost = metadata['total_cost']
        # Derive regional pricing from backend's calculation
        self.firewall_cost_per_gb = (total_cost / total_gb) if total_gb > 0 else 0.065
        
        # Create results window
        results_window = tk.Toplevel(self.parent.root)
        results_window.title("Analyze Traffic Costs - Results")
        # Height accommodates the tallest header case (the multi-line coverage-gap
        # warning) while keeping the bottom Help/Save/Close buttons visible. The
        # extra height applies to all runs, not just when the warning is shown.
        results_window.geometry("1000x870")
        results_window.transient(self.parent.root)
        results_window.resizable(True, True)
        
        # Center window
        results_window.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 50,
            self.parent.root.winfo_rooty() + 50
        ))
        
        main_frame = ttk.Frame(results_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        metadata = results['metadata']
        timestamp = metadata['timestamp']
        time_ago = self._format_time_ago(timestamp)
        
        ttk.Label(header_frame,
                 text=f"Analysis completed {time_ago}",
                 font=("TkDefaultFont", 10)).pack(side=tk.LEFT)
        
        # Hostname coverage of the Internet tab: share of Internet traffic (bytes)
        # shown under a hostname, computed from the tab's own rows so it matches
        # what the tab displays. Hostnames only apply to Internet traffic; AWS
        # service and internal traffic are excluded. None = no Internet traffic.
        hostname_cov = TrafficAnalyzer.internet_hostname_coverage(
            results.get('hostname_aggregation', {}))
        if hostname_cov is None:
            coverage_text = "Hostname Coverage: n/a (no Internet traffic)"
        else:
            coverage_text = f"Hostname Coverage: {hostname_cov:.0f}% of Internet traffic"
        
        # Check if custom date range was used
        if metadata.get('use_custom_dates'):
            meta_text = (f"Time Range: {metadata['start_date']} to {metadata['end_date']} | "
                        f"Flows: {metadata['total_flows']:,} | "
                        f"Region: {metadata['region']} | "
                        f"{coverage_text}")
        else:
            meta_text = (f"Time Range: Last {metadata['time_range_days']} days | "
                        f"Flows: {metadata['total_flows']:,} | "
                        f"Region: {metadata['region']} | "
                        f"{coverage_text}")
        
        # Color code based on coverage
        cov_for_color = 100.0 if hostname_cov is None else hostname_cov
        meta_color = "#2E7D32" if cov_for_color >= 70 else "#FF6F00" if cov_for_color >= 40 else "#D32F2F"
        ttk.Label(header_frame, text=meta_text,
                 font=("TkDefaultFont", 9), foreground=meta_color).pack(side=tk.LEFT, padx=(20, 0))
        
        # Info/warning frame for hostname coverage and CloudWatch costs
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Show CloudWatch query cost
        cloudwatch_cost = metadata.get('cloudwatch_query_cost', 0)
        cloudwatch_gb = metadata.get('cloudwatch_gb_scanned', 0)
        cloudwatch_rate = metadata.get('cloudwatch_price_per_gb', 0.005)
        cost_text = (f"💵 CloudWatch Query Cost: ${cloudwatch_cost:.2f} "
                     f"({cloudwatch_gb:.2f} GB scanned at ${cloudwatch_rate:g}/GB)")
        ttk.Label(info_frame, text=cost_text,
                 font=("TkDefaultFont", 8), foreground="#0066CC").pack(anchor=tk.W, pady=(0, 5))
        
        # Show a coverage-gap warning when the logs found cover materially less than
        # the selected window (observed span misses a window edge by >6h; set by the
        # analyzer as coverage_gap). Common cause: older logs aged out of CloudWatch
        # retention, or the firewall did not exist for the whole window. In this case
        # the analyzer bills endpoint hours on the OBSERVED span (not the full
        # window), so BOTH the endpoint-hour cost and the data-processing cost reflect
        # only the observed span and are a lower bound for the range requested.
        coverage_gap = bool(metadata.get('coverage_gap'))
        if coverage_gap:
            # Prefer the observed data span from the timestamps; fall back gracefully.
            earliest = metadata.get('earliest_timestamp')
            latest = metadata.get('latest_timestamp')

            def _fmt_ts(ts):
                try:
                    return ts.strftime('%Y-%m-%d %H:%M')
                except AttributeError:
                    return str(ts) if ts else "unknown"

            if metadata.get('use_custom_dates'):
                selected_range = f"{metadata.get('start_date')} to {metadata.get('end_date')}"
            else:
                selected_range = f"the last {metadata.get('time_range_days')} days"

            observed_hours = metadata.get('observed_span_hours')
            span_note = ""
            if isinstance(observed_hours, (int, float)) and observed_hours > 0:
                span_note = f" (~{observed_hours / 24:.1f} days of data)"

            gap_text = (
                "⚠️ Log coverage gap: the logs found span only "
                f"{_fmt_ts(earliest)} to {_fmt_ts(latest)}{span_note}, which is shorter "
                f"than the selected range ({selected_range}). Older logs may have aged "
                "out of CloudWatch (log retention), or the firewall may not have existed "
                "for the whole range. Because the missing time cannot be measured, BOTH "
                "the traffic/data-processing cost AND the endpoint-hour cost shown here "
                "reflect only the observed span — they are a LOWER BOUND for the range you "
                "requested, not the full-range total. An endpoint that passed no traffic "
                "during the observed span is not counted."
            )
            ttk.Label(info_frame, text=gap_text,
                     font=("TkDefaultFont", 8), foreground="#D32F2F",
                     wraplength=950, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 5))
        
        # Show warning if low hostname coverage. Suppressed during a coverage gap:
        # a gap naturally tanks hostname coverage, and the gap warning already
        # explains the incompleteness, so showing both is redundant noise.
        if hostname_cov is not None and hostname_cov < 50 and not coverage_gap:
            warning_text = (f"⚠️ Warning: Only {hostname_cov:.0f}% of Internet traffic has hostname information. "
                          f"This typically means alert logging is not enabled for all traffic. "
                          f"Consider enabling HTTP/TLS alert logging for better visibility.")
            ttk.Label(info_frame, text=warning_text,
                     font=("TkDefaultFont", 8), foreground="#FF6600",
                     wraplength=950, justify=tk.LEFT).pack(anchor=tk.W)
        
        # Show notice if the per-flow sample was truncated by the 10K-row limit.
        # The headline totals/costs remain authoritative (server-side aggregation);
        # only the per-flow breakdowns (top talkers, per-hostname/service/VPC) are a
        # sample of the traffic when this fires.
        if metadata.get('is_partial') or metadata.get('flow_bytes_truncated'):
            sample_fraction = metadata.get('sample_bytes_fraction', None)
            if isinstance(sample_fraction, (int, float)) and sample_fraction < 1.0:
                coverage_note = (f" The per-flow detail covers ~{sample_fraction * 100:.0f}% "
                                 f"of total traffic by volume.")
            else:
                coverage_note = ""
            partial_text = (
                "ℹ️ High traffic volume exceeded the CloudWatch Logs Insights 10,000-row "
                "limit, so the per-flow breakdowns below (Top Talkers and the per-hostname, "
                "per-service, and VPC-to-VPC tables) are based on a sample." + coverage_note +
                " Total traffic and cost figures are authoritative — they are computed by "
                "server-side aggregation and are not affected by this limit."
            )
            ttk.Label(info_frame, text=partial_text,
                     font=("TkDefaultFont", 8), foreground="#B26A00",
                     wraplength=950, justify=tk.LEFT).pack(anchor=tk.W, pady=(5, 0))
        
        # Warn when region pricing was not found and us-east-1 fallback rates were
        # used, since costs for that region may be inaccurate (often too low).
        if metadata.get('pricing_fallback'):
            region_name = metadata.get('region', 'this region')
            pricing_text = (
                f"⚠️ Pricing note: region '{region_name}' is not in the built-in pricing "
                f"tables, so all cost figures use US-East-1 fallback rates ($0.395/hr endpoint, "
                f"$0.065/GB data processing). Actual costs for this region may differ — treat "
                f"these dollar amounts as rough estimates."
            )
            ttk.Label(info_frame, text=pricing_text,
                     font=("TkDefaultFont", 8), foreground="#D32F2F",
                     wraplength=950, justify=tk.LEFT).pack(anchor=tk.W, pady=(5, 0))
        
        # Refresh and Export buttons
        ttk.Button(header_frame, text="Refresh", 
                  command=lambda: [results_window.destroy(), self.show_config_dialog(skip_cache_check=True)]).pack(side=tk.RIGHT)
        ttk.Button(header_frame, text="Export", 
                  command=lambda: self._export_results(results)).pack(side=tk.RIGHT, padx=(0, 5))
        
        # Tab notebook
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Tab 1: Internet Traffic (Top Talkers)
        self._create_tab1_internet_traffic(notebook, results)
        
        # Tab 2: AWS Service Traffic (VPC Endpoints)
        self._create_tab2_aws_services(notebook, results)
        
        # Tab 3: Internal Traffic (VPC-to-VPC and on-premises)
        self._create_tab3_vpc_to_vpc(notebook, results)
        
        # Help, Save and Close buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(10, 0))
        
        ttk.Button(button_frame, text="Help", 
                  command=self._show_results_help).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Save", 
                  command=lambda: self._save_analysis_results(results)).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Close", 
                  command=results_window.destroy).pack(side=tk.LEFT)
    
    def _create_tab1_internet_traffic(self, notebook: ttk.Notebook, results: Dict):
        """Create Tab 1: Internet Traffic (Top Talkers)
        
        Args:
            notebook: Parent notebook widget
            results: Analysis results
        """
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Internet Traffic")
        
        content = ttk.Frame(tab)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create container frame for side-by-side boxes
        overview_container = ttk.Frame(content)
        overview_container.pack(fill=tk.X, pady=(0, 10))
        
        # Left box: TRAFFIC BREAKDOWN (data processing costs)
        traffic_frame = ttk.LabelFrame(overview_container, text="📊 ESTIMATED TRAFFIC BREAKDOWN (Variable Costs)")
        traffic_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Calculate traffic breakdown for all categories
        hostname_agg = results['hostname_aggregation']
        total_internet_bytes = sum(data['bytes'] for data in hostname_agg.values())
        total_internet_gb = total_internet_bytes / (1024**3)
        
        # Calculate AWS service traffic
        service_totals = results['service_totals']
        total_aws_bytes = sum(sum(regions.values()) for regions in service_totals.values())
        total_aws_gb = total_aws_bytes / (1024**3)
        
        # Calculate VPC-to-VPC traffic
        vpc_connections = results['vpc_to_vpc_connections']
        total_vpc_bytes = sum(conn['total_bytes'] for conn in vpc_connections)
        total_vpc_gb = total_vpc_bytes / (1024**3)
        
        metadata = results['metadata']
        total_gb = metadata['total_gb']
        
        # Create breakdown text with costs
        internet_pct = (total_internet_gb / total_gb * 100) if total_gb > 0 else 0
        aws_pct = (total_aws_gb / total_gb * 100) if total_gb > 0 else 0
        vpc_pct = (total_vpc_gb / total_gb * 100) if total_gb > 0 else 0
        
        # Use region-specific firewall pricing from metadata
        # Backend already calculated total_cost with correct regional pricing
        total_cost = metadata['total_cost']
        
        # Derive the region-specific cost per GB from backend's calculation
        firewall_cost_per_gb = (total_cost / total_gb) if total_gb > 0 else 0.065
        
        # Calculate category costs using region-specific pricing
        internet_cost = total_internet_gb * firewall_cost_per_gb
        aws_cost = total_aws_gb * firewall_cost_per_gb
        vpc_cost = total_vpc_gb * firewall_cost_per_gb
        
        traffic_text = (
            f"Total: ~{total_gb:.1f} GB (~${total_cost:.2f})\n"
            f"├─ Internet: {total_internet_gb:.1f} GB ({internet_pct:.0f}%) - ${internet_cost:.2f}\n"
            f"├─ AWS Service: {total_aws_gb:.1f} GB ({aws_pct:.0f}%) - ${aws_cost:.2f}\n"
            f"└─ Internal: {total_vpc_gb:.1f} GB ({vpc_pct:.0f}%) - ${vpc_cost:.2f}"
        )
        ttk.Label(traffic_frame, text=traffic_text,
                 font=("Consolas", 9), justify=tk.LEFT).pack(padx=10, pady=10, anchor=tk.W)
        
        # Right box: FIXED COSTS (primary endpoint hourly charges)
        fixed_frame = ttk.LabelFrame(overview_container, text="💰 ESTIMATED FIXED COSTS (Primary Endpoint Hours)")
        fixed_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Add tooltip explaining the limitation
        tooltip_text = (
            "Endpoint costs shown are based on AZs that appear in logs.\n\n"
            "If your firewall has endpoints that didn't process any traffic\n"
            "during this period, actual costs may be higher.\n\n"
            "This primarily affects short analysis periods (single day)\n"
            "where some endpoints may not have processed traffic."
        )
        self._create_tooltip(fixed_frame, tooltip_text)
        
        # Get endpoint cost data from metadata
        endpoint_costs = metadata.get('endpoint_costs', [])
        total_endpoint_cost = metadata.get('total_endpoint_cost', 0)
        runtime_hours = metadata.get('runtime_hours', 0)
        total_gb = metadata.get('total_gb', 0)
        
        if endpoint_costs:
            # Build fixed costs text with traffic volume on single line
            fixed_lines = []
            for ec in endpoint_costs:
                az = ec['availability_zone']
                hours = ec['hours']
                rate = ec['hourly_rate']
                cost = ec['total_cost']
                traffic_gb = ec.get('traffic_gb', 0)
                traffic_pct = ec.get('traffic_pct', 0)
                
                # Format: Single line with cost breakdown and traffic
                fixed_lines.append(f"• {az}: ${cost:.2f} ({traffic_gb:.1f} GB, {traffic_pct:.1f}% of all traffic)")
            
            fixed_lines.append(f"\nTotal: ${total_endpoint_cost:.2f} ({total_gb:.1f} GB)")
            fixed_text = "\n".join(fixed_lines)
        else:
            fixed_text = "No endpoint data available"
        
        ttk.Label(fixed_frame, text=fixed_text,
                 font=("Consolas", 9), justify=tk.LEFT).pack(padx=10, pady=10, anchor=tk.W)
        
        # Top talkers table
        table_frame = ttk.LabelFrame(content, text="🔍 TOP TALKERS - NON-AWS TRAFFIC")
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview
        columns = ("Destination", "Port", "Protocol", "Traffic (GB)", "Cost", "Sources", "Flows")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        # Make columns sortable by clicking headers
        tree.heading("Destination", text="Destination",
                    command=lambda: self._sort_tree_column(tree, "Destination", False))
        tree.heading("Port", text="Dest Port",
                    command=lambda: self._sort_tree_column(tree, "Port", False))
        tree.heading("Protocol", text="Protocol",
                    command=lambda: self._sort_tree_column(tree, "Protocol", False))
        tree.heading("Traffic (GB)", text="Traffic (GB)",
                    command=lambda: self._sort_tree_column(tree, "Traffic (GB)", True))
        tree.heading("Cost", text="Total Cost",
                    command=lambda: self._sort_tree_column(tree, "Cost", True))
        tree.heading("Sources", text="Unique Src",
                    command=lambda: self._sort_tree_column(tree, "Sources", True))
        tree.heading("Flows", text="Flows",
                    command=lambda: self._sort_tree_column(tree, "Flows", True))
        
        tree.column("Destination", width=300, stretch=True)
        tree.column("Port", width=80, stretch=False)
        tree.column("Protocol", width=80, stretch=False)
        tree.column("Traffic (GB)", width=100, stretch=False)
        tree.column("Cost", width=80, stretch=False)
        tree.column("Sources", width=80, stretch=False)
        tree.column("Flows", width=80, stretch=False)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Populate table (sorted by traffic descending)
        sorted_hostnames = sorted(hostname_agg.items(), 
                                 key=lambda x: x[1]['bytes'], 
                                 reverse=True)
        
        # Store mapping from tree item to original aggregation key
        item_to_key = {}
        
        for destination_key, data in sorted_hostnames[:50]:  # Top 50
            traffic_gb = data['bytes'] / (1024**3)
            cost = traffic_gb * self.firewall_cost_per_gb
            
            # For IP:port destinations, show just the IP in Destination column
            # (port is already in the separate Port column)
            if data.get('is_ip_based') and ':' in destination_key:
                display_destination = destination_key.rsplit(':', 1)[0]  # Just the IP
            else:
                display_destination = destination_key  # Hostname as-is
            
            item_id = tree.insert("", tk.END, values=(
                display_destination,
                data['dest_port'],
                data['proto'],
                f"{traffic_gb:.2f}",
                f"${cost:.2f}",
                data['unique_sources'],
                f"{data['flow_count']:,}"
            ))
            
            # Store original key for drill-down
            item_to_key[item_id] = destination_key
        
        # Add double-click handler for drill-down
        def on_double_click(event):
            selection = tree.selection()
            if selection:
                item_id = selection[0]
                # Use original aggregation key
                destination_key = item_to_key.get(item_id)
                if destination_key:
                    self._show_drilldown_tab1(destination_key)
        
        tree.bind("<Double-1>", on_double_click)
        
        # Add helper text with aggregation explanation
        help_frame = ttk.Frame(content)
        help_frame.pack(fill=tk.X, pady=(5, 0))
        help_text = (
            "💡 Aggregation: Traffic grouped by destination (hostname or IP:port)\n"
            "   Click column headers to sort | Double-click any row to see source IP breakdown"
        )
        ttk.Label(help_frame, text=help_text,
                 font=("TkDefaultFont", 8), foreground="#666666",
                 justify=tk.LEFT).pack(anchor=tk.W)
    
    def _create_tab2_aws_services(self, notebook: ttk.Notebook, results: Dict):
        """Create Tab 2: AWS Service Traffic (VPC Endpoints)
        
        Args:
            notebook: Parent notebook widget
            results: Analysis results
        """
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="AWS Service Traffic")
        
        content = ttk.Frame(tab)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Traffic breakdown and cost summary
        summary_frame = ttk.LabelFrame(content, text="📊 AWS SERVICE TRAFFIC & COST SUMMARY")
        summary_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Calculate traffic totals
        service_totals = results['service_totals']
        total_aws_bytes = sum(sum(regions.values()) for regions in service_totals.values())
        total_aws_gb = total_aws_bytes / (1024**3)
        metadata = results['metadata']
        total_gb = metadata['total_gb']
        aws_pct = (total_aws_gb / total_gb * 100) if total_gb > 0 else 0
        
        recommendations = results['vpc_endpoint_recommendations']
        total_savings = sum(r['monthly_savings'] for r in recommendations if r['recommendation'] == 'DEPLOY')
        
        summary_text = (f"AWS Service Traffic: ~{total_aws_gb:.1f} GB ({aws_pct:.0f}% of total, for the analyzed window)\n"
                       f"Projected Monthly Savings (with recommended endpoints): ${total_savings:.2f} (~${total_savings*12:.0f}/year)")
        ttk.Label(summary_frame, text=summary_text,
                 font=("TkDefaultFont", 10), foreground="#2E7D32").pack(padx=15, pady=15, anchor=tk.W)
        
        # Recommendations table
        table_frame = ttk.LabelFrame(content, text="📊 VPC ENDPOINT RECOMMENDATIONS")
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Service", "Region", "Type", "Traffic", "Current", "Endpoint", "Savings", "Action")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        # Make columns sortable by clicking headers
        tree.heading("Service", text="AWS Service",
                    command=lambda: self._sort_tree_column(tree, "Service", False))
        tree.heading("Region", text="Dest Region",
                    command=lambda: self._sort_tree_column(tree, "Region", False))
        tree.heading("Type", text="Type",
                    command=lambda: self._sort_tree_column(tree, "Type", False))
        tree.heading("Traffic", text="Traffic (GB)",
                    command=lambda: self._sort_tree_column(tree, "Traffic", True))
        tree.heading("Current", text="Current Cost (window)",
                    command=lambda: self._sort_tree_column(tree, "Current", True))
        tree.heading("Endpoint", text="Endpoint Cost (window)",
                    command=lambda: self._sort_tree_column(tree, "Endpoint", True))
        tree.heading("Savings", text="Projected Monthly Savings",
                    command=lambda: self._sort_tree_column(tree, "Savings", True))
        tree.heading("Action", text="Recommendation",
                    command=lambda: self._sort_tree_column(tree, "Action", False))
        
        tree.column("Service", width=100, stretch=False)
        tree.column("Region", width=100, stretch=False)
        tree.column("Type", width=120, stretch=False)
        tree.column("Traffic", width=100, stretch=False)
        tree.column("Current", width=110, stretch=False)
        tree.column("Endpoint", width=150, stretch=False)
        tree.column("Savings", width=170, stretch=False)
        tree.column("Action", width=150, stretch=True)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Configure colors
        tree.tag_configure("deploy", foreground="#2E7D32")
        tree.tag_configure("skip", foreground="#666666")
        tree.tag_configure("consider", foreground="#FF6F00")
        
        # Populate table
        for rec in recommendations:
            tag = "deploy" if rec['recommendation'] == 'DEPLOY' else \
                  "consider" if rec['recommendation'] == 'CONSIDER' else "skip"
            
            tree.insert("", tk.END, values=(
                rec['service'],
                rec['region'],
                rec['endpoint_type'],
                f"{rec['traffic_gb']:.1f}",
                f"${rec['current_cost']:.2f}",
                f"${rec['endpoint_cost']:.2f}",
                f"${rec['monthly_savings']:.2f}",
                rec['recommendation']
            ), tags=(tag,))
        
        # Add double-click handler for drill-down
        def on_double_click(event):
            selection = tree.selection()
            if selection:
                item = selection[0]
                service = tree.set(item, "Service")
                region = tree.set(item, "Region")
                self._show_drilldown_tab2(service, region)
        
        tree.bind("<Double-1>", on_double_click)
        
        # Add helper text with aggregation explanation
        help_frame = ttk.Frame(content)
        help_frame.pack(fill=tk.X, pady=(5, 0))
        help_text = (
            "💡 Aggregation: Traffic grouped by AWS service and destination region\n"
            "   Traffic (GB), Current Cost, and Endpoint Cost are for the analyzed window. "
            "Projected Monthly Savings assumes this window's traffic repeats for a full month.\n"
            "   Click column headers to sort | Double-click any row to see source IP + hostname breakdown"
        )
        ttk.Label(help_frame, text=help_text,
                 font=("TkDefaultFont", 8), foreground="#666666",
                 justify=tk.LEFT).pack(anchor=tk.W)
    
    def _create_tab3_vpc_to_vpc(self, notebook: ttk.Notebook, results: Dict):
        """Create Tab 3: Internal Traffic (VPC-to-VPC and on-premises)
        
        Args:
            notebook: Parent notebook widget
            results: Analysis results
        """
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="Internal Traffic")
        
        content = ttk.Frame(tab)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Overview with percentage breakdown
        connections = results['vpc_to_vpc_connections']
        total_bytes = sum(conn['total_bytes'] for conn in connections)
        total_gb = total_bytes / (1024**3)
        total_cost = total_gb * self.firewall_cost_per_gb
        
        metadata = results['metadata']
        total_traffic_gb = metadata['total_gb']
        vpc_pct = (total_gb / total_traffic_gb * 100) if total_traffic_gb > 0 else 0
        
        overview_frame = ttk.LabelFrame(content, text="📊 INTERNAL TRAFFIC OVERVIEW")
        overview_frame.pack(fill=tk.X, pady=(0, 10))
        
        overview_text = (f"Total Internal Traffic: ~{total_gb:.1f} GB ({vpc_pct:.0f}% of total)\n"
                        f"Est. Firewall Data-Processing Cost: ${total_cost:.2f} (for the analyzed window)")
        ttk.Label(overview_frame, text=overview_text,
                 font=("TkDefaultFont", 10)).pack(padx=15, pady=15, anchor=tk.W)
        
        # Connections table
        table_frame = ttk.LabelFrame(content, text="🔍 TOP CONNECTIONS")
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Destination", "Port", "Protocol", "Traffic", "Cost", "Sources", "Flows")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        # Make columns sortable by clicking headers
        tree.heading("Destination", text="Dest IP",
                    command=lambda: self._sort_tree_column(tree, "Destination", False))
        tree.heading("Port", text="Dest Port",
                    command=lambda: self._sort_tree_column(tree, "Port", False))
        tree.heading("Protocol", text="Protocol",
                    command=lambda: self._sort_tree_column(tree, "Protocol", False))
        tree.heading("Traffic", text="Traffic (GB)",
                    command=lambda: self._sort_tree_column(tree, "Traffic", True))
        tree.heading("Cost", text="Total Cost",
                    command=lambda: self._sort_tree_column(tree, "Cost", True))
        tree.heading("Sources", text="Unique Src",
                    command=lambda: self._sort_tree_column(tree, "Sources", True))
        tree.heading("Flows", text="Flows",
                    command=lambda: self._sort_tree_column(tree, "Flows", True))
        
        tree.column("Destination", width=150, stretch=False)
        tree.column("Port", width=100, stretch=False)
        tree.column("Protocol", width=100, stretch=False)
        tree.column("Traffic", width=100, stretch=False)
        tree.column("Cost", width=80, stretch=False)
        tree.column("Sources", width=80, stretch=False)
        tree.column("Flows", width=80, stretch=True)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Aggregate by (dest_ip, dest_port) for display (combining all source IPs)
        dest_aggregation = {}
        for conn in connections:
            key = (conn['dest_ip'], conn['dest_port'])
            if key not in dest_aggregation:
                dest_aggregation[key] = {
                    'dest_ip': conn['dest_ip'],
                    'dest_port': conn['dest_port'],
                    'proto': conn['proto'],
                    'total_bytes': 0,
                    'flow_count': 0,
                    'source_ips': set()
                }
            dest_aggregation[key]['total_bytes'] += conn['total_bytes']
            dest_aggregation[key]['flow_count'] += conn['flow_count']
            dest_aggregation[key]['source_ips'].add(conn['src_ip'])
        
        # Sort by traffic and populate table (top 50)
        sorted_dests = sorted(dest_aggregation.values(), 
                             key=lambda x: x['total_bytes'], 
                             reverse=True)
        
        for conn in sorted_dests[:50]:
            traffic_gb = conn['total_bytes'] / (1024**3)
            cost = traffic_gb * self.firewall_cost_per_gb
            unique_sources = len(conn['source_ips'])
            
            tree.insert("", tk.END, values=(
                conn['dest_ip'],
                conn['dest_port'],
                conn['proto'],
                f"{traffic_gb:.2f}",
                f"${cost:.2f}",
                unique_sources,
                f"{conn['flow_count']:,}"
            ))
        
        # Add double-click handler for drill-down
        def on_double_click(event):
            selection = tree.selection()
            if selection:
                item = selection[0]
                dest_ip = tree.set(item, "Destination")
                dest_port = tree.set(item, "Port")
                self._show_drilldown_tab3(dest_ip, dest_port)
        
        tree.bind("<Double-1>", on_double_click)
        
        # Add helper text with aggregation explanation
        help_frame = ttk.Frame(content)
        help_frame.pack(fill=tk.X, pady=(5, 0))
        help_text = (
            "💡 Aggregation: Traffic grouped by (Dest IP → Dest Port) - all source IPs combined\n"
            "   Click column headers to sort | Double-click any row to see source IP breakdown"
        )
        ttk.Label(help_frame, text=help_text,
                 font=("TkDefaultFont", 8), foreground="#666666",
                 justify=tk.LEFT).pack(anchor=tk.W)
    
    def _show_drilldown_tab1(self, destination: str):
        """Show source IP breakdown for internet traffic destination
        
        Args:
            destination: Destination to drill down into (hostname or IP:port)
        """
        if not self.current_results:
            return
        
        sources = self.current_results.get('source_breakdowns', {}) \
            .get('internet', {}).get(destination)
        
        if not sources:
            messagebox.showinfo("No Data", f"No flow data found for {destination}")
            return
        
        self._show_source_breakdown_dialog(destination, sources)
    
    def _show_drilldown_tab2(self, service: str, region: str):
        """Show source IP breakdown for AWS service traffic
        
        Args:
            service: AWS service name
            region: AWS region
        """
        if not self.current_results:
            return
        
        sources = self.current_results.get('source_breakdowns', {}) \
            .get('aws_service', {}).get(str(service), {}).get(str(region))
        
        if not sources:
            messagebox.showinfo("No Data", f"No flow data found for {service} in {region}")
            return
        
        self._show_source_breakdown_dialog(f"{service} ({region})", sources)
    
    def _show_drilldown_tab3(self, dest_ip: str, dest_port: str):
        """Show source IP breakdown for VPC-to-VPC traffic
        
        Args:
            dest_ip: Destination IP address
            dest_port: Destination port
        """
        if not self.current_results:
            return
        
        sources = self.current_results.get('source_breakdowns', {}) \
            .get('internal', {}).get(str(dest_ip), {}).get(str(dest_port))
        
        if not sources:
            messagebox.showinfo("No Data", f"No flow data found for {dest_ip}:{dest_port}")
            return
        
        self._show_source_breakdown_dialog(f"{dest_ip}:{dest_port}", sources)
    
    def _show_source_breakdown_dialog(self, title: str, sources: Dict[str, Dict]):
        """Show the per-source-IP breakdown for one destination/service row
        
        Args:
            title: Dialog title (destination, service+region, or IP:port)
            sources: {src_ip: {'bytes': int, 'flow_count': int}}
        """
        dialog = tk.Toplevel(self.parent.root)
        dialog.title(f"Source IP Breakdown for: {title}")
        dialog.geometry("1000x600")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        source_totals = sources
        total_bytes = sum(data['bytes'] for data in source_totals.values())
        
        # Header
        total_gb = total_bytes / (1024**3)
        total_cost = total_gb * self.firewall_cost_per_gb
        header_text = f"Total Traffic: {total_gb:.2f} GB | Total Cost: ${total_cost:.2f} | Unique Sources: {len(source_totals)}"
        ttk.Label(main_frame, text=header_text,
                 font=("TkDefaultFont", 10)).pack(pady=(0, 15))
        
        # Table frame
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Source IP", "Traffic (GB)", "Cost", "Flows", "% of Total")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        tree.column("Source IP", width=150, stretch=False)
        tree.column("Traffic (GB)", width=120, stretch=False)
        tree.column("Cost", width=100, stretch=False)
        tree.column("Flows", width=100, stretch=False)
        tree.column("% of Total", width=100, stretch=True)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Store data for sorting
        tree_data = {
            'sort_column': 'Traffic (GB)',
            'sort_reverse': True
        }
        
        def repopulate_tree():
            """Repopulate tree based on current sort settings"""
            for item in tree.get_children():
                tree.delete(item)
            
            sort_col = tree_data['sort_column']
            reverse = tree_data['sort_reverse']
            
            if sort_col == "Source IP":
                sorted_sources = sorted(source_totals.items(), key=lambda x: x[0], reverse=reverse)
            elif sort_col == "Flows":
                sorted_sources = sorted(source_totals.items(), key=lambda x: x[1]['flow_count'], reverse=reverse)
            elif sort_col in ("Traffic (GB)", "Cost", "% of Total"):
                sorted_sources = sorted(source_totals.items(), key=lambda x: x[1]['bytes'], reverse=reverse)
            else:
                sorted_sources = sorted(source_totals.items(), key=lambda x: x[1]['bytes'], reverse=True)
            
            for src_ip, data in sorted_sources:
                traffic_gb = data['bytes'] / (1024**3)
                cost = traffic_gb * self.firewall_cost_per_gb
                percent = (data['bytes'] / total_bytes * 100) if total_bytes > 0 else 0
                
                tree.insert("", tk.END, values=(
                    src_ip,
                    f"{traffic_gb:.2f}",
                    f"${cost:.2f}",
                    f"{data['flow_count']:,}",
                    f"{percent:.1f}%"
                ), tags=('source',))
            
            # Update column headers
            for col in columns:
                header_text = col
                if col == tree_data['sort_column']:
                    header_text += ' ▼' if tree_data['sort_reverse'] else ' ▲'
                tree.heading(col, text=header_text)
        
        def on_column_click(column):
            """Handle column header click for sorting"""
            if tree_data['sort_column'] == column:
                tree_data['sort_reverse'] = not tree_data['sort_reverse']
            else:
                # New column, default to descending for numeric, ascending for text
                tree_data['sort_column'] = column
                tree_data['sort_reverse'] = (column != "Source IP")
            repopulate_tree()
        
        for col in columns:
            tree.heading(col, command=lambda c=col: on_column_click(c))
        
        repopulate_tree()
        
        tree.tag_configure('source', font=('TkDefaultFont', 9, 'bold'))
        
        # Right-click context menu for copying rows
        def show_copy_menu(event):
            selection = tree.selection()
            if not selection:
                return
            menu = tk.Menu(tree, tearoff=0)
            menu.add_command(label="Copy Selected Rows",
                           command=lambda: self._copy_selected_rows(tree, columns, selection))
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        
        tree.bind("<Button-3>", show_copy_menu)
        
        # Helper text
        help_frame = ttk.Frame(main_frame)
        help_frame.pack(fill=tk.X, pady=(10, 0))
        help_text = "💡 Click column headers to sort | Right-click to copy"
        ttk.Label(help_frame, text=help_text,
                 font=("TkDefaultFont", 8), foreground="#666666").pack(anchor=tk.W)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=dialog.destroy).pack(pady=(5, 0))
    
    def _copy_selected_rows(self, tree, columns, selection):
        """Copy the selected source rows to the clipboard (tab-separated)
        
        Args:
            tree: Treeview widget
            columns: Column names (written as a header line)
            selection: Tuple of selected item IDs
        """
        rows = []
        for item_id in selection:
            values = tree.item(item_id, 'values')
            if values:
                rows.append('\t'.join(str(v) for v in values))
        if not rows:
            return
        
        text_to_copy = '\n'.join(['\t'.join(columns)] + rows)
        self.parent.root.clipboard_clear()
        self.parent.root.clipboard_append(text_to_copy)
        
        messagebox.showinfo("Copied",
                          f"Copied {len(rows)} row{'s' if len(rows) != 1 else ''} to clipboard.\n\n"
                          "You can now paste into Excel, text editor, or any other program.")
    
    def _format_time_ago(self, timestamp: datetime) -> str:
        """Format timestamp as 'X minutes/hours ago'"""
        now = datetime.now()
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
    
    def _export_results(self, results: Dict):
        """Export analysis results to CSV
        
        Args:
            results: Analysis results dictionary
        """
        filename = filedialog.asksaveasfilename(
            title="Export Traffic Analysis",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="traffic_analysis_export.csv"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w', encoding='utf-8', newline='') as f:
                # Write internet traffic
                f.write("INTERNET TRAFFIC\n")
                f.write("Hostname,Dest_Port,Protocol,Traffic_GB,Cost_USD,Unique_Sources,Flow_Count\n")
                
                hostname_agg = results['hostname_aggregation']
                sorted_hostnames = sorted(hostname_agg.items(), 
                                         key=lambda x: x[1]['bytes'], 
                                         reverse=True)
                
                for hostname, data in sorted_hostnames:
                    traffic_gb = data['bytes'] / (1024**3)
                    cost = traffic_gb * self.firewall_cost_per_gb
                    f.write(f'"{hostname}",{data["dest_port"]},{data["proto"]},'
                           f'{traffic_gb:.2f},{cost:.2f},{data["unique_sources"]},{data["flow_count"]}\n')
                
                # Write AWS services section
                f.write("\nAWS SERVICE TRAFFIC\n")
                f.write("AWS_Service,Region,Endpoint_Type,Traffic_GB,Current_Cost,Endpoint_Cost,Monthly_Savings,Annual_Savings,Recommendation\n")
                
                recommendations = results['vpc_endpoint_recommendations']
                for rec in recommendations:
                    f.write(f'{rec["service"]},{rec["region"]},{rec["endpoint_type"]},'
                           f'{rec["traffic_gb"]:.2f},{rec["current_cost"]:.2f},'
                           f'{rec["endpoint_cost"]:.2f},{rec["monthly_savings"]:.2f},'
                           f'{rec["annual_savings"]:.0f},{rec["recommendation"]}\n')
                
                # Write VPC-to-VPC section
                f.write("\nVPC-TO-VPC TRAFFIC\n")
                f.write("Source_IP,Dest_IP,Dest_Port,Protocol,Traffic_GB,Firewall_Cost,Flow_Count,Percent_of_Total\n")
                
                connections = results['vpc_to_vpc_connections']
                total_vpc_bytes = sum(conn['total_bytes'] for conn in connections)
                
                for conn in connections:
                    traffic_gb = conn['total_bytes'] / (1024**3)
                    cost = traffic_gb * self.firewall_cost_per_gb
                    percent = (conn['total_bytes'] / total_vpc_bytes * 100) if total_vpc_bytes > 0 else 0
                    
                    f.write(f'{conn["src_ip"]},{conn["dest_ip"]},{conn["dest_port"]},'
                           f'{conn["proto"]},{traffic_gb:.2f},{cost:.2f},'
                           f'{conn["flow_count"]},{percent:.1f}%\n')
            
            messagebox.showinfo("Export Complete", 
                              f"Traffic analysis exported to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Export Error", 
                               f"Failed to export:\n{str(e)}")
    
    def _handle_analysis_error(self, error: Exception):
        """Handle errors during analysis
        
        Args:
            error: Exception that occurred
        """
        error_msg = str(error)
        
        # Handle specific AWS errors (follow rule_usage_analyzer pattern)
        if "NoCredentialsError" in error_msg or "NoCredentials" in error_msg:
            messagebox.showerror(
                "AWS Credentials Not Found",
                "No AWS credentials were found.\n\n"
                "Please configure your credentials using:\n"
                "• AWS CLI: aws configure\n"
                "• Environment variables\n"
                "• IAM role (if running on AWS)"
            )
        elif "AccessDenied" in error_msg:
            messagebox.showerror(
                "Access Denied",
                "Your AWS credentials do not have permission to access CloudWatch Logs.\n\n"
                "Required IAM permissions:\n"
                "• logs:StartQuery\n"
                "• logs:GetQueryResults\n"
                "• logs:StopQuery"
            )
        elif "ResourceNotFound" in error_msg:
            messagebox.showerror(
                "Log Group Not Found",
                "CloudWatch log group not found.\n\n"
                "Please verify:\n"
                "• Log group name is correct\n"
                "• Log group exists in your AWS account\n"
                "• You're using the correct AWS region"
            )
        elif "timeout" in error_msg.lower():
            messagebox.showerror(
                "Query Timeout",
                "CloudWatch query timed out.\n\n"
                "Try:\n"
                "• Reducing the time range\n"
                "• Running during off-peak hours\n"
                "• Checking AWS service status"
            )
        elif "connection" in error_msg.lower() or "ConnectionError" in error_msg:
            messagebox.showerror(
                "Connection Error",
                "Failed to connect to AWS CloudWatch.\n\n"
                "Please check:\n"
                "• Internet connectivity\n"
                "• AWS region configuration\n"
                "• Firewall/proxy settings"
            )
        elif "intervaltree" in error_msg.lower():
            messagebox.showerror(
                "Dependency Missing",
                "The 'intervaltree' library is required.\n\n"
                "Install with: pip install intervaltree\n\n"
                "This library provides fast IP lookups needed\n"
                "for analyzing large traffic datasets."
            )
        else:
            messagebox.showerror(
                "Analysis Error",
                f"An error occurred during analysis:\n\n{error_msg}"
            )
    
    def _show_boto3_install_help(self):
        """Show boto3 installation instructions"""
        help_text = (
            "Installing boto3 (AWS SDK for Python)\n"
            "=" * 50 + "\n\n"
            "Option 1: Using pip\n"
            "   pip install boto3\n\n"
            "Option 2: Using pip3\n"
            "   pip3 install boto3\n\n"
            "Option 3: Install all AWS dependencies\n"
            "   pip install boto3 intervaltree requests\n\n"
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
    
    def _show_install_help(self):
        """Show installation instructions for all dependencies"""
        help_text = (
            "Installing Traffic Analysis Dependencies\n" +
            "=" * 50 + "\n\n" +
            "Required libraries:\n"
            "• boto3 - AWS SDK for Python\n"
            "• intervaltree - Fast IP range lookups\n"
            "• requests - HTTP library\n\n"
            "Install all at once:\n"
            "   pip install boto3 intervaltree requests\n\n"
            "Or individually:\n"
            "   pip install boto3\n"
            "   pip install intervaltree\n"
            "   pip install requests\n\n"
            "After installation, restart the application."
        )
        
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Install Dependencies")
        dialog.geometry("600x400")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        text = tk.Text(dialog, wrap=tk.WORD, font=("Consolas", 10))
        text.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        text.insert("1.0", help_text)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=(0, 20))
    
    def _show_help(self):
        """Show help dialog for traffic analysis feature"""
        help_text = """Traffic Analysis & VPC Endpoint Optimization

This feature analyzes your AWS Network Firewall logs to:

1. Identify traffic patterns (Top Talkers)
   • Shows hostnames/domains from HTTP and TLS
   • Aggregates by destination
   • Calculates traffic volumes and costs

2. Recommend VPC endpoints for cost savings
   • Gateway endpoints (FREE for S3/DynamoDB)
   • Interface endpoints (cost-benefit analysis)
   • Cross-region optimization suggestions

3. Analyze VPC-to-VPC traffic
   • Internal east-west traffic patterns
   • PrivateLink opportunities

Note on figures:
Traffic volumes and costs are reported for the time range you select (the
"analyzed window"), not per month. The one exception is "Projected Monthly
Savings" on the AWS Service Traffic tab, which extrapolates the window's traffic
to a full month. For a monthly estimate close to your AWS bill, analyze ~30 days.

Prerequisites:
• AWS Network Firewall with alert and flow logs enabled
• Logs sent to CloudWatch Logs
• AWS credentials configured (aws configure)
• IAM permissions: logs:StartQuery, logs:GetQueryResults

Cost Warning:
CloudWatch Logs Insights charges per GB scanned: $0.005/GB in many
regions (including us-east-1 and us-east-2) and up to $0.009/GB in others.
The results window shows the rate used for your firewall's region.
Typical cost: $0.50 - $2.00 for 30-day analysis."""
        
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Help - Traffic Analysis")
        dialog.geometry("700x600")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        text = tk.Text(dialog, wrap=tk.WORD, font=("TkDefaultFont", 10))
        text.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        text.insert("1.0", help_text)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=(0, 20))
    
    def _save_analysis_results(self, results: Dict[str, Any]):
        """Save traffic analysis results to .stats file
        
        Args:
            results: Analysis results dictionary
        """
        try:
            from src.aws.traffic_analyzer import TrafficAnalyzer
            
            # Check if a rule file is currently loaded
            if hasattr(self.parent, 'current_file') and self.parent.current_file:
                # Derive .stats file path from current rule file
                rule_file = self.parent.current_file
                stats_file = rule_file.rsplit('.', 1)[0] + '.stats'
                
                # Save results (in the background; large analyses take minutes)
                self._save_results_in_background(
                    results, stats_file,
                    f"Traffic analysis saved to:\n{stats_file}\n\n"
                    f"This data can be loaded instantly next time you run traffic analysis "
                    f"(avoiding CloudWatch query charges)."
                )
            else:
                # No rule file loaded - prompt user to select one
                response = messagebox.askyesno(
                    "Select Rule File",
                    "No rule file is currently loaded.\n\n"
                    "To save traffic analysis data, please select the .suricata rule file "
                    "that corresponds to these logs.\n\n"
                    "The traffic analysis will be saved to a .stats file with the same name.\n\n"
                    "Would you like to browse for a .suricata file?",
                    icon='question'
                )
                
                if not response:  # No - cancel operation
                    return
                
                # User wants to browse for .suricata file
                filename = filedialog.askopenfilename(
                    title="Select Rule File for Traffic Analysis",
                    defaultextension=".suricata",
                    filetypes=[
                        ("Suricata files", "*.suricata"),
                        ("All files", "*.*")
                    ],
                    initialdir="user_files"
                )
                
                if not filename:
                    return  # User cancelled
                
                # Derive .stats file path from selected rule file
                stats_file = filename.rsplit('.', 1)[0] + '.stats'
                
                # Save results (in the background; large analyses take minutes)
                self._save_results_in_background(
                    results, stats_file,
                    f"Traffic analysis saved to:\n{stats_file}\n\n"
                    f"Tip: Load this rule file ({filename}) before running traffic analysis "
                    f"to automatically use the cached data."
                )
        
        except Exception as e:
            messagebox.showerror(
                "Save Error",
                f"Failed to save traffic analysis:\n\n{str(e)}"
            )
    
    def _save_results_in_background(self, results: Dict[str, Any], stats_file: str,
                                    success_message: str):
        """Write the .stats file on a background thread with a 'Saving...' dialog.

        Large analyses produce .stats files of several GB, which take minutes to
        write; doing that on the UI thread froze the application. The file format
        is unchanged (TrafficAnalyzer.save_results does the writing). The dialog
        cannot be cancelled, because stopping part-way would leave a truncated file.
        """
        from src.aws.traffic_analyzer import TrafficAnalyzer
        
        if getattr(self, '_save_in_progress', False):
            messagebox.showinfo("Save In Progress",
                                "The traffic analysis is already being saved. "
                                "Please wait for it to finish.")
            return
        self._save_in_progress = True
        
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Saving Traffic Analysis...")
        dialog.resizable(False, False)
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 220,
            self.parent.root.winfo_rooty() + 180
        ))
        frame = ttk.Frame(dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        ttk.Label(frame, text=f"Saving to {os.path.basename(stats_file)}...",
                  font=("TkDefaultFont", 10)).pack(pady=(0, 10))
        bar = ttk.Progressbar(frame, mode='indeterminate', length=360)
        bar.pack(pady=5)
        bar.start(10)
        ttk.Label(frame, text="Large analyses can take a few minutes to save.").pack(pady=(5, 0))
        elapsed_label = ttk.Label(frame, text="Elapsed time: 0s")
        elapsed_label.pack(pady=(5, 0))
        dialog.protocol("WM_DELETE_WINDOW", lambda: None)  # not cancellable
        dialog.grab_set()
        
        started = datetime.now()
        outcome = queue.Queue()
        
        def worker():
            try:
                TrafficAnalyzer.save_results(results, stats_file)
                outcome.put(None)
            except Exception as e:
                outcome.put(e)
        
        def poll():
            try:
                error = outcome.get_nowait()
            except queue.Empty:
                try:
                    elapsed = int((datetime.now() - started).total_seconds())
                    elapsed_label.config(text=f"Elapsed time: {elapsed}s")
                    dialog.after(250, poll)
                except tk.TclError:
                    self._save_in_progress = False
                return
            self._save_in_progress = False
            try:
                dialog.grab_release()
                dialog.destroy()
            except tk.TclError:
                pass
            if error is None:
                messagebox.showinfo("Save Successful", success_message)
            else:
                messagebox.showerror("Save Error",
                                     f"Failed to save traffic analysis:\n\n{str(error)}")
        
        # Not a daemon thread: if the application is closed mid-save, Python waits
        # for the write to finish instead of leaving a truncated .stats file.
        threading.Thread(target=worker, name='traffic-stats-save', daemon=False).start()
        dialog.after(250, poll)
    
    def _show_results_help(self):
        """Show comprehensive help dialog explaining results and common questions"""
        help_text = """Understanding Your Traffic Analysis Results

═══════════════════════════════════════════════════

COMMON QUESTIONS & INSIGHTS

Q: Are the costs shown monthly, or for the time range I analyzed?
A: Almost everything is for the ANALYZED WINDOW (the time range shown at the
   top of this window), not a month:

   • Traffic (GB), the traffic breakdown, "Current Cost", the fixed
     endpoint-hour costs, and the "Endpoint Cost (window)" column are all
     totals for the window you selected.
   • The ONLY projected-to-a-month figure is "Projected Monthly Savings" on
     the AWS Service Traffic tab. It answers: "if this window's traffic
     repeated for a full month, how much would the recommended endpoint save?"
     It scales the window's data-processing cost to a month (x 730 hours /
     window hours) and subtracts the endpoint's monthly price.

   Tip: for a monthly estimate that lines up with your AWS bill, analyze a
   ~30-day window (or use the projected-savings figure as your monthly guide).
   A very short window makes the monthly projection less reliable.

Q: How is the fixed endpoint (per-hour) cost calculated?
A: AWS bills each firewall endpoint per hour it is provisioned, whether or not
   it processes traffic. If an endpoint saw ANY traffic during the window, this
   tool assumes it ran for the ENTIRE window and charges hourly_rate x
   window_hours x number_of_endpoints. Endpoints that processed zero traffic
   emit no logs and therefore cannot be detected here.

   IMPORTANT - PRIMARY endpoints only: this calculation assumes the standard
   PRIMARY firewall endpoint hourly rate for every Availability Zone observed.
   It does NOT account for SECONDARY firewall endpoints (the additional endpoints
   created when a firewall is associated with multiple VPCs), which AWS bills at
   a different, reduced hourly rate. If your firewall uses secondary endpoints,
   the fixed cost shown here will not match your bill for those endpoints.

Q: Does this include Advanced Inspection (TLS inspection) charges?
A: No. When TLS inspection is enabled, AWS adds a separate per-hour Advanced
   Inspection endpoint charge on top of the standard endpoint hours. This tool
   does NOT estimate that charge, so if your firewall policy uses TLS inspection
   your actual bill will be higher than the fixed cost shown here.

Q: My AWS bill shows more endpoint hours than this tool reports. Why?
A: Two common reasons:
   • Multiple firewalls: AWS Cost Explorer aggregates Network Firewall endpoint
     hours across ALL firewalls in the account/region under the same usage type
     (e.g. "USE1-Endpoint-Hour"); it does not break them out per firewall unless
     you use cost allocation tags. This tool analyzes one firewall's logs, so its
     endpoint count reflects only that firewall's Availability Zones.
   • Idle/secondary endpoints: endpoints (including secondary VPC endpoint
     associations) that processed no logged traffic are invisible here, but AWS
     still bills for every hour they are provisioned.
   Treat the fixed endpoint cost as a LOWER BOUND based on the Availability Zones
   observed in this firewall's logs.

Q: I selected a full month but the results show a "Log coverage gap" warning.
   What does that mean for the costs?
A: It means the logs actually found cover materially less time than the range you
   selected (the observed span misses a window edge by more than 6 hours). The two
   usual causes are:
   • Log retention: CloudWatch Logs only keep events for the configured retention
     period, so for an older range the early part of the window may have aged out.
   • The firewall did not exist for the whole range (e.g. it was deployed partway
     through the selected window).

   These two cases cannot be told apart from the data, so the tool does NOT assume
   the firewall ran for the full selected window. Instead, in this special case:
   • Endpoint-hour cost is billed on the OBSERVED span (earliest to latest log
     seen), not the full window. This is a change from the normal behavior, where
     endpoint hours cover the entire selected window.
   • Data-processing/traffic cost already reflects only the traffic in the logs
     found, which is the observed span.

   So during a coverage gap BOTH cost components describe only the observed span
   and are a LOWER BOUND for the range you asked for — they will be lower than your
   actual AWS bill for that full range. An endpoint that passed no traffic during
   the observed span is not counted. To get complete results, analyze a range that
   falls entirely within your CloudWatch Logs retention period.

Q: How can I get accurate AWS billing for ONE specific firewall?
A: Use cost allocation tags so Cost Explorer can separate each firewall's cost:

   1. Tag each firewall. Give every firewall a distinct tag, e.g.
      Key = "firewall-name", Value = "ANF-Sandbox".
      Console: Network Firewall > Firewalls > (select) > Tags > Manage tags.
      CLI:  aws network-firewall tag-resource \\
              --resource-arn <firewall-arn> \\
              --tags Key=firewall-name,Value=ANF-Sandbox

   2. Activate the tag as a cost allocation tag (one-time, done by a management/
      payer account with billing access):
      Billing and Cost Management > Cost allocation tags > User-defined tags >
      select "firewall-name" > Activate.
      Note: activation is NOT retroactive - only usage AFTER activation is
      broken out, and it can take ~24 hours to start appearing.

   3. Filter Cost Explorer by that tag to see one firewall's cost:
      CLI:  aws ce get-cost-and-usage \\
              --time-period Start=2026-08-01,End=2026-09-01 \\
              --granularity MONTHLY --metrics UnblendedCost UsageQuantity \\
              --filter '{"And":[
                          {"Dimensions":{"Key":"SERVICE",
                             "Values":["AWS Network Firewall"]}},
                          {"Tags":{"Key":"firewall-name",
                             "Values":["ANF-Sandbox"]}}]}' \\
              --group-by Type=DIMENSION,Key=USAGE_TYPE
      (Console: Cost Explorer > filter by Service = AWS Network Firewall and by
      the "firewall-name" tag.)

   With per-firewall tagging in place, the bill's endpoint hours for a single
   firewall should line up with this tool's estimate for that same firewall
   (aside from Advanced Inspection, which this tool does not include).

Q: Are the total traffic and cost figures accurate for a high-traffic
   firewall, or can they be under-reported?
A: They are accurate at any traffic volume. Total bytes, the per-Availability-
   Zone distribution, and the traffic-category/service/VPC byte totals are
   computed by a server-side aggregation query (stats sum(...)), whose result
   limit applies to the number of returned groups (e.g. Availability Zones),
   NOT to the number of underlying flow records. So the headline volume and
   cost cannot be silently truncated, even for firewalls processing very large
   numbers of flows.

   You may occasionally see an amber notice at the top of the results that the
   per-flow breakdowns are "based on a sample." That refers ONLY to the detail
   tables (Top Talkers and the per-hostname, per-service, and VPC-to-VPC lists),
   which are retrieved per-flow and are subject to the CloudWatch Logs Insights
   10,000-row limit in extreme cases. When that happens the notice also shows
   roughly what fraction of traffic the sample covers. The total traffic and
   cost figures remain authoritative regardless, because they come from the
   aggregation query rather than the per-flow rows.

Q: Why do I see "(No hostname)" in the results?
A: Hostnames require traffic to match alert rules (or pass rules with 'alert' keyword).

   When you see "(No hostname)":
   • No HTTP/TLS alert rule matched this traffic
   • Pass rules without 'alert' keyword don't generate alerts

   To capture hostnames for more traffic:
   → Add alert rules that match HTTP/TLS traffic
   → Add 'alert' keyword to HTTP/TLS pass rules
   → Ensure traffic matches at least one rule that generates alerts

   Some "(No hostname)" is normal for:
   • Non-HTTP/TLS protocols (DNS, ICMP, etc.)
   • Traffic that intentionally doesn't match rules

Q: Why does my S3 bucket show different regions in URLs?
A: S3 supports multiple URL formats, and applications may use different ones:

   • Legacy: bucket.s3.amazonaws.com (no region)
   • Modern: bucket.s3.us-east-2.amazonaws.com (explicit region)

   Same bucket may appear twice with:
   • Different URLs (legacy vs modern format)
   • Different regions detected (us-east-1 vs actual)
   • Different traffic amounts

   Example: bucket.s3.us-east-1.amazonaws.com with 0.00 GB (44 flows)
   → These are S3 redirects or metadata operations
   → Bulk traffic uses correct region URL

Q: What is the "Endpoint Cost (window)" column, and why do cross-region
   values vary?
A: It is the cost of running the equivalent interface endpoint for the SAME
   window you analyzed (so it is comparable to the window-scoped "Current
   Cost" next to it). Interface endpoints have TWO cost components:

   1. Base infrastructure: $7.30/month (us-east-1), prorated to the window
      → Same for ALL endpoints in the firewall region
      → e.g. a 7-day window shows $7.30 x (168 / 730) ≈ $1.68

   2. Data processing: $0.01/GB (cross-region only)
      → Varies with the window's traffic volume

   So two cross-region rows differ only by their traffic volume, not by a
   different endpoint price. (Gateway endpoints for S3/DynamoDB are free, so
   their Endpoint Cost is $0.00.)

   Note: the "Projected Monthly Savings" column instead uses the FULL monthly
   base fee ($7.30) versus a full month of projected traffic - that is why the
   savings are a monthly projection while this column is window-scoped.

Q: What does 0.00 GB traffic with many flows mean?
A: Small operations that don't transfer much data:

   • S3 HEAD requests (metadata)
   • HTTP redirects
   • Health checks
   • API calls without large payloads

   Example: 0.00 GB with 44 flows = ~230 bytes/flow (tiny)

DRILL-DOWN FEATURES

• Double-click any row to see detailed breakdown
• Tab 2 (AWS Services): Shows source IP + hostname/bucket (when available)
• Multiple rows per IP = accessing different buckets
• Sort by any column to find patterns

UNDERSTANDING RECOMMENDATIONS

• DEPLOY: Cost-effective, implement immediately
• CONSIDER: Near break-even, evaluate
• SKIP: Not cost-effective
• SKIP - Consider CRR instead: S3 Cross-Region Replication may be a better option
• SKIP - No VPC endpoint available: AWS traffic that no VPC endpoint can serve
  (for example CloudFront), so there is nothing to deploy

Recommendation thresholds compare the MONTHLY-projected traffic volume against
the endpoint break-even point, so they stay consistent with the projected
monthly savings.

All costs are ESTIMATES based on list pricing for planning purposes. Total
traffic and cost come from a server-side aggregation query and are not subject
to per-flow row limits, so they stay accurate at any traffic volume. Traffic and
per-window costs are scoped to the analyzed window; only "Projected Monthly
Savings" is extrapolated to a month. Advanced Inspection (TLS inspection) hourly
charges are NOT included, and fixed endpoint costs reflect only the Availability
Zones seen in this firewall's logs. If a "Log coverage gap" warning is shown, the
logs cover less than the selected range, so endpoint-hour and data-processing
costs are billed on the observed span only and are a lower bound for the full
range requested."""
        
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Understanding Results - Common Questions")
        dialog.geometry("850x750")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        
        # Create scrollable text widget
        text_frame = ttk.Frame(dialog)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        text = tk.Text(text_frame, wrap=tk.WORD, font=("TkDefaultFont", 10))
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text.insert("1.0", help_text)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=(0, 20))
