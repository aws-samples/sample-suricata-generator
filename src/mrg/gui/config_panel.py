"""
Configuration Panel for Managed Rule Group Generator

Collapsible panel containing all configuration inputs:
- Region selector (ttk.Combobox with all AWS commercial regions)
- AWS Profile selector with refresh button
- Output rule group name entry (validates AWS naming rules)
- Output rule group capacity entry
- Missing metadata behavior selector
- Deployment mode radio buttons (As-Is / Test Mode)
- Notification email entry
- Source rule group browser (multi-select checklist)
- Filter builder (dynamic row-based)
- Collapse/Expand toggle

Cross-platform notes (Section 14.3):
- Uses trace_add() not trace()
- Uses expand=False for fixed-size frames
- Platform-safe font fallbacks
"""

import platform
import re
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from src.aws.aws_session_manager import AWSSessionManager
from src.mrg.core.rule_filter import FilterCondition, FilterConfig, filter_config_from_dict
from src.mrg.gui.filter_builder import FilterBuilder
from src.mrg.gui.source_browser import SourceBrowser


# All AWS commercial regions
AWS_REGIONS = [
    'us-east-1',
    'us-east-2',
    'us-west-1',
    'us-west-2',
    'af-south-1',
    'ap-east-1',
    'ap-south-1',
    'ap-south-2',
    'ap-southeast-1',
    'ap-southeast-2',
    'ap-southeast-3',
    'ap-southeast-4',
    'ap-northeast-1',
    'ap-northeast-2',
    'ap-northeast-3',
    'ca-central-1',
    'ca-west-1',
    'eu-central-1',
    'eu-central-2',
    'eu-west-1',
    'eu-west-2',
    'eu-west-3',
    'eu-south-1',
    'eu-south-2',
    'eu-north-1',
    'il-central-1',
    'me-south-1',
    'me-central-1',
    'sa-east-1',
]

# Default capacity (empty string = not yet calculated; auto-set after first build)
DEFAULT_CAPACITY = ''


class ConfigPanel(ttk.Frame):
    """Collapsible configuration panel for the main window.

    Contains all configuration inputs organized in a logical layout:
    1. Top row: Region, Profile, Name, Capacity
    2. Source rule group browser
    3. Filter builder
    4. Bottom row: Missing metadata behavior, Deployment mode, Email
    5. Build button

    The panel can be collapsed to a single summary line or expanded
    to show all controls.
    """

    def __init__(self, parent, session_manager: Optional[AWSSessionManager] = None,
                 on_build: Optional[Callable] = None, **kwargs):
        """Initialize the configuration panel.

        Args:
            parent: Parent tkinter widget.
            session_manager: AWSSessionManager instance for AWS operations.
            on_build: Callback when Build Rule Group button is clicked.
            **kwargs: Additional keyword arguments for Frame.
        """
        super().__init__(parent, **kwargs)

        self._session_manager = session_manager or AWSSessionManager()
        self._on_build = on_build
        self._is_collapsed = False
        self._has_built = False  # Track if build has been done at least once

        self._setup_ui()
        self._load_profiles()

    def _setup_ui(self):
        """Create all configuration panel widgets."""
        # Outer labeled frame with collapse toggle
        self._outer_frame = ttk.LabelFrame(self, text="Configuration")
        self._outer_frame.pack(fill=tk.X, padx=4, pady=(4, 2))

        # Collapse/Expand button in the label frame
        self._toggle_frame = ttk.Frame(self._outer_frame)
        self._toggle_frame.pack(fill=tk.X, padx=4, pady=(2, 0))

        self._toggle_btn = ttk.Button(
            self._toggle_frame,
            text="\u25bc Collapse",  # ▼
            command=self._toggle_collapse,
            width=12,
        )
        self._toggle_btn.pack(side=tk.RIGHT)

        # Collapsed summary label (hidden initially)
        self._summary_label = ttk.Label(self._toggle_frame, text="")
        self._summary_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Main content frame (hidden when collapsed)
        self._content_frame = ttk.Frame(self._outer_frame)
        self._content_frame.pack(fill=tk.X, padx=4, pady=4)

        self._setup_top_row()
        self._setup_source_browser()
        self._setup_filter_section()
        self._setup_bottom_row()
        self._setup_variables_row()
        self._setup_build_button()

    def _setup_top_row(self):
        """Create the top row: Region, Profile, Name, Capacity."""
        top_frame = ttk.Frame(self._content_frame)
        top_frame.pack(fill=tk.X, pady=(0, 4))

        # Region
        ttk.Label(top_frame, text="Region:").pack(side=tk.LEFT, padx=(0, 4))
        self._region_var = tk.StringVar(value='us-east-1')
        self._region_combo = ttk.Combobox(
            top_frame,
            textvariable=self._region_var,
            values=AWS_REGIONS,
            state='readonly',
            width=14,
        )
        self._region_combo.pack(side=tk.LEFT, padx=(0, 12))
        self._region_var.trace_add('write', self._on_region_changed)

        # Profile
        ttk.Label(top_frame, text="Profile:").pack(side=tk.LEFT, padx=(0, 4))
        self._profile_var = tk.StringVar(value='(default)')
        self._profile_combo = ttk.Combobox(
            top_frame,
            textvariable=self._profile_var,
            values=['(default)'],
            state='readonly',
            width=16,
        )
        self._profile_combo.pack(side=tk.LEFT, padx=(0, 2))
        self._profile_var.trace_add('write', self._on_profile_changed)

        # Refresh profiles button
        self._refresh_btn = ttk.Button(
            top_frame,
            text='\u21bb',  # ↻
            width=3,
            command=self._refresh_profiles,
        )
        self._refresh_btn.pack(side=tk.LEFT, padx=(0, 12))

        # Name
        ttk.Label(top_frame, text="Name:").pack(side=tk.LEFT, padx=(0, 4))
        self._name_var = tk.StringVar(value='')
        self._name_entry = ttk.Entry(
            top_frame,
            textvariable=self._name_var,
            width=24,
        )
        self._name_entry.pack(side=tk.LEFT, padx=(0, 12))
        self._name_var.trace_add('write', self._on_name_changed)

        # Name validation label
        self._name_error_label = ttk.Label(top_frame, text="", foreground='red')
        self._name_error_label.pack(side=tk.LEFT, padx=(0, 12))

        # Capacity
        ttk.Label(top_frame, text="Capacity:").pack(side=tk.LEFT, padx=(0, 4))
        self._capacity_var = tk.StringVar(value=str(DEFAULT_CAPACITY))
        self._capacity_entry = ttk.Entry(
            top_frame,
            textvariable=self._capacity_var,
            width=8,
        )
        self._capacity_entry.pack(side=tk.LEFT)

    def _setup_source_browser(self):
        """Create the source rule group browser."""
        self._source_browser = SourceBrowser(
            self._content_frame,
            session_manager=self._session_manager,
        )
        self._source_browser.pack(fill=tk.X, pady=(0, 4))

    def _setup_filter_section(self):
        """Create the filter builder and missing metadata behavior selector."""
        filter_section = ttk.Frame(self._content_frame)
        filter_section.pack(fill=tk.X, pady=(0, 4))

        # Filter builder on the left, missing metadata on the right
        self._filter_builder = FilterBuilder(
            filter_section,
            on_change=self._on_filter_changed,
        )
        self._filter_builder.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Missing metadata behavior on the right side
        meta_frame = ttk.LabelFrame(filter_section, text="Missing Metadata")
        meta_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(8, 0))

        self._missing_meta_var = tk.StringVar(value='exclude')
        ttk.Radiobutton(
            meta_frame,
            text="Exclude",
            variable=self._missing_meta_var,
            value='exclude',
        ).pack(anchor=tk.W, padx=4, pady=2)
        ttk.Radiobutton(
            meta_frame,
            text="Include",
            variable=self._missing_meta_var,
            value='include',
        ).pack(anchor=tk.W, padx=4, pady=2)

    def _setup_bottom_row(self):
        """Create bottom row: Deployment mode, Notification email."""
        bottom_frame = ttk.Frame(self._content_frame)
        bottom_frame.pack(fill=tk.X, pady=(0, 4))

        # Deployment mode
        mode_frame = ttk.LabelFrame(bottom_frame, text="Deployment Mode")
        mode_frame.pack(side=tk.LEFT, padx=(0, 12))

        self._mode_var = tk.StringVar(value='as_is')
        ttk.Radiobutton(
            mode_frame,
            text="As-Is",
            variable=self._mode_var,
            value='as_is',
        ).pack(side=tk.LEFT, padx=4, pady=2)
        ttk.Radiobutton(
            mode_frame,
            text="Test Mode",
            variable=self._mode_var,
            value='test_mode',
        ).pack(side=tk.LEFT, padx=4, pady=2)

        # Notification email
        ttk.Label(bottom_frame, text="Notification Email:").pack(side=tk.LEFT, padx=(0, 4))
        self._email_var = tk.StringVar(value='')
        self._email_entry = ttk.Entry(
            bottom_frame,
            textvariable=self._email_var,
            width=30,
        )
        self._email_entry.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(bottom_frame, text="(optional)", font=('TkDefaultFont', 8),
                  foreground='#888888').pack(side=tk.LEFT, padx=(0, 12))

    def _setup_variables_row(self):
        """Create variables row: $HOME_NET and $EXTERNAL_NET with hover tooltips."""
        vars_frame = ttk.Frame(self._content_frame)
        vars_frame.pack(fill=tk.X, pady=(0, 4))

        # Description label
        ttk.Label(vars_frame, text="Optionally define in generated rule group",
                  font=('TkDefaultFont', 9), foreground='#555555').pack(side=tk.LEFT, padx=(0, 12))

        # $HOME_NET
        ttk.Label(vars_frame, text="$HOME_NET:").pack(side=tk.LEFT, padx=(0, 4))
        self._home_net_var = tk.StringVar(value='')
        self._home_net_entry = ttk.Entry(
            vars_frame,
            textvariable=self._home_net_var,
            width=30,
        )
        self._home_net_entry.pack(side=tk.LEFT, padx=(0, 12))
        self._home_net_entry.bind('<Enter>', lambda e: self._show_tooltip(
            self._home_net_entry,
            "Comma-separated CIDRs, e.g. 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))
        self._home_net_entry.bind('<Leave>', self._hide_tooltip)

        # $EXTERNAL_NET
        ttk.Label(vars_frame, text="$EXTERNAL_NET:").pack(side=tk.LEFT, padx=(0, 4))
        self._external_net_var = tk.StringVar(value='')
        self._external_net_entry = ttk.Entry(
            vars_frame,
            textvariable=self._external_net_var,
            width=30,
        )
        self._external_net_entry.pack(side=tk.LEFT)
        self._external_net_entry.bind('<Enter>', lambda e: self._show_tooltip(
            self._external_net_entry,
            "Comma-separated CIDRs, e.g. !10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16"))
        self._external_net_entry.bind('<Leave>', self._hide_tooltip)

        # Initialize tooltip reference
        self._tooltip = None

    def _show_tooltip(self, widget, text):
        """Show a tooltip near the widget."""
        if not widget.winfo_exists():
            return
        x = widget.winfo_rootx() + 20
        y = widget.winfo_rooty() + widget.winfo_height() + 5
        self._tooltip = tk.Toplevel(widget)
        self._tooltip.wm_overrideredirect(True)
        self._tooltip.wm_geometry("+{}+{}".format(x, y))
        label = ttk.Label(self._tooltip, text=text, background="#FFFFDD",
                          relief=tk.SOLID, borderwidth=1, font=('TkDefaultFont', 9))
        label.pack()

    def _hide_tooltip(self, event=None):
        """Hide the tooltip."""
        if hasattr(self, '_tooltip') and self._tooltip:
            if self._tooltip.winfo_exists():
                self._tooltip.destroy()
            self._tooltip = None

    def _setup_build_button(self):
        """Create the Build Rule Group button."""
        btn_frame = ttk.Frame(self._content_frame)
        btn_frame.pack(fill=tk.X, pady=(4, 0))

        self._build_btn = ttk.Button(
            btn_frame,
            text="Build Rule Group",
            command=self._on_build_clicked,
        )
        self._build_btn.pack(side=tk.LEFT, padx=(0, 8))

        self._rebuild_btn = ttk.Button(
            btn_frame,
            text="Rebuild",
            command=self._on_build_clicked,
            state=tk.DISABLED,
        )
        self._rebuild_btn.pack(side=tk.LEFT)

    # ─── Profile Management ───────────────────────────────────────

    def _load_profiles(self):
        """Load available AWS profiles into the profile combobox."""
        profiles = self._session_manager.list_available_profiles()

        if not profiles:
            # Check if boto3 is available
            from src.aws.aws_session_manager import HAS_BOTO3
            if not HAS_BOTO3:
                self._profile_combo.config(values=['(boto3 not installed)'], state='disabled')
                self._profile_var.set('(boto3 not installed)')
            else:
                self._profile_combo.config(values=['(default)'])
                self._profile_var.set('(default)')
        else:
            display_profiles = ['(default)'] + [p for p in profiles if p != 'default']
            self._profile_combo.config(values=display_profiles)
            self._profile_var.set('(default)')

    def _refresh_profiles(self):
        """Refresh the profile list from AWS config files."""
        current = self._profile_var.get()
        self._load_profiles()

        # Restore previous selection if it still exists
        current_values = list(self._profile_combo['values'])
        if current in current_values:
            self._profile_var.set(current)

    def _on_profile_changed(self, *args):
        """Handle profile selection change."""
        profile = self._profile_var.get()
        if profile in ('(default)', '(boto3 not installed)', '(no profiles found)'):
            self._session_manager.profile_name = None
        else:
            self._session_manager.profile_name = profile

        # Update region to profile's default if available
        default_region = self._session_manager.get_default_region()
        if default_region and default_region in AWS_REGIONS:
            self._region_var.set(default_region)

    def _on_region_changed(self, *args):
        """Handle region selection change."""
        region = self._region_var.get()
        if region:
            self._source_browser.load_rule_groups(region, callback=self._on_sources_loaded)

    def _on_name_changed(self, *args):
        """Validate the rule group name as the user types."""
        name = self._name_var.get()
        if not name:
            self._name_error_label.config(text="")
            return

        errors = _validate_name(name)
        if errors:
            self._name_error_label.config(text=errors[0])
        else:
            self._name_error_label.config(text="")

    def _on_sources_loaded(self, success: bool, error: Optional[str]):
        """Handle completion of source rule group loading.

        Applies any pending source ARN selections from a loaded .mrg file.

        Args:
            success: True if loading succeeded.
            error: Error message if loading failed, None otherwise.
        """
        if success:
            self.apply_pending_source_arns()

    def _on_filter_changed(self):
        """Handle filter builder changes."""
        pass  # Could update summary or enable/disable build button

    # ─── Collapse / Expand ────────────────────────────────────────

    def _toggle_collapse(self):
        """Toggle between collapsed and expanded states."""
        if self._is_collapsed:
            self.expand()
        else:
            self.collapse()

    def collapse(self):
        """Collapse the configuration panel to a summary line."""
        self._is_collapsed = True
        self._content_frame.pack_forget()
        self._toggle_btn.config(text="\u25b6 Expand")  # ▶
        self._update_summary()
        self._summary_label.config(text=self._get_summary_text())

    def expand(self):
        """Expand the configuration panel to show all controls."""
        self._is_collapsed = False
        self._content_frame.pack(fill=tk.X, padx=4, pady=4)
        self._toggle_btn.config(text="\u25bc Collapse")  # ▼
        self._summary_label.config(text="")

    def is_collapsed(self) -> bool:
        """Check if the panel is currently collapsed."""
        return self._is_collapsed

    def _update_summary(self):
        """Update the collapsed summary text."""
        self._summary_label.config(text=self._get_summary_text())

    def _get_summary_text(self) -> str:
        """Build the collapsed summary text."""
        name = self._name_var.get() or '(unnamed)'
        region = self._region_var.get()
        profile = self._profile_var.get()
        sources = self._source_browser.get_selected_count()
        filters = self._filter_builder.get_row_count()
        return "{} | {} | {} | {} sources | {} filters".format(
            name, region, profile, sources, filters
        )

    # ─── Build ────────────────────────────────────────────────────

    def _on_build_clicked(self):
        """Handle Build/Rebuild button click."""
        self._has_built = True
        self._rebuild_btn.config(state=tk.NORMAL)

        if self._on_build:
            self._on_build()

    # ─── Get / Set Configuration ──────────────────────────────────

    def get_region(self) -> str:
        """Get the selected region."""
        return self._region_var.get()

    def set_region(self, region: str):
        """Set the region selector."""
        if region in AWS_REGIONS:
            self._region_var.set(region)

    def get_profile(self) -> Optional[str]:
        """Get the selected AWS profile name (None for default)."""
        profile = self._profile_var.get()
        if profile in ('(default)', '(boto3 not installed)', '(no profiles found)'):
            return None
        return profile

    def set_profile(self, profile: Optional[str]):
        """Set the AWS profile selector."""
        if profile is None or profile == 'default':
            self._profile_var.set('(default)')
        else:
            # Check if profile is in the combo values
            current_values = list(self._profile_combo['values'])
            if profile in current_values:
                self._profile_var.set(profile)
            else:
                # Profile not found — show warning and default
                self._profile_var.set('(default)')
                return False  # Indicates profile was not found
        return True

    def get_name(self) -> str:
        """Get the rule group name."""
        return self._name_var.get().strip()

    def set_name(self, name: str):
        """Set the rule group name."""
        self._name_var.set(name)

    def get_capacity(self) -> int:
        """Get the output rule group capacity.

        Returns 0 if the capacity field is empty or non-numeric.
        """
        try:
            return int(self._capacity_var.get())
        except (ValueError, TypeError):
            return 0

    def set_capacity(self, capacity: int):
        """Set the output rule group capacity."""
        self._capacity_var.set(str(capacity))

    def get_missing_metadata_behavior(self) -> str:
        """Get the missing metadata behavior ('exclude' or 'include')."""
        return self._missing_meta_var.get()

    def set_missing_metadata_behavior(self, behavior: str):
        """Set the missing metadata behavior."""
        if behavior in ('exclude', 'include'):
            self._missing_meta_var.set(behavior)

    def get_deployment_mode(self) -> str:
        """Get the deployment mode ('as_is' or 'test_mode')."""
        return self._mode_var.get()

    def set_deployment_mode(self, mode: str):
        """Set the deployment mode."""
        if mode in ('as_is', 'test_mode'):
            self._mode_var.set(mode)

    def get_notification_email(self) -> Optional[str]:
        """Get the notification email (None if empty)."""
        email = self._email_var.get().strip()
        return email if email else None

    def set_notification_email(self, email: Optional[str]):
        """Set the notification email."""
        self._email_var.set(email or '')

    def get_selected_source_arns(self) -> List[str]:
        """Get the selected source rule group ARNs."""
        return self._source_browser.get_selected_arns()

    def set_selected_source_arns(self, arns: List[str]):
        """Set the selected source rule group ARNs."""
        self._source_browser.set_selected_arns(arns)

    def get_filter_config(self) -> FilterConfig:
        """Get the current filter configuration."""
        return self._filter_builder.get_filter_config(
            missing_metadata_behavior=self.get_missing_metadata_behavior()
        )

    def set_filter_config(self, filter_config: FilterConfig):
        """Set the filter configuration."""
        self._filter_builder.set_from_filter_config(filter_config)
        self.set_missing_metadata_behavior(filter_config.missing_metadata_behavior)

    def get_source_browser(self) -> SourceBrowser:
        """Get the source browser widget."""
        return self._source_browser

    def get_filter_builder(self) -> FilterBuilder:
        """Get the filter builder widget."""
        return self._filter_builder

    def get_home_net(self) -> Optional[str]:
        """Get the $HOME_NET value, or None if empty."""
        val = self._home_net_var.get().strip()
        return val if val else None

    def set_home_net(self, value: Optional[str]):
        """Set the $HOME_NET value."""
        self._home_net_var.set(value or '')

    def get_external_net(self) -> Optional[str]:
        """Get the $EXTERNAL_NET value, or None if empty."""
        val = self._external_net_var.get().strip()
        return val if val else None

    def set_external_net(self, value: Optional[str]):
        """Set the $EXTERNAL_NET value."""
        self._external_net_var.set(value or '')

    # ─── MRG Config Integration ───────────────────────────────────

    def load_from_mrg_config(self, config):
        """Populate the panel from an MRGConfig object.

        Args:
            config: MRGConfig instance to load from.

        Returns:
            List of warning messages (e.g., missing profile).
        """
        warnings = []

        # Set region first (triggers source browser load)
        self.set_region(config.region)

        # Set profile
        if config.aws_profile:
            found = self.set_profile(config.aws_profile)
            if not found:
                warnings.append(
                    "AWS profile '{}' from this configuration was not found "
                    "in your AWS config files. The profile selector has been "
                    "reset to (default).".format(config.aws_profile)
                )

        # Set name and capacity
        self.set_name(config.output_rule_group_name or config.name)
        self.set_capacity(config.output_rule_group_capacity)

        # Set missing metadata behavior
        self.set_missing_metadata_behavior(config.missing_metadata_behavior)

        # Set deployment mode
        self.set_deployment_mode(config.deployment_mode)

        # Set notification email
        self.set_notification_email(config.notification_email)

        # Set filters
        try:
            filter_config = config.get_filter_config()
            self.set_filter_config(filter_config)
        except Exception:
            warnings.append("Could not load filter configuration from the file.")

        # Source ARNs will be set after rule groups are loaded
        # Store them for deferred application
        self._pending_source_arns = list(config.source_rule_groups)

        # Set home_net
        self.set_home_net(config.home_net if hasattr(config, 'home_net') else None)

        # Set external_net
        self.set_external_net(config.external_net if hasattr(config, 'external_net') else None)

        return warnings

    def save_to_mrg_config(self, config):
        """Save the panel state to an MRGConfig object.

        Args:
            config: MRGConfig instance to update.
        """
        config.region = self.get_region()
        config.aws_profile = self.get_profile()
        config.name = self.get_name()
        config.output_rule_group_name = self.get_name()
        config.output_rule_group_capacity = self.get_capacity()
        config.missing_metadata_behavior = self.get_missing_metadata_behavior()
        config.deployment_mode = self.get_deployment_mode()
        config.notification_email = self.get_notification_email()
        config.source_rule_groups = self.get_selected_source_arns()

        # Save home_net
        config.home_net = self.get_home_net()

        # Save external_net
        config.external_net = self.get_external_net()

        # Save filter config
        filter_config = self.get_filter_config()
        config.set_filter_config(filter_config)

    def apply_pending_source_arns(self):
        """Apply pending source ARN selections after rule groups are loaded.

        Call this after the source browser has finished loading rule groups
        from an Open Configuration operation.
        """
        if hasattr(self, '_pending_source_arns') and self._pending_source_arns:
            self._source_browser.set_selected_arns(self._pending_source_arns)
            self._pending_source_arns = []

    # ─── Reset ────────────────────────────────────────────────────

    def reset(self):
        """Reset all configuration fields to defaults."""
        self._region_var.set('us-east-1')
        self._profile_var.set('(default)')
        self._name_var.set('')
        self._capacity_var.set(str(DEFAULT_CAPACITY))
        self._missing_meta_var.set('exclude')
        self._mode_var.set('as_is')
        self._email_var.set('')
        self._home_net_var.set('')
        self._external_net_var.set('')
        self._filter_builder.clear()
        self._source_browser.deselect_all()
        self._has_built = False
        self._rebuild_btn.config(state=tk.DISABLED)
        self._name_error_label.config(text="")

        if self._is_collapsed:
            self.expand()

    # ─── Validation ───────────────────────────────────────────────

    def validate(self) -> List[str]:
        """Validate the current configuration.

        Returns:
            List of validation error messages. Empty if valid.
        """
        errors = []

        name = self.get_name()
        if not name:
            errors.append("Rule group name is required.")
        else:
            name_errors = _validate_name(name)
            errors.extend(name_errors)

        if not self.get_region():
            errors.append("AWS region is required.")

        if not self.get_selected_source_arns():
            errors.append("At least one source rule group must be selected.")

        email = self.get_notification_email()
        if email and '@' not in email:
            errors.append("Notification email appears to be invalid.")

        return errors


def _validate_name(name: str) -> List[str]:
    """Validate a rule group name against AWS naming rules.

    Args:
        name: The proposed rule group name.

    Returns:
        List of validation error messages. Empty if valid.
    """
    errors = []
    if len(name) > 128:
        errors.append("Name must be 128 characters or fewer.")
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        errors.append("Name must contain only alphanumeric, hyphens, and underscores.")
    return errors