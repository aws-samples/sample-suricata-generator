"""
Status Bar for Managed Rule Group Generator

Bottom-of-window status display (mirroring Suricata Generator's
setup_status_bar() pattern) showing:
- Capacity: used / total
- Action counts: color-coded Pass/Drop/Alert/Reject
- SID range: min – max
- Source count
- Deployment mode indicator
- AWS Profile name

Cross-platform notes (Section 14.3):
- Uses tk.Label (not ttk.Label) for foreground color support
- Platform-safe font fallbacks
"""

import platform
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional


class StatusBar(ttk.Frame):
    """Bottom status bar showing rule group statistics.

    Displays capacity, action counts (color-coded), SID range,
    source count, deployment mode, and AWS profile.
    """

    # Color constants matching Suricata Generator
    COLOR_PASS = '#2E7D32'
    COLOR_ALERT = '#1976D2'
    COLOR_DROP = '#D32F2F'
    COLOR_REJECT = '#7B1FA2'
    COLOR_TEST_MODE = '#FF6600'  # Orange for test mode indicator
    COLOR_MUTED = '#666666'

    def __init__(self, parent, session_manager=None,
                 on_profile_change: Optional[Callable] = None, **kwargs):
        """Initialize the status bar.

        Args:
            parent: Parent tkinter widget.
            session_manager: AWSSessionManager instance for profile listing.
            on_profile_change: Optional callback when profile selection changes.
            **kwargs: Additional keyword arguments for Frame.
        """
        super().__init__(parent, relief=tk.SUNKEN, **kwargs)

        self._session_manager = session_manager
        self._on_profile_change = on_profile_change
        self._capacity_used = 0
        self._capacity_total = 0
        self._action_counts = {'pass': 0, 'alert': 0, 'drop': 0, 'reject': 0}
        self._sid_min = None
        self._sid_max = None
        self._source_count = 0
        self._deployment_mode = 'as_is'
        self._aws_profile = '(default)'

        self._setup_ui()

    def _setup_ui(self):
        """Create the status bar layout."""
        font = ('TkDefaultFont', 9)

        # Single row for all stats + profile selector
        row1 = ttk.Frame(self)
        row1.pack(fill=tk.X, padx=4, pady=2)

        # Capacity
        self._capacity_label = tk.Label(
            row1, text='Capacity: 0 / 0', font=font, anchor=tk.W,
        )
        self._capacity_label.pack(side=tk.LEFT, padx=(0, 8))

        # Separator
        ttk.Separator(row1, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)

        # Action counts (colored labels)
        self._pass_label = tk.Label(
            row1, text='Pass: 0', fg=self.COLOR_PASS, font=font,
        )
        self._pass_label.pack(side=tk.LEFT, padx=(0, 6))

        self._drop_label = tk.Label(
            row1, text='Drop: 0', fg=self.COLOR_DROP, font=font,
        )
        self._drop_label.pack(side=tk.LEFT, padx=(0, 6))

        self._alert_label = tk.Label(
            row1, text='Alert: 0', fg=self.COLOR_ALERT, font=font,
        )
        self._alert_label.pack(side=tk.LEFT, padx=(0, 6))

        self._reject_label = tk.Label(
            row1, text='Reject: 0', fg=self.COLOR_REJECT, font=font,
        )
        self._reject_label.pack(side=tk.LEFT, padx=(0, 6))

        # Separator
        ttk.Separator(row1, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)

        # SID range
        self._sid_label = tk.Label(
            row1, text='SIDs: –', fg=self.COLOR_MUTED, font=font,
        )
        self._sid_label.pack(side=tk.LEFT, padx=(0, 8))

        # Separator
        ttk.Separator(row1, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)

        # Rules string size
        self._size_label = tk.Label(
            row1, text='Size: –', fg=self.COLOR_MUTED, font=font,
        )
        self._size_label.pack(side=tk.LEFT, padx=(0, 8))

        # Separator
        ttk.Separator(row1, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)

        # Source count
        self._source_label = tk.Label(
            row1, text='Sources: 0', fg=self.COLOR_MUTED, font=font,
        )
        self._source_label.pack(side=tk.LEFT, padx=(0, 8))

        # Separator
        ttk.Separator(row1, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=4)

        # Deployment mode
        self._mode_label = tk.Label(
            row1, text='Mode: As-Is', font=font,
        )
        self._mode_label.pack(side=tk.LEFT, padx=(0, 4))

        # AWS Profile selector (right side of same row)
        profile_frame = ttk.Frame(row1)
        profile_frame.pack(side=tk.RIGHT, padx=(0, 0))

        self._profile_refresh_btn = ttk.Button(
            profile_frame, text='\u21bb', width=2,  # ↻
            command=self._refresh_profiles,
        )
        self._profile_refresh_btn.pack(side=tk.RIGHT, padx=(4, 0))

        self._profile_var = tk.StringVar(value='(default)')
        self._profile_combo = ttk.Combobox(
            profile_frame,
            textvariable=self._profile_var,
            state='readonly',
            width=18,
            values=['(default)'],
        )
        self._profile_combo.pack(side=tk.RIGHT, padx=(4, 0))
        self._profile_combo.bind('<<ComboboxSelected>>', self._on_profile_selected)

        tk.Label(
            profile_frame, text='AWS Profile:', fg=self.COLOR_MUTED, font=font,
        ).pack(side=tk.RIGHT, padx=(0, 0))

        # Row 2: Status text
        row2 = ttk.Frame(self)
        row2.pack(fill=tk.X, padx=4, pady=(0, 2))

        self._status_text_label = tk.Label(
            row2, text='Ready', fg=self.COLOR_MUTED, font=font, anchor=tk.W,
        )
        self._status_text_label.pack(side=tk.LEFT)

        # Populate profiles on startup
        self._refresh_profiles()

    # ─── Update Methods ───────────────────────────────────────

    def update_capacity(self, used: int, total: int):
        """Update the capacity display.

        Args:
            used: Number of rules in the rule group.
            total: Maximum capacity of the rule group.
        """
        self._capacity_used = used
        self._capacity_total = total
        self._capacity_label.config(
            text='Capacity: {:,} / {:,}'.format(used, total)
        )

    def update_action_counts(self, counts: Dict[str, int]):
        """Update action count labels.

        Args:
            counts: Dict mapping action name to count.
                    Expected keys: 'pass', 'alert', 'drop', 'reject'.
        """
        self._action_counts = dict(counts)
        self._pass_label.config(text='Pass: {}'.format(counts.get('pass', 0)))
        self._drop_label.config(text='Drop: {}'.format(counts.get('drop', 0)))
        self._alert_label.config(text='Alert: {}'.format(counts.get('alert', 0)))
        self._reject_label.config(text='Reject: {}'.format(counts.get('reject', 0)))

    def update_sid_range(self, sid_min: Optional[int], sid_max: Optional[int]):
        """Update the SID range display.

        Args:
            sid_min: Minimum SID, or None if no rules.
            sid_max: Maximum SID, or None if no rules.
        """
        self._sid_min = sid_min
        self._sid_max = sid_max
        if sid_min is not None and sid_max is not None:
            self._sid_label.config(
                text='SIDs: {} \u2013 {}'.format(sid_min, sid_max)
            )
        else:
            self._sid_label.config(text='SIDs: \u2013')

    def update_rules_size(self, size_bytes: int):
        """Update the rules string size display.

        Shows size in KB or MB with color coding:
        - Green: under 50% of 2MB limit
        - Orange: 50-80% of 2MB limit
        - Red: over 80% of 2MB limit

        Args:
            size_bytes: Size of the rules string in bytes.
        """
        max_bytes = 2_000_000  # AWS Network Firewall 2MB limit

        # Format the size
        if size_bytes < 0:
            self._size_label.config(text='Size: \u2013', fg=self.COLOR_MUTED)
            return

        if size_bytes >= 1_000_000:
            size_text = '{:.1f} MB'.format(size_bytes / 1_000_000)
        else:
            size_text = '{:,.0f} KB'.format(size_bytes / 1000)

        max_text = '{:.0f} MB'.format(max_bytes / 1_000_000)
        display = 'Size: {} / {}'.format(size_text, max_text)

        # Color based on percentage of limit
        pct = size_bytes / max_bytes
        if pct >= 0.80:
            color = self.COLOR_DROP  # Red
        elif pct >= 0.50:
            color = self.COLOR_TEST_MODE  # Orange
        else:
            color = self.COLOR_PASS  # Green

        self._size_label.config(text=display, fg=color)

    def update_source_count(self, count: int):
        """Update the source rule group count.

        Args:
            count: Number of source rule groups.
        """
        self._source_count = count
        self._source_label.config(text='Sources: {}'.format(count))

    def update_deployment_mode(self, mode: str):
        """Update the deployment mode indicator.

        Args:
            mode: 'as_is' or 'test_mode'.
        """
        self._deployment_mode = mode
        if mode == 'test_mode':
            self._mode_label.config(
                text='Mode: TEST MODE', fg=self.COLOR_TEST_MODE,
            )
        else:
            self._mode_label.config(text='Mode: As-Is', fg='black')

    def update_aws_profile(self, profile: Optional[str]):
        """Update the AWS profile selector to show the given profile.

        Args:
            profile: Profile name, or None/'(default)' for default.
        """
        display = profile if profile else '(default)'
        self._aws_profile = display

        # Ensure the profile is in the combo values
        current_values = list(self._profile_combo['values'])
        if display not in current_values:
            current_values.append(display)
            self._profile_combo['values'] = current_values

        self._profile_var.set(display)

    def set_status_text(self, text: str):
        """Set the general status text.

        Args:
            text: Status message to display.
        """
        self._status_text_label.config(text=text)

    def update_from_rules(self, rules: list, capacity: int = 0,
                          source_count: int = 0, deployment_mode: str = 'as_is',
                          profile: Optional[str] = None):
        """Convenience method to update all status bar fields at once.

        Args:
            rules: List of ParsedRule objects.
            capacity: Rule group capacity.
            source_count: Number of source rule groups.
            deployment_mode: 'as_is' or 'test_mode'.
            profile: AWS profile name or None.
        """
        # Count actions
        action_counts = {'pass': 0, 'alert': 0, 'drop': 0, 'reject': 0}
        sids = []
        for rule in rules:
            action = rule.action.lower() if hasattr(rule, 'action') else ''
            if action in action_counts:
                action_counts[action] += 1
            if hasattr(rule, 'sid') and rule.sid is not None:
                sids.append(rule.sid)

        self.update_capacity(len(rules), capacity)
        self.update_action_counts(action_counts)

        if sids:
            self.update_sid_range(min(sids), max(sids))
        else:
            self.update_sid_range(None, None)

        self.update_source_count(source_count)
        self.update_deployment_mode(deployment_mode)
        self.update_aws_profile(profile)

    # ─── Profile Selector ─────────────────────────────────────

    def _refresh_profiles(self):
        """Refresh the profile dropdown from AWS config files."""
        profiles = ['(default)']
        if self._session_manager:
            try:
                available = self._session_manager.list_available_profiles()
                if available:
                    # Build list: (default) first, then sorted profiles
                    profiles = ['(default)']
                    for p in available:
                        if p == 'default':
                            continue  # Already represented by (default)
                        profiles.append(p)
            except Exception:
                pass

        self._profile_combo['values'] = profiles

        # Preserve current selection if still valid
        current = self._profile_var.get()
        if current not in profiles:
            self._profile_var.set('(default)')

    def _on_profile_selected(self, event=None):
        """Handle profile selection change from the dropdown."""
        selected = self._profile_var.get()
        self._aws_profile = selected

        # Update session manager
        if self._session_manager:
            profile_name = None if selected == '(default)' else selected
            self._session_manager.profile_name = profile_name

        # Notify callback
        if self._on_profile_change:
            self._on_profile_change(selected)

    def get_profile_combo(self):
        """Get the profile combobox widget (for testing)."""
        return self._profile_combo

    # ─── Getters ──────────────────────────────────────────────

    def get_capacity_used(self) -> int:
        """Get the current used capacity."""
        return self._capacity_used

    def get_capacity_total(self) -> int:
        """Get the total capacity."""
        return self._capacity_total

    def get_action_counts(self) -> Dict[str, int]:
        """Get the current action counts."""
        return dict(self._action_counts)

    def get_sid_range(self):
        """Get the SID range as (min, max) tuple."""
        return (self._sid_min, self._sid_max)

    def get_source_count(self) -> int:
        """Get the source count."""
        return self._source_count

    def get_deployment_mode(self) -> str:
        """Get the deployment mode."""
        return self._deployment_mode

    def get_aws_profile(self) -> str:
        """Get the displayed AWS profile."""
        return self._aws_profile