"""
View Filter Bar for Managed Rule Group Generator

Collapsible filter bar above the rule table that allows the user to
temporarily hide rules from the display without changing the actual
filter configuration. View filters are display-only — they do not
affect what gets deployed or saved.

Filters include:
- Protocol checkboxes (tcp, udp, ip, icmp, http, tls, etc.)
- Network variable dropdown ($HOME_NET, $EXTERNAL_NET, etc.)
- SID range (from/to)

Similar to Suricata Generator's setup_filter_bar() pattern.

Cross-platform notes (Section 14.3):
- Uses trace_add() not trace()
- Uses expand=False for fixed-size frames
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional, Set


# Common Suricata protocols
COMMON_PROTOCOLS = [
    'tcp', 'udp', 'ip', 'icmp', 'http', 'tls', 'dns', 'ftp',
    'smtp', 'ssh', 'dcerpc', 'smb', 'ntp', 'dhcp', 'krb5',
]


class ViewFilterBar(ttk.Frame):
    """Collapsible view filter bar above the rule table.

    Provides display-only filters: protocol checkboxes, network variable
    dropdown, and SID range. These filters affect only what's visible
    in the rule table — they don't change the deployment ruleset.
    """

    def __init__(self, parent, on_filter_change: Optional[Callable] = None, **kwargs):
        """Initialize the view filter bar.

        Args:
            parent: Parent tkinter widget.
            on_filter_change: Callback when any filter changes. Called with no args.
            **kwargs: Additional keyword arguments for Frame.
        """
        super().__init__(parent, **kwargs)

        self._on_filter_change = on_filter_change
        self._is_collapsed = True
        self._protocol_vars = {}  # {protocol: BooleanVar}
        self._available_protocols = set()
        self._available_variables = set()

        self._setup_ui()

    def _setup_ui(self):
        """Create the filter bar layout."""
        # Outer frame
        self._outer_frame = ttk.LabelFrame(self, text='View Filters')
        self._outer_frame.pack(fill=tk.X, padx=4, pady=(0, 2))

        # Row 1: Always visible — collapse toggle + protocol checkboxes
        self._row1 = ttk.Frame(self._outer_frame)
        self._row1.pack(fill=tk.X, padx=4, pady=2)

        # Collapse/Expand toggle
        self._toggle_label = ttk.Label(
            self._row1, text='\u25b6', cursor='hand2',
            font=('TkDefaultFont', 9, 'bold'),
        )
        self._toggle_label.pack(side=tk.LEFT, padx=(0, 8))
        self._toggle_label.bind('<Button-1>', lambda e: self._toggle_collapse())

        # Protocol checkboxes (common ones always visible)
        ttk.Label(self._row1, text='Protocols:', font=('TkDefaultFont', 9)).pack(
            side=tk.LEFT, padx=(0, 4),
        )

        for proto in ['tcp', 'udp', 'ip', 'icmp', 'http', 'tls', 'dns', 'smb', 'smtp']:
            var = tk.BooleanVar(value=True)
            self._protocol_vars[proto] = var
            cb = ttk.Checkbutton(
                self._row1, text=proto.upper(), variable=var,
                command=self._on_change,
            )
            cb.pack(side=tk.LEFT, padx=2)

        # "Other" checkbox for protocols not explicitly listed
        self._other_proto_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            self._row1, text='Other', variable=self._other_proto_var,
            command=self._on_change,
        ).pack(side=tk.LEFT, padx=2)

        # Clear button on the right
        ttk.Button(
            self._row1, text='Clear', width=6, command=self.clear_filters,
        ).pack(side=tk.RIGHT, padx=(4, 0))

        # Apply button on the right
        ttk.Button(
            self._row1, text='Apply', width=6, command=self._on_change,
        ).pack(side=tk.RIGHT, padx=(4, 0))

        # Row 2: Expandable — network variable dropdown + SID range
        self._row2 = ttk.Frame(self._outer_frame)

        # Spacing to align with row1
        ttk.Label(self._row2, text='    ').pack(side=tk.LEFT)

        # Network variable dropdown
        ttk.Label(self._row2, text='Network:', font=('TkDefaultFont', 9)).pack(
            side=tk.LEFT, padx=(0, 4),
        )
        self._variable_var = tk.StringVar(value='All')
        self._variable_combo = ttk.Combobox(
            self._row2, textvariable=self._variable_var,
            values=['All'], state='readonly', width=16,
        )
        self._variable_combo.pack(side=tk.LEFT, padx=(0, 12))
        self._variable_combo.bind('<<ComboboxSelected>>', lambda e: self._on_change())

        # SID range
        ttk.Label(self._row2, text='SID:', font=('TkDefaultFont', 9)).pack(
            side=tk.LEFT, padx=(0, 4),
        )
        self._sid_from_var = tk.StringVar(value='')
        ttk.Entry(
            self._row2, textvariable=self._sid_from_var, width=8,
        ).pack(side=tk.LEFT)

        ttk.Label(self._row2, text='to', font=('TkDefaultFont', 9)).pack(
            side=tk.LEFT, padx=4,
        )
        self._sid_to_var = tk.StringVar(value='')
        ttk.Entry(
            self._row2, textvariable=self._sid_to_var, width=8,
        ).pack(side=tk.LEFT)

    # ─── Collapse / Expand ────────────────────────────────────

    def _toggle_collapse(self):
        """Toggle between collapsed and expanded states."""
        if self._is_collapsed:
            self.expand()
        else:
            self.collapse()

    def collapse(self):
        """Collapse to show only row 1 (protocols)."""
        self._is_collapsed = True
        self._row2.pack_forget()
        self._toggle_label.config(text='\u25b6')  # ▶

    def expand(self):
        """Expand to show both rows."""
        self._is_collapsed = False
        self._row2.pack(fill=tk.X, padx=4, pady=2)
        self._toggle_label.config(text='\u25bc')  # ▼

    def is_collapsed(self) -> bool:
        """Check if the bar is collapsed."""
        return self._is_collapsed

    # ─── Filter State ─────────────────────────────────────────

    def get_enabled_protocols(self) -> Set[str]:
        """Get the set of currently enabled protocol filters.

        Returns:
            Set of lowercase protocol names that are checked.
        """
        enabled = set()
        for proto, var in self._protocol_vars.items():
            if var.get():
                enabled.add(proto)
        return enabled

    def is_other_protocols_enabled(self) -> bool:
        """Check if the 'Other' protocol checkbox is enabled."""
        return self._other_proto_var.get()

    def get_network_variable(self) -> Optional[str]:
        """Get the selected network variable filter.

        Returns:
            Network variable string (e.g., '$HOME_NET') or None for 'All'.
        """
        val = self._variable_var.get()
        if val == 'All' or not val:
            return None
        return val

    def get_sid_range(self):
        """Get the SID range filter.

        Returns:
            Tuple (from_sid, to_sid) where either can be None.
        """
        from_val = self._sid_from_var.get().strip()
        to_val = self._sid_to_var.get().strip()

        try:
            from_sid = int(from_val) if from_val else None
        except ValueError:
            from_sid = None

        try:
            to_sid = int(to_val) if to_val else None
        except ValueError:
            to_sid = None

        return (from_sid, to_sid)

    def is_active(self) -> bool:
        """Check if any view filters are currently active (non-default).

        Returns:
            True if any filter is restricting the view.
        """
        # Check protocols
        for var in self._protocol_vars.values():
            if not var.get():
                return True
        if not self._other_proto_var.get():
            return True

        # Check network variable
        if self._variable_var.get() != 'All':
            return True

        # Check SID range
        from_sid, to_sid = self.get_sid_range()
        if from_sid is not None or to_sid is not None:
            return True

        return False

    def build_filter_func(self):
        """Build a filter function based on current filter state.

        Returns:
            A callable that takes a ParsedRule and returns True to show it.
            Returns None if no filters are active (show all).
        """
        if not self.is_active():
            return None

        enabled_protocols = self.get_enabled_protocols()
        other_enabled = self.is_other_protocols_enabled()
        known_protocols = set(self._protocol_vars.keys())
        network_var = self.get_network_variable()
        sid_from, sid_to = self.get_sid_range()

        def _filter(rule):
            # Protocol filter
            proto = rule.protocol.lower() if rule.protocol else ''
            if proto in known_protocols:
                if proto not in enabled_protocols:
                    return False
            else:
                # Unknown protocol — use 'Other' checkbox
                if not other_enabled:
                    return False

            # Network variable filter
            if network_var:
                source = rule.source or ''
                dest = rule.destination or ''
                if network_var not in source and network_var not in dest:
                    return False

            # SID range filter
            if rule.sid is not None:
                if sid_from is not None and rule.sid < sid_from:
                    return False
                if sid_to is not None and rule.sid > sid_to:
                    return False

            return True

        return _filter

    # ─── Update Available Options ─────────────────────────────

    def update_available_protocols(self, protocols: Set[str]):
        """Update the set of available protocols from loaded rules.

        Args:
            protocols: Set of protocol strings (lowercase).
        """
        self._available_protocols = protocols

    def update_available_variables(self, variables: Set[str]):
        """Update the network variable dropdown with available variables.

        Args:
            variables: Set of variable strings (e.g., '$HOME_NET').
        """
        self._available_variables = variables
        values = ['All'] + sorted(variables)
        self._variable_combo.config(values=values)

        # If current selection is no longer valid, reset
        if self._variable_var.get() not in values:
            self._variable_var.set('All')

    def clear_filters(self):
        """Reset all view filters to defaults (show all)."""
        # Enable all protocol checkboxes
        for var in self._protocol_vars.values():
            var.set(True)
        self._other_proto_var.set(True)

        # Reset network variable
        self._variable_var.set('All')

        # Clear SID range
        self._sid_from_var.set('')
        self._sid_to_var.set('')

        self._on_change()

    # ─── Internal ─────────────────────────────────────────────

    def _on_change(self):
        """Called when any filter changes. Notifies the parent."""
        if self._on_filter_change:
            self._on_filter_change()