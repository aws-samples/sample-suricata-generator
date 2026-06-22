"""
Source Rule Group Browser for Managed Rule Group Generator

Provides a multi-select checklist for AWS-managed strict-order threat
signature rule groups. Fetches available rule groups via the Network
Firewall API and presents them in a Treeview with checkboxes.

Features:
- Treeview-based checklist with checkboxes (☑/☐)
- Shows rule group name and capacity
- Loading indicator during API calls
- Threaded API calls to keep UI responsive
- Pre-selection support for loading from .mrg files
"""

import platform
import threading
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional


class SourceBrowser(ttk.LabelFrame):
    """Multi-select checklist for source managed rule groups.

    Displays available AWS-managed strict-order threat signature rule groups
    in a Treeview with checkboxes. Users can check/uncheck groups to select
    them as filter sources.

    The browser fetches rule groups from the Network Firewall API in a
    background thread so the UI remains responsive during the API call.
    """

    # Checkbox characters
    CHECK_ON = '\u2611'   # ☑
    CHECK_OFF = '\u2610'  # ☐

    def __init__(self, parent, session_manager=None, **kwargs):
        """Initialize the source browser.

        Args:
            parent: Parent tkinter widget.
            session_manager: AWSSessionManager instance for API calls.
            **kwargs: Additional keyword arguments for LabelFrame.
        """
        super().__init__(parent, text="Source Rule Groups", **kwargs)

        self._session_manager = session_manager
        self._rule_groups = []  # List of dicts: {'Name': ..., 'Arn': ...}
        self._checked = {}  # item_id -> bool
        self._loading = False
        self._on_selection_change = None  # Optional callback

        self._setup_ui()

    def _setup_ui(self):
        """Create the treeview and scrollbar widgets."""
        # Container frame
        container = ttk.Frame(self)
        container.pack(fill=tk.BOTH, expand=False, padx=2, pady=2)

        # Status label (shown during loading or when empty)
        self._status_label = ttk.Label(container, text="Select a region to load rule groups.")
        self._status_label.pack(fill=tk.X, padx=2, pady=(2, 0))

        # Treeview frame
        tree_frame = ttk.Frame(container)
        tree_frame.pack(fill=tk.BOTH, expand=False, padx=2, pady=2)

        # Treeview
        self._tree = ttk.Treeview(
            tree_frame,
            columns=('name', 'arn'),
            show='tree',
            selectmode='none',
            height=6,
        )
        self._tree.heading('#0', text='', anchor=tk.W)
        self._tree.column('#0', width=500, minwidth=200, stretch=True)
        self._tree.column('name', width=0, stretch=False)
        self._tree.column('arn', width=0, stretch=False)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind click to toggle checkbox
        self._tree.bind('<ButtonRelease-1>', self._on_click)
        self._tree.bind('<space>', self._on_space)

        # Button bar (Select All / Clear Selection)
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, padx=2, pady=(0, 2))

        self._select_all_btn = ttk.Button(
            btn_frame, text="Select All", command=self.select_all,
        )
        self._select_all_btn.pack(side=tk.LEFT, padx=(0, 4))

        self._clear_selection_btn = ttk.Button(
            btn_frame, text="Clear Selection", command=self.deselect_all,
        )
        self._clear_selection_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Summary label
        self._summary_label = ttk.Label(btn_frame, text="0 selected")
        self._summary_label.pack(side=tk.LEFT, padx=(4, 0))

    def _on_click(self, event):
        """Handle mouse click on treeview items to toggle checkboxes."""
        item = self._tree.identify_row(event.y)
        if item:
            self._toggle_item(item)

    def _on_space(self, event):
        """Handle space key to toggle the focused item."""
        item = self._tree.focus()
        if item:
            self._toggle_item(item)

    def _toggle_item(self, item_id):
        """Toggle the checkbox state of a treeview item."""
        if item_id not in self._checked:
            return

        self._checked[item_id] = not self._checked[item_id]
        self._update_item_display(item_id)
        self._update_summary()

        if self._on_selection_change:
            self._on_selection_change()

    def _update_item_display(self, item_id):
        """Update the display text of a treeview item to reflect checkbox state."""
        name = self._tree.set(item_id, 'name')
        check = self.CHECK_ON if self._checked.get(item_id, False) else self.CHECK_OFF
        display_text = "{} {}".format(check, name)
        self._tree.item(item_id, text=display_text)

    def _update_summary(self):
        """Update the selection summary label."""
        selected = sum(1 for v in self._checked.values() if v)
        total = len(self._checked)
        self._summary_label.config(text="{} of {} selected".format(selected, total))

    def set_on_selection_change(self, callback: Optional[Callable]):
        """Set a callback to be invoked when selection changes.

        Args:
            callback: Callable with no arguments, or None to clear.
        """
        self._on_selection_change = callback

    def load_rule_groups(self, region: str, callback: Optional[Callable] = None):
        """Fetch available managed rule groups for the given region.

        Makes the API call in a background thread to keep the UI responsive.
        Shows a loading indicator while the call is in progress.

        Args:
            region: AWS region to query.
            callback: Optional callback invoked when loading is complete.
                Receives (success: bool, error_msg: str or None).
        """
        if self._loading:
            return

        self._loading = True
        self._clear()
        self._status_label.config(text="Loading rule groups for {}...".format(region))
        self._tree.pack_forget()  # Hide tree during loading

        def _fetch():
            try:
                from src.mrg.aws.network_firewall import list_managed_rule_groups
                rule_groups = list_managed_rule_groups(self._session_manager, region)
                self.after(0, lambda: self._on_load_complete(rule_groups, None, callback))
            except Exception as e:
                self.after(0, lambda: self._on_load_complete([], str(e), callback))

        thread = threading.Thread(target=_fetch, daemon=True)
        thread.start()

    def _on_load_complete(self, rule_groups, error, callback):
        """Handle completion of the rule group loading operation.

        Args:
            rule_groups: List of rule group dicts, or empty on error.
            error: Error message string, or None on success.
            callback: Optional callback to invoke.
        """
        # Guard against widget being destroyed while fetch was in progress
        if not self.winfo_exists():
            return

        self._loading = False
        self._rule_groups = rule_groups

        if error:
            self._status_label.config(
                text="Error loading rule groups: {}".format(error)
            )
            self._tree.pack_forget()
        elif not rule_groups:
            self._status_label.config(
                text="No compatible rule groups found in this region."
            )
            self._tree.pack_forget()
        else:
            self._status_label.config(text="")
            # Re-pack tree
            tree_frame = self._tree.master
            self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self._populate_tree(rule_groups)

        if callback:
            callback(error is None, error)

    def _clear(self):
        """Clear the treeview and internal state."""
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._checked.clear()
        self._rule_groups = []
        self._update_summary()

    def _populate_tree(self, rule_groups):
        """Populate the treeview with rule group entries.

        Args:
            rule_groups: List of dicts with 'Name' and 'Arn' keys.
        """
        for rg in sorted(rule_groups, key=lambda x: x.get('Name', '')):
            name = rg.get('Name', '')
            arn = rg.get('Arn', '')
            display = "{} {}".format(self.CHECK_OFF, name)

            item_id = self._tree.insert(
                '', tk.END,
                text=display,
                values=(name, arn),
            )
            self._checked[item_id] = False

        self._update_summary()

    def set_rule_groups(self, rule_groups: List[Dict]):
        """Directly set rule groups without an API call.

        Useful for testing or when rule groups are already available.

        Args:
            rule_groups: List of dicts with 'Name' and 'Arn' keys.
        """
        self._clear()
        self._rule_groups = rule_groups
        if rule_groups:
            self._status_label.config(text="")
            tree_frame = self._tree.master
            if not self._tree.winfo_ismapped():
                self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self._populate_tree(rule_groups)
        else:
            self._status_label.config(text="No rule groups available.")
            self._tree.pack_forget()

    def get_selected_arns(self) -> List[str]:
        """Get the ARNs of all selected (checked) rule groups.

        Returns:
            List of ARN strings for checked rule groups.
        """
        selected = []
        for item_id, is_checked in self._checked.items():
            if is_checked:
                arn = self._tree.set(item_id, 'arn')
                if arn:
                    selected.append(arn)
        return selected

    def get_selected_names(self) -> List[str]:
        """Get the names of all selected (checked) rule groups.

        Returns:
            List of name strings for checked rule groups.
        """
        selected = []
        for item_id, is_checked in self._checked.items():
            if is_checked:
                name = self._tree.set(item_id, 'name')
                if name:
                    selected.append(name)
        return selected

    def set_selected_arns(self, arns: List[str]):
        """Set the selection state based on a list of ARNs.

        Used when loading a configuration from a .mrg file.

        Args:
            arns: List of ARN strings to check.
        """
        arn_set = set(arns)
        for item_id in self._checked:
            arn = self._tree.set(item_id, 'arn')
            self._checked[item_id] = arn in arn_set
            self._update_item_display(item_id)
        self._update_summary()

    def select_all(self):
        """Select (check) all rule groups."""
        for item_id in self._checked:
            self._checked[item_id] = True
            self._update_item_display(item_id)
        self._update_summary()

    def deselect_all(self):
        """Deselect (uncheck) all rule groups."""
        for item_id in self._checked:
            self._checked[item_id] = False
            self._update_item_display(item_id)
        self._update_summary()

    def get_selected_count(self) -> int:
        """Get the number of selected rule groups.

        Returns:
            Number of checked rule groups.
        """
        return sum(1 for v in self._checked.values() if v)

    def get_total_count(self) -> int:
        """Get the total number of rule groups.

        Returns:
            Total number of rule groups in the list.
        """
        return len(self._checked)

    def is_loading(self) -> bool:
        """Check if the browser is currently loading rule groups.

        Returns:
            True if an API call is in progress.
        """
        return self._loading