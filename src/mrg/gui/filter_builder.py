"""
Filter Builder for Managed Rule Group Generator

Provides a dynamic row-based filter builder UI component. Each row
consists of a metadata field combobox, operator combobox, and values
entry/multi-select. Rows can be added and removed dynamically.

Filter Logic:
- Between rows: AND (a rule must satisfy ALL rows)
- Within a row: Multiple values are OR-combined

Supports operators: equals, not_equals, in, not_in, contains
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional, Set, Tuple

from src.mrg.core.rule_filter import FilterCondition, FilterConfig


# Metadata fields with known value sets (Section 15 of spec)
METADATA_FIELDS = {
    'signature_deployment': {
        'label': 'Signature Deployment',
        'values': ['Perimeter', 'Datacenter', 'Internal', 'Internet', 'SSLDecrypt', 'alert_only'],
    },
    'signature_severity': {
        'label': 'Signature Severity',
        'values': ['Info', 'Minor', 'Major', 'Critical'],
    },
    'attack_target': {
        'label': 'Attack Target',
        'values': [
            'Client_Endpoint', 'Server_Endpoint', 'IOT', 'Mobile_Client',
            'Network_Equipment', 'Web_Server', 'SQL_Server', 'SMTP_Server',
            'SMB_Server', 'SMB_Client', 'Client_and_Server',
        ],
    },
    'performance_impact': {
        'label': 'Performance Impact',
        'values': ['Low', 'Moderate', 'Significant', 'Unknown'],
    },
    'confidence': {
        'label': 'Confidence',
        'values': ['Low', 'Medium', 'High'],
    },
    'tls_state': {
        'label': 'TLS State',
        'values': ['plaintext', 'TLSDecrypt', 'TLSEncrypt'],
    },
    'mitre_tactic_id': {
        'label': 'MITRE Tactic ID',
        'values': [],  # Free-text
    },
    'mitre_technique_id': {
        'label': 'MITRE Technique ID',
        'values': [],  # Free-text
    },
    'malware_family': {
        'label': 'Malware Family',
        'values': [],  # Free-text
    },
    'tag': {
        'label': 'Tag',
        'values': [],  # Free-text
    },
}

# Ordered list of field keys for the combobox
FIELD_KEYS = list(METADATA_FIELDS.keys())

# Field labels for display in the combobox
FIELD_LABELS = [METADATA_FIELDS[k]['label'] for k in FIELD_KEYS]

# Mapping from label to key
_LABEL_TO_KEY = {METADATA_FIELDS[k]['label']: k for k in FIELD_KEYS}

# Mapping from key to label
_KEY_TO_LABEL = {k: METADATA_FIELDS[k]['label'] for k in FIELD_KEYS}

# Supported operators with display labels
OPERATORS = [
    ('equals', 'equals'),
    ('not_equals', 'not equals'),
    ('in', 'in'),
    ('not_in', 'not in'),
    ('contains', 'contains'),
]

OPERATOR_KEYS = [op[0] for op in OPERATORS]
OPERATOR_LABELS = [op[1] for op in OPERATORS]
_OP_LABEL_TO_KEY = {op[1]: op[0] for op in OPERATORS}
_OP_KEY_TO_LABEL = {op[0]: op[1] for op in OPERATORS}


class ValueSelectorDialog(tk.Toplevel):
    """A popup dialog for selecting values from a list of checkboxes.

    Displays all possible values for a metadata field in a clean grid layout.
    Returns the set of selected values when the user clicks OK.
    """

    def __init__(self, parent, title: str, values: List[str],
                 selected: Optional[Set[str]] = None):
        """Initialize the value selector dialog.

        Args:
            parent: Parent widget.
            title: Dialog title (typically the field label).
            values: List of all possible values to display.
            selected: Optional set of currently selected values.
        """
        super().__init__(parent)
        self.title(f"Select Values — {title}")
        self.resizable(True, True)
        self.transient(parent)
        self.grab_set()

        self._values = values
        self._selected = selected or set()
        self._result: Optional[Set[str]] = None  # None means cancelled
        self._vars: Dict[str, tk.BooleanVar] = {}

        self._setup_ui()
        self._center_on_parent(parent)

        # Handle window close (X button) as cancel
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _setup_ui(self):
        """Create the dialog UI with checkboxes in a grid and OK/Cancel buttons."""
        # Main frame with padding
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Instruction label
        ttk.Label(
            main_frame,
            text="Select one or more values:",
        ).pack(anchor=tk.W, pady=(0, 8))

        # Checkbox grid frame
        cb_frame = ttk.Frame(main_frame)
        cb_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Arrange checkboxes in a grid — use 2 columns for longer lists, 1 for short
        num_cols = 2 if len(self._values) > 4 else 1
        for i, val in enumerate(self._values):
            var = tk.BooleanVar(value=(val in self._selected))
            self._vars[val] = var
            cb = ttk.Checkbutton(cb_frame, text=val, variable=var)
            row = i // num_cols
            col = i % num_cols
            cb.grid(row=row, column=col, sticky=tk.W, padx=(0, 20), pady=2)

        # Select All / Clear All buttons
        select_frame = ttk.Frame(main_frame)
        select_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Button(
            select_frame,
            text="Select All",
            command=self._select_all,
        ).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(
            select_frame,
            text="Clear All",
            command=self._clear_all,
        ).pack(side=tk.LEFT)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 8))

        # OK / Cancel buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="OK", command=self._on_ok, width=10).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel, width=10).pack(side=tk.RIGHT)

    def _select_all(self):
        """Check all checkboxes."""
        for var in self._vars.values():
            var.set(True)

    def _clear_all(self):
        """Uncheck all checkboxes."""
        for var in self._vars.values():
            var.set(False)

    def _center_on_parent(self, parent):
        """Center the dialog on the parent window."""
        self.update_idletasks()
        # Get parent geometry
        try:
            px = parent.winfo_rootx()
            py = parent.winfo_rooty()
            pw = parent.winfo_width()
            ph = parent.winfo_height()
        except Exception:
            px, py, pw, ph = 100, 100, 800, 600

        dw = self.winfo_width()
        dh = self.winfo_height()
        x = px + (pw - dw) // 2
        y = py + (ph - dh) // 2
        self.geometry(f"+{x}+{y}")

    def _on_ok(self):
        """Handle OK button — store selected values and close."""
        self._result = {val for val, var in self._vars.items() if var.get()}
        self.destroy()

    def _on_cancel(self):
        """Handle Cancel button — close without storing."""
        self._result = None
        self.destroy()

    def get_result(self) -> Optional[Set[str]]:
        """Get the dialog result after it closes.

        Returns:
            Set of selected value strings, or None if cancelled.
        """
        return self._result

    @staticmethod
    def ask_values(parent, title: str, values: List[str],
                   selected: Optional[Set[str]] = None) -> Optional[Set[str]]:
        """Show the dialog and return selected values.

        This is a convenience static method that creates the dialog,
        waits for it to close, and returns the result.

        Args:
            parent: Parent widget.
            title: Dialog title.
            values: List of all possible values.
            selected: Optional set of currently selected values.

        Returns:
            Set of selected values, or None if cancelled.
        """
        dialog = ValueSelectorDialog(parent, title, values, selected)
        dialog.wait_window()
        return dialog.get_result()


class FilterRow:
    """Represents a single filter row in the filter builder.

    Each row contains:
    - A metadata field combobox
    - An operator combobox
    - A values entry (text entry or multi-select depending on field)
    - A remove button (✕)
    """

    def __init__(self, parent_frame, row_index, on_remove, on_change):
        """Initialize a filter row.

        Args:
            parent_frame: The parent frame to pack widgets into.
            row_index: The row index (for grid positioning).
            on_remove: Callback when remove button is clicked (receives this FilterRow).
            on_change: Callback when any value changes.
        """
        self.parent_frame = parent_frame
        self.row_index = row_index
        self._on_remove = on_remove
        self._on_change = on_change
        self._widgets = []
        self._loading_condition = False
        self._known_values = []
        self._selected_values: Set[str] = set()

        self._setup_widgets()

    def _setup_widgets(self):
        """Create the widgets for this filter row."""
        # Field combobox
        self.field_var = tk.StringVar(value='')
        self.field_combo = ttk.Combobox(
            self.parent_frame,
            textvariable=self.field_var,
            values=FIELD_LABELS,
            state='readonly',
            width=22,
        )
        self.field_combo.grid(row=self.row_index, column=0, padx=(0, 4), pady=2, sticky=tk.W)
        self.field_var.trace_add('write', self._on_field_changed)
        self._widgets.append(self.field_combo)

        # Operator combobox
        self.operator_var = tk.StringVar(value='equals')
        self.operator_combo = ttk.Combobox(
            self.parent_frame,
            textvariable=self.operator_var,
            values=OPERATOR_LABELS,
            state='readonly',
            width=10,
        )
        self.operator_combo.grid(row=self.row_index, column=1, padx=4, pady=2, sticky=tk.W)
        self.operator_var.trace_add('write', self._on_value_changed)
        self._widgets.append(self.operator_combo)

        # Values frame (contains either entry or checkbuttons)
        self.values_frame = ttk.Frame(self.parent_frame)
        self.values_frame.grid(row=self.row_index, column=2, padx=4, pady=2, sticky=tk.EW)
        self._widgets.append(self.values_frame)

        # Default: text entry for values
        self.values_entry_var = tk.StringVar(value='')
        self.values_entry = ttk.Entry(
            self.values_frame,
            textvariable=self.values_entry_var,
            width=30,
        )
        self.values_entry.pack(fill=tk.X, expand=True)
        self.values_entry_var.trace_add('write', self._on_value_changed)

        # Multi-select checkbuttons (created when a field with known values is selected)
        self._value_checkbuttons = []
        self._value_vars = {}  # value -> BooleanVar

        # Remove button
        self.remove_btn = ttk.Button(
            self.parent_frame,
            text='\u2715',  # ✕
            width=3,
            command=self._remove_clicked,
        )
        self.remove_btn.grid(row=self.row_index, column=3, padx=(4, 0), pady=2)
        self._widgets.append(self.remove_btn)

    def _on_field_changed(self, *args):
        """Handle field selection change — update values widget.

        For fields with known values, opens a popup dialog for value selection.
        For free-text fields, displays a text entry.
        """
        field_label = self.field_var.get()
        field_key = _LABEL_TO_KEY.get(field_label, '')
        field_info = METADATA_FIELDS.get(field_key, {})
        known_values = field_info.get('values', [])

        # Clear existing value widgets
        for widget in self.values_frame.winfo_children():
            widget.destroy()
        self._value_checkbuttons.clear()
        self._value_vars.clear()

        if known_values:
            # Store the known values for this field (used by popup)
            self._known_values = known_values
            self._selected_values = set()

            if not self._loading_condition:
                # Show the popup immediately for initial selection (user-driven)
                self._open_value_selector()

            # Build the inline display (selected values + Edit button)
            self._rebuild_selected_display()
        else:
            self._known_values = []
            self._selected_values = set()

            # Free-text entry
            self.values_entry_var = tk.StringVar(value='')
            self.values_entry = ttk.Entry(
                self.values_frame,
                textvariable=self.values_entry_var,
                width=30,
            )
            self.values_entry.pack(fill=tk.X, expand=True)
            self.values_entry_var.trace_add('write', self._on_value_changed)

        self._on_value_changed()

    def _open_value_selector(self):
        """Open the value selector popup dialog for the current field."""
        field_label = self.field_var.get()
        result = ValueSelectorDialog.ask_values(
            self.parent_frame.winfo_toplevel(),
            field_label,
            self._known_values,
            self._selected_values,
        )
        if result is not None:
            self._selected_values = result
            self._rebuild_selected_display()
            self._on_value_changed()

    def _rebuild_selected_display(self):
        """Rebuild the inline display showing selected values and an Edit button."""
        # Clear the values frame
        for widget in self.values_frame.winfo_children():
            widget.destroy()

        # Edit button to re-open the popup
        edit_btn = ttk.Button(
            self.values_frame,
            text="Edit\u2026",
            width=6,
            command=self._open_value_selector,
        )
        edit_btn.pack(side=tk.LEFT, padx=(0, 6))

        if self._selected_values:
            # Show selected values as read-only labels
            # Maintain the order from the known_values list
            ordered = [v for v in self._known_values if v in self._selected_values]
            summary = ", ".join(ordered)
            lbl = ttk.Label(self.values_frame, text=summary, foreground="#006600")
            lbl.pack(side=tk.LEFT, padx=(0, 4))
        else:
            lbl = ttk.Label(self.values_frame, text="(none selected)", foreground="#999999")
            lbl.pack(side=tk.LEFT, padx=(0, 4))

    def _on_value_changed(self, *args):
        """Handle value change in any widget."""
        if self._on_change:
            self._on_change()

    def _remove_clicked(self):
        """Handle remove button click."""
        if self._on_remove:
            self._on_remove(self)

    def get_field_key(self) -> str:
        """Get the selected metadata field key.

        Returns:
            The field key string (e.g., 'signature_deployment'), or empty string.
        """
        label = self.field_var.get()
        return _LABEL_TO_KEY.get(label, '')

    def get_operator(self) -> str:
        """Get the selected operator key.

        Returns:
            The operator key string (e.g., 'equals'), or 'equals' as default.
        """
        label = self.operator_var.get()
        return _OP_LABEL_TO_KEY.get(label, 'equals')

    def get_values(self) -> List[str]:
        """Get the selected/entered values.

        Returns:
            List of value strings.
        """
        if hasattr(self, '_known_values') and self._known_values:
            # Popup multi-select mode: return selected values in field-order
            return [v for v in self._known_values if v in self._selected_values]
        else:
            # Free-text mode: split comma-separated values
            text = self.values_entry_var.get().strip()
            if not text:
                return []
            return [v.strip() for v in text.split(',') if v.strip()]

    def get_condition(self) -> Optional[FilterCondition]:
        """Build a FilterCondition from this row's current state.

        Returns:
            FilterCondition if the row has valid data, or None if incomplete.
        """
        field_key = self.get_field_key()
        operator = self.get_operator()
        values = self.get_values()

        if not field_key or not values:
            return None

        return FilterCondition(
            field=field_key,
            operator=operator,
            values=values,
        )

    def set_condition(self, condition: FilterCondition):
        """Set this row's widgets from a FilterCondition.

        Args:
            condition: The condition to populate from.
        """
        # Flag to suppress the popup when loading a saved condition
        self._loading_condition = True

        # Set field
        label = _KEY_TO_LABEL.get(condition.field, '')
        if label:
            self.field_var.set(label)
        else:
            # Unknown field — set it as-is
            self.field_var.set(condition.field)

        # Set operator
        op_label = _OP_KEY_TO_LABEL.get(condition.operator, 'equals')
        self.operator_var.set(op_label)

        # Set values — need to wait for field_changed to create widgets
        self.parent_frame.update_idletasks()

        if hasattr(self, '_known_values') and self._known_values:
            # Popup multi-select mode: set selected values directly
            self._selected_values = set(condition.values)
            self._rebuild_selected_display()
        else:
            # Free-text mode
            self.values_entry_var.set(', '.join(condition.values))

        self._loading_condition = False

    def destroy(self):
        """Remove all widgets for this row."""
        for widget in self._widgets:
            widget.destroy()
        self._widgets.clear()
        self._value_checkbuttons.clear()
        self._value_vars.clear()

    def update_row_index(self, new_index):
        """Update the grid row position of all widgets.

        Args:
            new_index: The new row index in the grid.
        """
        self.row_index = new_index
        self.field_combo.grid(row=new_index, column=0)
        self.operator_combo.grid(row=new_index, column=1)
        self.values_frame.grid(row=new_index, column=2)
        self.remove_btn.grid(row=new_index, column=3)


class FilterBuilder(ttk.LabelFrame):
    """Dynamic row-based filter builder widget.

    Allows users to build filter criteria as rows, where each row
    targets a metadata field with an operator and value(s).

    Rows are AND-combined. Multiple values within a row are OR-combined.
    """

    def __init__(self, parent, on_change: Optional[Callable] = None, **kwargs):
        """Initialize the filter builder.

        Args:
            parent: Parent tkinter widget.
            on_change: Optional callback invoked when any filter value changes.
            **kwargs: Additional keyword arguments for LabelFrame.
        """
        super().__init__(parent, text="Filter Rows", **kwargs)

        self._rows = []  # List of FilterRow
        self._on_change = on_change

        self._setup_ui()

    def _setup_ui(self):
        """Create the filter builder UI."""
        # Header labels
        header_frame = ttk.Frame(self)
        header_frame.pack(fill=tk.X, padx=2, pady=(2, 0))

        ttk.Label(header_frame, text="Field", width=24).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(header_frame, text="Operator", width=12).pack(side=tk.LEFT, padx=4)
        ttk.Label(header_frame, text="Values").pack(side=tk.LEFT, padx=4)

        # Rows container (uses grid layout)
        self._rows_frame = ttk.Frame(self)
        self._rows_frame.pack(fill=tk.X, padx=2, pady=2)
        self._rows_frame.columnconfigure(2, weight=1)  # Values column stretches

        # Add Row button
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=2, pady=(0, 4))

        self._add_btn = ttk.Button(
            btn_frame,
            text="+ Add Row",
            command=self.add_row,
        )
        self._add_btn.pack(side=tk.LEFT)

    def add_row(self, condition: Optional[FilterCondition] = None) -> FilterRow:
        """Add a new filter row.

        Args:
            condition: Optional FilterCondition to pre-populate the row.

        Returns:
            The newly created FilterRow.
        """
        row_index = len(self._rows)
        row = FilterRow(
            self._rows_frame,
            row_index,
            on_remove=self._remove_row,
            on_change=self._on_row_changed,
        )
        self._rows.append(row)

        if condition:
            row.set_condition(condition)

        return row

    def _remove_row(self, row: FilterRow):
        """Remove a filter row.

        Args:
            row: The FilterRow to remove.
        """
        if row in self._rows:
            self._rows.remove(row)
            row.destroy()
            # Re-index remaining rows
            for i, r in enumerate(self._rows):
                r.update_row_index(i)

            if self._on_change:
                self._on_change()

    def _on_row_changed(self):
        """Handle changes in any filter row."""
        if self._on_change:
            self._on_change()

    def get_conditions(self) -> List[FilterCondition]:
        """Get all valid filter conditions from the current rows.

        Returns:
            List of FilterCondition objects (only rows with valid data).
        """
        conditions = []
        for row in self._rows:
            condition = row.get_condition()
            if condition is not None:
                conditions.append(condition)
        return conditions

    def get_filter_config(self, missing_metadata_behavior: str = 'exclude') -> FilterConfig:
        """Build a complete FilterConfig from the current rows.

        Args:
            missing_metadata_behavior: 'exclude' or 'include'.

        Returns:
            FilterConfig with all valid conditions.
        """
        return FilterConfig(
            conditions=self.get_conditions(),
            missing_metadata_behavior=missing_metadata_behavior,
        )

    def set_conditions(self, conditions: List[FilterCondition]):
        """Set the filter rows from a list of conditions.

        Clears all existing rows and creates new ones.

        Args:
            conditions: List of FilterCondition objects.
        """
        self.clear()
        for condition in conditions:
            self.add_row(condition)

    def set_from_filter_config(self, filter_config: FilterConfig):
        """Set the filter rows from a FilterConfig object.

        Args:
            filter_config: FilterConfig to populate from.
        """
        self.set_conditions(filter_config.conditions)

    def clear(self):
        """Remove all filter rows."""
        for row in self._rows[:]:
            row.destroy()
        self._rows.clear()

    def get_row_count(self) -> int:
        """Get the number of filter rows.

        Returns:
            Number of rows currently in the builder.
        """
        return len(self._rows)

    def get_rows(self) -> List[FilterRow]:
        """Get all filter rows.

        Returns:
            List of FilterRow objects.
        """
        return list(self._rows)