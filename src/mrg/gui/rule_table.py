"""
Rule Table for Managed Rule Group Generator

Read-only ttk.Treeview displaying filtered/deduplicated rules with
Suricata Generator column layout (Line, Action, Protocol, Rule Data)
and color tags for action types.

Color tags match Suricata Generator's ui_manager.py:
- action_pass:   #2E7D32 (green)
- action_alert:  #1976D2 (blue)
- action_drop:   #D32F2F (red)
- action_reject: #7B1FA2 (purple)
- comment:       #808080 (grey)
- search_highlight: #FFFF00 (yellow background)

Cross-platform notes (Section 14.3):
- Platform-safe font fallbacks (Consolas/Monaco/DejaVu Sans Mono)
- Mouse wheel scrolling for Windows/macOS/Linux
- expand=False for fixed-size option not used here (table expands)
"""

import platform
import re
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

# Try to import ParsedRule for type hints
try:
    from src.mrg.core.rule_parser import ParsedRule
except ImportError:
    ParsedRule = None


def _get_monospace_font():
    """Get platform-appropriate monospace font.

    Returns:
        Tuple of (family, size) for the monospace font.
    """
    system = platform.system()
    if system == 'Darwin':
        return ('Menlo', 10)
    elif system == 'Windows':
        return ('Consolas', 10)
    else:
        return ('DejaVu Sans Mono', 10)


class RuleTable(ttk.Frame):
    """Read-only treeview displaying Suricata rules.

    Columns: Line, Action, Protocol, Rule Data
    Color-coded by action type (pass=green, alert=blue, drop=red, reject=purple).

    This is a display-only table — no inline editing, drag-and-drop,
    or rule manipulation. Rules are populated via load_rules().
    """

    # Column definitions
    COLUMNS = ('Line', 'Action', 'Protocol', 'Rule Data')

    # Action color tags matching Suricata Generator
    ACTION_COLORS = {
        'pass': '#2E7D32',
        'alert': '#1976D2',
        'drop': '#D32F2F',
        'reject': '#7B1FA2',
    }

    def __init__(self, parent, **kwargs):
        """Initialize the rule table.

        Args:
            parent: Parent tkinter widget.
            **kwargs: Additional keyword arguments for Frame.
        """
        super().__init__(parent, **kwargs)
        self._rules = []  # List of ParsedRule objects
        self._displayed_items = []  # Item IDs currently displayed
        self._view_filter_func = None  # Optional view filter function
        self._search_matches = set()  # Set of item IDs matching search
        self._active_filter_conditions = []  # Active filter conditions for viewer highlight

        self._setup_ui()

    def _setup_ui(self):
        """Create the treeview with scrollbars."""
        # Labeled frame
        self._label_frame = ttk.LabelFrame(self, text='Generated Rule Group')
        self._label_frame.pack(fill=tk.BOTH, expand=True)

        # Container for tree + scrollbars
        container = ttk.Frame(self._label_frame)
        container.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Treeview
        self._tree = ttk.Treeview(
            container,
            columns=self.COLUMNS,
            show='headings',
            selectmode='extended',
        )

        # Configure headings
        self._tree.heading('Line', text='Line')
        self._tree.heading('Action', text='Action')
        self._tree.heading('Protocol', text='Protocol')
        self._tree.heading('Rule Data', text='Rule Data')

        # Configure column widths
        # All columns use stretch=False so horizontal scrollbar works
        # with long Suricata rule strings
        self._tree.column('Line', width=50, stretch=False, minwidth=40)
        self._tree.column('Action', width=70, stretch=False, minwidth=60)
        self._tree.column('Protocol', width=80, stretch=False, minwidth=60)
        self._tree.column('Rule Data', width=1200, stretch=False, minwidth=200)

        # Scrollbars
        v_scroll = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self._tree.yview)
        h_scroll = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        # Grid layout
        self._tree.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # Configure color tags
        for action, color in self.ACTION_COLORS.items():
            self._tree.tag_configure('action_{}'.format(action), foreground=color)
        self._tree.tag_configure('comment', foreground='#808080')
        self._tree.tag_configure('search_highlight', background='#FFFF00')

        # Bind mouse wheel scrolling (cross-platform)
        self._tree.bind('<MouseWheel>', self._on_mousewheel)
        self._tree.bind('<Button-4>', self._on_mousewheel)  # Linux scroll up
        self._tree.bind('<Button-5>', self._on_mousewheel)  # Linux scroll down

        # Right-click context menu
        self._context_menu = tk.Menu(self._tree, tearoff=0)
        self._context_menu.add_command(label="Copy Rule", command=self._copy_selected_rules)
        self._context_menu.add_command(label="Copy All Rules", command=self._copy_all_rules)

        # Double-click to view full rule
        self._tree.bind('<Double-1>', self._on_double_click)

        if platform.system() == 'Darwin':
            self._tree.bind('<Button-2>', self._on_right_click)
            self._tree.bind('<Control-Button-1>', self._on_right_click)
        else:
            self._tree.bind('<Button-3>', self._on_right_click)

    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling (cross-platform)."""
        try:
            if event.delta:
                # Windows / macOS
                if platform.system() == 'Darwin':
                    delta = -1 * event.delta
                else:
                    delta = -1 * (event.delta // 120)
            elif event.num == 4:
                delta = -3
            elif event.num == 5:
                delta = 3
            else:
                delta = 0

            self._tree.yview_scroll(int(delta), 'units')
        except (AttributeError, tk.TclError):
            pass

    # ─── Public API ───────────────────────────────────────────

    @property
    def tree(self) -> ttk.Treeview:
        """Get the underlying Treeview widget."""
        return self._tree

    def load_rules(self, rules: list):
        """Load rules into the table, replacing any existing content.

        Args:
            rules: List of ParsedRule objects to display.
        """
        self._rules = list(rules)
        self._refresh_display()

    def get_rules(self) -> list:
        """Get the currently loaded rules.

        Returns:
            List of ParsedRule objects.
        """
        return list(self._rules)

    def get_rule_count(self) -> int:
        """Get the total number of loaded rules."""
        return len(self._rules)

    def get_displayed_count(self) -> int:
        """Get the number of currently displayed (visible) rules."""
        return len(self._tree.get_children())

    def clear(self):
        """Clear all rules from the table."""
        self._rules = []
        self._tree.delete(*self._tree.get_children())
        self._displayed_items = []
        self._search_matches = set()

    def set_view_filter(self, filter_func):
        """Set a view filter function.

        The filter function receives a ParsedRule and returns True to show,
        False to hide. Pass None to clear the filter.

        Args:
            filter_func: Callable[[ParsedRule], bool] or None.
        """
        self._view_filter_func = filter_func
        self._refresh_display()

    def clear_view_filter(self):
        """Remove the view filter and show all rules."""
        self._view_filter_func = None
        self._refresh_display()

    def get_action_counts(self) -> Dict[str, int]:
        """Count rules by action type.

        Returns:
            Dict mapping action name to count (e.g., {'drop': 98, 'alert': 42}).
        """
        counts = {'pass': 0, 'alert': 0, 'drop': 0, 'reject': 0}
        for rule in self._rules:
            action = rule.action.lower()
            if action in counts:
                counts[action] += 1
        return counts

    def get_sid_range(self):
        """Get the min and max SID of loaded rules.

        Returns:
            Tuple (min_sid, max_sid) or (None, None) if no rules.
        """
        sids = [rule.sid for rule in self._rules if rule.sid is not None]
        if not sids:
            return (None, None)
        return (min(sids), max(sids))

    def get_protocol_set(self) -> set:
        """Get the set of unique protocols in loaded rules.

        Returns:
            Set of protocol strings (lowercase).
        """
        return {rule.protocol.lower() for rule in self._rules if rule.protocol}

    def get_network_variables(self) -> set:
        """Get the set of network variables used in loaded rules.

        Returns:
            Set of variable strings (e.g., '$HOME_NET', '$EXTERNAL_NET').
        """
        variables = set()
        var_pattern = re.compile(r'\$[A-Za-z_][A-Za-z0-9_]*')
        for rule in self._rules:
            for field in (rule.source, rule.destination):
                if field:
                    variables.update(var_pattern.findall(field))
        return variables

    # ─── Search Support ───────────────────────────────────────

    def highlight_search_matches(self, match_items: set):
        """Highlight items matching a search.

        Args:
            match_items: Set of treeview item IDs to highlight.
        """
        # Clear previous highlights
        self.clear_search_highlights()

        self._search_matches = set(match_items)
        for item_id in match_items:
            try:
                current_tags = list(self._tree.item(item_id, 'tags'))
                if 'search_highlight' not in current_tags:
                    current_tags.append('search_highlight')
                    self._tree.item(item_id, tags=tuple(current_tags))
            except tk.TclError:
                pass

    def clear_search_highlights(self):
        """Clear all search highlights."""
        for item_id in self._search_matches:
            try:
                current_tags = list(self._tree.item(item_id, 'tags'))
                if 'search_highlight' in current_tags:
                    current_tags.remove('search_highlight')
                    self._tree.item(item_id, tags=tuple(current_tags))
            except tk.TclError:
                pass
        self._search_matches = set()

    def find_matching_items(self, search_text: str, case_sensitive: bool = False) -> list:
        """Find tree items matching a search string.

        Searches across all visible columns (Action, Protocol, Rule Data).

        Args:
            search_text: Text to search for.
            case_sensitive: Whether the search is case-sensitive.

        Returns:
            List of matching item IDs in display order.
        """
        if not search_text:
            return []

        if not case_sensitive:
            search_text = search_text.lower()

        matches = []
        for item_id in self._tree.get_children():
            values = self._tree.item(item_id, 'values')
            # Search in Action, Protocol, Rule Data columns
            for val in values[1:]:  # Skip Line column
                text = str(val)
                if not case_sensitive:
                    text = text.lower()
                if search_text in text:
                    matches.append(item_id)
                    break

        return matches

    def select_and_see(self, item_id: str):
        """Select an item and scroll it into view.

        Args:
            item_id: Treeview item ID to select.
        """
        try:
            self._tree.selection_set(item_id)
            self._tree.focus(item_id)
            self._tree.see(item_id)
        except tk.TclError:
            pass

    # ─── Context Menu ─────────────────────────────────────────

    def _on_right_click(self, event):
        """Handle right-click to show context menu."""
        # Select the item under the cursor
        item = self._tree.identify_row(event.y)
        if item:
            if item not in self._tree.selection():
                self._tree.selection_set(item)
            self._tree.focus(item)
        try:
            self._context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._context_menu.grab_release()

    def _copy_selected_rules(self):
        """Copy the full raw text of selected rules to the clipboard."""
        selected = self._tree.selection()
        if not selected:
            return

        # Map displayed item IDs to rule indices
        all_items = self._tree.get_children()
        lines = []
        for item_id in selected:
            try:
                values = self._tree.item(item_id, 'values')
                line_num = int(values[0]) - 1  # Line column is 1-based
                if 0 <= line_num < len(self._rules):
                    raw = self._rules[line_num].raw
                    if raw:
                        lines.append(raw.rstrip())
            except (IndexError, ValueError, tk.TclError):
                pass

        if lines:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(lines))

    def _copy_all_rules(self):
        """Copy the full raw text of all loaded rules to the clipboard."""
        lines = []
        for rule in self._rules:
            if rule.raw and not rule.is_comment and not rule.is_blank:
                lines.append(rule.raw.rstrip())
        if lines:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(lines))

    # ─── Double-Click Rule Viewer ─────────────────────────────

    def set_active_filters(self, filter_conditions: list):
        """Store the active filter conditions for display in the rule viewer.

        When a user double-clicks a rule, matched filter fields are highlighted
        in the Rule Summary panel so the user can see why the rule was included.

        Args:
            filter_conditions: List of condition dicts from the filter config,
                             each with 'field', 'operator', and 'values' keys.
        """
        self._active_filter_conditions = list(filter_conditions) if filter_conditions else []

    def _on_double_click(self, event):
        """Handle double-click on a rule to show full rule viewer popup."""
        item = self._tree.identify_row(event.y)
        if not item:
            return

        try:
            values = self._tree.item(item, 'values')
            line_num = int(values[0]) - 1  # Line column is 1-based
            if 0 <= line_num < len(self._rules):
                rule = self._rules[line_num]
                _show_rule_viewer(self.winfo_toplevel(), rule, line_num + 1,
                                  self._active_filter_conditions)
        except (IndexError, ValueError, tk.TclError):
            pass

    # ─── Internal ─────────────────────────────────────────────

    def _refresh_display(self):
        """Rebuild the treeview from the rules list with optional filtering."""
        self._tree.delete(*self._tree.get_children())
        self._displayed_items = []
        self._search_matches = set()

        for i, rule in enumerate(self._rules, 1):
            # Apply view filter if set
            if self._view_filter_func and not self._view_filter_func(rule):
                continue

            action = rule.action
            protocol = rule.protocol
            rule_data = self._format_rule_data(rule)

            # Determine tag for color coding
            tag = self._get_action_tag(action)

            item_id = self._tree.insert(
                '', 'end',
                values=(i, action, protocol, rule_data),
                tags=(tag,),
            )
            self._displayed_items.append(item_id)

    def _format_rule_data(self, rule) -> str:
        """Format the Rule Data column content from a ParsedRule.

        Shows the complete rule content after the action and protocol:
        source ports direction destination ports (full options string)

        This displays the exact rule text so the user can see the complete
        rule as it will appear when deployed or exported.

        Args:
            rule: ParsedRule object.

        Returns:
            Formatted rule data string.
        """
        # Use the raw rule text, stripped of the leading action and protocol
        # to avoid duplication with the Action and Protocol columns
        raw = rule.raw.strip() if rule.raw else ''
        if raw and rule.action and rule.protocol:
            # Remove "action protocol " prefix from the raw string
            # to get everything after (source, ports, direction, dest, options)
            prefix = '{} {} '.format(rule.action, rule.protocol)
            if raw.lower().startswith(prefix.lower()):
                return raw[len(prefix):]

        # Fallback: reconstruct from parsed fields
        parts = []
        src = rule.source or ''
        src_port = rule.source_port or ''
        direction = rule.direction or '->'
        dst = rule.destination or ''
        dst_port = rule.destination_port or ''
        parts.append('{} {} {} {} {}'.format(src, src_port, direction, dst, dst_port))

        if rule.options_raw:
            parts.append('({})'.format(rule.options_raw))
        else:
            # Build minimal options from parsed fields
            options_parts = []
            if rule.msg:
                options_parts.append('msg:"{}";'.format(rule.msg))
            if rule.sid is not None:
                options_parts.append('sid:{};'.format(rule.sid))
            if rule.rev is not None:
                options_parts.append('rev:{};'.format(rule.rev))
            if options_parts:
                parts.append('({})'.format(' '.join(options_parts)))

        return ' '.join(parts)

    def _get_action_tag(self, action: str) -> str:
        """Get the treeview tag for a rule action.

        Args:
            action: Rule action string.

        Returns:
            Tag name string.
        """
        action_lower = action.lower() if action else ''
        if action_lower in self.ACTION_COLORS:
            return 'action_{}'.format(action_lower)
        return ''


# Color for filter-matched metadata values in the rule viewer
_FILTER_MATCH_COLOR = '#1565C0'  # Bold blue for matched filter fields

# Metadata field aliases: maps display field names to alternative keys
# that may appear in actual rule metadata. Mirrors _FIELD_ALIASES in rule_filter.py.
_FIELD_ALIASES = {
    'signature_deployment': ['deployment'],
    'deployment': ['signature_deployment'],
    'signature_severity': ['severity'],
    'severity': ['signature_severity'],
}


def _resolve_meta_value(meta_dict: dict, primary_key: str) -> Optional[str]:
    """Resolve a metadata value by checking the primary key and aliases.

    Args:
        meta_dict: The rule's metadata dictionary (keys are lowercase).
        primary_key: The primary metadata key to look up.

    Returns:
        The value string if found, or None.
    """
    if primary_key in meta_dict:
        return meta_dict[primary_key]

    # Check aliases
    aliases = _FIELD_ALIASES.get(primary_key, [])
    for alias in aliases:
        if alias in meta_dict:
            return meta_dict[alias]

    return None


def _build_matched_fields(rule, filter_conditions: list) -> set:
    """Determine which metadata fields in a rule matched the active filters.

    Compares the rule's metadata against each filter condition to build
    a set of metadata keys whose values satisfied the filter criteria.

    Args:
        rule: ParsedRule object with a metadata dict.
        filter_conditions: List of filter condition dicts with
                         'field', 'operator', and 'values' keys.

    Returns:
        Set of metadata key strings that matched a filter condition.
    """
    matched = set()
    if not filter_conditions:
        return matched

    meta_dict = {}
    if hasattr(rule, 'metadata') and rule.metadata:
        meta_dict = rule.metadata if isinstance(rule.metadata, dict) else {}

    if not meta_dict:
        return matched

    for cond in filter_conditions:
        field = cond.get('field', '')
        operator = cond.get('operator', '')
        values = cond.get('values', [])

        rule_val = _resolve_meta_value(meta_dict, field)
        if not rule_val:
            continue

        rule_val_lower = str(rule_val).lower()
        values_lower = [str(v).lower() for v in values]

        is_match = False
        if operator in ('equals', 'in'):
            is_match = rule_val_lower in values_lower
        elif operator == 'not_equals':
            is_match = rule_val_lower not in values_lower
        elif operator == 'not_in':
            is_match = rule_val_lower not in values_lower
        elif operator == 'contains':
            is_match = any(v in rule_val_lower for v in values_lower)

        if is_match:
            matched.add(field)

    return matched


def _show_rule_viewer(parent, rule, line_number: int,
                      filter_conditions: Optional[list] = None):
    """Show a popup dialog displaying the full rule text.

    The dialog shows the complete raw Suricata rule in a read-only text
    widget with word wrap, along with parsed metadata (SID, action, protocol,
    message). Metadata fields that matched the active filter criteria are
    highlighted in blue. Includes a Copy to Clipboard button.

    Args:
        parent: Parent tkinter window.
        rule: ParsedRule object to display.
        line_number: 1-based line number for the title bar.
        filter_conditions: Optional list of active filter condition dicts.
    """
    mono_font = _get_monospace_font()

    # Determine which metadata fields matched the filter
    matched_fields = _build_matched_fields(rule, filter_conditions or [])

    dialog = tk.Toplevel(parent)

    # Build a descriptive title
    sid_text = 'SID {}'.format(rule.sid) if rule.sid else 'Rule'
    msg_text = rule.msg if rule.msg else ''
    if msg_text and len(msg_text) > 60:
        msg_text = msg_text[:57] + '...'
    title = 'Rule Viewer \u2014 Line {} \u2014 {} {}'.format(
        line_number, sid_text,
        '\u2014 {}'.format(msg_text) if msg_text else ''
    )
    dialog.title(title)
    dialog.geometry('800x450')
    dialog.minsize(500, 280)
    dialog.resizable(True, True)

    if platform.system() != 'Darwin':
        dialog.transient(parent)
    dialog.grab_set()

    main_frame = ttk.Frame(dialog, padding=12)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # ── Metadata summary ──
    meta_frame = ttk.LabelFrame(main_frame, text='Rule Summary')
    meta_frame.pack(fill=tk.X, pady=(0, 8))

    meta_font_normal = ('TkDefaultFont', 9)
    meta_font_bold = ('TkDefaultFont', 9, 'bold')
    meta_grid = ttk.Frame(meta_frame)
    meta_grid.pack(fill=tk.X, padx=8, pady=4)

    # Build the list of fields to display, tracking their metadata keys
    # Each entry: (label_text, value_text, metadata_key_or_None)
    row = 0

    # Get metadata dict for lookups
    meta_dict = {}
    if hasattr(rule, 'metadata') and rule.metadata:
        meta_dict = rule.metadata if isinstance(rule.metadata, dict) else {}

    fields = [
        ('SID:', str(rule.sid) if rule.sid else 'N/A', None),
        ('Rev:', str(rule.rev) if rule.rev else 'N/A', None),
        ('Protocol:', rule.protocol or 'N/A', None),
        ('Message:', rule.msg or 'N/A', None),
        # Always-visible metadata fields
        ('Severity:', _resolve_meta_value(meta_dict, 'signature_severity') or 'N/A', 'signature_severity'),
        ('Deployment:', _resolve_meta_value(meta_dict, 'signature_deployment') or 'N/A', 'signature_deployment'),
        ('Confidence:', _resolve_meta_value(meta_dict, 'confidence') or 'N/A', 'confidence'),
        ('Performance Impact:', _resolve_meta_value(meta_dict, 'performance_impact') or 'N/A', 'performance_impact'),
        ('TLS State:', _resolve_meta_value(meta_dict, 'tls_state') or 'N/A', 'tls_state'),
        ('Attack Target:', _resolve_meta_value(meta_dict, 'attack_target') or 'N/A', 'attack_target'),
    ]

    # Show additional metadata fields if they have values
    additional_keys = [
        'malware_family', 'mitre_tactic_id', 'mitre_technique_id', 'tag',
    ]
    for key in additional_keys:
        val = _resolve_meta_value(meta_dict, key)
        if val:
            display_key = key.replace('_', ' ').title() + ':'
            fields.append((display_key, str(val), key))

    # Layout as 2-column grid for compactness
    col = 0
    for entry in fields:
        label_text, value_text, meta_key = entry
        is_matched = meta_key is not None and meta_key in matched_fields

        # Label (always bold)
        label_widget = tk.Label(
            meta_grid, text=label_text,
            font=meta_font_bold,
            fg=_FILTER_MATCH_COLOR if is_matched else 'black',
        )
        label_widget.grid(row=row, column=col, sticky=tk.W, padx=(0, 4), pady=1)

        # Value — highlighted if matched
        if is_matched:
            value_widget = tk.Label(
                meta_grid, text='\u2714 {}'.format(value_text),  # ✔ prefix
                font=('TkDefaultFont', 9, 'bold'),
                fg=_FILTER_MATCH_COLOR,
            )
        else:
            value_widget = tk.Label(
                meta_grid, text=value_text,
                font=meta_font_normal,
            )
        value_widget.grid(row=row, column=col + 1, sticky=tk.W, padx=(0, 16), pady=1)

        col += 2
        if col >= 4:  # 2 pairs per row
            col = 0
            row += 1
    if col != 0:
        row += 1

    # Filter match legend (only show if there are matched fields)
    if matched_fields:
        legend = tk.Label(
            meta_frame,
            text='\u2714 = matched active filter',
            font=('TkDefaultFont', 8, 'italic'),
            fg=_FILTER_MATCH_COLOR,
        )
        legend.pack(anchor=tk.W, padx=8, pady=(0, 4))

    # ── Full rule text ──
    text_frame = ttk.LabelFrame(main_frame, text='Complete Rule')
    text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

    rule_text = tk.Text(
        text_frame,
        wrap=tk.WORD,
        font=mono_font,
        state=tk.DISABLED,
        padx=8,
        pady=8,
    )
    text_scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=rule_text.yview)
    rule_text.configure(yscrollcommand=text_scroll.set)
    rule_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0), pady=4)
    text_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 4), pady=4)

    # Insert the full raw rule text
    raw_text = rule.raw.rstrip() if rule.raw else '(no rule text available)'
    rule_text.config(state=tk.NORMAL)
    rule_text.insert('1.0', raw_text)
    rule_text.config(state=tk.DISABLED)

    # ── Buttons ──
    btn_frame = ttk.Frame(main_frame)
    btn_frame.pack(fill=tk.X)

    copy_status = ttk.Label(btn_frame, text='', foreground='#2E7D32', font=meta_font_normal)
    copy_status.pack(side=tk.LEFT, padx=(0, 8))

    def _copy_to_clipboard():
        try:
            dialog.clipboard_clear()
            dialog.clipboard_append(raw_text)
            copy_status.config(text='Copied to clipboard!')
            dialog.after(2000, lambda: copy_status.config(text=''))
        except tk.TclError:
            copy_status.config(text='Copy failed')

    ttk.Button(btn_frame, text='Copy to Clipboard', command=_copy_to_clipboard).pack(
        side=tk.LEFT, padx=(0, 8))

    ttk.Button(btn_frame, text='Close', command=lambda: _close_viewer(dialog)).pack(
        side=tk.RIGHT)

    # Escape to close
    dialog.bind('<Escape>', lambda e: _close_viewer(dialog))

    # Focus the dialog
    dialog.focus_set()


def _close_viewer(dialog):
    """Close the rule viewer dialog safely."""
    if dialog.winfo_exists():
        dialog.grab_release()
        dialog.destroy()
