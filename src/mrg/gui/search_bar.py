"""
Search Bar for Managed Rule Group Generator

Ctrl+F find bar with text entry, Find Next (F3), Close (Escape),
highlights matching rows in the rule table treeview.

Mirrors Suricata Generator's search_manager.py pattern.

Cross-platform notes (Section 14.3):
- Binds both Ctrl and Command for Ctrl+F on macOS
- Uses trace_add() not trace()
"""

import platform
import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional


class SearchBar(ttk.Frame):
    """Find bar for searching the rule table.

    Features:
    - Text entry field with search-as-you-type
    - Find Next button (F3)
    - Close button (Escape)
    - Match count display
    - Highlights matching rows in the treeview
    """

    def __init__(self, parent, rule_table=None, **kwargs):
        """Initialize the search bar.

        Args:
            parent: Parent tkinter widget.
            rule_table: RuleTable instance to search within.
            **kwargs: Additional keyword arguments for Frame.
        """
        super().__init__(parent, **kwargs)

        self._rule_table = rule_table
        self._matches = []  # List of matching item IDs
        self._current_match_index = -1
        self._is_visible = False

        self._setup_ui()
        # Start hidden
        self.pack_forget()

    def _setup_ui(self):
        """Create the search bar layout."""
        # Inner frame with border
        inner = ttk.Frame(self)
        inner.pack(fill=tk.X, padx=4, pady=2)

        # Find label
        ttk.Label(inner, text='Find:', font=('TkDefaultFont', 9)).pack(
            side=tk.LEFT, padx=(4, 4),
        )

        # Search entry
        self._search_var = tk.StringVar(value='')
        self._search_entry = ttk.Entry(
            inner, textvariable=self._search_var, width=30,
        )
        self._search_entry.pack(side=tk.LEFT, padx=(0, 4))

        # Bind search-as-you-type
        self._search_var.trace_add('write', self._on_search_text_changed)

        # Bind Enter in search entry to Find Next
        self._search_entry.bind('<Return>', lambda e: self.find_next())

        # Find Next button
        self._find_next_btn = ttk.Button(
            inner, text='Next', width=6, command=self.find_next,
        )
        self._find_next_btn.pack(side=tk.LEFT, padx=(0, 4))

        # Find Previous button
        self._find_prev_btn = ttk.Button(
            inner, text='Prev', width=6, command=self.find_previous,
        )
        self._find_prev_btn.pack(side=tk.LEFT, padx=(0, 4))

        # Match count label
        self._match_label = ttk.Label(
            inner, text='', font=('TkDefaultFont', 9),
        )
        self._match_label.pack(side=tk.LEFT, padx=(0, 8))

        # Close button
        self._close_btn = ttk.Button(
            inner, text='\u2715', width=3, command=self.close,
        )
        self._close_btn.pack(side=tk.RIGHT, padx=(0, 4))

        # Shortcut hint
        ttk.Label(inner, text='F3: Next | Esc: Close',
                  font=('TkDefaultFont', 8), foreground='#999999').pack(
            side=tk.RIGHT, padx=(0, 8),
        )

    # ─── Public API ───────────────────────────────────────────

    def set_rule_table(self, rule_table):
        """Set or change the rule table to search within.

        Args:
            rule_table: RuleTable instance.
        """
        self._rule_table = rule_table

    def show(self):
        """Show the search bar and focus the entry."""
        if not self._is_visible:
            sibling = self._get_sibling_widget()
            if sibling is not None:
                self.pack(fill=tk.X, before=sibling)
            else:
                self.pack(fill=tk.X)
            self._is_visible = True

        # Focus and select all text
        self._search_entry.focus_set()
        self._search_entry.select_range(0, tk.END)

    def close(self):
        """Close the search bar and clear highlights."""
        self._is_visible = False
        self.pack_forget()
        self._clear_state()
        if self._rule_table:
            self._rule_table.clear_search_highlights()

    def is_visible(self) -> bool:
        """Check if the search bar is visible."""
        return self._is_visible

    def find_next(self):
        """Navigate to the next match."""
        if not self._matches:
            self._perform_search()
            if not self._matches:
                return

        if self._matches:
            self._current_match_index = (self._current_match_index + 1) % len(self._matches)
            self._navigate_to_current()

    def find_previous(self):
        """Navigate to the previous match."""
        if not self._matches:
            self._perform_search()
            if not self._matches:
                return

        if self._matches:
            self._current_match_index = (self._current_match_index - 1) % len(self._matches)
            self._navigate_to_current()

    def get_search_text(self) -> str:
        """Get the current search text."""
        return self._search_var.get()

    def get_match_count(self) -> int:
        """Get the number of matches found."""
        return len(self._matches)

    def get_current_match_index(self) -> int:
        """Get the index of the current match (0-based), or -1 if none."""
        return self._current_match_index

    # ─── Keyboard Binding Setup ───────────────────────────────

    def bind_shortcuts(self, root):
        """Bind keyboard shortcuts to the root window.

        Args:
            root: Tk root window to bind shortcuts on.
        """
        # Ctrl+F (and Cmd+F on macOS) — open search
        modifier = 'Command' if platform.system() == 'Darwin' else 'Control'
        root.bind('<{}-f>'.format(modifier), lambda e: self.show())
        root.bind('<{}-F>'.format(modifier), lambda e: self.show())

        # Also bind Control-f on macOS for users who expect it
        if platform.system() == 'Darwin':
            root.bind('<Control-f>', lambda e: self.show())

        # F3 — find next
        root.bind('<F3>', lambda e: self.find_next())

        # Escape — close search (only when search is visible)
        root.bind('<Escape>', lambda e: self._on_escape())

    # ─── Internal ─────────────────────────────────────────────

    def _on_search_text_changed(self, *args):
        """Handle search text changes (search-as-you-type)."""
        self._perform_search()

    def _perform_search(self):
        """Run the search and update highlights."""
        if not self._rule_table:
            return

        search_text = self._search_var.get()

        if not search_text:
            self._clear_state()
            self._rule_table.clear_search_highlights()
            self._update_match_label()
            return

        # Find matching items
        self._matches = self._rule_table.find_matching_items(search_text)
        self._current_match_index = 0 if self._matches else -1

        # Update highlights
        self._rule_table.highlight_search_matches(set(self._matches))

        # Navigate to first match
        if self._matches:
            self._navigate_to_current()

        self._update_match_label()

    def _navigate_to_current(self):
        """Navigate to the current match in the treeview."""
        if not self._rule_table or not self._matches:
            return

        if 0 <= self._current_match_index < len(self._matches):
            item_id = self._matches[self._current_match_index]
            self._rule_table.select_and_see(item_id)
            self._update_match_label()

    def _update_match_label(self):
        """Update the match count label."""
        search_text = self._search_var.get()
        if not search_text:
            self._match_label.config(text='')
        elif not self._matches:
            self._match_label.config(text='No matches')
        else:
            current = self._current_match_index + 1
            total = len(self._matches)
            self._match_label.config(
                text='{} of {} matches'.format(current, total)
            )

    def _clear_state(self):
        """Clear internal search state."""
        self._matches = []
        self._current_match_index = -1
        self._match_label.config(text='')

    def _on_escape(self):
        """Handle Escape key — close if visible."""
        if self._is_visible:
            self.close()

    def _get_sibling_widget(self):
        """Get the widget to pack before (for positioning).

        Returns the first sibling in the parent, or None.
        """
        parent = self.master
        if parent:
            children = parent.pack_slaves()
            if children:
                return children[0]
        return None