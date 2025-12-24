import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import re
from typing import List, Dict, Optional, Tuple
from suricata_rule import SuricataRule
from constants import SuricataConstants


class AdvancedEditor:
    """Advanced text-based editor for Suricata rules with Advanced IDE-like features"""
    
    def __init__(self, parent, rules, variables, main_app=None):
        """Initialize the Advanced Editor
        
        Args:
            parent: Parent window (main application root)
            rules: List of SuricataRule objects
            variables: Dictionary of variables
            main_app: Reference to main SuricataRuleGenerator instance (for validation methods)
        """
        self.parent = parent
        self.main_app = main_app  # Store reference to main app for validation methods
        self.rules = rules.copy()  # Work on a copy
        self.variables = variables.copy()
        self.original_rules = rules.copy()  # Keep original for cancel
        self.original_variables = variables.copy()
        self.result = None  # Will contain rules if OK clicked
        self.modified = False
        self.keywords_data = None
        
        # Create modal dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Advanced Editor")
        self.dialog.geometry("1000x700")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.resizable(True, True)
        
        # Center the dialog
        self.dialog.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - 1000) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - 700) // 2
        self.dialog.geometry(f"+{x}+{y}")
        
        # Track undo/redo
        self.undo_stack = []
        self.redo_stack = []
        
        # Dark mode state
        self.dark_mode = False
        
        # Search state
        self.search_term = ""
        self.search_results = []  # List of (line_num, start_col, end_col, matched_text)
        self.current_search_index = -1
        self.search_active = False
        self.search_field = "all"
        
        # Search configuration
        self.search_filters = {
            'pass': True,
            'drop': True,
            'reject': True,
            'alert': True,
            'comments': True
        }
        
        self.search_options = {
            'case_sensitive': False,
            'whole_word': False,
            'regex': False
        }
        
        # Auto-complete state
        self.autocomplete_window = None
        self.autocomplete_delay_id = None
        self.autocomplete_suppressed = False  # Flag to suppress autocomplete after Escape
        
        # Real-time validation state
        self.validation_delay_id = None
        
        # Tooltip state
        self.tooltip_window = None
        self.tooltip_delay_id = None
        self.last_tooltip_pos = None
        
        # Load content keywords
        self.load_content_keywords()
        
        # Setup UI
        self.setup_ui()
        
        # Convert rules to text and populate editor
        self.populate_editor()
        
        # Mark as unmodified initially
        self.modified = False
        self.text_widget.edit_modified(False)  # Clear edit flag after initial population
        self.update_status_bar()
        
        # Handle window close
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_window_close)
        
        # Wait for dialog to close
        self.dialog.wait_window()
    
    def load_content_keywords(self):
        """Load content keywords from JSON file"""
        try:
            keywords_file = os.path.join(os.path.dirname(__file__), 'content_keywords.json')
            if os.path.exists(keywords_file):
                with open(keywords_file, 'r', encoding='utf-8') as f:
                    self.keywords_data = json.load(f)
            else:
                # File doesn't exist - offer to create
                response = messagebox.askyesnocancel(
                    "Content Keywords File Issue",
                    "The content_keywords.json file could not be found.\n\n"
                    "Auto-complete will work with basic suggestions only:\n"
                    "- Actions, protocols, networks, ports, directions\n"
                    "- Content keywords will not have auto-complete suggestions\n\n"
                    "Continue editing with limited auto-complete?",
                    icon='warning'
                )
                if response is None:  # Cancel
                    self.dialog.destroy()
                    return
                # Continue with basic functionality
                self.keywords_data = None
        except json.JSONDecodeError:
            response = messagebox.askyesnocancel(
                "Content Keywords File Issue",
                "The content_keywords.json file has invalid JSON format.\n\n"
                "Auto-complete will work with basic suggestions only.\n\n"
                "Continue editing with limited auto-complete?",
                icon='warning'
            )
            if response is None:  # Cancel
                self.dialog.destroy()
                return
            self.keywords_data = None
        except Exception as e:
            response = messagebox.askyesnocancel(
                "Content Keywords File Issue",
                f"Error loading content_keywords.json: {str(e)}\n\n"
                "Auto-complete will work with basic suggestions only.\n\n"
                "Continue editing?",
                icon='warning'
            )
            if response is None:  # Cancel
                self.dialog.destroy()
                return
            self.keywords_data = None
    
    def setup_ui(self):
        """Setup the editor UI components"""
        # Main frame
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Editor frame (with line numbers and text widget)
        editor_frame = ttk.Frame(main_frame)
        editor_frame.pack(fill=tk.BOTH, expand=True)
        
        # Line numbers
        self.line_numbers = tk.Text(editor_frame, width=5, padx=5, takefocus=0,
                                    border=0, background='#F0F0F0', state='disabled',
                                    wrap='none', font=('Consolas', 10))
        self.line_numbers.pack(side=tk.LEFT, fill=tk.Y)
        
        # Text editor with scrollbars
        text_scroll_frame = ttk.Frame(editor_frame)
        text_scroll_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Vertical scrollbar
        self.v_scrollbar = ttk.Scrollbar(text_scroll_frame, orient=tk.VERTICAL)
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Horizontal scrollbar
        h_scrollbar = ttk.Scrollbar(text_scroll_frame, orient=tk.HORIZONTAL)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Text widget
        self.text_widget = tk.Text(text_scroll_frame, wrap='none',
                                   font=('Consolas', 10),
                                   undo=True, maxundo=-1,
                                   yscrollcommand=self.v_scrollbar.set,
                                   xscrollcommand=h_scrollbar.set)
        self.text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Configure tags for validation underlines with background highlighting
        self.text_widget.tag_config('error', underline=True, underlinefg='red', background='#FFE6E6')
        self.text_widget.tag_config('warning', underline=True, underlinefg='orange', background='#FFF4E6')
        
        # Configure tags for search highlighting
        self.text_widget.tag_config('search_current', background='#FFFF00')  # Yellow for current match
        self.text_widget.tag_config('search_other', background='#E0E0E0')    # Light gray for other matches
        self.text_widget.tag_raise('search_current')  # Ensure search highlights appear above other tags
        
        # Configure synchronized scrolling for line numbers and text
        self.v_scrollbar.config(command=self.on_text_scroll)
        h_scrollbar.config(command=self.text_widget.xview)
        self.text_widget.config(yscrollcommand=self.on_text_yscroll)
        
        # Sync scrolling between line numbers and text
        self.text_widget.bind('<KeyPress>', self.on_key_press)
        self.text_widget.bind('<KeyRelease>', self.on_key_release)
        self.text_widget.bind('<<Modified>>', self.on_text_modified)
        self.text_widget.bind('<Button-1>', self.on_click)
        self.text_widget.bind('<Button-3>', self.on_right_click)  # Right-click context menu
        self.text_widget.bind('<Motion>', self.on_motion)
        self.text_widget.bind('<Leave>', self.on_leave)
        
        # Keyboard shortcuts
        self.text_widget.bind('<Control-x>', lambda e: self.cut_text())
        self.text_widget.bind('<Control-c>', lambda e: self.copy_text())
        self.text_widget.bind('<Control-v>', lambda e: self.paste_text())
        self.text_widget.bind('<Control-a>', lambda e: self.select_all_text())
        self.text_widget.bind('<Control-z>', lambda e: self.undo_action())
        self.text_widget.bind('<Control-y>', lambda e: self.redo_action())
        self.text_widget.bind('<Control-g>', lambda e: self.goto_line())
        self.text_widget.bind('<Control-space>', lambda e: self.trigger_autocomplete())
        self.text_widget.bind('<Escape>', lambda e: self.on_escape_key())
        self.text_widget.bind('<Tab>', self.on_tab_key)
        self.text_widget.bind('<BackSpace>', self.on_backspace_key)
        
        # Search shortcuts
        self.text_widget.bind('<Control-f>', lambda e: self.show_find_replace_dialog())
        self.text_widget.bind('<F3>', lambda e: self.find_next())
        self.text_widget.bind('<Shift-F3>', lambda e: self.find_previous())
        
        # Comment toggle shortcut
        self.text_widget.bind('<Control-slash>', lambda e: self.toggle_comment())
        
        # Cursor movement bindings to update status bar
        for key in ['<Left>', '<Right>', '<Up>', '<Down>', '<Home>', '<End>', 
                    '<Prior>', '<Next>',  # Page Up/Page Down
                    '<Control-Home>', '<Control-End>']:
            self.text_widget.bind(key, lambda e: self.text_widget.after_idle(self.update_status_bar), add='+')
        
        # Status bar
        self.status_bar = ttk.Frame(main_frame)
        self.status_bar.pack(fill=tk.X, pady=(5, 0))
        
        self.cursor_label = ttk.Label(self.status_bar, text="Ln 1, Col 1")
        self.cursor_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Separator(self.status_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        self.lines_label = ttk.Label(self.status_bar, text="0 lines")
        self.lines_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Separator(self.status_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        self.rule_label = ttk.Label(self.status_bar, text="Rule 0/0")
        self.rule_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Separator(self.status_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        self.modified_label = ttk.Label(self.status_bar, text="(no changes)")
        self.modified_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Separator(self.status_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        self.validation_label = ttk.Label(self.status_bar, text="✓ No errors", foreground="green")
        self.validation_label.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(button_frame, text="Shortcuts", command=self.show_keyboard_shortcuts).pack(side=tk.LEFT)
        
        # Dark mode checkbox
        self.dark_mode_var = tk.BooleanVar(value=False)
        dark_mode_check = ttk.Checkbutton(button_frame, text="Dark Mode", 
                                         variable=self.dark_mode_var,
                                         command=self.toggle_dark_mode)
        dark_mode_check.pack(side=tk.LEFT, padx=(10, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="OK", command=self.on_ok).pack(side=tk.RIGHT)
    
    def populate_editor(self):
        """Convert rules to text and populate the editor"""
        # Clear existing content
        self.text_widget.delete('1.0', 'end')
        
        text_lines = []
        
        for rule in self.rules:
            # Convert rule to text
            if getattr(rule, 'is_blank', False):
                text_lines.append('')
            elif getattr(rule, 'is_comment', False):
                text_lines.append(rule.comment_text)
            else:
                text_lines.append(rule.to_string())
        
        # Insert text
        if text_lines:
            self.text_widget.insert('1.0', '\n'.join(text_lines))
        
        # Update line numbers
        self.update_line_numbers()
        
        # Position cursor at start
        self.text_widget.mark_set('insert', '1.0')
        self.text_widget.focus_set()
    
    def update_line_numbers(self):
        """Update line numbers display"""
        self.line_numbers.config(state='normal')
        self.line_numbers.delete('1.0', 'end')
        
        line_count = int(self.text_widget.index('end-1c').split('.')[0])
        line_numbers_text = '\n'.join(str(i) for i in range(1, line_count + 1))
        
        self.line_numbers.insert('1.0', line_numbers_text)
        self.line_numbers.config(state='disabled')
    
    def update_status_bar(self):
        """Update status bar information"""
        # Cursor position
        cursor_pos = self.text_widget.index('insert')
        line, col = cursor_pos.split('.')
        self.cursor_label.config(text=f"Ln {line}, Col {int(col) + 1}")
        
        # Total lines
        line_count = int(self.text_widget.index('end-1c').split('.')[0])
        self.lines_label.config(text=f"{line_count} lines")
        
        # Get the current line number
        line_num = int(cursor_pos.split('.')[0])
        
        # Get the FULL current line (not just up to cursor)
        current_line_full = self.text_widget.get(f'{line_num}.0', f'{line_num}.end')
        
        # Count total rules
        all_content = self.text_widget.get('1.0', 'end-1c')
        all_lines = all_content.split('\n')
        total_rules = sum(1 for l in all_lines if l.strip() and not l.strip().startswith('#'))
        
        # Count rules up to cursor (use content up to cursor for this count)
        content = self.text_widget.get('1.0', cursor_pos)
        lines = content.split('\n')
        rules_before = sum(1 for l in lines[:-1] if l.strip() and not l.strip().startswith('#'))
        
        # Show search status if active (prioritize over rule position)
        if self.search_active and self.search_results:
            self.rule_label.config(text=f"Search: {self.current_search_index + 1}/{len(self.search_results)}")
        elif current_line_full.strip() and not current_line_full.strip().startswith('#'):
            current_rule_num = rules_before + 1
            
            # Calculate SIG type for FULL current line if main_app is available
            sig_type_text = ""
            if self.main_app:
                # Check if rule_analyzer is available
                rule_analyzer = getattr(self.main_app, 'rule_analyzer', None)
                if rule_analyzer:
                    try:
                        # Parse the FULL current line as a rule
                        rule = SuricataRule.from_string(current_line_full.strip())
                        if rule:
                            # Get detailed classification
                            sig_type = rule_analyzer.get_detailed_suricata_rule_type(rule)
                            if sig_type:
                                sig_type_text = f" | {sig_type}"
                    except (AttributeError, ValueError, TypeError, Exception):
                        # If classification fails, just show rule number (no SIG type)
                        pass
            
            self.rule_label.config(text=f"Rule {current_rule_num}/{total_rules}{sig_type_text}")
        elif current_line_full.strip().startswith('#'):
            self.rule_label.config(text="Comment")
        elif not current_line_full.strip():
            self.rule_label.config(text="Blank")
        else:
            self.rule_label.config(text=f"Rule {rules_before}/{total_rules}")
        
        # Modified status
        if self.modified:
            self.modified_label.config(text="Modified")
        else:
            self.modified_label.config(text="(no changes)")
    
    def on_key_press(self, event):
        """Handle key press events for auto-close brackets and quotes, and smart skipping"""
        char = event.char
        keysym = event.keysym
        
        # Clear autocomplete suppression on space, semicolon, or new line (new section/context)
        if char in (' ', ';') or keysym == 'Return':
            self.autocomplete_suppressed = False
        
        # Smart skipping: If typing a closing character that's already at cursor position, skip over it
        if char in (')', ']', '"'):
            cursor_pos = self.text_widget.index('insert')
            next_char = self.text_widget.get(cursor_pos, f'{cursor_pos}+1c')
            
            if char == '"':
                # For quotes, check if next two chars are ";
                next_two_chars = self.text_widget.get(cursor_pos, f'{cursor_pos}+2c')
                if next_two_chars == '";':
                    # Skip over both the quote and semicolon
                    self.text_widget.mark_set('insert', f'{cursor_pos}+2c')
                    return 'break'
            elif next_char == char:
                # For ) and ], just skip over the matching character
                self.text_widget.mark_set('insert', f'{cursor_pos}+1c')
                return 'break'
        
        # Auto-close: Let the opening character be inserted normally,
        # then insert the closing character after it
        if char == '(':
            # Insert the closing paren after the opening one is inserted
            self.text_widget.after(1, lambda: self._insert_closing_char(')'))
            return  # Don't break - allow ( to be inserted
        elif char == '[':
            self.text_widget.after(1, lambda: self._insert_closing_char(']'))
            return
        elif char == '"':
            # Modified: Insert closing quote with semicolon
            self.text_widget.after(1, lambda: self._insert_closing_char('";'))
            return
    
    def _insert_closing_char(self, closing_char):
        """Insert closing character and move cursor back"""
        self.text_widget.insert('insert', closing_char)
        # Move cursor back by the length of closing_char to position it correctly
        # For ";", we want cursor between the quotes, so move back 2 characters
        chars_to_move = len(closing_char)
        self.text_widget.mark_set('insert', f'insert-{chars_to_move}c')
    
    def on_key_release(self, event):
        """Handle key release for auto-complete"""
        # Trigger auto-complete after brief delay
        if self.autocomplete_delay_id:
            self.text_widget.after_cancel(self.autocomplete_delay_id)
        
        # Don't trigger on special keys (except when navigating autocomplete)
        if event.keysym in ('Shift_L', 'Shift_R', 'Control_L', 'Control_R', 
                            'Alt_L', 'Alt_R', 'Home', 'End', 'Page_Up', 'Page_Down'):
            return
        
        # Don't trigger autocomplete refresh on arrow keys when autocomplete is visible
        # (arrow keys are used for navigation within the autocomplete list)
        if self.autocomplete_window and event.keysym in ('Up', 'Down', 'Left', 'Right'):
            return
        
        # Shorter delay for more responsive autocomplete (100ms instead of 300ms)
        self.autocomplete_delay_id = self.text_widget.after(100, self.check_autocomplete)
    
    def on_tab_key(self, event):
        """Handle Tab key - accept autocomplete, jump to next semicolon or closing paren in rule options, or insert 4 spaces"""
        # If autocomplete is visible, accept the selection
        if self.autocomplete_window and self.autocomplete_listbox:
            self.accept_autocomplete_from_text()
            return 'break'
        
        # Check if we're inside parentheses (rule options section)
        cursor_pos = self.text_widget.index('insert')
        line_num = int(cursor_pos.split('.')[0])
        col_num = int(cursor_pos.split('.')[1])
        
        # Get the entire line content
        line_content = self.text_widget.get(f'{line_num}.0', f'{line_num}.end')
        
        # Check if cursor is between opening and closing parentheses
        text_before_cursor = line_content[:col_num]
        text_after_cursor = line_content[col_num:]
        
        # Count parentheses to determine if we're inside a rule's options section
        open_parens_before = text_before_cursor.count('(') - text_before_cursor.count(')')
        
        # If we're inside parentheses (more opening than closing before cursor)
        # and there's a closing paren somewhere after the cursor
        if open_parens_before > 0 and ')' in text_after_cursor:
            # Find the next semicolon after the cursor position
            semicolon_pos = text_after_cursor.find(';')
            closing_paren_pos = text_after_cursor.find(')')
            
            if semicolon_pos != -1:
                # Move cursor to position after the semicolon
                new_col = col_num + semicolon_pos + 1
                self.text_widget.mark_set('insert', f'{line_num}.{new_col}')
                self.text_widget.see('insert')
                return 'break'
            elif closing_paren_pos != -1:
                # No semicolon found, but there's a closing paren - jump past it
                new_col = col_num + closing_paren_pos + 1
                self.text_widget.mark_set('insert', f'{line_num}.{new_col}')
                self.text_widget.see('insert')
                return 'break'
        
        # Otherwise insert 4 spaces (default behavior)
        self.text_widget.insert('insert', '    ')
        return 'break'
    
    def on_backspace_key(self, event):
        """Handle Backspace key - delete pair if cursor is between matching brackets/quotes"""
        cursor_pos = self.text_widget.index('insert')
        
        # Get character before and after cursor
        char_before = self.text_widget.get(f'{cursor_pos}-1c', cursor_pos)
        char_after = self.text_widget.get(cursor_pos, f'{cursor_pos}+1c')
        
        # Check for matching pairs and delete both if found
        # For quotes, check for "; pattern
        if char_before == '"':
            # Check if next two characters are ";
            next_two_chars = self.text_widget.get(cursor_pos, f'{cursor_pos}+2c')
            if next_two_chars == '";':
                # Delete all three characters: opening quote, closing quote, and semicolon
                self.text_widget.delete(f'{cursor_pos}-1c', f'{cursor_pos}+2c')
                return 'break'
        
        # Check for () pair
        if char_before == '(' and char_after == ')':
            # Delete both characters
            self.text_widget.delete(f'{cursor_pos}-1c', f'{cursor_pos}+1c')
            return 'break'
        
        # Check for [] pair
        if char_before == '[' and char_after == ']':
            # Delete both characters
            self.text_widget.delete(f'{cursor_pos}-1c', f'{cursor_pos}+1c')
            return 'break'
        
        # Default behavior - let normal backspace work
        return None
    
    def on_click(self, event):
        """Handle left-click - show tooltip for errors/warnings"""
        # Get the position under the click
        x, y = event.x, event.y
        index = self.text_widget.index(f"@{x},{y}")
        
        # Check if clicking on an error or warning
        tags = self.text_widget.tag_names(index)
        if 'error' in tags or 'warning' in tags:
            # Show tooltip immediately for errors/warnings
            self.show_tooltip_at_index(index)
        else:
            # Normal click - just update status bar
            self.dismiss_tooltip()
        
        # Delay status bar update until after tkinter processes the click
        # and updates the cursor position
        self.text_widget.after_idle(self.update_status_bar)
    
    def on_right_click(self, event):
        """Handle right-click to show context menu with clipboard and search options"""
        # Dismiss any existing tooltip first
        self.dismiss_tooltip()
        
        # Get the position under the click
        x, y = event.x, event.y
        index = self.text_widget.index(f"@{x},{y}")
        
        # Create context menu
        context_menu = tk.Menu(self.dialog, tearoff=0)
        
        # Check if there's selected text
        has_selection = False
        try:
            sel_start = self.text_widget.index(tk.SEL_FIRST)
            sel_end = self.text_widget.index(tk.SEL_LAST)
            has_selection = True
        except tk.TclError:
            has_selection = False
        
        # Cut option (only if there's a selection)
        if has_selection:
            context_menu.add_command(label="Cut", command=self.cut_text, accelerator="Ctrl+X")
        
        # Copy option (only if there's a selection)
        if has_selection:
            context_menu.add_command(label="Copy", command=self.copy_text, accelerator="Ctrl+C")
        
        # Paste option (check if clipboard has content)
        try:
            clipboard_content = self.dialog.clipboard_get()
            if clipboard_content:
                if has_selection:
                    context_menu.add_separator()
                context_menu.add_command(label="Paste", command=self.paste_text, accelerator="Ctrl+V")
        except tk.TclError:
            # No clipboard content
            pass
        
        # Select All option
        context_menu.add_separator()
        context_menu.add_command(label="Select All", command=self.select_all_text, accelerator="Ctrl+A")
        
        # Search options
        context_menu.add_separator()
        context_menu.add_command(label="Find and Replace...", command=self.show_find_replace_dialog, accelerator="Ctrl+F")
        
        if self.search_active and self.search_results:
            context_menu.add_command(label="Find Next", command=self.find_next, accelerator="F3")
            context_menu.add_command(label="Find Previous", command=self.find_previous, accelerator="Shift+F3")
        
        # Comment toggle option
        context_menu.add_separator()
        context_menu.add_command(label="Toggle Comment", command=self.toggle_comment, accelerator="Ctrl+/")
        
        # Show error/warning tooltip if clicking on an error/warning
        tags = self.text_widget.tag_names(index)
        if 'error' in tags or 'warning' in tags:
            context_menu.add_separator()
            context_menu.add_command(label="Show Error Details", command=lambda: self.show_tooltip_at_index(index))
        
        # Show the menu at mouse position
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def on_motion(self, event):
        """Handle mouse motion for hover tooltips"""
        # Get the position under the mouse
        x, y = event.x, event.y
        index = self.text_widget.index(f"@{x},{y}")
        
        # Cancel any pending tooltip
        if self.tooltip_delay_id:
            self.text_widget.after_cancel(self.tooltip_delay_id)
            self.tooltip_delay_id = None
        
        # Check if we're over the same position as before
        if self.last_tooltip_pos == index:
            return
        
        self.last_tooltip_pos = index
        
        # Dismiss existing tooltip
        self.dismiss_tooltip()
        
        # Schedule tooltip to appear after a delay (500ms)
        self.tooltip_delay_id = self.text_widget.after(500, lambda: self.show_tooltip_at_index(index))
    
    def on_leave(self, event):
        """Handle mouse leaving the text widget"""
        self.dismiss_tooltip()
        if self.tooltip_delay_id:
            self.text_widget.after_cancel(self.tooltip_delay_id)
            self.tooltip_delay_id = None
        self.last_tooltip_pos = None
    
    def on_text_modified(self, event):
        """Handle text modification"""
        if self.text_widget.edit_modified():
            self.modified = True
            self.update_line_numbers()
            self.update_status_bar()
            self.text_widget.edit_modified(False)
            
            # Schedule real-time validation with delay
            if self.validation_delay_id:
                self.text_widget.after_cancel(self.validation_delay_id)
            self.validation_delay_id = self.text_widget.after(500, self.perform_realtime_validation)
    
    def perform_realtime_validation(self):
        """Perform real-time validation and show wavy underlines"""
        # Clear all existing error/warning tags
        self.text_widget.tag_remove('error', '1.0', 'end')
        self.text_widget.tag_remove('warning', '1.0', 'end')
        
        # Get all content
        content = self.text_widget.get('1.0', 'end-1c')
        lines = content.split('\n')
        
        total_errors = 0
        total_warnings = 0
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip blank lines and comments
            if not line_stripped or line_stripped.startswith('#'):
                continue
            
            # Validate this line
            errors, warnings = self.validate_line(line, line_num)
            
            total_errors += len(errors)
            total_warnings += len(warnings)
            
            # Apply error underlines
            for start_col, end_col, error_msg in errors:
                start_idx = f'{line_num}.{start_col}'
                end_idx = f'{line_num}.{end_col}'
                self.text_widget.tag_add('error', start_idx, end_idx)
            
            # Apply warning underlines
            for start_col, end_col, warning_msg in warnings:
                start_idx = f'{line_num}.{start_col}'
                end_idx = f'{line_num}.{end_col}'
                self.text_widget.tag_add('warning', start_idx, end_idx)
        
        # Update validation status in status bar
        if total_errors > 0:
            self.validation_label.config(text=f"✗ {total_errors} errors", foreground="red")
        elif total_warnings > 0:
            self.validation_label.config(text=f"⚠ {total_warnings} warnings", foreground="orange")
        else:
            self.validation_label.config(text="✓ No errors", foreground="green")
    
    def validate_line(self, line, line_num):
        """Validate a single line and return error/warning positions
        
        Returns:
            tuple: (errors_list, warnings_list) where each item is (start_col, end_col, message)
        """
        errors = []
        warnings = []
        
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            return errors, warnings
        
        # Parse the line into tokens - handle brackets specially to avoid splitting on commas inside brackets
        tokens = self._parse_rule_tokens(line_stripped)
        
        # Don't show errors for incomplete rules - only validate what's been typed
        # This allows progressive typing without constant red underlines
        
        # Find positions of each token in the original line
        current_pos = 0
        token_positions = []
        for token in tokens:
            start = line.find(token, current_pos)
            if start != -1:
                end = start + len(token)
                token_positions.append((start, end, token))
                current_pos = end
        
        # Validate action (first word) - only if it's complete
        if len(token_positions) > 0:
            start, end, action = token_positions[0]
            # Only validate if it looks like a complete word (not being typed)
            # Check if there's a space after it or if it's followed by another token
            if len(token_positions) > 1 or (len(tokens) == 1 and end < len(line) and line[end:].strip()):
                if action.lower() not in ['pass', 'alert', 'drop', 'reject']:
                    errors.append((start, end, f"Invalid action: {action}"))
        
        # Validate protocol (second word) - only if action is valid and protocol is complete
        if len(token_positions) > 1:
            start, end, protocol = token_positions[1]
            # Only validate if there's a space after it or another token follows
            if len(token_positions) > 2 or (len(tokens) == 2 and end < len(line) and line[end:].strip()):
                if protocol.lower() not in [p.lower() for p in SuricataConstants.SUPPORTED_PROTOCOLS]:
                    errors.append((start, end, f"Invalid protocol: {protocol}"))
        
        # Validate source network (3rd word) - only if we have that many tokens
        if len(token_positions) > 2:
            start, end, src_net = token_positions[2]
            # Only validate if it's complete (followed by another token or space)
            if len(token_positions) > 3 or (end < len(line) and line[end:].strip()):
                if not self._validate_network_format_silent(src_net):
                    errors.append((start, end, f"Invalid network: {src_net}"))
        
        # Validate direction (should be -> or <>) - only if we have that many tokens
        if len(token_positions) > 4:
            start, end, direction = token_positions[4]
            # Only validate if it's complete (followed by another token or space)
            if len(token_positions) > 5 or (end < len(line) and line[end:].strip()):
                if direction not in ['->', '<>']:
                    errors.append((start, end, f"Invalid direction: {direction}"))
        
        # Validate source port (4th token, index 3) - only if we have that many tokens
        if len(token_positions) > 3:
            start, end, src_port = token_positions[3]
            # Only validate if it's complete (followed by another token or space)
            if len(token_positions) > 4 or (end < len(line) and line[end:].strip()):
                # Don't validate if it looks like a network (has slash or starts with bracket containing dots)
                if not ('/' in src_port or (src_port.startswith('[') and '.' in src_port)):
                    if not self._validate_port_format(src_port):
                        errors.append((start, end, f"Invalid port: {src_port}"))
        
        # Validate destination network (6th token, index 5) - only if we have that many tokens
        if len(token_positions) > 5:
            start, end, dst_net = token_positions[5]
            # Only validate if it's complete (followed by another token or space)
            if len(token_positions) > 6 or (end < len(line) and line[end:].strip()):
                # Don't validate if it looks like a port (all digits or bracketed port range)
                if not (dst_net.isdigit() or (dst_net.startswith('[') and ':' in dst_net)):
                    if not self._validate_network_format_silent(dst_net):
                        errors.append((start, end, f"Invalid network: {dst_net}"))
        
        # Validate destination port (7th token, index 6) - only if we have that many tokens
        if len(token_positions) > 6:
            start, end, dest_port = token_positions[6]
            # Only validate if it's complete (followed by another token or space)
            if len(token_positions) > 7 or (end < len(line) and line[end:].strip()):
                # Don't validate if it looks like a network (has slash or bracketed CIDRs)
                if not ('/' in dest_port or (dest_port.startswith('[') and '.' in dest_port)):
                    if not self._validate_port_format(dest_port):
                        errors.append((start, end, f"Invalid port: {dest_port}"))
        
        # Check for parentheses and validate content keywords
        if '(' in line and ')' in line:
            paren_start = line.find('(')
            paren_end = line.rfind(')')
            content_section = line[paren_start+1:paren_end]
            
            # Check for SID (required) - only if parentheses are closed
            if 'sid:' not in content_section.lower():
                # Only show this error if the rule looks complete (has closing paren)
                # Don't flag incomplete rules
                pass  # Don't error on missing SID for incomplete rules
            else:
                # Validate SID format
                sid_match = re.search(r'sid:\s*(\d+)', content_section, re.IGNORECASE)
                if sid_match:
                    sid_value = int(sid_match.group(1))
                    if sid_value < SuricataConstants.SID_MIN or sid_value > SuricataConstants.SID_MAX:
                        # Find position of sid value in original line
                        sid_start = line.find(sid_match.group(0), paren_start)
                        sid_end = sid_start + len(sid_match.group(0))
                        errors.append((sid_start, sid_end, f"SID must be between {SuricataConstants.SID_MIN}-{SuricataConstants.SID_MAX}"))
            
            # Validate unknown keywords (warnings only) - only if content_keywords.json is loaded
            if self.keywords_data:
                # Split content section by semicolons to get individual keyword-value pairs
                # Then extract the keyword name from each pair
                known_keywords = [kw.get('name', '') for kw in self.keywords_data.get('keywords', [])]
                
                # Split by semicolon to get each statement
                statements = content_section.split(';')
                current_pos = 0
                
                for statement in statements:
                    statement = statement.strip()
                    if not statement:
                        current_pos += 1  # Account for semicolon
                        continue
                    
                    # Extract keyword name (part before colon, or entire statement if no colon)
                    if ':' in statement:
                        # Keyword with value: "flow:to_client, stateless" -> keyword is "flow"
                        keyword = statement.split(':')[0].strip()
                    else:
                        # Standalone keyword (no colon): "noalert" -> keyword is "noalert"
                        keyword = statement.strip()
                    
                    # Check if this is a valid keyword
                    if keyword and keyword.lower() not in [k.lower() for k in known_keywords]:
                        # Find position of this keyword in the original line
                        # Need to find it after paren_start and at current_pos offset
                        search_start = paren_start + current_pos
                        keyword_pos = line.find(keyword, search_start)
                        if keyword_pos != -1:
                            warnings.append((keyword_pos, keyword_pos + len(keyword), 
                                           f"Unknown keyword: {keyword}"))
                    
                    # Update position (length of statement + semicolon)
                    current_pos += len(statement) + 1
        
        # Check for undefined variables (only in network/port sections, not inside quoted strings)
        var_pattern = r'([\$@]\w+)'
        for match in re.finditer(var_pattern, line):
            var_name = match.group(1)
            var_pos = match.start()
            
            # Don't flag variables inside quoted strings
            in_quotes = False
            for i, char in enumerate(line[:var_pos]):
                if char == '"':
                    in_quotes = not in_quotes
            
            if not in_quotes and var_name not in self.variables:
                var_start = match.start()
                var_end = match.end()
                warnings.append((var_start, var_end, f"Undefined variable: {var_name}"))
        
        return errors, warnings
    
    def _parse_rule_tokens(self, line_stripped):
        """Parse rule into tokens, treating bracketed groups as single tokens
        
        Args:
            line_stripped: Stripped line text
            
        Returns:
            List of tokens
        """
        tokens = []
        current_token = ""
        bracket_depth = 0
        paren_depth = 0
        in_quotes = False
        
        for char in line_stripped:
            if char == '"' and bracket_depth == 0 and paren_depth == 0:
                in_quotes = not in_quotes
                current_token += char
            elif in_quotes:
                current_token += char
            elif char == '[':
                bracket_depth += 1
                current_token += char
            elif char == ']':
                bracket_depth -= 1
                current_token += char
            elif char == '(':
                paren_depth += 1
                current_token += char
            elif char == ')':
                paren_depth -= 1
                current_token += char
            elif char == ' ' and bracket_depth == 0 and paren_depth == 0:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char
        
        # Add last token
        if current_token:
            tokens.append(current_token)
        
        return tokens
    
    def _validate_port_format(self, port_str):
        """Validate port format using main app's validation method
        
        Args:
            port_str: Port string to validate
            
        Returns:
            bool: True if valid port format
        """
        port_str = port_str.strip()
        
        # Handle negation FIRST (e.g., !443 or ![80,443])
        # This must be done before calling main app validation
        if port_str.startswith('!'):
            inner = port_str[1:].strip()
            # Recursively validate the negated part
            return self._validate_port_format(inner)
        
        # Use main app's validation method if available
        if self.main_app and hasattr(self.main_app, 'validate_port_list'):
            return self.main_app.validate_port_list(port_str)
        
        # Fallback validation if main app not available
        # "any" is always valid
        if port_str.lower() == 'any':
            return True
        
        # Variable reference ($VAR) is valid (@ not allowed for ports)
        if port_str.startswith('$'):
            return True
        
        if port_str.startswith('@'):
            return False  # @ variables not allowed for ports
        
        # Single port number (allowed without brackets)
        if port_str.isdigit():
            port_num = int(port_str)
            return 1 <= port_num <= 65535
        
        # Bracketed specifications
        if port_str.startswith('[') and port_str.endswith(']'):
            return True  # Assume bracketed content is valid (main parser will catch issues)
        
        # Anything else with colons or commas requires brackets
        if ':' in port_str or ',' in port_str:
            return False
        
        return False
    
    def _validate_network_format_silent(self, network_str):
        """Validate network format using main app's validation (silent mode - no popups)
        
        Args:
            network_str: Network string to validate
            
        Returns:
            bool: True if valid network format
        """
        network_str = network_str.strip()
        
        # Handle negation FIRST (e.g., !192.168.1.0/24 or !$HOME_NET)
        # This must be done before calling main app validation
        if network_str.startswith('!'):
            inner = network_str[1:].strip()
            # Recursively validate the negated part
            return self._validate_network_format_silent(inner)
        
        # "any" is always valid
        if network_str.lower() == 'any':
            return True
        
        # Variables are valid
        if network_str.startswith(('$', '@')):
            return True
        
        # Check for bracketed groups - validate contents properly
        if network_str.startswith('[') and network_str.endswith(']'):
            group_content = network_str[1:-1].strip()
            if not group_content:
                return False  # Empty brackets not valid
            
            # Split by commas and validate each item
            items = [item.strip() for item in group_content.split(',')]
            for item in items:
                if not item:
                    return False  # Empty item not valid
                
                # Handle negated items within group
                if item.startswith('!'):
                    item = item[1:].strip()
                    if not item:
                        return False
                
                # Validate the individual item (recursive call for non-bracketed items)
                if not self._validate_single_network_item_silent(item):
                    return False
            
            return True
        
        # Single item validation
        return self._validate_single_network_item_silent(network_str)
    
    def _validate_single_network_item_silent(self, value):
        """Validate a single network item without brackets
        
        Args:
            value: Single network item (CIDR, IP, or variable)
            
        Returns:
            bool: True if valid
        """
        value = value.strip()
        
        # Variables are valid
        if value.startswith(('$', '@')):
            return True
        
        # "any" is valid
        if value.lower() == 'any':
            return True
        
        # Try to validate as CIDR or IP
        try:
            import ipaddress
            ipaddress.ip_network(value, strict=False)
            return True
        except (ValueError, AttributeError):
            return False
    
    def check_autocomplete(self):
        """Check if auto-complete should be shown"""
        # If autocomplete is suppressed (user pressed Escape), don't show it
        if self.autocomplete_suppressed:
            return
        
        # Get current line and cursor position
        cursor_pos = self.text_widget.index('insert')
        line_num = int(cursor_pos.split('.')[0])
        col_num = int(cursor_pos.split('.')[1])
        
        line_content = self.text_widget.get(f'{line_num}.0', f'{line_num}.end')
        text_before_cursor = line_content[:col_num]
        
        # Don't show autocomplete for comments or blank lines
        if not text_before_cursor.strip() or text_before_cursor.strip().startswith('#'):
            self.dismiss_autocomplete()
            return
        
        # Determine context and get base suggestions
        suggestions = self.get_autocomplete_suggestions(text_before_cursor, line_content)
        
        # Determine what partial text to filter on
        # Check if we're typing a keyword value (after "keyword:")
        keyword_value_match = re.search(r'(\w+(?:\.\w+)?):([^;]*?)$', text_before_cursor)
        
        if keyword_value_match and '(' in line_content and ')' not in text_before_cursor:
            # We're typing a value for a keyword (like "flow:to_ser")
            value_part = keyword_value_match.group(2)
            # Get the partial value after the last comma
            partial_value = value_part.split(',')[-1].strip()
            
            # Filter based on partial value
            if partial_value:
                filtered_suggestions = [s for s in suggestions if s.lower().startswith(partial_value.lower())]
            else:
                filtered_suggestions = suggestions
        elif '(' in line_content and ')' not in text_before_cursor:
            # Inside parentheses - extract partial keyword after last semicolon or opening paren
            # Handle first keyword: "...(flo" or subsequent keywords: "...;flo"
            paren_content = text_before_cursor.split('(')[-1]  # Get content after last (
            
            # If there's a semicolon, get text after it; otherwise use all content
            if ';' in paren_content:
                partial_keyword = paren_content.split(';')[-1].strip()
            else:
                partial_keyword = paren_content.strip()
            
            # Filter suggestions based on partial keyword
            if partial_keyword:
                filtered_suggestions = [s for s in suggestions if s.lower().startswith(partial_keyword.lower())]
            else:
                filtered_suggestions = suggestions
        else:
            # Regular word filtering (for actions, protocols, etc.)
            words = text_before_cursor.split()
            current_partial = ''
            if words and not text_before_cursor.endswith(' '):
                current_partial = words[-1]
            
            if current_partial:
                filtered_suggestions = [s for s in suggestions if s.lower().startswith(current_partial.lower())]
            else:
                filtered_suggestions = suggestions
        
        if filtered_suggestions:
            self.show_autocomplete(filtered_suggestions)
        else:
            # No matches - dismiss autocomplete
            self.dismiss_autocomplete()
    
    def get_autocomplete_suggestions(self, text_before_cursor, full_line):
        """Get auto-complete suggestions based on context"""
        words = text_before_cursor.split()
        word_count = len([w for w in words if w])
        
        # Action (first word)
        if word_count == 0 or (word_count == 1 and not text_before_cursor.endswith(' ')):
            return ['#', 'alert', 'pass', 'drop', 'reject']
        
        # Protocol (second word)
        if word_count == 1 or (word_count == 2 and not text_before_cursor.endswith(' ')):
            return SuricataConstants.SUPPORTED_PROTOCOLS
        
        # Source Network (third section)
        if word_count == 2 or (word_count == 3 and not text_before_cursor.endswith(' ')):
            suggestions = ['any', '192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12']
            # Add defined variables
            suggestions.extend([var for var in self.variables.keys() if var.startswith('$')])
            suggestions.extend([var for var in self.variables.keys() if var.startswith('@')])
            return suggestions
        
        # Source Port (fourth section)
        if word_count == 3 or (word_count == 4 and not text_before_cursor.endswith(' ')):
            return ['any', '80', '443', '[8080:8090]', '[80,443,8080]']
        
        # Direction (fifth section)
        if word_count == 4 or (word_count == 5 and not text_before_cursor.endswith(' ')):
            return ['->', '<>']
        
        # Destination Network (sixth section)
        if word_count == 5 or (word_count == 6 and not text_before_cursor.endswith(' ')):
            suggestions = ['any', '192.168.1.0/24', '10.0.0.0/8']
            suggestions.extend([var for var in self.variables.keys() if var.startswith('$')])
            suggestions.extend([var for var in self.variables.keys() if var.startswith('@')])
            return suggestions
        
        # Destination Port (seventh section)
        if word_count == 6 or (word_count == 7 and not text_before_cursor.endswith(' ')):
            return ['any', '80', '443', '[8080:8090]']
        
        # Content keywords (inside parentheses)
        if '(' in full_line and ')' not in text_before_cursor:
            return self.get_content_keyword_suggestions(text_before_cursor)
        
        return []
    
    def get_content_keyword_suggestions(self, text_before_cursor=None):
        """Get content keyword suggestions from loaded JSON
        
        Args:
            text_before_cursor: Text before cursor to check for keyword value context
        """
        if not self.keywords_data:
            # Basic fallback keywords
            return ['msg:', 'sid:', 'rev:', 'content:', 'flow:', 'http.host;', 'tls.sni;', 'dns.query;']
        
        # Check if we're typing a value for a keyword (e.g., after "flow:")
        if text_before_cursor:
            # Check if we're right after a completed sid keyword - suggest rev
            # Pattern: sid:XXX; or sid:XXX; (with optional space)
            if re.search(r'sid:\s*\d+;\s*$', text_before_cursor):
                return ['rev:1;']
            
            # Check if we're right after a completed rev keyword - suppress auto-complete
            # Pattern: rev:X; or rev:X; (with optional space)
            if re.search(r'rev:\s*\d+;\s*$', text_before_cursor):
                return []  # Return empty to suppress auto-complete after rev
            
            # Look for pattern like "flow:" or "flow:to_server," at the end
            keyword_value_match = re.search(r'(\w+(?:\.\w+)?):([^;]*?)$', text_before_cursor)
            if keyword_value_match:
                keyword_name = keyword_value_match.group(1)
                partial_value = keyword_value_match.group(2).split(',')[-1].strip()  # Get last value after comma
                
                # Special handling for SID keyword - suggest next available SID
                if keyword_name.lower() == 'sid':
                    # If user just typed "sid:" with no value yet, suggest next available SID
                    if not partial_value or partial_value.isdigit():
                        try:
                            # Get SIDs from current editor content (not main app rules)
                            editor_content = self.text_widget.get('1.0', 'end-1c')
                            editor_lines = editor_content.split('\n')
                            used_sids = set()
                            
                            # Parse SIDs from all rules in the editor
                            for line in editor_lines:
                                line_stripped = line.strip()
                                # Skip blank lines and comments
                                if not line_stripped or line_stripped.startswith('#'):
                                    continue
                                # Extract SID from line using regex
                                sid_match = re.search(r'sid:\s*(\d+)', line_stripped, re.IGNORECASE)
                                if sid_match:
                                    used_sids.add(int(sid_match.group(1)))
                            
                            # Find next available SID (max + 1, like main program)
                            if used_sids:
                                next_sid = max(used_sids) + 1
                            else:
                                next_sid = 100
                            
                            # Safety check to prevent infinite loop
                            while next_sid in used_sids:
                                next_sid += 1
                                if next_sid > 999999999:  # Prevent infinite loop
                                    break
                            
                            # Return SID with semicolon
                            return [f"{next_sid};"]
                        except:
                            # If there's an error getting next SID, return empty
                            return []
                
                # Special handling for REV keyword - suggest default value of 1
                if keyword_name.lower() == 'rev':
                    # If user just typed "rev:" with no value yet, suggest 1;
                    if not partial_value or partial_value.isdigit():
                        return ['1;']
                
                # Find this keyword in our data
                keywords = self.keywords_data.get('keywords', [])
                for kw in keywords:
                    if kw.get('name', '') == keyword_name:
                        values = kw.get('values', [])
                        if values:
                            # Filter values based on partial input
                            if partial_value:
                                return [v for v in values if v.lower().startswith(partial_value.lower())]
                            else:
                                return values
        
        # Default: show keyword names (not full syntax templates)
        keywords = self.keywords_data.get('keywords', [])
        suggestions = []
        
        for kw in keywords:
            name = kw.get('name', '')
            if name:
                # For keywords with values, just show "name:" (not the full template)
                # For keywords without values, show appropriate syntax
                if kw.get('values'):
                    suggestions.append(f"{name}:")
                else:
                    # Use simplified syntax without placeholders
                    syntax = kw.get('syntax', '')
                    if '<' in syntax:
                        # Has placeholder - extract just the keyword part
                        suggestions.append(f"{name}:")
                    else:
                        suggestions.append(syntax if syntax else f"{name}:")
        
        return suggestions
    
    def show_autocomplete(self, suggestions):
        """Show auto-complete popup with suggestions (Advanced IDE-like, no focus stealing)"""
        if not suggestions:
            self.dismiss_autocomplete()
            return
        
        # Get cursor position
        cursor_pos = self.text_widget.index('insert')
        bbox = self.text_widget.bbox('insert')
        
        if not bbox:
            return
        
        # Calculate position
        x = self.text_widget.winfo_rootx() + bbox[0]
        y = self.text_widget.winfo_rooty() + bbox[1] + bbox[3]
        
        # If window already exists, update it instead of recreating
        if self.autocomplete_window and self.autocomplete_listbox:
            # Update position
            self.autocomplete_window.wm_geometry(f"+{x}+{y}")
            
            # Update listbox contents
            self.autocomplete_listbox.delete(0, tk.END)
            self.autocomplete_suggestions = suggestions[:10]
            
            for suggestion in self.autocomplete_suggestions:
                self.autocomplete_listbox.insert(tk.END, suggestion)
            
            # Update height
            self.autocomplete_listbox.config(height=min(10, len(self.autocomplete_suggestions)))
            
            if self.autocomplete_listbox.size() > 0:
                self.autocomplete_listbox.selection_set(0)
                self.autocomplete_listbox.activate(0)
        else:
            # Create new popup window
            self.autocomplete_window = tk.Toplevel(self.dialog)
            self.autocomplete_window.wm_overrideredirect(True)
            self.autocomplete_window.wm_geometry(f"+{x}+{y}")
            
            # Create listbox
            self.autocomplete_listbox = tk.Listbox(self.autocomplete_window, height=min(10, len(suggestions)),
                                                   font=('Consolas', 9), takefocus=0)
            self.autocomplete_listbox.pack()
            
            # Store suggestions
            self.autocomplete_suggestions = suggestions[:10]
            
            # Populate with suggestions
            for suggestion in self.autocomplete_suggestions:
                self.autocomplete_listbox.insert(tk.END, suggestion)
            
            if self.autocomplete_listbox.size() > 0:
                self.autocomplete_listbox.selection_set(0)
                self.autocomplete_listbox.activate(0)
            
            # Bind mouse click on listbox
            self.autocomplete_listbox.bind('<Button-1>', self.on_autocomplete_click)
            
            # DON'T steal focus - keep focus on text_widget
            # This allows continuous typing while autocomplete is visible
            
            # Set up text_widget bindings to handle autocomplete navigation
            self.setup_autocomplete_bindings()
    
    def setup_autocomplete_bindings(self):
        """Set up keyboard bindings when autocomplete is visible"""
        # Handle Tab and Enter in text_widget when autocomplete is visible
        self.text_widget.bind('<Return>', self.on_autocomplete_return, add='+')
        self.text_widget.bind('<Up>', self.on_autocomplete_up, add='+')
        self.text_widget.bind('<Down>', self.on_autocomplete_down, add='+')
    
    def remove_autocomplete_bindings(self):
        """Remove autocomplete-specific bindings"""
        # Unbind the autocomplete navigation keys
        try:
            self.text_widget.unbind('<Return>')
            self.text_widget.unbind('<Up>')
            self.text_widget.unbind('<Down>')
        except:
            pass
    
    def on_autocomplete_return(self, event):
        """Handle Return key when autocomplete is visible"""
        if self.autocomplete_window and self.autocomplete_listbox:
            self.accept_autocomplete_from_text()
            return 'break'
        return None
    
    def on_autocomplete_up(self, event):
        """Handle Up arrow when autocomplete is visible"""
        if self.autocomplete_window and self.autocomplete_listbox:
            current = self.autocomplete_listbox.curselection()
            if current:
                index = current[0]
                if index > 0:
                    self.autocomplete_listbox.selection_clear(0, tk.END)
                    self.autocomplete_listbox.selection_set(index - 1)
                    self.autocomplete_listbox.activate(index - 1)
                    self.autocomplete_listbox.see(index - 1)
            return 'break'
        return None
    
    def on_autocomplete_down(self, event):
        """Handle Down arrow when autocomplete is visible"""
        if self.autocomplete_window and self.autocomplete_listbox:
            current = self.autocomplete_listbox.curselection()
            if current:
                index = current[0]
                if index < self.autocomplete_listbox.size() - 1:
                    self.autocomplete_listbox.selection_clear(0, tk.END)
                    self.autocomplete_listbox.selection_set(index + 1)
                    self.autocomplete_listbox.activate(index + 1)
                    self.autocomplete_listbox.see(index + 1)
            return 'break'
        return None
    
    def on_autocomplete_click(self, event):
        """Handle click on autocomplete listbox"""
        # Get the clicked item
        widget = event.widget
        index = widget.nearest(event.y)
        if index >= 0:
            widget.selection_clear(0, tk.END)
            widget.selection_set(index)
            # Accept the suggestion
            self.accept_autocomplete_from_text()
    
    def accept_autocomplete_from_text(self):
        """Accept currently selected autocomplete suggestion without needing listbox reference"""
        if not self.autocomplete_window or not self.autocomplete_listbox:
            return
        
        selection = self.autocomplete_listbox.curselection()
        if selection:
            value = self.autocomplete_listbox.get(selection[0])
            
            # Get current position and word
            cursor_pos = self.text_widget.index('insert')
            line_num = int(cursor_pos.split('.')[0])
            col_num = int(cursor_pos.split('.')[1])
            
            # Get current line
            line_content = self.text_widget.get(f'{line_num}.0', f'{line_num}.end')
            text_before = line_content[:col_num]
            
            # Check if this is the rev keyword suggestion (special handling)
            is_rev_keyword = (value == 'rev:1;')
            
            # Check if this is a sid value suggestion (number followed by semicolon)
            is_sid_value = re.match(r'^\d+;$', value) is not None
            
            # Check if we're inserting a keyword value (after "keyword:")
            is_keyword_value = False
            keyword_match = re.search(r'(\w+(?:\.\w+)?):([^;]*?)$', text_before)
            if keyword_match and ':' in text_before:
                # We're inserting a value for a keyword
                is_keyword_value = True
                # Delete only the partial value after the last comma (if any)
                value_part = keyword_match.group(2)
                if ',' in value_part:
                    # Delete only after last comma
                    last_comma_pos = value_part.rfind(',')
                    partial_after_comma = value_part[last_comma_pos + 1:].strip()
                    if partial_after_comma:
                        # Delete the partial value after comma
                        delete_count = len(partial_after_comma)
                        self.text_widget.delete(f'insert-{delete_count}c', 'insert')
                else:
                    # Delete the entire value part (everything after colon)
                    if value_part.strip():
                        delete_count = len(value_part)
                        self.text_widget.delete(f'insert-{delete_count}c', 'insert')
            else:
                # Regular word completion
                # Check if we're inside parentheses (first keyword after opening paren)
                if '(' in text_before and ')' not in text_before:
                    paren_content = text_before.split('(')[-1]
                    # Extract the partial keyword (after last semicolon or opening paren)
                    if ';' in paren_content:
                        partial_keyword = paren_content.split(';')[-1].strip()
                    else:
                        partial_keyword = paren_content.strip()
                    
                    if partial_keyword:
                        # Delete only the partial keyword, not the opening paren
                        delete_count = len(partial_keyword)
                        self.text_widget.delete(f'insert-{delete_count}c', 'insert')
                else:
                    # Outside parentheses - normal word deletion
                    words = text_before.split()
                    if words and not text_before.endswith(' '):
                        current_word = words[-1]
                        # Delete current word
                        start_col = col_num - len(current_word)
                        self.text_widget.delete(f'{line_num}.{start_col}', 'insert')
            
            # Insert suggestion with special handling for sid value and rev keyword
            if is_rev_keyword:
                # Rev keyword: insert without space
                self.text_widget.insert('insert', value)
                # Move cursor to next line (after closing paren)
                # Find the closing paren on this line
                updated_line = self.text_widget.get(f'{line_num}.0', f'{line_num}.end')
                closing_paren_pos = updated_line.find(')', col_num)
                if closing_paren_pos != -1:
                    # Position cursor after the closing paren
                    self.text_widget.mark_set('insert', f'{line_num}.{closing_paren_pos + 1}')
                    # Insert a newline to move to next line
                    self.text_widget.insert('insert', '\n')
                    # Cursor is now on the new line
            elif is_sid_value:
                # SID value: insert with space after semicolon
                self.text_widget.insert('insert', value + ' ')
            elif is_keyword_value or value.endswith(':'):
                # Other keyword values or keywords ending with ':' - no trailing space
                self.text_widget.insert('insert', value)
            else:
                # Default: add trailing space
                self.text_widget.insert('insert', value + ' ')
        
        self.dismiss_autocomplete()
    
    def accept_autocomplete(self, listbox):
        """Accept selected auto-complete suggestion (legacy method for backward compatibility)"""
        selection = listbox.curselection()
        if selection:
            value = listbox.get(selection[0])
            
            # Get current position and word
            cursor_pos = self.text_widget.index('insert')
            line_num = int(cursor_pos.split('.')[0])
            col_num = int(cursor_pos.split('.')[1])
            
            # Get current line
            line_content = self.text_widget.get(f'{line_num}.0', f'{line_num}.end')
            text_before = line_content[:col_num]
            
            # Find start of current word
            words = text_before.split()
            if words and not text_before.endswith(' '):
                current_word = words[-1]
                # Delete current word
                start_col = col_num - len(current_word)
                self.text_widget.delete(f'{line_num}.{start_col}', 'insert')
            
            # Insert suggestion
            self.text_widget.insert('insert', value + ' ')
        
        self.dismiss_autocomplete()
    
    def trigger_autocomplete(self):
        """Manually trigger auto-complete (Ctrl+Space)"""
        # Clear suppression when manually triggering
        self.autocomplete_suppressed = False
        self.check_autocomplete()
        return 'break'
    
    def dismiss_autocomplete(self, suppress=False):
        """Dismiss auto-complete popup and restore bindings
        
        Args:
            suppress: If True, suppress autocomplete until next section (used for Escape key)
        """
        if self.autocomplete_window:
            self.remove_autocomplete_bindings()
            self.autocomplete_window.destroy()
            self.autocomplete_window = None
            self.autocomplete_listbox = None
            # Only set suppression flag if explicitly requested (Escape key)
            if suppress:
                self.autocomplete_suppressed = True
        return 'break'
    
    def undo_action(self):
        """Undo last change"""
        try:
            self.text_widget.edit_undo()
        except tk.TclError:
            pass
        return 'break'
    
    def redo_action(self):
        """Redo last undone change"""
        try:
            self.text_widget.edit_redo()
        except tk.TclError:
            pass
        return 'break'
    
    def goto_line(self):
        """Go to specific line number"""
        line_count = int(self.text_widget.index('end-1c').split('.')[0])
        
        line_num = simpledialog.askinteger(
            "Go to Line",
            f"Enter line number (1-{line_count}):",
            minvalue=1,
            maxvalue=line_count,
            parent=self.dialog
        )
        
        if line_num:
            self.text_widget.mark_set('insert', f'{line_num}.0')
            self.text_widget.see('insert')
            self.update_status_bar()
        
        return 'break'
    
    def validate_and_parse_rules(self):
        """Validate rules and parse text back to rule objects
        
        Returns:
            tuple: (rules_list, errors_list, warnings_list, undefined_vars)
        """
        content = self.text_widget.get('1.0', 'end-1c')
        lines = content.split('\n')
        
        # Parse rules from editor
        edited_rules = []
        errors = []
        warnings = []
        undefined_vars = set()
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Blank line
            if not line_stripped:
                blank_rule = SuricataRule()
                blank_rule.is_blank = True
                edited_rules.append(blank_rule)
                continue
            
            # Comment line
            if line_stripped.startswith('#'):
                comment_rule = SuricataRule()
                comment_rule.is_comment = True
                comment_rule.comment_text = line
                edited_rules.append(comment_rule)
                continue
            
            # Try to parse as rule
            try:
                rule = SuricataRule.from_string(line)
                if rule:
                    # Basic validation
                    error_found = False
                    
                    # Validate action
                    if rule.action.lower() not in ['pass', 'alert', 'drop', 'reject']:
                        errors.append((i, f"Invalid action: {rule.action}"))
                        error_found = True
                    
                    # Validate protocol
                    if rule.protocol.lower() not in [p.lower() for p in SuricataConstants.SUPPORTED_PROTOCOLS]:
                        errors.append((i, f"Invalid protocol: {rule.protocol}"))
                        error_found = True
                    
                    # Check for undefined variables
                    for field in [rule.src_net, rule.dst_net, rule.src_port, rule.dst_port]:
                        if field.startswith(('$', '@')) and field not in self.variables:
                            undefined_vars.add(field)
                            warnings.append((i, f"Undefined variable: {field}"))
                    
                    if error_found:
                        # Comment out the rule
                        comment_rule = SuricataRule()
                        comment_rule.is_comment = True
                        comment_rule.comment_text = f"# [SYNTAX ERROR] {line}"
                        edited_rules.append(comment_rule)
                    else:
                        edited_rules.append(rule)
                else:
                    errors.append((i, "Failed to parse rule"))
                    comment_rule = SuricataRule()
                    comment_rule.is_comment = True
                    comment_rule.comment_text = f"# [SYNTAX ERROR] {line}"
                    edited_rules.append(comment_rule)
            except Exception as e:
                errors.append((i, f"Parse error: {str(e)}"))
                comment_rule = SuricataRule()
                comment_rule.is_comment = True
                comment_rule.comment_text = f"# [SYNTAX ERROR] {line}"
                edited_rules.append(comment_rule)
        
        return edited_rules, errors, warnings, undefined_vars
    
    def on_ok(self):
        """Handle OK button click"""
        # Validate and parse rules
        parsed_rules, errors, warnings, undefined_vars = self.validate_and_parse_rules()
        
        # Show validation results if there are issues
        if errors or warnings:
            report = "Validation Results:\n\n"
            
            if errors:
                report += "ERRORS (rules commented out):\n"
                for line_num, error_msg in errors[:10]:  # Show first 10
                    report += f"- Line {line_num}: {error_msg}\n"
                if len(errors) > 10:
                    report += f"... and {len(errors) - 10} more errors\n"
                report += "\n"
            
            if warnings:
                report += "WARNINGS (rules preserved):\n"
                for line_num, warning_msg in warnings[:10]:
                    report += f"- Line {line_num}: {warning_msg}\n"
                if len(warnings) > 10:
                    report += f"... and {len(warnings) - 10} more warnings\n"
                report += "\n"
            
            if undefined_vars:
                report += f"Undefined variables will be auto-created:\n"
                for var in sorted(list(undefined_vars)[:5]):
                    report += f"- {var}\n"
                if len(undefined_vars) > 5:
                    report += f"... and {len(undefined_vars) - 5} more\n"
                report += "\n"
            
            report += "Continue with these changes?"
            
            if not messagebox.askyesno("Validation Results", report, parent=self.dialog):
                return
        
        # Auto-create undefined variables
        for var in undefined_vars:
            if var not in self.variables:
                self.variables[var] = ""
        
        # Set result
        self.result = parsed_rules
        self.dialog.destroy()
    
    def on_cancel(self):
        """Handle Cancel button click"""
        if self.modified:
            if not messagebox.askyesno("Unsaved Changes",
                                      "You have unsaved changes in the Advanced Editor. Discard all changes?",
                                      parent=self.dialog):
                return
        
        self.result = None
        self.dialog.destroy()
    
    def show_tooltip_at_index(self, index):
        """Show tooltip at the given text index if there's an error/warning"""
        # Check if there's an error or warning tag at this position
        tags = self.text_widget.tag_names(index)
        
        if 'error' not in tags and 'warning' not in tags:
            return
        
        # Get the line content and position
        line_num = int(index.split('.')[0])
        col_num = int(index.split('.')[1])
        line_content = self.text_widget.get(f'{line_num}.0', f'{line_num}.end')
        
        # Find what word/token is at this position
        # Get all error/warning ranges on this line
        errors, warnings = self.validate_line(line_content, line_num)
        all_issues = errors + warnings
        
        # Find which issue matches this position
        tooltip_text = None
        suggestions = []
        
        for start_col, end_col, msg in all_issues:
            if start_col <= col_num < end_col:
                # Found the issue at this position
                word = line_content[start_col:end_col]
                
                # Determine what suggestions to show based on the error type
                if 'Invalid action' in msg:
                    tooltip_text = f"Invalid action: '{word}'\n\nValid actions:"
                    suggestions = ['pass', 'alert', 'drop', 'reject']
                elif 'Invalid protocol' in msg:
                    tooltip_text = f"Invalid protocol: '{word}'\n\nValid protocols:"
                    suggestions = SuricataConstants.SUPPORTED_PROTOCOLS[:10]  # Show first 10
                    if len(SuricataConstants.SUPPORTED_PROTOCOLS) > 10:
                        suggestions.append('...')
                elif 'Invalid direction' in msg:
                    tooltip_text = f"Invalid direction: '{word}'\n\nValid directions:"
                    suggestions = ['->', '<>']
                elif 'Unknown keyword' in msg:
                    tooltip_text = f"Unknown keyword: '{word}'\n\nValid keywords:"
                    if self.keywords_data:
                        known = [kw.get('name', '') for kw in self.keywords_data.get('keywords', [])]
                        suggestions = sorted(known[:15])  # Show first 15 alphabetically
                        if len(known) > 15:
                            suggestions.append('...')
                    else:
                        suggestions = ['(Load content_keywords.json for suggestions)']
                elif 'Undefined variable' in msg:
                    tooltip_text = f"Undefined variable: '{word}'\n\n{msg}"
                elif 'SID must be' in msg:
                    tooltip_text = f"{msg}\n\nSID must be between {SuricataConstants.SID_MIN}-{SuricataConstants.SID_MAX}"
                else:
                    tooltip_text = msg
                
                break
        
        if not tooltip_text:
            return
        
        # Create tooltip window
        bbox = self.text_widget.bbox(index)
        if not bbox:
            return
        
        x = self.text_widget.winfo_rootx() + bbox[0]
        y = self.text_widget.winfo_rooty() + bbox[1] + bbox[3] + 5  # 5px below
        
        self.tooltip_window = tk.Toplevel(self.dialog)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_transient(self.dialog)
        self.tooltip_window.wm_attributes('-topmost', True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        
        # Create frame with border
        frame = tk.Frame(self.tooltip_window, background='#FFFFE0', 
                        borderwidth=1, relief='solid', highlightthickness=1,
                        highlightbackground='black')
        frame.pack()
        
        # Add text
        label = tk.Label(frame, text=tooltip_text, justify=tk.LEFT,
                        background='#FFFFE0', foreground='black',
                        font=('Consolas', 9), padx=8, pady=5)
        label.pack()
        
        # Add suggestions if any
        if suggestions:
            for suggestion in suggestions:
                sugg_label = tk.Label(frame, text=f"  • {suggestion}", justify=tk.LEFT,
                                     background='#FFFFE0', foreground='#0066CC',
                                     font=('Consolas', 9), padx=8, pady=2)
                sugg_label.pack(anchor='w')
        
        # Force the window to update and display
        self.tooltip_window.update_idletasks()
        self.tooltip_window.deiconify()
        self.tooltip_window.lift()
    
    def dismiss_tooltip(self):
        """Dismiss the tooltip if visible"""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None
    
    def on_text_scroll(self, *args):
        """Handle text widget scroll to sync line numbers"""
        # Scroll the text widget
        self.text_widget.yview(*args)
        # Sync line numbers
        self.line_numbers.yview_moveto(args[1] if len(args) > 1 else args[0])
    
    def on_text_yscroll(self, *args):
        """Handle text widget yscroll callback to sync line numbers and scrollbar"""
        # Update the scrollbar
        if hasattr(self, 'v_scrollbar'):
            self.v_scrollbar.set(*args)
        # Sync line numbers with text widget
        self.line_numbers.yview_moveto(args[0])
    
    def cut_text(self):
        """Cut selected text to clipboard"""
        try:
            # Get selected text
            selected_text = self.text_widget.selection_get()
            # Copy to clipboard
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(selected_text)
            # Delete selected text
            self.text_widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            pass  # No selection
        return 'break'  # Prevent default handler from running
    
    def copy_text(self):
        """Copy selected text to clipboard"""
        try:
            # Get selected text
            selected_text = self.text_widget.selection_get()
            # Copy to clipboard
            self.dialog.clipboard_clear()
            self.dialog.clipboard_append(selected_text)
        except tk.TclError:
            pass  # No selection
        return 'break'  # Prevent default handler from running
    
    def paste_text(self):
        """Paste text from clipboard"""
        try:
            # Get clipboard content
            clipboard_content = self.dialog.clipboard_get()
            # Delete selection if any
            try:
                self.text_widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
            except tk.TclError:
                pass  # No selection
            # Insert at cursor position
            self.text_widget.insert('insert', clipboard_content)
        except tk.TclError:
            pass  # No clipboard content
        return 'break'  # Prevent default handler from running (fixes double paste bug)
    
    def select_all_text(self):
        """Select all text in the editor"""
        self.text_widget.tag_add(tk.SEL, '1.0', 'end-1c')
        self.text_widget.mark_set('insert', 'end-1c')
        self.text_widget.see('insert')
    
    def on_escape_key(self):
        """Handle Escape key - close search or dismiss autocomplete"""
        # If search is active, close it first
        if self.search_active:
            self.close_search()
            return 'break'
        # Otherwise dismiss autocomplete
        return self.dismiss_autocomplete(suppress=True)
    
    def show_find_replace_dialog(self):
        """Show unified Find and Replace dialog"""
        dialog = tk.Toplevel(self.dialog)
        dialog.title("Find and Replace")
        dialog.geometry("600x750")
        dialog.transient(self.dialog)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.dialog.winfo_rootx() + 200, self.dialog.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Search term section
        search_frame = ttk.LabelFrame(main_frame, text="Search Term")
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(search_frame, text="Find what:").pack(anchor=tk.W, padx=10, pady=(10, 5))
        search_var = tk.StringVar(value=self.search_term)
        entry = ttk.Entry(search_frame, textvariable=search_var, width=50)
        entry.pack(fill=tk.X, padx=10, pady=(0, 10))
        entry.focus()
        entry.select_range(0, tk.END)
        
        # Replace section (always shown now)
        ttk.Label(search_frame, text="Replace with:").pack(anchor=tk.W, padx=10, pady=(5, 5))
        replace_var = tk.StringVar(value="")
        replace_entry = ttk.Entry(search_frame, textvariable=replace_var, width=50)
        replace_entry.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Field-specific search section
        field_frame = ttk.LabelFrame(main_frame, text="Field-Specific Search")
        field_frame.pack(fill=tk.X, pady=(0, 10))
        
        search_field_var = tk.StringVar(value="all")
        field_options = [
            ("All fields", "all"),
            ("Message", "message"),
            ("Content", "content"),
            ("Networks (src/dst)", "networks"),
            ("Ports (src/dst)", "ports"),
            ("SID", "sid"),
            ("Protocol", "protocol")
        ]
        
        field_combo_frame = ttk.Frame(field_frame)
        field_combo_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(field_combo_frame, text="Search in:").pack(side=tk.LEFT)
        # Create combobox with display values (no textvariable to avoid mismatch)
        field_combo = ttk.Combobox(field_combo_frame, 
                                  values=[opt[0] for opt in field_options], state="readonly", width=20)
        field_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        # Set default to "All fields" (index 0)
        field_combo.current(0)
        
        # Action-based filtering section
        action_frame = ttk.LabelFrame(main_frame, text="Action-Based Filtering")
        action_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create BooleanVars for filters
        filter_vars = {
            'pass': tk.BooleanVar(value=self.search_filters['pass']),
            'drop': tk.BooleanVar(value=self.search_filters['drop']),
            'reject': tk.BooleanVar(value=self.search_filters['reject']),
            'alert': tk.BooleanVar(value=self.search_filters['alert']),
            'comments': tk.BooleanVar(value=self.search_filters['comments'])
        }
        
        # Arrange checkboxes in a grid
        checkbox_frame = ttk.Frame(action_frame)
        checkbox_frame.pack(padx=10, pady=10)
        
        ttk.Checkbutton(checkbox_frame, text="Pass rules", variable=filter_vars['pass']).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Checkbutton(checkbox_frame, text="Drop rules", variable=filter_vars['drop']).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(checkbox_frame, text="Reject rules", variable=filter_vars['reject']).grid(row=1, column=0, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        ttk.Checkbutton(checkbox_frame, text="Alert rules", variable=filter_vars['alert']).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        ttk.Checkbutton(checkbox_frame, text="Comments", variable=filter_vars['comments']).grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
        
        # Select/Deselect all buttons
        select_frame = ttk.Frame(action_frame)
        select_frame.pack(padx=10, pady=(0, 10))
        
        def select_all():
            for var in filter_vars.values():
                var.set(True)
        
        def deselect_all():
            for var in filter_vars.values():
                var.set(False)
        
        ttk.Button(select_frame, text="Select All", command=select_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(select_frame, text="Deselect All", command=deselect_all).pack(side=tk.LEFT)
        
        # Advanced search options section
        advanced_frame = ttk.LabelFrame(main_frame, text="Advanced Search Options")
        advanced_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create BooleanVars for options
        option_vars = {
            'case_sensitive': tk.BooleanVar(value=self.search_options['case_sensitive']),
            'whole_word': tk.BooleanVar(value=self.search_options['whole_word']),
            'regex': tk.BooleanVar(value=self.search_options['regex'])
        }
        
        options_frame = ttk.Frame(advanced_frame)
        options_frame.pack(padx=10, pady=10)
        
        ttk.Checkbutton(options_frame, text="Case sensitive", variable=option_vars['case_sensitive']).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Checkbutton(options_frame, text="Whole word matching", variable=option_vars['whole_word']).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Regular expression", variable=option_vars['regex']).grid(row=1, column=0, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        
        # Add "Include comments" checkbox
        include_comments_var = tk.BooleanVar(value=self.search_filters.get('comments', True))
        ttk.Checkbutton(options_frame, text="Include comments", variable=include_comments_var).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def on_find_next():
            """Find next match without replacing - dynamically updates if filters changed"""
            term = search_var.get().strip()
            if not term:
                messagebox.showwarning("Find", "Please enter a search term.", parent=dialog)
                return
            
            # Update replace term
            replace_text = replace_var.get() if replace_var else ""
            self.replace_term = replace_text
            
            # Check if search term or field changed
            field_index = field_combo.current()
            new_field = field_options[field_index][1] if field_index >= 0 else "all"
            
            # Check if any filters changed
            filters_changed = False
            for key in self.search_filters:
                if self.search_filters[key] != filter_vars[key].get():
                    filters_changed = True
                    break
            
            # Check if search options changed
            if not filters_changed:
                for key in self.search_options:
                    if key in option_vars and self.search_options[key] != option_vars[key].get():
                        filters_changed = True
                        break
            
            # Check if include_comments changed
            if not filters_changed and self.search_filters.get('comments', True) != include_comments_var.get():
                filters_changed = True
            
            # If search hasn't been performed yet, search term/field changed, or filters changed, perform new search
            if not self.search_active or self.search_term != term or self.search_field != new_field or filters_changed:
                self.search_term = term
                self.search_field = new_field
                
                # Update search filters and options
                for key in self.search_filters:
                    self.search_filters[key] = filter_vars[key].get()
                for key in self.search_options:
                    self.search_options[key] = option_vars[key].get()
                
                # Update include comments setting
                self.search_filters['comments'] = include_comments_var.get()
                
                # Perform search to highlight first match
                self.perform_search()
                return
            
            # Search is already active and nothing changed - move to next match
            if self.search_results:
                self.find_next()
            else:
                messagebox.showinfo("Find", "No matches found.", parent=dialog)
        
        def on_replace():
            """Replace current match and move to next - dynamically updates if filters changed"""
            term = search_var.get().strip()
            replace_text = replace_var.get() if replace_var else ""
            if not term:
                messagebox.showwarning("Replace", "Please enter a search term.", parent=dialog)
                return
            
            # Update replace term
            self.replace_term = replace_text
            
            # Check if search term or field changed
            field_index = field_combo.current()
            new_field = field_options[field_index][1] if field_index >= 0 else "all"
            
            # Check if any filters changed
            filters_changed = False
            for key in self.search_filters:
                if self.search_filters[key] != filter_vars[key].get():
                    filters_changed = True
                    break
            
            if not filters_changed:
                for key in self.search_options:
                    if key in option_vars and self.search_options[key] != option_vars[key].get():
                        filters_changed = True
                        break
            
            # Check if include_comments changed
            if not filters_changed and self.search_filters.get('comments', True) != include_comments_var.get():
                filters_changed = True
            
            # If search hasn't been performed yet, search term/field changed, or filters changed, just highlight first match (don't replace)
            if not self.search_active or self.search_term != term or self.search_field != new_field or filters_changed:
                self.search_term = term
                self.search_field = new_field
                
                # Update search filters and options
                for key in self.search_filters:
                    self.search_filters[key] = filter_vars[key].get()
                for key in self.search_options:
                    self.search_options[key] = option_vars[key].get()
                
                # Update include comments setting
                self.search_filters['comments'] = include_comments_var.get()
                
                # Perform search to highlight first match (don't replace yet)
                self.perform_search()
                # Dialog stays open, user can now review first match and decide to replace or skip
                return
            
            # Search is already active and nothing changed - replace current match and move to next
            if self.search_results and self.current_search_index >= 0:
                self.replace_current()
                # Dialog stays open for next replacement
                if not self.search_results:
                    # No more matches - show message
                    messagebox.showinfo("Replace", "No more matches found. All replacements complete.", parent=dialog)
            else:
                messagebox.showinfo("Replace", "No match at current position.", parent=dialog)
        
        
        def on_replace_all():
            term = search_var.get().strip()
            replace_text = replace_var.get() if replace_var else ""
            if term:
                self.search_term = term
                self.replace_term = replace_text
                # Store the field selection
                field_index = field_combo.current()
                if field_index >= 0:
                    self.search_field = field_options[field_index][1]
                else:
                    self.search_field = "all"
                
                # Update search filters and options
                for key in self.search_filters:
                    self.search_filters[key] = filter_vars[key].get()
                for key in self.search_options:
                    self.search_options[key] = option_vars[key].get()
                
                # Update include comments setting
                self.search_filters['comments'] = include_comments_var.get()
                
                # Perform replacement
                count = self.replace_all()
                dialog.destroy()
                if count > 0:
                    messagebox.showinfo("Replace All", 
                                      f"Replaced {count} occurrences of '{self.search_term}' with '{replace_text}'.",
                                      parent=self.dialog)
                else:
                    messagebox.showinfo("Replace All",
                                      f"No occurrences found to replace.",
                                      parent=self.dialog)
            else:
                messagebox.showwarning("Replace All", "Please enter a search term.", parent=dialog)
        
        def on_find():
            """Perform find and close dialog, keeping search active for F3"""
            term = search_var.get().strip()
            if not term:
                messagebox.showwarning("Find", "Please enter a search term.", parent=dialog)
                return
            
            self.search_term = term
            self.replace_term = replace_var.get() if replace_var else ""
            
            # Store the field selection
            field_index = field_combo.current()
            if field_index >= 0:
                self.search_field = field_options[field_index][1]
            else:
                self.search_field = "all"
            
            # Update search filters and options
            for key in self.search_filters:
                self.search_filters[key] = filter_vars[key].get()
            for key in self.search_options:
                self.search_options[key] = option_vars[key].get()
            
            # Update include comments setting
            self.search_filters['comments'] = include_comments_var.get()
            
            # Perform search
            self.perform_search()
            
            # Show F3 navigation message only when Find button is used
            if self.search_results:
                messagebox.showinfo("Search", 
                                  f"Found {len(self.search_results)} matches for '{self.search_term}'.\n\n"
                                  "Press F3 for next, Shift+F3 for previous, Escape to close.", 
                                  parent=self.dialog)
            
            # Close dialog but keep search active
            dialog.destroy()
        
        def on_cancel():
            # Clear search when closing with Close button
            self.close_search()
            dialog.destroy()
        
        # Add buttons (always show all buttons since this is unified dialog)
        ttk.Button(button_frame, text="Replace All", command=on_replace_all).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Replace", command=on_replace).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Find Next", command=on_find_next).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Find", command=on_find).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Close", command=on_cancel).pack(side=tk.RIGHT)
        
        # Handle window close button (X) - same as Close button
        dialog.protocol("WM_DELETE_WINDOW", on_cancel)
        
        # Bind Enter key to Find
        dialog.bind('<Return>', lambda e: on_find())
        
        return 'break'
    
    def perform_search(self):
        """Perform search with current settings"""
        if not self.search_term:
            return
        
        # Clear previous search results
        self.clear_search_highlights()
        self.search_results = []
        self.current_search_index = -1
        
        # Get all content
        content = self.text_widget.get('1.0', 'end-1c')
        lines = content.split('\n')
        
        # Compile regex pattern if needed
        regex_pattern = None
        if self.search_options['regex']:
            try:
                flags = 0 if self.search_options['case_sensitive'] else re.IGNORECASE
                regex_pattern = re.compile(self.search_term, flags)
            except re.error as e:
                messagebox.showerror("Regex Error", f"Invalid regular expression: {str(e)}", parent=self.dialog)
                return
        
        # Prepare search term
        search_term = self.search_term
        if not self.search_options['case_sensitive']:
            search_term = search_term.lower()
        
        # Search through lines
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip blank lines
            if not line_stripped:
                continue
            
            # Check if this is a comment
            is_comment = line_stripped.startswith('#')
            
            # Apply action filters
            if is_comment:
                if not self.search_filters['comments']:
                    continue
            else:
                # Parse line to get action
                tokens = line_stripped.split()
                if tokens:
                    action = tokens[0].lower()
                    if action not in ['pass', 'drop', 'reject', 'alert']:
                        continue  # Invalid action, skip
                    if not self.search_filters.get(action, True):
                        continue  # Filtered out by action
            
            # Determine which part of the line to search based on field filter
            search_text = self.get_search_text_from_line(line, line_stripped, is_comment)
            if search_text is None:
                continue  # This field doesn't apply to this line
            
            # Check if the search text actually contains the search term
            # before performing detailed match finding
            search_text_lower = search_text.lower() if not self.search_options['case_sensitive'] else search_text
            search_term_lower = search_term
            
            # Quick check: does this line contain the search term at all?
            if regex_pattern:
                if not regex_pattern.search(search_text):
                    continue  # No match in this field
            elif self.search_options['whole_word']:
                pattern = r'\b' + re.escape(self.search_term) + r'\b'
                flags = 0 if self.search_options['case_sensitive'] else re.IGNORECASE
                if not re.search(pattern, search_text, flags):
                    continue  # No match in this field
            else:
                if search_term_lower not in search_text_lower:
                    continue  # No match in this field
            
            # Perform the detailed search to find exact positions
            matches = self.find_matches_in_text(search_text, line, line_num, regex_pattern)
            self.search_results.extend(matches)
        
        # Show results - only show message if no results found
        if self.search_results:
            self.search_active = True
            self.current_search_index = 0
            self.highlight_current_match()
        else:
            self.search_active = False
            messagebox.showinfo("Search", f"No results found for '{self.search_term}' with current filters.", 
                              parent=self.dialog)
    
    def get_search_text_from_line(self, line, line_stripped, is_comment):
        """Extract the appropriate text to search based on field filter"""
        if is_comment:
            return line if self.search_field == "all" else line if self.search_field == "message" else None
        
        # For rules, parse components
        if self.search_field == "all":
            return line
        
        # Parse the rule to extract specific fields
        try:
            # Simple parsing for field extraction
            tokens = line_stripped.split()
            if len(tokens) < 7:
                return None  # Incomplete rule
            
            # Extract fields by position
            action = tokens[0]
            protocol = tokens[1]
            src_net = tokens[2]
            src_port = tokens[3]
            dst_net = tokens[5]
            dst_port = tokens[6]
            
            # Extract message and content from options section
            message = ""
            content = ""
            sid = ""
            
            if '(' in line and ')' in line:
                options_start = line.find('(')
                options_end = line.rfind(')')
                options_section = line[options_start+1:options_end]
                
                # Extract message
                msg_match = re.search(r'msg:"([^"]*)"', options_section)
                if msg_match:
                    message = msg_match.group(1)
                
                # Extract SID
                sid_match = re.search(r'sid:(\d+)', options_section)
                if sid_match:
                    sid = sid_match.group(1)
                
                # Content is everything else (simplified)
                content = options_section
            
            # Return appropriate field
            if self.search_field == "message":
                return message
            elif self.search_field == "content":
                return content
            elif self.search_field == "networks":
                return f"{src_net} {dst_net}"
            elif self.search_field == "ports":
                return f"{src_port} {dst_port}"
            elif self.search_field == "sid":
                return sid
            elif self.search_field == "protocol":
                return protocol
        except:
            return None
        
        return line  # Fallback
    
    def find_matches_in_text(self, search_text, original_line, line_num, regex_pattern):
        """Find all matches of search term in the given text
        
        Args:
            search_text: The text to search in (may be a field or full line)
            original_line: The original full line (for position calculation)
            line_num: Line number
            regex_pattern: Compiled regex pattern if regex mode is active
        
        Returns:
            List of (line_num, start_col, end_col, matched_text) tuples
        """
        matches = []
        
        # Determine if we're searching a specific field or the whole line
        searching_full_line = (self.search_field == "all")
        
        if regex_pattern:
            # Regex search - search in the filtered search_text
            for match in regex_pattern.finditer(search_text if not searching_full_line else original_line):
                if searching_full_line:
                    start_col = match.start()
                    end_col = match.end()
                    matched_text = match.group(0)
                    matches.append((line_num, start_col, end_col, matched_text))
                else:
                    # Field-specific: find position of this field text in original line
                    field_match_start = original_line.find(search_text)
                    if field_match_start >= 0:
                        start_col = field_match_start + match.start()
                        end_col = field_match_start + match.end()
                        matched_text = match.group(0)
                        matches.append((line_num, start_col, end_col, matched_text))
        elif self.search_options['whole_word']:
            # Whole word matching
            pattern = r'\b' + re.escape(self.search_term) + r'\b'
            flags = 0 if self.search_options['case_sensitive'] else re.IGNORECASE
            text_to_search = original_line if searching_full_line else search_text
            for match in re.finditer(pattern, text_to_search, flags):
                if searching_full_line:
                    start_col = match.start()
                    end_col = match.end()
                    matched_text = match.group(0)
                    matches.append((line_num, start_col, end_col, matched_text))
                else:
                    # Field-specific: find position of field in original line
                    field_match_start = original_line.find(search_text)
                    if field_match_start >= 0:
                        start_col = field_match_start + match.start()
                        end_col = field_match_start + match.end()
                        matched_text = match.group(0)
                        matches.append((line_num, start_col, end_col, matched_text))
        else:
            # Simple substring search
            text_to_search = original_line if searching_full_line else search_text
            search_in = text_to_search
            if not self.search_options['case_sensitive']:
                search_in = text_to_search.lower()
            
            search_term = self.search_term
            if not self.search_options['case_sensitive']:
                search_term = search_term.lower()
            
            start_pos = 0
            while True:
                pos = search_in.find(search_term, start_pos)
                if pos == -1:
                    break
                if searching_full_line:
                    start_col = pos
                    end_col = pos + len(self.search_term)
                    matched_text = original_line[pos:end_col]
                    matches.append((line_num, start_col, end_col, matched_text))
                else:
                    # Field-specific: find position of field in original line
                    field_match_start = original_line.find(search_text)
                    if field_match_start >= 0:
                        start_col = field_match_start + pos
                        end_col = field_match_start + pos + len(self.search_term)
                        matched_text = original_line[start_col:end_col]
                        matches.append((line_num, start_col, end_col, matched_text))
                start_pos = pos + 1  # Move past this match
        
        return matches
    
    def highlight_current_match(self):
        """Highlight current match and show all other matches"""
        if not self.search_results or self.current_search_index < 0:
            return
        
        # Clear all search highlights
        self.text_widget.tag_remove('search_current', '1.0', 'end')
        self.text_widget.tag_remove('search_other', '1.0', 'end')
        
        # Highlight all matches in gray
        for i, (line_num, start_col, end_col, matched_text) in enumerate(self.search_results):
            start_idx = f'{line_num}.{start_col}'
            end_idx = f'{line_num}.{end_col}'
            self.text_widget.tag_add('search_other', start_idx, end_idx)
        
        # Highlight current match in yellow
        current_match = self.search_results[self.current_search_index]
        line_num, start_col, end_col, matched_text = current_match
        start_idx = f'{line_num}.{start_col}'
        end_idx = f'{line_num}.{end_col}'
        self.text_widget.tag_add('search_current', start_idx, end_idx)
        
        # Scroll to show current match
        self.text_widget.see(start_idx)
        
        # Update status bar
        self.update_status_bar()
    
    def find_next(self):
        """Find next search result"""
        if not self.search_active or not self.search_results:
            if not self.search_term:
                self.show_find_replace_dialog()
            return 'break'
        
        # Move to next result with wraparound
        self.current_search_index = (self.current_search_index + 1) % len(self.search_results)
        self.highlight_current_match()
        
        return 'break'
    
    def find_previous(self):
        """Find previous search result"""
        if not self.search_active or not self.search_results:
            if not self.search_term:
                self.show_find_replace_dialog()
            return 'break'
        
        # Move to previous result with wraparound
        self.current_search_index = (self.current_search_index - 1) % len(self.search_results)
        self.highlight_current_match()
        
        return 'break'
    
    def clear_search_highlights(self):
        """Clear all search highlights"""
        self.text_widget.tag_remove('search_current', '1.0', 'end')
        self.text_widget.tag_remove('search_other', '1.0', 'end')
    
    def close_search(self):
        """Close search mode and clear highlights"""
        self.search_active = False
        self.search_results = []
        self.current_search_index = -1
        self.clear_search_highlights()
        self.update_status_bar()
    
    def replace_current(self):
        """Replace the current search match"""
        if not self.search_results or self.current_search_index < 0:
            return
        
        # Get current match
        line_num, start_col, end_col, matched_text = self.search_results[self.current_search_index]
        start_idx = f'{line_num}.{start_col}'
        end_idx = f'{line_num}.{end_col}'
        
        # Calculate the position shift (difference between replacement and original text length)
        position_shift = len(self.replace_term) - len(matched_text)
        
        # Delete the matched text
        self.text_widget.delete(start_idx, end_idx)
        
        # Insert replacement text
        self.text_widget.insert(start_idx, self.replace_term)
        
        # Update positions of all remaining matches on the same line
        if position_shift != 0:
            for i in range(self.current_search_index + 1, len(self.search_results)):
                match_line_num, match_start_col, match_end_col, match_text = self.search_results[i]
                if match_line_num == line_num:
                    # Update positions for matches on the same line
                    self.search_results[i] = (
                        match_line_num,
                        match_start_col + position_shift,
                        match_end_col + position_shift,
                        match_text
                    )
        
        # Remove the current match from results
        del self.search_results[self.current_search_index]
        
        # If there are more results, stay at same index (which is now the next match)
        # Otherwise, close search
        if self.search_results:
            # Adjust index if we were at the end
            if self.current_search_index >= len(self.search_results):
                self.current_search_index = 0
            self.highlight_current_match()
        else:
            self.close_search()
            messagebox.showinfo("Replace", "No more matches found.", parent=self.dialog)
    
    def replace_all(self):
        """Replace all search matches
        
        Returns:
            int: Number of replacements made
        """
        if not self.search_term:
            return 0
        
        # Perform search first if not already done
        if not self.search_results:
            self.perform_search()
        
        if not self.search_results:
            return 0
        
        # Replace all matches in reverse order (from end to start)
        # This prevents position shifts from affecting subsequent replacements
        replace_count = 0
        for line_num, start_col, end_col, matched_text in reversed(self.search_results):
            start_idx = f'{line_num}.{start_col}'
            end_idx = f'{line_num}.{end_col}'
            
            # Delete the matched text
            self.text_widget.delete(start_idx, end_idx)
            
            # Insert replacement text
            self.text_widget.insert(start_idx, self.replace_term)
            replace_count += 1
        
        # Clear search state
        self.close_search()
        
        return replace_count
    
    def toggle_comment(self):
        """Toggle comment status for selected lines or current line"""
        try:
            # Check if there's a selection
            try:
                sel_start = self.text_widget.index(tk.SEL_FIRST)
                sel_end = self.text_widget.index(tk.SEL_LAST)
                has_selection = True
            except tk.TclError:
                has_selection = False
            
            if has_selection:
                # Get the range of selected lines
                start_line = int(sel_start.split('.')[0])
                end_line = int(sel_end.split('.')[0])
                
                # If selection ends at column 0 of a line, don't include that line
                if sel_end.split('.')[1] == '0' and end_line > start_line:
                    end_line -= 1
            else:
                # No selection - use current line
                cursor_pos = self.text_widget.index('insert')
                start_line = int(cursor_pos.split('.')[0])
                end_line = start_line
            
            # Check if all selected lines are comments
            all_comments = True
            for line_num in range(start_line, end_line + 1):
                line_content = self.text_widget.get(f'{line_num}.0', f'{line_num}.end')
                line_stripped = line_content.lstrip()
                if line_stripped and not line_stripped.startswith('#'):
                    all_comments = False
                    break
            
            # Toggle comments for each line
            for line_num in range(start_line, end_line + 1):
                line_content = self.text_widget.get(f'{line_num}.0', f'{line_num}.end')
                line_stripped = line_content.lstrip()
                
                if not line_stripped:
                    # Skip blank lines
                    continue
                
                if all_comments:
                    # Uncomment: remove # and one space if present
                    if line_stripped.startswith('# '):
                        # Remove "# " (hash and space)
                        new_line = line_content.replace('# ', '', 1)
                    elif line_stripped.startswith('#'):
                        # Remove just "#" (no space)
                        new_line = line_content.replace('#', '', 1)
                    else:
                        # Already uncommented
                        continue
                else:
                    # Comment: add # and space at the start
                    # Find the position of first non-whitespace character
                    leading_spaces = len(line_content) - len(line_stripped)
                    new_line = line_content[:leading_spaces] + '# ' + line_stripped
                
                # Replace the line
                self.text_widget.delete(f'{line_num}.0', f'{line_num}.end')
                self.text_widget.insert(f'{line_num}.0', new_line)
            
            # Restore selection if there was one
            if has_selection:
                self.text_widget.tag_add(tk.SEL, f'{start_line}.0', f'{end_line}.end')
            
        except Exception as e:
            messagebox.showerror("Comment Toggle Error", f"Error toggling comments: {str(e)}", parent=self.dialog)
        
        return 'break'
    
    def show_keyboard_shortcuts(self):
        """Display keyboard shortcuts for the Advanced Editor"""
        shortcuts_dialog = tk.Toplevel(self.dialog)
        shortcuts_dialog.title("Advanced Editor - Keyboard Shortcuts")
        shortcuts_dialog.geometry("650x550")
        shortcuts_dialog.transient(self.dialog)
        shortcuts_dialog.grab_set()
        shortcuts_dialog.resizable(False, False)
        
        # Center the dialog
        shortcuts_dialog.geometry("+%d+%d" % (self.dialog.winfo_rootx() + 100, self.dialog.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(shortcuts_dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Editor Keyboard Shortcuts", 
                               font=("TkDefaultFont", 14, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Create text widget with scrollbar for shortcuts
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("TkDefaultFont", 10),
                             bg=shortcuts_dialog.cget('bg'), relief=tk.FLAT, cursor="arrow")
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
            ("Clipboard Operations", [
                ("Ctrl+X", "Cut selected text"),
                ("Ctrl+C", "Copy selected text"),
                ("Ctrl+V", "Paste from clipboard"),
                ("Ctrl+A", "Select all text"),
            ]),
            ("Editing", [
                ("Ctrl+Z", "Undo last change"),
                ("Ctrl+Y", "Redo last undone change"),
                ("Ctrl+/", "Toggle comment for selected lines"),
                ("Tab", "Accept autocomplete or jump to next position in rule options"),
            ]),
            ("Search and Replace", [
                ("Ctrl+F", "Open Find and Replace dialog"),
                ("F3", "Find next match"),
                ("Shift+F3", "Find previous match"),
                ("Escape", "Close search and clear highlights"),
            ]),
            ("Navigation", [
                ("Ctrl+G", "Go to line number"),
                ("Home/End", "Move to start/end of line"),
                ("Ctrl+Home/End", "Move to start/end of document"),
                ("Page Up/Down", "Scroll by page"),
            ]),
            ("Auto-Complete", [
                ("Ctrl+Space", "Manually trigger auto-complete"),
                ("Up/Down", "Navigate auto-complete suggestions"),
                ("Enter or Tab", "Accept selected suggestion"),
                ("Escape", "Dismiss auto-complete"),
            ]),
            ("Special Features", [
                ("(, [, \"", "Auto-close brackets and quotes"),
                ("Hover over error", "Show error tooltip with suggestions"),
                ("Right-click", "Show context menu"),
            ]),
        ]
        
        # Insert shortcuts into text widget
        for category, shortcuts_list in shortcuts:
            # Category header
            text_widget.insert(tk.END, f"{category}\n", "category")
            
            # Shortcuts in this category
            for shortcut, description in shortcuts_list:
                text_widget.insert(tk.END, f"  {shortcut:<25}", "shortcut")
                text_widget.insert(tk.END, f"{description}\n", "description")
            
            text_widget.insert(tk.END, "\n")
        
        # Make text widget read-only
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        ttk.Button(button_frame, text="Close", command=shortcuts_dialog.destroy).pack(side=tk.RIGHT)
        
        # Focus on dialog
        shortcuts_dialog.focus_set()
    
    def toggle_dark_mode(self):
        """Toggle dark mode on/off"""
        self.dark_mode = self.dark_mode_var.get()
        self.apply_theme()
    
    def apply_theme(self):
        """Apply the current theme (light or dark) to all UI elements"""
        if self.dark_mode:
            # Dark mode colors
            bg_color = '#1E1E1E'
            fg_color = '#D4D4D4'
            line_num_bg = '#252526'
            line_num_fg = '#858585'
            cursor_color = '#AEAFAD'
            selection_bg = '#264F78'
            selection_fg = '#FFFFFF'
            
            # Apply to text widget
            self.text_widget.config(
                background=bg_color,
                foreground=fg_color,
                insertbackground=cursor_color,
                selectbackground=selection_bg,
                selectforeground=selection_fg
            )
            
            # Apply to line numbers
            self.line_numbers.config(
                background=line_num_bg,
                foreground=line_num_fg
            )
            
            # Status bar labels - keep text colors unchanged (don't modify)
            
            # Reconfigure tags for dark mode
            self.text_widget.tag_config('error', underline=True, underlinefg='#F48771', background='#5A1D1D')
            self.text_widget.tag_config('warning', underline=True, underlinefg='#F0AD4E', background='#5A4A1D')
            self.text_widget.tag_config('search_current', background='#4A4A00')  # Darker yellow
            self.text_widget.tag_config('search_other', background='#3A3A3A')    # Dark gray
        else:
            # Light mode colors (original)
            bg_color = '#FFFFFF'
            fg_color = '#000000'
            line_num_bg = '#F0F0F0'
            line_num_fg = '#000000'
            cursor_color = '#000000'
            selection_bg = '#0078D7'
            selection_fg = '#FFFFFF'
            
            # Apply to text widget
            self.text_widget.config(
                background=bg_color,
                foreground=fg_color,
                insertbackground=cursor_color,
                selectbackground=selection_bg,
                selectforeground=selection_fg
            )
            
            # Apply to line numbers
            self.line_numbers.config(
                background=line_num_bg,
                foreground=line_num_fg
            )
            
            # Status bar labels - keep text colors unchanged (don't modify)
            
            # Reconfigure tags for light mode (original)
            self.text_widget.tag_config('error', underline=True, underlinefg='red', background='#FFE6E6')
            self.text_widget.tag_config('warning', underline=True, underlinefg='orange', background='#FFF4E6')
            self.text_widget.tag_config('search_current', background='#FFFF00')  # Yellow
            self.text_widget.tag_config('search_other', background='#E0E0E0')    # Light gray
    
    def on_window_close(self):
        """Handle window close (X button)"""
        self.dismiss_tooltip()
        self.on_cancel()
