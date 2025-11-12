import tkinter as tk
from tkinter import ttk, messagebox
import re
from typing import List

class SearchManager:
    """Manages all search functionality for the Suricata Rule Generator"""
    
    def __init__(self, parent_app):
        """Initialize SearchManager with reference to parent application
        
        Args:
            parent_app: Reference to main SuricataRuleGenerator instance
        """
        self.parent = parent_app
        
        # Search state variables
        self.search_term = ""
        self.search_results = []
        self.current_search_index = -1
        self.search_active = False
        self.search_field = "all"
        
        # Search configuration variables
        self.search_filters = {
            'pass': tk.BooleanVar(value=True),
            'drop': tk.BooleanVar(value=True),
            'reject': tk.BooleanVar(value=True),
            'alert': tk.BooleanVar(value=True),
            'comments': tk.BooleanVar(value=True)
        }
        
        self.search_options = {
            'case_sensitive': tk.BooleanVar(value=False),
            'whole_word': tk.BooleanVar(value=False),
            'regex': tk.BooleanVar(value=False),
            'include_comments': tk.BooleanVar(value=True)
        }
    
    def show_find_dialog(self):
        """Show enhanced find dialog with comprehensive search options"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Enhanced Search")
        dialog.geometry("600x600")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 100, self.parent.root.winfo_rooty() + 50))
        
        # Main frame with scrollable content
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
        field_combo = ttk.Combobox(field_combo_frame, textvariable=search_field_var, 
                                  values=[opt[1] for opt in field_options], state="readonly", width=15)
        field_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        # Set display values
        field_combo['values'] = [opt[0] for opt in field_options]
        field_combo.set("All fields")
        
        # Action-based filtering section
        action_frame = ttk.LabelFrame(main_frame, text="Action-Based Filtering")
        action_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Arrange checkboxes in a grid
        checkbox_frame = ttk.Frame(action_frame)
        checkbox_frame.pack(padx=10, pady=10)
        
        ttk.Checkbutton(checkbox_frame, text="Pass rules", variable=self.search_filters['pass']).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Checkbutton(checkbox_frame, text="Drop rules", variable=self.search_filters['drop']).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(checkbox_frame, text="Reject rules", variable=self.search_filters['reject']).grid(row=1, column=0, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        ttk.Checkbutton(checkbox_frame, text="Alert rules", variable=self.search_filters['alert']).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        ttk.Checkbutton(checkbox_frame, text="Comments", variable=self.search_filters['comments']).grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
        
        # Select/Deselect all buttons
        select_frame = ttk.Frame(action_frame)
        select_frame.pack(padx=10, pady=(0, 10))
        
        def select_all():
            for var in self.search_filters.values():
                var.set(True)
        
        def deselect_all():
            for var in self.search_filters.values():
                var.set(False)
        
        ttk.Button(select_frame, text="Select All", command=select_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(select_frame, text="Deselect All", command=deselect_all).pack(side=tk.LEFT)
        
        # Advanced search options section
        advanced_frame = ttk.LabelFrame(main_frame, text="Advanced Search Options")
        advanced_frame.pack(fill=tk.X, pady=(0, 10))
        
        options_frame = ttk.Frame(advanced_frame)
        options_frame.pack(padx=10, pady=10)
        
        ttk.Checkbutton(options_frame, text="Case sensitive", variable=self.search_options['case_sensitive']).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Checkbutton(options_frame, text="Whole word matching", variable=self.search_options['whole_word']).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(options_frame, text="Regular expression", variable=self.search_options['regex']).grid(row=1, column=0, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        ttk.Checkbutton(options_frame, text="Include comments", variable=self.search_options['include_comments']).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def on_find():
            term = search_var.get().strip()
            if term:
                self.search_term = term
                # Store the field selection
                field_index = field_combo.current()
                if field_index >= 0:
                    self.search_field = field_options[field_index][1]
                else:
                    self.search_field = "all"
                self.perform_enhanced_search()
                dialog.destroy()
            else:
                messagebox.showwarning("Search", "Please enter a search term.")
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Find", command=on_find).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT)
        
        # Bind Enter key
        dialog.bind('<Return>', lambda e: on_find())
    
    def perform_enhanced_search(self):
        """Perform enhanced search with filtering options - searches all rules by default"""
        if not self.search_term:
            return
        
        # Clear previous search highlights and results
        self.clear_search_highlights()
        self.search_results = []
        self.current_search_index = -1
        
        # Get search parameters
        search_term = self.search_term
        case_sensitive = self.search_options['case_sensitive'].get()
        whole_word = self.search_options['whole_word'].get()
        regex_search = self.search_options['regex'].get()
        include_comments = self.search_options['include_comments'].get()
        search_field = self.search_field
        
        # Prepare search term based on options
        if not case_sensitive:
            search_term = search_term.lower()
        
        # Compile regex if needed
        regex_pattern = None
        if regex_search:
            try:
                flags = 0 if case_sensitive else re.IGNORECASE
                regex_pattern = re.compile(search_term, flags)
            except re.error:
                messagebox.showerror("Regex Error", "Invalid regular expression pattern.")
                return
        
        # Search through all rules
        all_items = self.parent.tree.get_children()
        for item in all_items:
            if item == self.parent.placeholder_item:
                continue  # Skip placeholder
            
            # Get rule index and rule object
            rule_index = self.parent.tree.index(item)
            if rule_index >= len(self.parent.rules):
                continue
            
            rule = self.parent.rules[rule_index]
            
            # Apply action-based filtering
            if not self.passes_action_filter(rule):
                continue
            
            # Skip comments if not included
            if getattr(rule, 'is_comment', False) and not include_comments:
                continue
            
            # Perform field-specific search
            if self.matches_search_criteria(rule, search_term, search_field, regex_pattern, whole_word, case_sensitive):
                self.search_results.append(item)
        
        # Show search results
        if self.search_results:
            self.search_active = True
            self.current_search_index = 0
            self.highlight_search_result()
            self.parent.update_status_bar()
            messagebox.showinfo("Enhanced Search", f"Found {len(self.search_results)} matches for '{self.search_term}'. Press F3 for next, Escape to close search.")
        else:
            self.search_active = False
            messagebox.showinfo("Enhanced Search", f"No results found for '{self.search_term}' with current filters.")
    
    def passes_action_filter(self, rule):
        """Check if rule passes action-based filtering"""
        if getattr(rule, 'is_comment', False):
            return self.search_filters['comments'].get()
        elif getattr(rule, 'is_blank', False):
            return True  # Always include blank lines
        else:
            # Check rule action
            action = rule.action.lower()
            return self.search_filters.get(action, tk.BooleanVar(value=True)).get()
    
    def matches_search_criteria(self, rule, search_term, search_field, regex_pattern, whole_word, case_sensitive):
        """Check if rule matches the search criteria for specified field"""
        if getattr(rule, 'is_comment', False):
            # Search in comment text
            text_to_search = rule.comment_text
            if not case_sensitive:
                text_to_search = text_to_search.lower()
            return self.perform_text_match(text_to_search, search_term, regex_pattern, whole_word)
        elif getattr(rule, 'is_blank', False):
            return False  # Blank lines don't match text searches
        else:
            # Regular rule - search in specified field
            if search_field == "message":
                text_to_search = rule.message
            elif search_field == "content":
                text_to_search = rule.content
            elif search_field == "networks":
                text_to_search = f"{rule.src_net} {rule.dst_net}"
            elif search_field == "ports":
                text_to_search = f"{rule.src_port} {rule.dst_port}"
            elif search_field == "sid":
                text_to_search = str(rule.sid)
            elif search_field == "protocol":
                text_to_search = rule.protocol
            else:  # search_field == "all"
                # Search all fields
                all_text = f"{rule.message} {rule.content} {rule.src_net} {rule.dst_net} {rule.src_port} {rule.dst_port} {rule.sid} {rule.protocol} {rule.action}"
                text_to_search = all_text
            
            # Apply case sensitivity
            if not case_sensitive:
                text_to_search = text_to_search.lower()
            
            return self.perform_text_match(text_to_search, search_term, regex_pattern, whole_word)
    
    def perform_text_match(self, text, search_term, regex_pattern, whole_word):
        """Perform text matching with various options"""
        if regex_pattern:
            # Regular expression search
            return bool(regex_pattern.search(text))
        elif whole_word:
            # Whole word matching
            word_pattern = r'\b' + re.escape(search_term) + r'\b'
            return bool(re.search(word_pattern, text, re.IGNORECASE))
        else:
            # Simple substring search
            return search_term in text
    
    def perform_search(self):
        """Perform search and highlight results"""
        if not self.search_term:
            return
        
        # Clear previous search results
        self.search_results.clear()
        self.current_search_index = -1
        
        # Search through all tree items
        all_items = self.parent.tree.get_children()
        for item in all_items:
            values = self.parent.tree.item(item, "values")
            # Search in rule data (column 2)
            if len(values) > 2 and self.search_term.lower() in values[2].lower():
                self.search_results.append(item)
        
        if self.search_results:
            self.search_active = True
            self.current_search_index = 0
            self.highlight_search_result()
            self.parent.update_status_bar()
        else:
            messagebox.showinfo("Search", f"No results found for '{self.search_term}'.")
    
    def find_next(self):
        """Find next search result"""
        if not self.search_active or not self.search_results:
            if not self.search_term:
                self.show_find_dialog()
            return
        
        self.current_search_index = (self.current_search_index + 1) % len(self.search_results)
        self.highlight_search_result()
        self.parent.update_status_bar()
    
    def highlight_search_result(self):
        """Highlight current search result"""
        if not self.search_results or self.current_search_index < 0:
            return
        
        # Clear previous highlights
        self.clear_search_highlights()
        
        # Highlight current result
        current_item = self.search_results[self.current_search_index]
        tags = list(self.parent.tree.item(current_item, "tags"))
        tags.append("search_highlight")
        self.parent.tree.item(current_item, tags=tags)
        
        # Clear selection so yellow highlight is visible
        self.parent.tree.selection_remove(self.parent.tree.selection())
        
        # Focus and scroll to item without selecting
        self.parent.tree.focus(current_item)
        self.parent.tree.see(current_item)
    
    def clear_search_highlights(self):
        """Clear all search highlights from the tree"""
        all_items = self.parent.tree.get_children()
        for item in all_items:
            current_tags = list(self.parent.tree.item(item, "tags"))
            if "search_highlight" in current_tags:
                current_tags.remove("search_highlight")
                self.parent.tree.item(item, tags=current_tags)
    
    def close_search(self):
        """Close search mode and clear highlights"""
        self.search_active = False
        self.search_results = []
        self.current_search_index = -1
        self.search_term = ""
        self.clear_search_highlights()
        self.parent.update_status_bar()
    
    def is_search_active(self):
        """Check if search is currently active"""
        return self.search_active
    
    def get_search_status(self):
        """Get current search status for status bar display"""
        if self.search_active and self.search_results:
            return f"Search: {self.current_search_index + 1} of {len(self.search_results)} matches for '{self.search_term}'"
        return None
    
    def handle_rule_selection_during_search(self, selected_item):
        """Handle rule selection when search is active - clear search if different item selected"""
        if self.search_active and self.search_results and self.current_search_index >= 0:
            current_search_item = self.search_results[self.current_search_index]
            if selected_item != current_search_item:
                self.close_search()
                return True  # Search was cleared
        return False  # Search was not cleared
