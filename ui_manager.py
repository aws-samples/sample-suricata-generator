import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import re
import os
from typing import Optional
from constants import SuricataConstants

class UIManager:
    """Manages all UI components and setup for the Suricata Rule Generator"""
    
    def __init__(self, parent_app):
        """Initialize UIManager with reference to parent application
        
        Args:
            parent_app: Reference to main SuricataRuleGenerator instance
        """
        self.parent = parent_app
        
        # UI component references (will be set during setup)
        self.tree = None
        self.notebook = None
        self.buttons_frame = None
        self.paste_button = None
        self.status_label = None
        self.pass_label = None
        self.drop_label = None
        self.reject_label = None
        self.alert_label = None
        self.sid_label = None
        self.vars_label = None
        self.variables_tree = None
        self.history_text = None
        
        # Editor field references
        self.action_var = None
        self.protocol_var = None
        self.src_net_var = None
        self.src_port_var = None
        self.direction_var = None
        self.dst_net_var = None
        self.dst_port_var = None
        self.message_var = None
        self.content_var = None
        self.sid_var = None
        self.comment_var = None
        self.comment_label = None
        self.comment_entry = None
        self.comment_save_button = None
    
    def setup_ui(self):
        """Setup the main UI components including menus, table, and editor"""
        # Create menu bar
        menubar = tk.Menu(self.parent.root)
        self.parent.root.config(menu=menubar)
        
        # File menu - file operations and domain import
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New", command=self.parent.new_file, accelerator="Ctrl+N")
        file_menu.add_command(label="Open", command=self.parent.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Save", command=self.parent.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As", command=self.parent.save_as_file)
        file_menu.add_command(label="Export", command=self.parent.export_file)
        file_menu.add_separator()
        file_menu.add_command(label="Load AWS Best Practices Template", command=self.parent.domain_importer.load_aws_template)
        file_menu.add_command(label="Import Domain List", command=self.parent.domain_importer.import_domains)
        file_menu.add_command(label="Import Stateful Rule Group", command=self.parent.stateful_rule_importer.import_standard_rule_group)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.parent.on_closing)
        
        # Edit menu - undo functionality and search
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Undo", command=self.parent.undo_last_change, accelerator="Ctrl+Z")
        edit_menu.add_separator()
        edit_menu.add_command(label="Find", command=self.parent.search_manager.show_find_dialog, accelerator="Ctrl+F")
        edit_menu.add_command(label="Go to Line", command=self.show_jump_to_line_dialog, accelerator="Ctrl+G")
        
        # Tools menu - rule conflict detection, SID management, flow testing, and change tracking
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Review Rules", command=self.parent.review_rules)
        tools_menu.add_command(label="SID Management", command=self.show_sid_management)
        tools_menu.add_command(label="Test Flow", command=self.show_test_flow_dialog)
        tools_menu.add_separator()
        self.parent.tracking_menu_var = tk.BooleanVar(value=self.parent.tracking_enabled)
        tools_menu.add_checkbutton(label="Enable Change Tracking", variable=self.parent.tracking_menu_var, command=self.parent.toggle_tracking)
        
        # Help menu - about dialog and keyboard shortcuts
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_keyboard_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.parent.show_about)
        
        # Keyboard shortcuts
        self.parent.root.bind('<Control-n>', lambda e: self.parent.new_file())
        self.parent.root.bind('<Control-o>', lambda e: self.parent.open_file())
        self.parent.root.bind('<Control-s>', lambda e: self.parent.save_file())
        self.parent.root.bind('<Control-z>', lambda e: self.parent.undo_last_change())
        self.parent.root.bind('<Delete>', self.on_delete_key)
        self.parent.root.bind('<Control-c>', lambda e: self.handle_ctrl_c())
        self.parent.root.bind('<Control-a>', lambda e: self.select_all_rules())
        self.parent.root.bind('<Control-f>', lambda e: self.parent.search_manager.show_find_dialog())
        self.parent.root.bind('<F3>', lambda e: self.parent.search_manager.find_next())
        self.parent.root.bind('<Escape>', lambda e: self.parent.search_manager.close_search())
        self.parent.root.bind('<Down>', self.on_key_down)
        self.parent.root.bind('<End>', self.on_key_end)
        self.parent.root.bind('<Home>', self.on_key_home)
        self.parent.root.bind('<space>', self.on_space_key)
        self.parent.root.bind('<Control-g>', self.on_ctrl_g_key)
        
        # Main frame
        main_frame = ttk.Frame(self.parent.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Rules table
        self.setup_rules_table(main_frame)
        
        # Tabbed editor frame
        self.setup_tabbed_editor(main_frame)
        
        # Status bar (packed last so it appears at the very bottom)
        self.setup_status_bar(main_frame)
        
        self.parent.root.protocol("WM_DELETE_WINDOW", self.parent.on_closing)
    
    def setup_rules_table(self, parent):
        """Setup the rules display table with color coding and enhanced scrolling"""
        table_frame = ttk.LabelFrame(parent, text="Suricata Rules")
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create container for table and scrollbars
        table_container = ttk.Frame(table_frame)
        table_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview with enhanced scrolling capabilities
        # Reduced height to allocate more space to editor section below
        columns = ("Line", "Action", "Protocol", "Rule Data")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", 
                                height=15, selectmode="extended")
        
        # Configure column headings and widths
        self.tree.heading("Line", text="Line")
        self.tree.heading("Action", text="Action") 
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Rule Data", text="Source | Src Port | Direction | Destination | Dst Port | Options | Message | SID | Rev")
        
        self.tree.column("Line", width=50, stretch=False, minwidth=40)
        self.tree.column("Action", width=80, stretch=False, minwidth=60)
        self.tree.column("Protocol", width=80, stretch=False, minwidth=60)
        self.tree.column("Rule Data", width=1000, stretch=True, minwidth=300)
        
        # Create vertical scrollbar with enhanced configuration
        v_scrollbar = ttk.Scrollbar(table_container, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scrollbar.set)
        
        # Create horizontal scrollbar for wide rule data
        h_scrollbar = ttk.Scrollbar(table_container, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(xscrollcommand=h_scrollbar.set)
        
        # Grid layout for better scrollbar positioning
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights for proper resizing
        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)
        
        # Enable mouse wheel scrolling
        self.tree.bind("<MouseWheel>", self._on_mousewheel)
        self.tree.bind("<Button-4>", self._on_mousewheel)  # Linux scroll up
        self.tree.bind("<Button-5>", self._on_mousewheel)  # Linux scroll down
        
        # Configure color tags for different columns
        self.tree.tag_configure("action_pass", foreground="#2E7D32")
        self.tree.tag_configure("action_alert", foreground="#1976D2")
        self.tree.tag_configure("action_drop", foreground="#D32F2F")
        self.tree.tag_configure("action_reject", foreground="#7B1FA2")  # Purple
        self.tree.tag_configure("comment", foreground="#808080")  # Grey for comments
        self.tree.tag_configure("search_highlight", background="#FFFF00")  # Yellow highlight for search results
        
        # Bind selection and double-click events
        self.tree.bind("<<TreeviewSelect>>", self.on_rule_select)
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<Button-3>", self.on_right_click)  # Right-click context menu
        # Bind events that can cause treeview redraw
        self.tree.bind("<Configure>", self.on_tree_configure)
        self.tree.bind("<ButtonRelease-1>", self.on_column_resize)
        # Bind Ctrl-V specifically to tree for pasting rules
        self.tree.bind("<Control-v>", lambda e: self.parent.paste_rules())
        
        # Store reference in parent for access by other components
        self.parent.tree = self.tree
        
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling for the rules table"""
        try:
            # Windows and MacOS
            if event.delta:
                delta = -1 * (event.delta / 120)
            # Linux
            elif event.num == 4:
                delta = -1
            elif event.num == 5:
                delta = 1
            else:
                delta = 0
            
            # Only scroll if there are enough items to require scrolling
            if len(self.tree.get_children()) > 20:  # More items than visible height
                self.tree.yview_scroll(int(delta), "units")
                
        except (AttributeError, tk.TclError):
            # Ignore any scrolling errors
            pass
    
    def setup_tabbed_editor(self, parent):
        """Setup the tabbed editor interface"""
        editor_frame = ttk.LabelFrame(parent, text="Editor", height=360)
        editor_frame.pack(fill=tk.X, pady=(10, 0))
        editor_frame.pack_propagate(False)  # Prevent frame from shrinking
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(editor_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tab styling for better visual distinction
        style = ttk.Style()
        style.configure('TNotebook.Tab', padding=[20, 8])
        
        # Setup tabs
        self.setup_rule_editor_tab()
        self.setup_variables_tab()
        self.setup_history_tab()
        
        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # Store reference in parent for access by other components
        self.parent.notebook = self.notebook
    
    def setup_rule_editor_tab(self):
        """Setup the rule editor tab"""
        # Create rule editor tab
        rule_tab = ttk.Frame(self.notebook)
        self.notebook.add(rule_tab, text="Rule Editor")
        
        # Create form fields in a grid
        fields_frame = ttk.Frame(rule_tab)
        fields_frame.pack(fill=tk.X, expand=False, anchor=tk.N, padx=5, pady=(5, 0))
        
        # Row 1: Action, Protocol, Direction
        ttk.Label(fields_frame, text="Action:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.action_var = tk.StringVar(value="pass")
        action_combo = ttk.Combobox(fields_frame, textvariable=self.action_var, 
                                   values=["pass", "alert", "drop", "reject"], state="readonly", width=10)
        action_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        ttk.Label(fields_frame, text="Protocol:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.protocol_var = tk.StringVar(value="tcp")
        protocol_combo = ttk.Combobox(fields_frame, textvariable=self.protocol_var,
                                     values=SuricataConstants.SUPPORTED_PROTOCOLS, state="readonly", width=10)
        protocol_combo.grid(row=0, column=3, sticky=tk.W, padx=(0, 20))
        
        # Bind protocol change to update Content Keywords for new rules
        protocol_combo.bind('<<ComboboxSelected>>', self.on_protocol_changed)
        
        ttk.Label(fields_frame, text="Direction:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        self.direction_var = tk.StringVar(value="->")
        direction_combo = ttk.Combobox(fields_frame, textvariable=self.direction_var,
                                    values=["->", "<>"], state="readonly", width=5)
        direction_combo.grid(row=0, column=5, sticky=tk.W)
        
        # Row 2: Source Network, Dest Network with enhanced tooltips
        src_net_label = ttk.Label(fields_frame, text="Source Network:")
        src_net_label.grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.src_net_var = tk.StringVar(value="$HOME_NET")
        self.src_net_entry = ttk.Entry(fields_frame, textvariable=self.src_net_var, width=15)
        self.src_net_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.src_net_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Add tooltip for source network
        self.create_tooltip(self.src_net_entry, 
            "Source Network Examples:\n" +
            "• any\n" +
            "• $HOME_NET (variable)\n" +
            "• @VPC_REFERENCE (reference)\n" +
            "• 192.168.1.0/24 (single CIDR)\n" +
            "• !192.168.1.5 (negation)\n" +
            "• [10.0.0.0/24, !10.0.0.5] (group)\n" +
            "• [$HOME_NET, !192.168.1.0/24] (variable group)")
        
        dst_net_label = ttk.Label(fields_frame, text="Dest Network:")
        dst_net_label.grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.dst_net_var = tk.StringVar(value="$EXTERNAL_NET")
        self.dst_net_entry = ttk.Entry(fields_frame, textvariable=self.dst_net_var, width=15)
        self.dst_net_entry.grid(row=1, column=3, sticky=tk.W, pady=(5, 0))
        self.dst_net_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Add tooltip for destination network
        self.create_tooltip(self.dst_net_entry,
            "Destination Network Examples:\n" +
            "• any\n" +
            "• $EXTERNAL_NET (variable)\n" +
            "• @VPC_REFERENCE (reference)\n" +
            "• 192.168.1.0/24 (single CIDR)\n" +
            "• !192.168.1.5 (negation)\n" +
            "• [10.0.0.0/24, !10.0.0.5] (group)\n" +
            "• [$EXTERNAL_NET, !$HOME_NET] (variable group)")
        
        # Row 3: Source Port, Dest Port with validation warnings
        ttk.Label(fields_frame, text="Source Port:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.src_port_var = tk.StringVar(value="any")
        self.src_port_entry = ttk.Entry(fields_frame, textvariable=self.src_port_var, width=15)
        self.src_port_entry.grid(row=2, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.src_port_entry.bind("<Button-3>", self.on_entry_right_click)
        
        ttk.Label(fields_frame, text="Dest Port:").grid(row=2, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.dst_port_var = tk.StringVar(value="any")
        self.dst_port_entry = ttk.Entry(fields_frame, textvariable=self.dst_port_var, width=15)
        self.dst_port_entry.grid(row=2, column=3, sticky=tk.W, pady=(5, 0))
        self.dst_port_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Row 4: Message
        ttk.Label(fields_frame, text="Message:").grid(row=3, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(fields_frame, textvariable=self.message_var, width=50)
        self.message_entry.grid(row=3, column=1, columnspan=4, sticky=tk.W+tk.E, pady=(5, 0))
        self.message_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Row 5: Content Keywords
        ttk.Label(fields_frame, text="Content Keywords:").grid(row=4, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.content_var = tk.StringVar()
        self.content_entry = ttk.Entry(fields_frame, textvariable=self.content_var, width=50)
        self.content_entry.grid(row=4, column=1, columnspan=4, sticky=tk.W+tk.E, pady=(5, 0))
        self.content_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Row 6: SID and REV
        ttk.Label(fields_frame, text="SID:").grid(row=5, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.sid_var = tk.StringVar()
        self.sid_entry = ttk.Entry(fields_frame, textvariable=self.sid_var, width=10)
        self.sid_entry.grid(row=5, column=1, sticky=tk.W, pady=(5, 0))
        self.sid_entry.bind("<Button-3>", self.on_entry_right_click)
        
        ttk.Label(fields_frame, text="Rev:").grid(row=5, column=2, sticky=tk.W, padx=(20, 5), pady=(5, 0))
        self.rev_var = tk.StringVar()
        self.rev_entry = ttk.Entry(fields_frame, textvariable=self.rev_var, width=5, state="readonly")
        self.rev_entry.grid(row=5, column=3, sticky=tk.W, pady=(5, 0))
        
        # Comment (hidden by default)
        self.comment_label = ttk.Label(fields_frame, text="Comment:")
        self.comment_var = tk.StringVar()
        self.comment_entry = ttk.Entry(fields_frame, textvariable=self.comment_var, width=50)
        
        # Save button
        ttk.Button(fields_frame, text="Save Changes", command=self.parent.save_rule_changes).grid(row=5, column=4, sticky=tk.W, padx=(20, 0), pady=(5, 0))
        
        # Configure column weights for resizing
        fields_frame.columnconfigure(1, weight=1)
        fields_frame.columnconfigure(3, weight=1)
        
        # Rule management buttons (inside the tab to maintain consistent frame height)
        buttons_container = ttk.Frame(rule_tab)
        buttons_container.pack(fill=tk.X, padx=5, pady=(10, 5))
        
        ttk.Button(buttons_container, text="Delete Selected", command=self.parent.delete_selected_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_container, text="Copy Selected", command=self.parent.copy_selected_rules).pack(side=tk.LEFT, padx=(0, 5))
        self.paste_button = ttk.Button(buttons_container, text="Paste", command=self.parent.paste_rules, state="disabled")
        self.paste_button.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_container, text="Insert Rule", command=self.parent.insert_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_container, text="Insert Comment", command=self.parent.insert_comment).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_container, text="Insert Domain Allow Rule", command=self.parent.domain_importer.insert_domain_rule).pack(side=tk.LEFT, padx=(0, 5))
        
        # Move buttons on the right side
        ttk.Button(buttons_container, text="Move Up", command=self.parent.move_rule_up).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(buttons_container, text="Move Down", command=self.parent.move_rule_down).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Store button reference for paste button state management
        self.parent.paste_button = self.paste_button
        
        # Store references in parent for access by other components
        self.parent.action_var = self.action_var
        self.parent.protocol_var = self.protocol_var
        self.parent.src_net_var = self.src_net_var
        self.parent.src_port_var = self.src_port_var
        self.parent.direction_var = self.direction_var
        self.parent.dst_net_var = self.dst_net_var
        self.parent.dst_port_var = self.dst_port_var
        self.parent.message_var = self.message_var
        self.parent.content_var = self.content_var
        self.parent.sid_var = self.sid_var
        self.parent.rev_var = self.rev_var
        self.parent.comment_var = self.comment_var
        self.parent.comment_label = self.comment_label
        self.parent.comment_entry = self.comment_entry
        self.parent.src_port_entry = self.src_port_entry
        self.parent.dst_port_entry = self.dst_port_entry
    
    def setup_variables_tab(self):
        """Setup the rule variables tab"""
        # Create variables tab
        variables_tab = ttk.Frame(self.notebook)
        self.notebook.add(variables_tab, text="Rule Variables")
        
        # Variables table frame
        table_frame = ttk.Frame(variables_tab)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Variables table
        columns = ("Variable", "Type", "Definition")
        self.variables_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        
        self.variables_tree.heading("Variable", text="Variable")
        self.variables_tree.heading("Type", text="Type")
        self.variables_tree.heading("Definition", text="Definition")
        
        self.variables_tree.column("Variable", width=120, stretch=False)
        self.variables_tree.column("Type", width=80, stretch=False)
        self.variables_tree.column("Definition", width=250, stretch=True)
        
        # Scrollbar for variables table
        var_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.variables_tree.yview)
        self.variables_tree.configure(yscrollcommand=var_scrollbar.set)
        
        self.variables_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        var_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event to edit variable
        self.variables_tree.bind("<Double-1>", self.on_variable_double_click)
        
        # Variables buttons
        var_buttons_frame = ttk.Frame(variables_tab)
        var_buttons_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(var_buttons_frame, text="Add IP Set ($)", command=lambda: self.add_variable("ip_set")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(var_buttons_frame, text="Add Port Set ($)", command=lambda: self.add_variable("port_set")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(var_buttons_frame, text="Add Reference", command=lambda: self.add_variable("reference")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(var_buttons_frame, text="Edit", command=self.edit_variable).pack(side=tk.LEFT, padx=(10, 5))
        ttk.Button(var_buttons_frame, text="Delete", command=self.delete_variable).pack(side=tk.LEFT, padx=(0, 5))
        
        # Store reference in parent for access by other components
        self.parent.variables_tree = self.variables_tree
    
    def setup_history_tab(self):
        """Setup the change history tab"""
        # Create history tab
        history_tab = ttk.Frame(self.notebook)
        self.notebook.add(history_tab, text="Change History")
        
        # History display frame
        history_frame = ttk.Frame(history_tab)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # History text area with scrollbar
        self.history_text = tk.Text(history_frame, wrap=tk.WORD, font=("Consolas", 9), state=tk.DISABLED)
        history_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_text.yview)
        self.history_text.configure(yscrollcommand=history_scrollbar.set)
        
        # Bind right-click context menu for history text
        self.history_text.bind("<Button-3>", self.on_history_right_click)
        
        self.history_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # History buttons
        history_buttons_frame = ttk.Frame(history_tab)
        history_buttons_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(history_buttons_frame, text="Refresh", command=self.refresh_history_display).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(history_buttons_frame, text="Clear Display", command=self.clear_history_display).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(history_buttons_frame, text="Export History", command=self.export_history).pack(side=tk.RIGHT)
        
        # Store reference in parent for access by other components
        self.parent.history_text = self.history_text
    
    def on_tab_changed(self, event):
        """Handle tab change events"""
        selected_tab = self.notebook.select()
        tab_text = self.notebook.tab(selected_tab, "text")
        
        if tab_text == "Rule Variables":
            # Auto-detect variables when Variables tab is selected
            self.parent.auto_detect_variables()
        elif tab_text == "Change History":
            # Refresh history display
            self.refresh_history_display()
    
    def setup_status_bar(self, parent):
        """Setup status bar at bottom of window with colored action counts"""
        status_frame = ttk.Frame(parent, relief=tk.SUNKEN, borderwidth=1)
        status_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Main status label for capacity and file status
        self.status_label = ttk.Label(status_frame, text="Capacity: 0 | New", 
                                     font=("TkDefaultFont", 9))
        self.status_label.pack(side=tk.LEFT, padx=5, pady=2)
        
        # Colored labels for action counts
        self.pass_label = tk.Label(status_frame, text="", fg="#2E7D32", font=("TkDefaultFont", 9))
        self.drop_label = tk.Label(status_frame, text="", fg="#D32F2F", font=("TkDefaultFont", 9))
        self.reject_label = tk.Label(status_frame, text="", fg="#7B1FA2", font=("TkDefaultFont", 9))
        self.alert_label = tk.Label(status_frame, text="", fg="#1976D2", font=("TkDefaultFont", 9))
        
        # Additional info labels
        self.sid_label = tk.Label(status_frame, text="", fg="#666666", font=("TkDefaultFont", 9))
        self.vars_label = tk.Label(status_frame, text="", fg="#FF6600", font=("TkDefaultFont", 9))
        self.refs_label = tk.Label(status_frame, text="", fg="#008B8B", font=("TkDefaultFont", 9))
        
        # Store references in parent for access by other components
        self.parent.status_label = self.status_label
        self.parent.pass_label = self.pass_label
        self.parent.drop_label = self.drop_label
        self.parent.reject_label = self.reject_label
        self.parent.alert_label = self.alert_label
        self.parent.sid_label = self.sid_label
        self.parent.vars_label = self.vars_label
        self.parent.refs_label = self.refs_label
    
    def on_rule_select(self, event):
        """Handle rule selection to populate editor fields with selected rule data"""
        # Clear search highlights when user manually selects a different item
        selection = self.tree.selection()
        if selection:
            if self.parent.search_manager.handle_rule_selection_during_search(selection[0]):
                # Search was cleared by the search manager
                pass
        
        selection = self.tree.selection()
        if not selection:
            # No selection - hide editor fields
            self.hide_all_editor_fields()
            self.parent.selected_rule_index = None
            return
        
        # Clean up placeholder if selecting a real rule
        selected_item = selection[0]
        if selected_item != self.parent.placeholder_item:
            self.parent.remove_placeholder_row()
        
        # Get the index of the selected rule
        selected_item = selection[0]
        rule_index = self.tree.index(selected_item)
        
        if rule_index < len(self.parent.rules):
            rule = self.parent.rules[rule_index]
            self.parent.selected_rule_index = rule_index
            
            # Show appropriate editor based on rule type
            if getattr(rule, 'is_blank', False):
                # Blank line - no editor fields needed
                self.hide_all_editor_fields()
            elif getattr(rule, 'is_comment', False):
                # Comment line - show comment editor only
                self.show_comment_editor()
                self.comment_var.set(rule.comment_text)
            else:
                # Regular rule - populate all rule editor fields
                self.show_rule_editor()
                self.action_var.set(rule.action)
                self.protocol_var.set(rule.protocol)
                self.src_net_var.set(rule.src_net)
                self.src_port_var.set(rule.src_port)
                self.direction_var.set(rule.direction)
                self.dst_net_var.set(rule.dst_net)
                self.dst_port_var.set(rule.dst_port)
                self.message_var.set(rule.message)
                self.content_var.set(rule.content)
                self.sid_var.set(str(rule.sid))
                self.rev_var.set(str(rule.rev))
    
    def show_rule_editor(self):
        """Show rule editing fields, hide comment fields"""
        # Hide comment fields and save button
        self.comment_label.grid_remove()
        self.comment_entry.grid_remove()
        if hasattr(self.parent, 'comment_save_button'):
            self.parent.comment_save_button.grid_remove()
        
        # Restore all rule fields to their original positions
        fields_frame = self.comment_label.master
        for widget in fields_frame.winfo_children():
            if widget not in [self.comment_label, self.comment_entry, getattr(self.parent, 'comment_save_button', None)]:
                try:
                    widget.grid()
                except tk.TclError:
                    pass
    
    def hide_all_editor_fields(self):
        """Hide all editor fields for blank lines"""
        fields_frame = self.comment_label.master
        for widget in fields_frame.winfo_children():
            widget.grid_remove()
    
    def show_comment_editor(self):
        """Show only comment editing field and save button"""
        # Hide all fields first
        self.hide_all_editor_fields()
        
        # Show only comment field and save button
        fields_frame = self.comment_label.master
        self.comment_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.comment_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W+tk.E, padx=(0, 10), pady=(5, 0))
        
        # Bind right-click context menu to comment entry
        self.comment_entry.bind("<Button-3>", self.on_entry_right_click)
        
        # Add save button for comments if it doesn't exist
        if not hasattr(self.parent, 'comment_save_button'):
            self.parent.comment_save_button = ttk.Button(fields_frame, text="Save Changes", command=self.parent.save_rule_changes)
        self.parent.comment_save_button.grid(row=0, column=3, sticky=tk.W, padx=(5, 0), pady=(5, 0))
    
    def on_double_click(self, event):
        """Handle double-click events on tree items"""
        item = self.tree.identify_row(event.y)
        if item == self.parent.placeholder_item:
            # Double-click on placeholder - show insert rule dialog
            self.parent.insert_rule()
        else:
            # Double-click on regular rule - show edit dialog
            self.parent.edit_selected_rule()
    
    def on_tree_click(self, event):
        """Handle clicks on the tree to manage rule selection and insertion"""
        # Determine if click is on an existing item or empty area
        item = self.tree.identify_row(event.y)
        if not item:
            # Click in empty area below rules - just clear selection and hide editor
            self.tree.selection_remove(self.tree.selection())  # Clear any selection
            if not self.parent.placeholder_item:  # Only add if doesn't exist
                self.parent.add_placeholder_row()  # Add placeholder
            self.parent.selected_rule_index = None  # Clear selection
            self.hide_all_editor_fields()  # Hide editor for empty area clicks
        elif item == self.parent.placeholder_item:
            # Click on placeholder - keep it and set up for new rule insertion
            self.tree.selection_remove(self.tree.selection())  # Clear any selection
            self.parent.selected_rule_index = len(self.parent.rules)  # Set insertion point
            self.show_rule_editor()  # Show editor fields
            self.parent.set_default_editor_values()  # Populate with defaults
            # Auto-generate next available SID for convenience
            max_sid = max([rule.sid for rule in self.parent.rules], default=99)
            self.sid_var.set(str(max_sid + 1))
        else:
            # Check if clicking on already selected item to toggle selection
            current_selection = self.tree.selection()
            if len(current_selection) == 1 and current_selection[0] == item:
                # Toggle off - deselect the item and schedule deselection after event processing
                # Use after_idle to avoid conflict with TreeviewSelect event
                self.parent.root.after_idle(lambda: self.deselect_item(item))
                return
            
            # Click on existing rule - clean up placeholder only if it exists
            if self.parent.placeholder_item:
                self.parent.remove_placeholder_row()
    
    def deselect_item(self, item):
        """Deselect a tree item"""
        try:
            self.tree.selection_remove(item)
            self.parent.selected_rule_index = None
            self.hide_all_editor_fields()
        except tk.TclError:
            pass
    
    def on_right_click(self, event):
        """Handle right-click context menu"""
        def select_all_wrapper():
            self.select_all_rules()
        
        try:
            # Create context menu
            context_menu = tk.Menu(self.parent.root, tearoff=0)
            context_menu.add_command(label="Select All", command=select_all_wrapper)
            context_menu.add_separator()
            
            # Check clipboard states
            has_internal_clipboard = bool(self.parent.clipboard)
            system_content = self.parent.get_system_clipboard_content()
            has_system_clipboard = bool(system_content and system_content.strip())
            
            # Determine which clipboard source will be used (same logic as paste_rules method)
            use_system_clipboard = False
            if system_content and system_content.strip():
                # Check if system clipboard has different content than what we last copied
                if hasattr(self.parent, '_last_copied_text'):
                    # If system clipboard content is different from our last copy, prefer system
                    if system_content.strip() != self.parent._last_copied_text.strip():
                        use_system_clipboard = True
                else:
                    # No record of last copy, check if system content looks like rules
                    if any(keyword in system_content.lower() for keyword in ['alert', 'drop', 'pass', 'reject', 'sid:', '->', 'tcp', 'udp', 'http']):
                        use_system_clipboard = True
            
            # Show appropriate paste option based on which clipboard will be used
            if use_system_clipboard and has_system_clipboard:
                context_menu.add_command(label="Paste (system clipboard)", command=self.parent.paste_rules)
            elif has_internal_clipboard:
                context_menu.add_command(label="Paste (internal clipboard)", command=self.parent.paste_rules)
            
            # Check if there's a selection for copy/delete
            selection = self.tree.selection()
            if selection:
                context_menu.add_command(label="Copy", command=self.parent.copy_selected_rules)
            
            # Show delete option if there's a selection
            if selection:
                if use_system_clipboard and has_system_clipboard or has_internal_clipboard:  # Only add separator if paste was added
                    context_menu.add_separator()
                context_menu.add_command(label="Delete", command=self.parent.delete_selected_rule)
            
            # Show the menu with explicit positioning
            try:
                # Ensure menu appears on screen
                screen_width = self.parent.root.winfo_screenwidth()
                screen_height = self.parent.root.winfo_screenheight()
                menu_x = min(event.x_root, screen_width - 200)
                menu_y = min(event.y_root, screen_height - 150)
                
                context_menu.tk_popup(menu_x, menu_y)
                
            except Exception as popup_error:
                # Fallback: show at mouse position
                context_menu.tk_popup(event.x_root, event.y_root)
                
        except Exception as e:
            # Ultimate fallback - show error message
            messagebox.showinfo("Menu Error", f"Context menu error: {str(e)}")
        finally:
            try:
                context_menu.grab_release()
            except:
                pass
    
    def select_all_rules(self):
        """Select all rules in the tree (excludes placeholder)"""
        # Clear any existing selection first
        self.tree.selection_remove(self.tree.selection())
        
        all_items = self.tree.get_children()
        if all_items:
            # Filter out placeholder item if it exists
            items_to_select = [item for item in all_items if item != self.parent.placeholder_item]
            if items_to_select:
                # Add each item to selection
                for item in items_to_select:
                    self.tree.selection_add(item)
                # Focus on first selected item
                self.tree.focus(items_to_select[0])
    
    def on_tree_configure(self, event):
        """Handle tree configure events (including after redraw) to restore placeholder"""
        # Use after_idle to avoid duplicate placeholders during rapid events
        self.parent.root.after_idle(self.restore_placeholder_if_needed)
    
    def on_column_resize(self, event):
        """Handle column resize events to restore placeholder row"""
        self.restore_placeholder_if_needed()
    
    def restore_placeholder_if_needed(self):
        """Restore placeholder row if conditions are met"""
        if len(self.parent.rules) > 0 and not self.parent.placeholder_item:
            # Only restore if placeholder doesn't exist
            self.parent.root.after_idle(self.parent.add_placeholder_row)
    
    def on_delete_key(self, event):
        """Handle Delete key - only delete rules when tree view has focus"""
        # Only delete rules if the tree view has focus
        if self.parent.root.focus_get() == self.tree:
            self.parent.delete_selected_rule()
        # If focus is elsewhere (like text entry fields), let the default behavior handle it
    
    def on_key_down(self, event):
        """Handle Down arrow key to navigate to placeholder when at last rule"""
        # Only handle if the tree has focus
        if self.parent.root.focus_get() != self.tree:
            return
        
        selection = self.tree.selection()
        if not selection or not self.parent.placeholder_item:
            return
        
        selected_item = selection[0]
        all_items = self.tree.get_children()
        
        # If we have rules and a placeholder
        if len(all_items) >= 2:
            # Check if we're on the last actual rule (not the placeholder)
            last_rule_item = all_items[-2]  # Second to last (placeholder is last)
            if selected_item == last_rule_item:
                # Move to placeholder
                self.tree.selection_set(self.parent.placeholder_item)
                self.tree.focus(self.parent.placeholder_item)
                return 'break'
    
    def on_key_end(self, event):
        """Handle End key to navigate to placeholder"""
        # Only handle if the tree has focus
        if self.parent.root.focus_get() != self.tree:
            return
        
        if self.parent.placeholder_item:
            self.tree.selection_set(self.parent.placeholder_item)
            self.tree.focus(self.parent.placeholder_item)
            self.tree.see(self.parent.placeholder_item)  # Scroll to show the placeholder
            return 'break'
    
    def on_key_home(self, event):
        """Handle Home key to navigate to first line"""
        # Only handle if the tree has focus
        if self.parent.root.focus_get() != self.tree:
            return
        
        all_items = self.tree.get_children()
        if all_items:
            first_item = all_items[0]
            self.tree.selection_set(first_item)
            self.tree.focus(first_item)
            self.tree.see(first_item)  # Scroll to show the first item
            return 'break'
    
    def on_space_key(self, event):
        """Handle Space key - only toggle rules when tree view has focus"""
        # Only handle if the tree view has focus
        if self.parent.root.focus_get() == self.tree:
            self.parent.toggle_rule_disabled()
            return 'break'  # Prevent default space behavior
        # If focus is elsewhere, let the default behavior handle it
    
    def on_ctrl_g_key(self, event):
        """Handle Ctrl+G key - only show dialog when tree view has focus"""
        # Only handle if the tree view has focus
        if self.parent.root.focus_get() == self.tree:
            self.show_jump_to_line_dialog()
            return 'break'  # Prevent default behavior
        # If focus is elsewhere, let the default behavior handle it
    
    def show_jump_to_line_dialog(self):
        """Show dialog to jump to a specific line number"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Go to Line")
        dialog.geometry("300x120")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 200, self.parent.root.winfo_rooty() + 200))
        
        # Calculate total lines (including comments and blanks)
        total_lines = len(self.parent.rules)
        if self.parent.placeholder_item:
            total_lines += 1  # Include placeholder in count
        
        ttk.Label(dialog, text=f"Line number (1-{total_lines}):").pack(pady=10)
        
        line_var = tk.StringVar()
        entry = ttk.Entry(dialog, textvariable=line_var, width=10)
        entry.pack(pady=5)
        entry.focus()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def on_go():
            try:
                line_num = int(line_var.get().strip())
                if line_num < 1:
                    messagebox.showerror("Error", "Line number must be 1 or greater.")
                    return
                
                # Convert to 0-based index
                target_index = line_num - 1
                
                # Get all tree items
                all_items = self.tree.get_children()
                
                if target_index < len(all_items):
                    # Jump to the specified line
                    target_item = all_items[target_index]
                    self.tree.selection_set(target_item)
                    self.tree.focus(target_item)
                    self.tree.see(target_item)
                else:
                    # Line number exceeds available lines - jump to placeholder if it exists
                    if self.parent.placeholder_item:
                        self.tree.selection_set(self.parent.placeholder_item)
                        self.tree.focus(self.parent.placeholder_item)
                        self.tree.see(self.parent.placeholder_item)
                    else:
                        # No placeholder, jump to last line
                        if all_items:
                            last_item = all_items[-1]
                            self.tree.selection_set(last_item)
                            self.tree.focus(last_item)
                            self.tree.see(last_item)
                
                dialog.destroy()
                
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid line number.")
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Go", command=on_go).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key
        dialog.bind('<Return>', lambda e: on_go())
    
    def show_keyboard_shortcuts(self):
        """Display keyboard shortcuts cheatsheet in a dialog"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Keyboard Shortcuts")
        dialog.geometry("700x600")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 100, self.parent.root.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="Keyboard Shortcuts", 
                               font=("TkDefaultFont", 14, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Create text widget with scrollbar for shortcuts
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("TkDefaultFont", 10),
                             bg=dialog.cget('bg'), relief=tk.FLAT, cursor="arrow")
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
            ("File Operations", [
                ("Ctrl+S", "Save current file"),
                ("Ctrl+O", "Open file"),
                ("Ctrl+N", "New file"),
            ]),
            ("Editing & Selection", [
                ("Ctrl+Z", "Undo last change"),
                ("Ctrl+C", "Copy selected rules"),
                ("Ctrl+V", "Paste rules"),
                ("Ctrl+A", "Select all rules"),
                ("Delete", "Delete selected rule(s) (when rules table has focus)"),
                ("Space", "Toggle rule enabled/disabled (when rules table has focus)"),
            ]),
            ("Navigation", [
                ("Home", "Jump to first rule"),
                ("End", "Jump to placeholder/last rule"),
                ("Down Arrow", "Navigate to placeholder when at last rule"),
                ("Ctrl+G", "Go to line number"),
            ]),
            ("Search", [
                ("Ctrl+F", "Open Find dialog"),
                ("F3", "Find next occurrence"),
                ("Escape", "Close search and clear highlights"),
            ]),
            ("Rules Table Interactions", [
                ("Double-Click", "Edit selected rule or comment"),
                ("Right-Click", "Show context menu with copy/paste options"),
                ("Click below rules", "Add new rule (shows placeholder)"),
            ]),
        ]
        
        # Insert shortcuts into text widget
        for category, shortcuts_list in shortcuts:
            # Category header
            text_widget.insert(tk.END, f"{category}\n", "category")
            
            # Shortcuts in this category
            for shortcut, description in shortcuts_list:
                text_widget.insert(tk.END, f"  {shortcut:<20}", "shortcut")
                text_widget.insert(tk.END, f"{description}\n", "description")
            
            text_widget.insert(tk.END, "\n")
        
        # Add tip at the bottom
        text_widget.insert(tk.END, "\n")
        text_widget.tag_configure("tip", font=("TkDefaultFont", 9, "italic"), 
                                foreground="#666666")
        text_widget.insert(tk.END, "Tip: Most shortcuts work when the rules table has focus. ", "tip")
        text_widget.insert(tk.END, "Click on the rules table first if a shortcut isn't working.", "tip")
        
        # Make text widget read-only
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Focus on dialog
        dialog.focus_set()
    
    def show_sid_management(self):
        """Show SID Management dialog for bulk SID renumbering"""
        # This method is quite large, so we'll delegate to the parent for now
        # to keep this UI manager focused on UI setup and event handling
        self.parent.show_sid_management()
    
    def add_variable(self, var_type=None):
        """Add a new variable of specified type"""
        if var_type:
            self.show_variable_dialog(f"Add {var_type.replace('_', ' ').title()}", var_type=var_type)
        else:
            self.show_variable_dialog("Add Variable")
    
    def edit_variable(self):
        """Edit selected variable"""
        selection = self.parent.variables_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a variable to edit.")
            return
        
        item = selection[0]
        values = self.parent.variables_tree.item(item, "values")
        var_name = values[0]
        
        # Prevent editing $EXTERNAL_NET
        if var_name == '$EXTERNAL_NET':
            messagebox.showinfo("Information", "$EXTERNAL_NET is automatically defined by AWS Network Firewall as the inverse of $HOME_NET and cannot be edited.")
            return
        
        var_type = values[1].lower().replace(' ', '_')
        self.show_variable_dialog("Edit Variable", var_name, var_type)
    
    def delete_variable(self):
        """Delete selected variable"""
        selection = self.parent.variables_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a variable to delete.")
            return
        
        item = selection[0]
        var_name = self.parent.variables_tree.item(item, "values")[0]
        
        # Prevent deleting $EXTERNAL_NET
        if var_name == '$EXTERNAL_NET':
            messagebox.showinfo("Information", "$EXTERNAL_NET is automatically defined by AWS Network Firewall and cannot be deleted.")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Delete variable {var_name}?"):
            del self.parent.variables[var_name]
            self.parent.add_history_entry('variable_deleted', {'variable': var_name})
            self.parent.refresh_variables_table()
            self.parent.update_status_bar()  # Update status bar to reflect undefined variable count
    
    def on_variable_double_click(self, event):
        """Handle double-click events on variables tree items"""
        item = self.variables_tree.identify_row(event.y)
        if not item:
            return
        
        # Get the variable name from the double-clicked item
        values = self.variables_tree.item(item, "values")
        if not values:
            return
        
        var_name = values[0]
        
        # Prevent editing $EXTERNAL_NET
        if var_name == '$EXTERNAL_NET':
            messagebox.showinfo("Information", "$EXTERNAL_NET is automatically defined by AWS Network Firewall as the inverse of $HOME_NET and cannot be edited.")
            return
        
        # Determine variable type and call edit dialog
        var_type = values[1].lower().replace(' ', '_')
        self.show_variable_dialog("Edit Variable", var_name, var_type)
    
    def show_variable_dialog(self, title, var_name=None, var_type=None):
        """Show dialog for adding/editing variables"""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title(title)
        dialog.geometry("450x220")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Variable name with prefix hint
        ttk.Label(dialog, text="Variable Name:").pack(pady=5)
        name_var = tk.StringVar(value=var_name or "")
        name_entry = ttk.Entry(dialog, textvariable=name_var, width=30)
        name_entry.pack(pady=5)
        
        # Show prefix hint based on type and existing variable name
        if var_type == "ip_set":
            hint_text = "Must start with $ (e.g., $HOME_NET)"
            definition_label = "CIDR Definition:"
            definition_hint = "e.g., 192.168.1.0/24,10.0.0.0/8"
            if not var_name:
                name_var.set("$")
        elif var_type == "port_set":
            # AWS Network Firewall requires port variables to use $ prefix only
            hint_text = "Must start with $ (e.g., $WEB_PORTS, $SRC_PORTS)"
            definition_label = "Port Definition:"
            definition_hint = "e.g., 80,443,8080:8090"
            if not var_name:
                name_var.set("$")
        elif var_type == "reference":
            hint_text = "Reference name (no prefix required)"
            definition_label = "Reference ARN:"
            definition_hint = "AWS VPC IP Set Reference ARN"
        else:
            hint_text = "$ for IP sets and port sets, or reference name"
            definition_label = "Definition:"
            definition_hint = ""
        
        ttk.Label(dialog, text=hint_text, font=("TkDefaultFont", 8)).pack(pady=(0, 10))
        
        # Definition
        ttk.Label(dialog, text=definition_label).pack(pady=5)
        definition_var = tk.StringVar(value=self.parent.variables.get(var_name, "") if var_name else "")
        definition_entry = ttk.Entry(dialog, textvariable=definition_var, width=50)
        definition_entry.pack(pady=5)
        
        if definition_hint:
            ttk.Label(dialog, text=definition_hint, font=("TkDefaultFont", 8)).pack(pady=(0, 10))
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def save_variable():
            name = name_var.get().strip()
            definition = definition_var.get().strip()
            
            if not name:
                messagebox.showerror("Error", "Variable name is required.")
                return
            
            # Use context-aware validation based on actual usage
            if definition:  # Only validate if definition is provided
                # Analyze current variable usage to determine correct validation
                variable_usage = self.parent.file_manager.analyze_variable_usage(self.parent.rules)
                determined_type = self.parent.file_manager.get_variable_type_from_usage(name, variable_usage)
                
                # Validate based on determined type, not just prefix
                if determined_type == "Port Set":
                    # Port Set validation
                    if not self.parent.validate_port_list(definition):
                        messagebox.showerror("Port Validation Error", 
                            "Invalid port definition. Port ranges and lists MUST use brackets:\n" +
                            "• Single port: 80\n" +
                            "• Port range: [8080:8090]\n" +
                            "• Multiple ports: [80,443,8080]\n" +
                            "• Complex specs: [80:100,!85]\n\n" +
                            "Suricata syntax requires brackets for all port ranges and complex port specifications.")
                        return
                elif determined_type == "IP Set":
                    # IP Set validation
                    if not self.parent.validate_cidr_list(definition):
                        messagebox.showerror("Error", "Invalid CIDR definition. Use comma-separated CIDR blocks.")
                        return
                elif determined_type == "Reference":
                    # Reference Set - minimal validation (just check it's not empty)
                    if not definition.strip():
                        messagebox.showerror("Error", "Reference ARN is required for reference variables.")
                        return
                else:
                    # Fallback validation based on prefix for new variables not yet used in rules
                    if name.startswith('$'):
                        # Default to IP Set validation for $ variables not yet used
                        if not self.parent.validate_cidr_list(definition):
                            messagebox.showerror("Error", "Invalid CIDR definition. Use comma-separated CIDR blocks.")
                            return
                    elif name.startswith('@'):
                        # Default to Port Set validation for @ variables
                        if not self.parent.validate_port_list(definition):
                            messagebox.showerror("Port Validation Error", 
                                "Invalid port definition. Port ranges and lists MUST use brackets:\n" +
                                "• Single port: 80\n" +
                                "• Port range: [8080:8090]\n" +
                                "• Multiple ports: [80,443,8080]\n" +
                                "• Complex specs: [80:100,!85]\n\n" +
                                "Suricata syntax requires brackets for all port ranges and complex port specifications.")
                            return
            
            # Determine if this is adding a new variable or editing existing one
            is_new_variable = var_name is None or var_name not in self.parent.variables
            action_type = 'variable_added' if is_new_variable else 'variable_modified'
            
            self.parent.variables[name] = definition
            self.parent.add_history_entry(action_type, {'variable': name, 'definition': definition})
            self.parent.refresh_variables_table()
            self.parent.update_status_bar()  # Update status bar to reflect variable definition changes
            dialog.destroy()
        
        ttk.Button(button_frame, text="Save", command=save_variable).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        name_entry.focus()
    
    def refresh_history_display(self):
        """Refresh the history display with current tracking data"""
        self.parent.history_text.config(state=tk.NORMAL)
        self.parent.history_text.delete(1.0, tk.END)
        
        if not self.parent.tracking_enabled:
            self.parent.history_text.insert(tk.END, "Change tracking is currently disabled.\n\n")
            self.parent.history_text.insert(tk.END, "To enable change tracking:\n")
            self.parent.history_text.insert(tk.END, "1. Go to Tools > Enable Change Tracking\n")
            self.parent.history_text.insert(tk.END, "2. Changes will be tracked and displayed here\n")
            self.parent.history_text.config(state=tk.DISABLED)
            return
        
        # Display current file info
        if self.parent.current_file:
            filename = os.path.basename(self.parent.current_file)
            self.parent.history_text.insert(tk.END, f"File: {filename}\n")
        else:
            self.parent.history_text.insert(tk.END, "File: New (unsaved)\n")
        
        self.parent.history_text.insert(tk.END, f"Tracking: {'Enabled' if self.parent.tracking_enabled else 'Disabled'}\n")
        
        # Show header info if present
        if self.parent.has_header and self.parent.created_timestamp:
            self.parent.history_text.insert(tk.END, f"Created: {self.parent.created_timestamp}\n")
        
        self.parent.history_text.insert(tk.END, "\n" + "="*50 + "\n\n")
        
        # Display pending history entries
        if self.parent.pending_history:
            self.parent.history_text.insert(tk.END, "Pending Changes (not yet saved):\n")
            self.parent.history_text.insert(tk.END, "-" * 30 + "\n")
            
            for entry in self.parent.pending_history:
                timestamp = entry.get('timestamp', 'Unknown')
                action = entry.get('action', 'Unknown')
                details = entry.get('details', {})
                count = entry.get('count')
                
                # Format timestamp
                try:
                    import datetime
                    dt = datetime.datetime.fromisoformat(timestamp)
                    formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    formatted_time = timestamp
                
                self.parent.history_text.insert(tk.END, f"[{formatted_time}] ")
                
                # Format action description
                if action == 'file_created':
                    self.parent.history_text.insert(tk.END, "File created\n")
                elif action == 'file_opened':
                    filename = details.get('filename', 'unknown')
                    self.parent.history_text.insert(tk.END, f"Opened file: {filename}\n")
                elif action == 'file_saved':
                    filename = details.get('filename', 'unknown')
                    self.parent.history_text.insert(tk.END, f"Saved file: {filename}\n")
                elif action == 'rule_added':
                    line = details.get('line', '?')
                    rule_text = details.get('rule_text', '')
                    
                    # Extract action and SID from rule_text if individual fields not available
                    rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                    sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                    
                    # Base message with rule identification
                    self.parent.history_text.insert(tk.END, f"Added {rule_action} rule at line {line} (SID: {sid})")
                    
                    # Add detailed rule information if available
                    protocol = details.get('protocol')
                    src_net = details.get('src_net')
                    src_port = details.get('src_port')
                    direction = details.get('direction')
                    dst_net = details.get('dst_net')
                    dst_port = details.get('dst_port')
                    message = details.get('message')
                    content = details.get('content')
                    
                    if any([protocol, src_net, src_port, direction, dst_net, dst_port, message, content]):
                        self.parent.history_text.insert(tk.END, " - Details:\n")
                        if protocol:
                            self.parent.history_text.insert(tk.END, f"  - Protocol: {protocol}\n")
                        if src_net:
                            self.parent.history_text.insert(tk.END, f"  - Source Network: {src_net}\n")
                        if src_port:
                            self.parent.history_text.insert(tk.END, f"  - Source Port: {src_port}\n")
                        if direction:
                            self.parent.history_text.insert(tk.END, f"  - Direction: {direction}\n")
                        if dst_net:
                            self.parent.history_text.insert(tk.END, f"  - Dest Network: {dst_net}\n")
                        if dst_port:
                            self.parent.history_text.insert(tk.END, f"  - Dest Port: {dst_port}\n")
                        if message:
                            # Truncate long messages for readability
                            display_message = (message[:50] + '...' if len(message) > 50 else message)
                            self.parent.history_text.insert(tk.END, f"  - Message: \"{display_message}\"\n")
                        if content:
                            # Truncate long content for readability
                            display_content = (content[:50] + '...' if len(content) > 50 else content)
                            self.parent.history_text.insert(tk.END, f"  - Content: {display_content}\n")
                    else:
                        self.parent.history_text.insert(tk.END, "\n")
                elif action == 'rule_modified':
                    line = details.get('line', '?')
                    rule_text = details.get('rule_text', '')
                    
                    # Extract action and SID from rule_text if individual fields not available
                    rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                    sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                    changes = details.get('changes', {})
                    
                    # Base message with rule identification
                    self.parent.history_text.insert(tk.END, f"Modified {rule_action} rule at line {line} (SID: {sid})")
                    
                    # Add detailed change information if available
                    if changes:
                        self.parent.history_text.insert(tk.END, " - Changes:\n")
                        for field, change_info in changes.items():
                            from_val = change_info.get('from', '')
                            to_val = change_info.get('to', '')
                            # Format field name for display
                            field_display = {
                                'action': 'Action',
                                'protocol': 'Protocol', 
                                'src_net': 'Source Network',
                                'src_port': 'Source Port',
                                'direction': 'Direction',
                                'dst_net': 'Dest Network', 
                                'dst_port': 'Dest Port',
                                'message': 'Message',
                                'content': 'Content',
                                'sid': 'SID'
                            }.get(field, field.title())
                            
                            # Truncate long values for readability
                            from_display = (from_val[:30] + '...' if len(str(from_val)) > 30 else str(from_val)) if from_val else '(empty)'
                            to_display = (to_val[:30] + '...' if len(str(to_val)) > 30 else str(to_val)) if to_val else '(empty)'
                            
                            self.parent.history_text.insert(tk.END, f"  - {field_display}: '{from_display}' → '{to_display}'\n")
                    else:
                        self.parent.history_text.insert(tk.END, "\n")
                elif action == 'rule_deleted':
                    line = details.get('line', '?')
                    rule_text = details.get('rule_text', '')
                    
                    # Extract action and SID from rule_text if individual fields not available
                    rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                    sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                    message = details.get('message', '')
                    
                    if message:
                        self.parent.history_text.insert(tk.END, f"Deleted {rule_action} rule from line {line} (SID: {sid}): \"{message}\"\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Deleted {rule_action} rule from line {line} (SID: {sid})\n")
                    
                    if rule_text:
                        # Show truncated rule text (first 80 characters)
                        truncated_rule = rule_text[:80] + '...' if len(rule_text) > 80 else rule_text
                        self.parent.history_text.insert(tk.END, f"  Rule: {truncated_rule}\n")
                elif action == 'rules_deleted':
                    if count:
                        self.parent.history_text.insert(tk.END, f"Deleted {count} rules\n")
                    else:
                        self.parent.history_text.insert(tk.END, "Deleted rules\n")
                elif action == 'rules_copied':
                    rule_count = details.get('count', '?')
                    self.parent.history_text.insert(tk.END, f"Copied {rule_count} rules to clipboard\n")
                elif action == 'rules_pasted':
                    line = details.get('line', '?')
                    rule_count = details.get('count', '?')
                    rules_info = details.get('rules', [])
                    if rules_info:
                        self.parent.history_text.insert(tk.END, f"Pasted {rule_count} rules at line {line}:\n")
                        for i, rule_info in enumerate(rules_info[:3]):  # Show first 3 rules
                            if rule_info.get('type') == 'comment':
                                comment_text = rule_info.get('text', 'comment')
                                self.parent.history_text.insert(tk.END, f"  - Comment: {comment_text}\n")
                            elif rule_info.get('type') == 'blank':
                                self.parent.history_text.insert(tk.END, f"  - Blank line\n")
                            else:
                                action_type = rule_info.get('action', 'unknown')
                                sid = rule_info.get('sid', '?')
                                message = rule_info.get('message', '')
                                if message:
                                    self.parent.history_text.insert(tk.END, f"  - {action_type.upper()} rule (SID: {sid}): {message}\n")
                                else:
                                    self.parent.history_text.insert(tk.END, f"  - {action_type.upper()} rule (SID: {sid})\n")
                        if len(rules_info) > 3:
                            self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Pasted {rule_count} rules at line {line}\n")
                elif action == 'rule_moved':
                    direction = details.get('direction', 'unknown')
                    from_line = details.get('from_line', '?')
                    to_line = details.get('to_line', '?')
                    self.parent.history_text.insert(tk.END, f"Moved rule {direction} from line {from_line} to {to_line}\n")
                elif action == 'domain_import':
                    rule_count = details.get('count', '?')
                    domain_count = details.get('domains', '?')
                    import_action = details.get('action', 'unknown')
                    domain_details = details.get('domain_details', [])
                    start_sid = details.get('start_sid')
                    end_sid = details.get('end_sid')
                    
                    if domain_details and start_sid and end_sid:
                        self.parent.history_text.insert(tk.END, f"Imported {rule_count} {import_action} rules for {domain_count} domains (SIDs {start_sid}-{end_sid}):\n")
                        for domain_info in domain_details:
                            domain = domain_info['domain']
                            d_start = domain_info['start_sid']
                            d_end = domain_info['end_sid']
                            self.parent.history_text.insert(tk.END, f"  - {domain}: SIDs {d_start}-{d_end}\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Imported {rule_count} {import_action} rules for {domain_count} domains\n")
                elif action == 'variable_added':
                    variable = details.get('variable', 'unknown')
                    definition = details.get('definition', '')
                    if definition:
                        # Truncate long definitions for readability
                        display_def = definition[:30] + '...' if len(definition) > 30 else definition
                        self.parent.history_text.insert(tk.END, f"Added variable {variable} = {display_def}\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Added variable {variable}\n")
                elif action == 'variable_modified':
                    variable = details.get('variable', 'unknown')
                    definition = details.get('definition', '')
                    if definition:
                        # Truncate long definitions for readability
                        display_def = definition[:30] + '...' if len(definition) > 30 else definition
                        self.parent.history_text.insert(tk.END, f"Modified variable {variable} = {display_def}\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Modified variable {variable}\n")
                elif action == 'variable_deleted':
                    variable = details.get('variable', 'unknown')
                    # Show the variable type for context
                    var_type = 'IP Set' if variable.startswith('$') else 'Port Set' if variable.startswith('@') else 'Reference'
                    self.parent.history_text.insert(tk.END, f"Deleted {var_type.lower()} variable {variable}\n")
                elif action == 'rules_enabled':
                    rule_count = details.get('count', '?')
                    rules_info = details.get('rules', [])
                    if rules_info:
                        self.parent.history_text.insert(tk.END, f"Enabled {rule_count} rules (uncommented):\n")
                        for rule_info in rules_info[:3]:  # Show first 3 rules
                            action_type = rule_info.get('action', 'unknown')
                            sid = rule_info.get('sid', '?')
                            line = rule_info.get('line', '?')
                            message = rule_info.get('message', '')
                            if message:
                                self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid}): {message}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid})\n")
                        if len(rules_info) > 3:
                            self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Enabled {rule_count} rules\n")
                elif action == 'rules_disabled':
                    rule_count = details.get('count', '?')
                    rules_info = details.get('rules', [])
                    if rules_info:
                        self.parent.history_text.insert(tk.END, f"Disabled {rule_count} rules (commented out):\n")
                        for rule_info in rules_info[:3]:  # Show first 3 rules
                            action_type = rule_info.get('action', 'unknown')
                            sid = rule_info.get('sid', '?')
                            line = rule_info.get('line', '?')
                            message = rule_info.get('message', '')
                            if message:
                                self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid}): {message}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid})\n")
                        if len(rules_info) > 3:
                            self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Disabled {rule_count} rules\n")
                elif action == 'undo_performed':
                    rules_before = details.get('rules_before', '?')
                    rules_after = details.get('rules_after', '?')
                    rules_changed = details.get('rules_changed', 0)
                    if rules_changed > 0:
                        self.parent.history_text.insert(tk.END, f"Undo operation performed ({rules_changed} rules affected: {rules_before} → {rules_after})\n")
                    else:
                        self.parent.history_text.insert(tk.END, f"Undo operation performed (rules restored: {rules_before} → {rules_after})\n")
                else:
                    self.parent.history_text.insert(tk.END, f"{action}\n")
        
        # Try to load and display saved history
        if self.parent.current_file:
            self.display_saved_history()
        
        if not self.parent.pending_history and not self.parent.current_file:
            self.parent.history_text.insert(tk.END, "No changes recorded yet.\n")
            self.parent.history_text.insert(tk.END, "\nChanges will appear here as you work with rules.\n")
        
        self.parent.history_text.config(state=tk.DISABLED)
    
    def display_saved_history(self):
        """Display saved history from .history file if it exists"""
        if not self.parent.current_file:
            return
        
        history_filename = self.parent.current_file.replace('.suricata', '.history')
        if not history_filename.endswith('.history'):
            history_filename += '.history'
        
        if os.path.exists(history_filename):
            try:
                import json
                with open(history_filename, 'r', encoding='utf-8') as f:
                    history_data = json.load(f)
                
                saved_changes = history_data.get('changes', [])
                if saved_changes:
                    self.parent.history_text.insert(tk.END, "\nSaved History:\n")
                    self.parent.history_text.insert(tk.END, "-" * 30 + "\n")
                    
                    # Show most recent entries first
                    for entry in reversed(saved_changes[-20:]):  # Show last 20 entries
                        timestamp = entry.get('timestamp', 'Unknown')
                        action = entry.get('action', 'Unknown')
                        details = entry.get('details', {})
                        count = entry.get('count')
                        
                        # Format timestamp
                        try:
                            import datetime
                            dt = datetime.datetime.fromisoformat(timestamp)
                            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                        except:
                            formatted_time = timestamp
                        
                        self.parent.history_text.insert(tk.END, f"[{formatted_time}] ")
                        
                        # Use same formatting logic as pending changes
                        if action == 'file_created':
                            self.parent.history_text.insert(tk.END, "File created\n")
                        elif action == 'file_opened':
                            filename = details.get('filename', 'unknown')
                            self.parent.history_text.insert(tk.END, f"Opened file: {filename}\n")
                        elif action == 'file_saved':
                            filename = details.get('filename', 'unknown')
                            self.parent.history_text.insert(tk.END, f"Saved file: {filename}\n")
                        elif action == 'rule_added':
                            line = details.get('line', '?')
                            rule_text = details.get('rule_text', '')
                            
                            # Extract action and SID from rule_text if individual fields not available
                            rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                            sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                            
                            self.parent.history_text.insert(tk.END, f"Added {rule_action} rule at line {line} (SID: {sid})\n")
                        elif action == 'rule_modified':
                            line = details.get('line', '?')
                            rule_text = details.get('rule_text', '')
                            
                            # Extract action and SID from rule_text if individual fields not available
                            rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                            sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                            changes = details.get('changes', {})
                            
                            # Base message with rule identification
                            self.parent.history_text.insert(tk.END, f"Modified {rule_action} rule at line {line} (SID: {sid})")
                            
                            # Add detailed change information if available
                            if changes:
                                self.parent.history_text.insert(tk.END, " - Changes:\n")
                                for field, change_info in changes.items():
                                    from_val = change_info.get('from', '')
                                    to_val = change_info.get('to', '')
                                    # Format field name for display
                                    field_display = {
                                        'action': 'Action',
                                        'protocol': 'Protocol', 
                                        'src_net': 'Source Network',
                                        'src_port': 'Source Port',
                                        'direction': 'Direction',
                                        'dst_net': 'Dest Network', 
                                        'dst_port': 'Dest Port',
                                        'message': 'Message',
                                        'content': 'Content',
                                        'sid': 'SID'
                                    }.get(field, field.title())
                                    
                                    # Truncate long values for readability
                                    from_display = (from_val[:30] + '...' if len(str(from_val)) > 30 else str(from_val)) if from_val else '(empty)'
                                    to_display = (to_val[:30] + '...' if len(str(to_val)) > 30 else str(to_val)) if to_val else '(empty)'
                                    
                                    self.parent.history_text.insert(tk.END, f"  - {field_display}: '{from_display}' → '{to_display}'\n")
                            else:
                                self.parent.history_text.insert(tk.END, "\n")
                        elif action == 'rule_deleted':
                            line = details.get('line', '?')
                            rule_text = details.get('rule_text', '')
                            
                            # Extract action and SID from rule_text if individual fields not available
                            rule_action = details.get('action', self._extract_action_from_rule_text(rule_text))
                            sid = details.get('sid', self._extract_sid_from_rule_text(rule_text))
                            message = details.get('message', '')
                            
                            if message:
                                self.parent.history_text.insert(tk.END, f"Deleted {rule_action} rule from line {line} (SID: {sid}): \"{message}\"\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Deleted {rule_action} rule from line {line} (SID: {sid})\n")
                            
                            if rule_text:
                                # Show truncated rule text (first 80 characters)
                                truncated_rule = rule_text[:80] + '...' if len(rule_text) > 80 else rule_text
                                self.parent.history_text.insert(tk.END, f"  Rule: {truncated_rule}\n")
                        elif action == 'rules_deleted':
                            if count:
                                self.parent.history_text.insert(tk.END, f"Deleted {count} rules\n")
                            else:
                                self.parent.history_text.insert(tk.END, "Deleted rules\n")
                        elif action == 'rules_copied':
                            rule_count = details.get('count', '?')
                            self.parent.history_text.insert(tk.END, f"Copied {rule_count} rules to clipboard\n")
                        elif action == 'rules_pasted':
                            line = details.get('line', '?')
                            rule_count = details.get('count', '?')
                            rules_info = details.get('rules', [])
                            if rules_info:
                                self.parent.history_text.insert(tk.END, f"Pasted {rule_count} rules at line {line}:\n")
                                for i, rule_info in enumerate(rules_info[:3]):  # Show first 3 rules
                                    if rule_info.get('type') == 'comment':
                                        comment_text = rule_info.get('text', 'comment')
                                        self.parent.history_text.insert(tk.END, f"  - Comment: {comment_text}\n")
                                    elif rule_info.get('type') == 'blank':
                                        self.parent.history_text.insert(tk.END, f"  - Blank line\n")
                                    else:
                                        action_type = rule_info.get('action', 'unknown')
                                        sid = rule_info.get('sid', '?')
                                        message = rule_info.get('message', '')
                                        if message:
                                            self.parent.history_text.insert(tk.END, f"  - {action_type.upper()} rule (SID: {sid}): {message}\n")
                                        else:
                                            self.parent.history_text.insert(tk.END, f"  - {action_type.upper()} rule (SID: {sid})\n")
                                if len(rules_info) > 3:
                                    self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Pasted {rule_count} rules at line {line}\n")
                        elif action == 'rule_moved':
                            direction = details.get('direction', 'unknown')
                            from_line = details.get('from_line', '?')
                            to_line = details.get('to_line', '?')
                            self.parent.history_text.insert(tk.END, f"Moved rule {direction} from line {from_line} to {to_line}\n")
                        elif action == 'domain_import':
                            rule_count = details.get('count', '?')
                            domain_count = details.get('domains', '?')
                            import_action = details.get('action', 'unknown')
                            domain_details = details.get('domain_details', [])
                            start_sid = details.get('start_sid')
                            end_sid = details.get('end_sid')
                            
                            if domain_details and start_sid and end_sid:
                                self.parent.history_text.insert(tk.END, f"Imported {rule_count} {import_action} rules for {domain_count} domains (SIDs {start_sid}-{end_sid}):\n")
                                for domain_info in domain_details:
                                    domain = domain_info['domain']
                                    d_start = domain_info['start_sid']
                                    d_end = domain_info['end_sid']
                                    self.parent.history_text.insert(tk.END, f"  - {domain}: SIDs {d_start}-{d_end}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Imported {rule_count} {import_action} rules for {domain_count} domains\n")
                        elif action == 'variable_added':
                            variable = details.get('variable', 'unknown')
                            definition = details.get('definition', '')
                            if definition:
                                display_def = definition[:30] + '...' if len(definition) > 30 else definition
                                self.parent.history_text.insert(tk.END, f"Added variable {variable} = {display_def}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Added variable {variable}\n")
                        elif action == 'variable_modified':
                            variable = details.get('variable', 'unknown')
                            definition = details.get('definition', '')
                            if definition:
                                display_def = definition[:30] + '...' if len(definition) > 30 else definition
                                self.parent.history_text.insert(tk.END, f"Modified variable {variable} = {display_def}\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Modified variable {variable}\n")
                        elif action == 'variable_deleted':
                            variable = details.get('variable', 'unknown')
                            var_type = 'IP Set' if variable.startswith('$') else 'Port Set' if variable.startswith('@') else 'Reference'
                            self.parent.history_text.insert(tk.END, f"Deleted {var_type.lower()} variable {variable}\n")
                        elif action == 'rules_enabled':
                            rule_count = details.get('count', '?')
                            rules_info = details.get('rules', [])
                            if rules_info:
                                self.parent.history_text.insert(tk.END, f"Enabled {rule_count} rules (uncommented):\n")
                                for rule_info in rules_info[:3]:  # Show first 3 rules
                                    action_type = rule_info.get('action', 'unknown')
                                    sid = rule_info.get('sid', '?')
                                    line = rule_info.get('line', '?')
                                    message = rule_info.get('message', '')
                                    if message:
                                        self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid}): {message}\n")
                                    else:
                                        self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid})\n")
                                if len(rules_info) > 3:
                                    self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Enabled {rule_count} rules\n")
                        elif action == 'rules_disabled':
                            rule_count = details.get('count', '?')
                            rules_info = details.get('rules', [])
                            if rules_info:
                                self.parent.history_text.insert(tk.END, f"Disabled {rule_count} rules (commented out):\n")
                                for rule_info in rules_info[:3]:  # Show first 3 rules
                                    action_type = rule_info.get('action', 'unknown')
                                    sid = rule_info.get('sid', '?')
                                    line = rule_info.get('line', '?')
                                    message = rule_info.get('message', '')
                                    if message:
                                        self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid}): {message}\n")
                                    else:
                                        self.parent.history_text.insert(tk.END, f"  - Line {line}: {action_type.upper()} rule (SID: {sid})\n")
                                if len(rules_info) > 3:
                                    self.parent.history_text.insert(tk.END, f"  ... and {len(rules_info) - 3} more\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Disabled {rule_count} rules\n")
                        elif action == 'undo_performed':
                            rules_before = details.get('rules_before', '?')
                            rules_after = details.get('rules_after', '?')
                            rules_changed = details.get('rules_changed', 0)
                            if rules_changed > 0:
                                self.parent.history_text.insert(tk.END, f"Undo operation performed ({rules_changed} rules affected: {rules_before} → {rules_after})\n")
                            else:
                                self.parent.history_text.insert(tk.END, f"Undo operation performed (rules restored: {rules_before} → {rules_after})\n")
                        else:
                            self.parent.history_text.insert(tk.END, f"{action}\n")
                    
                    if len(saved_changes) > 20:
                        self.parent.history_text.insert(tk.END, f"... and {len(saved_changes) - 20} earlier entries\n")
            
            except (OSError, IOError, json.JSONDecodeError, KeyError) as e:
                self.parent.history_text.insert(tk.END, f"\nError loading saved history: {str(e)}\n")
                # Add some debugging info
                self.parent.history_text.insert(tk.END, f"File exists: {os.path.exists(history_filename)}\n")
                if os.path.exists(history_filename):
                    try:
                        with open(history_filename, 'r', encoding='utf-8') as debug_f:
                            debug_data = json.load(debug_f)
                            self.parent.history_text.insert(tk.END, f"JSON keys: {list(debug_data.keys())}\n")
                    except Exception as debug_e:
                        self.parent.history_text.insert(tk.END, f"Debug error: {str(debug_e)}\n")
    
    def clear_history_display(self):
        """Clear the history display"""
        self.parent.history_text.config(state=tk.NORMAL)
        self.parent.history_text.delete(1.0, tk.END)
        self.parent.history_text.insert(tk.END, "History display cleared.\n\n")
        self.parent.history_text.insert(tk.END, "Click 'Refresh' to reload history data.\n")
        self.parent.history_text.config(state=tk.DISABLED)
    
    def export_history(self):
        """Export history to a text file"""
        from tkinter import filedialog
        
        if not self.parent.tracking_enabled:
            messagebox.showwarning("Export History", "Change tracking is not enabled.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export Change History",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    # Get current history content
                    current_content = self.parent.history_text.get(1.0, tk.END)
                    f.write(current_content)
                
                messagebox.showinfo("Export Complete", f"History exported to {filename}")
            except FileNotFoundError as e:
                messagebox.showerror("Directory Error", f"Export directory not found: {str(e)}")
            except PermissionError as e:
                messagebox.showerror("Permission Error", f"Cannot write to export location: {str(e)}")
            except OSError as e:
                messagebox.showerror("File System Error", f"Cannot write export file: {str(e)}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export history: {str(e)}")
    
    def handle_ctrl_c(self):
        """Handle Ctrl-C with focus awareness - copy rules or history text based on focus"""
        focused_widget = self.parent.root.focus_get()
        
        # Check if focus is on the Change History text widget
        if focused_widget == self.history_text:
            self.copy_history_selection()
        elif focused_widget == self.tree:
            # Focus is on the rules tree - copy selected rules
            self.parent.copy_selected_rules()
        else:
            # Check if focus is on any text entry field, let default behavior handle it
            if isinstance(focused_widget, (tk.Entry, tk.Text)):
                # For entry fields, let the default copy behavior work
                try:
                    focused_widget.event_generate("<<Copy>>")
                except:
                    pass  # If copy fails, ignore silently
            else:
                # Default to copying selected rules if no specific focus detected
                self.parent.copy_selected_rules()
    
    def handle_ctrl_v(self, event):
        """Handle Ctrl-V with focus awareness - paste rules or allow normal paste based on focus"""
        focused_widget = self.parent.root.focus_get()
        
        # Check if focus is on the rules tree - paste rules
        if focused_widget == self.tree:
            self.parent.paste_rules()
            return 'break'  # Prevent default handler
        # Check if focus is on any text entry field - allow default paste behavior
        elif isinstance(focused_widget, (tk.Entry, tk.Text)):
            # For entry fields, don't intercept - let tkinter's default paste handler work
            # By not returning 'break', the event continues to the widget's default handler
            return  # Allow default behavior
        else:
            # If no specific focus detected, default to pasting rules for backward compatibility
            self.parent.paste_rules()
            return 'break'  # Prevent default handler
    
    def copy_history_selection(self):
        """Copy selected text from Change History to system clipboard"""
        try:
            # Get selected text from history widget
            if self.history_text.tag_ranges(tk.SEL):
                selected_text = self.history_text.selection_get()
                # Copy to system clipboard
                self.parent.root.clipboard_clear()
                self.parent.root.clipboard_append(selected_text)
                # Show brief feedback
                messagebox.showinfo("Copy", "Selected history text copied to clipboard.")
            else:
                # No selection - copy all visible history text
                all_text = self.history_text.get(1.0, tk.END).strip()
                if all_text:
                    self.parent.root.clipboard_clear()
                    self.parent.root.clipboard_append(all_text)
                    messagebox.showinfo("Copy", "All history text copied to clipboard.")
                else:
                    messagebox.showwarning("Copy", "No history text to copy.")
        except tk.TclError:
            # No selection available
            messagebox.showwarning("Copy", "No text selected to copy.")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy text: {str(e)}")
    
    def on_history_right_click(self, event):
        """Handle right-click context menu for Change History text"""
        try:
            # Create context menu for history text
            context_menu = tk.Menu(self.parent.root, tearoff=0)
            
            # Check if there's selected text
            has_selection = bool(self.history_text.tag_ranges(tk.SEL))
            
            if has_selection:
                context_menu.add_command(label="Copy Selection", command=self.copy_history_selection)
                context_menu.add_separator()
            
            # Always show "Copy All" option
            context_menu.add_command(label="Copy All", command=self.copy_all_history_text)
            
            # Add "Select All" option
            context_menu.add_command(label="Select All", command=self.select_all_history_text)
            
            # Show the menu at mouse position
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            except Exception as popup_error:
                # Fallback: show at approximate position
                context_menu.tk_popup(event.x_root, event.y_root)
                
        except Exception as e:
            # Ultimate fallback - show error message
            messagebox.showinfo("Menu Error", f"Context menu error: {str(e)}")
        finally:
            try:
                context_menu.grab_release()
            except:
                pass
    
    def copy_all_history_text(self):
        """Copy all history text to system clipboard"""
        try:
            all_text = self.history_text.get(1.0, tk.END).strip()
            if all_text:
                self.parent.root.clipboard_clear()
                self.parent.root.clipboard_append(all_text)
                messagebox.showinfo("Copy", "All history text copied to clipboard.")
            else:
                messagebox.showwarning("Copy", "No history text to copy.")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy all text: {str(e)}")
    
    def select_all_history_text(self):
        """Select all text in the Change History tab"""
        try:
            # Enable the text widget temporarily to allow selection
            self.history_text.config(state=tk.NORMAL)
            self.history_text.tag_add(tk.SEL, "1.0", tk.END)
            # Set focus to the text widget so selection is visible
            self.history_text.focus_set()
            # Disable it again
            self.history_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Select All Error", f"Failed to select all text: {str(e)}")
    
    def on_entry_right_click(self, event):
        """Handle right-click context menu for text entry fields"""
        try:
            entry_widget = event.widget
            
            # Create context menu for entry fields
            context_menu = tk.Menu(self.parent.root, tearoff=0)
            
            # Check if there's selected text in the entry
            has_selection = False
            try:
                if entry_widget.selection_present():
                    has_selection = True
            except tk.TclError:
                has_selection = False
            
            # Cut option (only if there's a selection)
            if has_selection:
                context_menu.add_command(label="Cut", command=lambda: self.entry_cut(entry_widget))
            
            # Copy option (only if there's a selection)  
            if has_selection:
                context_menu.add_command(label="Copy", command=lambda: self.entry_copy(entry_widget))
            
            # Paste option (check if clipboard has content)
            try:
                clipboard_content = self.parent.root.clipboard_get()
                if clipboard_content:
                    if has_selection:
                        context_menu.add_separator()
                    context_menu.add_command(label="Paste", command=lambda: self.entry_paste(entry_widget))
            except tk.TclError:
                # No clipboard content
                pass
            
            # Select All option (only if entry has content)
            entry_content = entry_widget.get()
            if entry_content:
                context_menu.add_separator()
                context_menu.add_command(label="Select All", command=lambda: self.entry_select_all(entry_widget))
            
            # Only show menu if it has items
            if context_menu.index("end") is not None:
                # Show the menu at mouse position
                try:
                    context_menu.tk_popup(event.x_root, event.y_root)
                except Exception as popup_error:
                    # Fallback: show at approximate position
                    context_menu.tk_popup(event.x_root, event.y_root)
                    
        except Exception as e:
            # Ultimate fallback - show error message
            messagebox.showinfo("Menu Error", f"Context menu error: {str(e)}")
        finally:
            try:
                context_menu.grab_release()
            except:
                pass
    
    def entry_cut(self, entry_widget):
        """Cut selected text from entry widget"""
        try:
            entry_widget.event_generate("<<Cut>>")
        except Exception as e:
            messagebox.showerror("Cut Error", f"Failed to cut text: {str(e)}")
    
    def entry_copy(self, entry_widget):
        """Copy selected text from entry widget"""
        try:
            entry_widget.event_generate("<<Copy>>")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy text: {str(e)}")
    
    def entry_paste(self, entry_widget):
        """Paste text into entry widget"""
        try:
            entry_widget.event_generate("<<Paste>>")
        except Exception as e:
            messagebox.showerror("Paste Error", f"Failed to paste text: {str(e)}")
    
    def entry_select_all(self, entry_widget):
        """Select all text in entry widget"""
        try:
            entry_widget.select_range(0, tk.END)
            entry_widget.icursor(tk.END)
        except Exception as e:
            messagebox.showerror("Select All Error", f"Failed to select all text: {str(e)}")
    
    def create_tooltip(self, widget, text):
        """Create a tooltip for a widget"""
        def show_tooltip(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
            
            label = tk.Label(tooltip, text=text, background="lightyellow", 
                           relief="solid", borderwidth=1, font=("TkDefaultFont", 9))
            label.pack()
            
            def hide_tooltip():
                tooltip.destroy()
            
            # Hide tooltip after 5 seconds or when mouse leaves
            tooltip.after(5000, hide_tooltip)
            widget.tooltip = tooltip
            widget.hide_tooltip = hide_tooltip
        
        def hide_tooltip(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                delattr(widget, 'tooltip')
        
        # Bind events
        widget.bind("<Enter>", show_tooltip)
        widget.bind("<Leave>", hide_tooltip)
    
    def on_protocol_changed(self, event):
        """Handle protocol dropdown change to update Content Keywords for new rules only"""
        # Only update Content Keywords when creating a new rule (not editing existing)
        if (self.parent.selected_rule_index is not None and 
            self.parent.selected_rule_index >= len(self.parent.rules)):
            # This is a new rule being created
            protocol = self.protocol_var.get().lower()
            if protocol in ["udp", "icmp"]:
                self.content_var.set("")
            else:
                self.content_var.set("flow: to_server")
    
    def _extract_action_from_rule_text(self, rule_text):
        """Extract action from rule_text string"""
        if not rule_text:
            return 'unknown'
        try:
            # Extract first word which should be the action
            action = rule_text.split()[0].lower()
            if action in ['pass', 'alert', 'drop', 'reject']:
                return action
        except (IndexError, AttributeError):
            pass
        return 'unknown'
    
    def _extract_sid_from_rule_text(self, rule_text):
        """Extract SID from rule_text string"""
        if not rule_text:
            return '?'
        try:
            # Look for sid:number pattern
            import re
            sid_match = re.search(r'sid:(\d+)', rule_text)
            if sid_match:
                return sid_match.group(1)
        except (AttributeError, ValueError):
            pass
        return '?'
    
    def show_test_flow_dialog(self):
        """Show dialog for testing a flow against current rules"""
        if not self.parent.rules:
            messagebox.showinfo("Test Flow", "No rules to test against. Please add some rules first.")
            return
        
        # Create dialog (increased height to show all elements)
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Test Flow Against Rules")
        dialog.geometry("950x900")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 50, self.parent.root.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title
        title_label = ttk.Label(main_frame, text="Test Flow Against Rules", 
                               font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 5))
        
        # Disclaimer
        disclaimer_label = ttk.Label(main_frame, 
                                    text="For illustrative purposes only. Proper testing should be performed to fully determine real flow results.",
                                    font=("TkDefaultFont", 8, "italic"),
                                    foreground="#666666")
        disclaimer_label.pack(pady=(0, 2))
        
        # Version
        from version import get_flow_tester_version
        version_label = ttk.Label(main_frame,
                                 text=f"Flow Tester Version: {get_flow_tester_version()}",
                                 font=("TkDefaultFont", 8),
                                 foreground="#999999")
        version_label.pack(pady=(0, 15))
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Flow Information")
        input_frame.pack(fill=tk.X, pady=(0, 15))
        
        fields = ttk.Frame(input_frame)
        fields.pack(fill=tk.X, padx=10, pady=10)
        
        # Row 1: Source IP and Port
        row = 0
        ttk.Label(fields, text="Source IP:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        src_ip_var = tk.StringVar(value="192.168.1.100")
        ttk.Entry(fields, textvariable=src_ip_var, width=20).grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(fields, text="Source Port:").grid(row=row, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        src_port_var = tk.StringVar(value="12345")
        src_port_entry = ttk.Entry(fields, textvariable=src_port_var, width=10)
        src_port_entry.grid(row=row, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Row 2: Destination IP and Port
        row += 1
        dst_ip_label = ttk.Label(fields, text="Dest IP:")
        dst_ip_label.grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        dst_ip_var = tk.StringVar(value="8.8.8.8")
        dst_ip_entry = ttk.Entry(fields, textvariable=dst_ip_var, width=20)
        dst_ip_entry.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for dest IP when testing HTTP/TLS
        self.create_tooltip(dst_ip_entry,
            "Note: For HTTP/TLS testing, the destination IP is used only for \n" +
            "network/port matching. Domain matching is done via the URL/Domain field.\n" +
            "You can use any IP (e.g., 8.8.8.8) when testing domain-based rules.")
        
        ttk.Label(fields, text="Dest Port:").grid(row=row, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        dst_port_var = tk.StringVar(value="443")
        dst_port_entry = ttk.Entry(fields, textvariable=dst_port_var, width=10)
        dst_port_entry.grid(row=row, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Row 3: Protocol, Direction, and URL/Domain (on same row to save space)
        row += 1
        ttk.Label(fields, text="Protocol:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
        protocol_var = tk.StringVar(value="tcp")
        protocol_combo = ttk.Combobox(fields, textvariable=protocol_var, 
                                     values=["ip", "icmp", "udp", "tcp", "http", "tls"], 
                                     state="readonly", width=10)
        protocol_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(fields, text="Direction:").grid(row=row, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        direction_var = tk.StringVar(value="->")
        direction_combo = ttk.Combobox(fields, textvariable=direction_var,
                                      values=["->", "<>"],
                                      state="readonly", width=5)
        direction_combo.grid(row=row, column=3, sticky=tk.W, padx=5, pady=5)
        
        # URL/Domain field (for HTTP/TLS protocols) - placed after Direction to save space
        url_label = ttk.Label(fields, text="URL/Domain:")
        url_var = tk.StringVar(value="")
        url_entry = ttk.Entry(fields, textvariable=url_var, width=35)
        
        # Protocol change handler to show/hide URL field and manage port states
        def on_test_protocol_change(event):
            protocol = protocol_var.get().lower()
            
            # Handle ICMP - disable ports
            if protocol == 'icmp':
                src_port_var.set("any")
                dst_port_var.set("any")
                src_port_entry.config(state="disabled")
                dst_port_entry.config(state="disabled")
            else:
                src_port_entry.config(state="normal")
                dst_port_entry.config(state="normal")
            
            # Show URL field for HTTP/TLS protocols (on same row as protocol/direction)
            if protocol in ['http', 'tls', 'https']:
                url_label.grid(row=2, column=4, sticky=tk.W, padx=(20, 5), pady=5)
                url_entry.grid(row=2, column=5, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=5)
                
                # Set default port based on protocol
                if protocol == 'http':
                    dst_port_var.set("80")
                    url_var.set("www.example.com/path")
                elif protocol in ['tls', 'https']:
                    dst_port_var.set("443")
                    url_var.set("www.example.com")
            else:
                # Hide URL field for other protocols
                url_label.grid_remove()
                url_entry.grid_remove()
                url_var.set("")
                
                # Reset to default values for non-HTTP/TLS
                if protocol == 'tcp':
                    dst_port_var.set("443")
                elif protocol == 'udp':
                    dst_port_var.set("53")
        
        protocol_combo.bind('<<ComboboxSelected>>', on_test_protocol_change)
        
        # Test button
        test_button = ttk.Button(input_frame, text="Test Flow")
        test_button.pack(pady=(0, 10))
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Test Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Create paned window for flow diagram and matched rules
        paned = ttk.PanedWindow(results_frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Flow diagram section
        flow_frame = ttk.Frame(paned)
        paned.add(flow_frame, weight=1)
        
        ttk.Label(flow_frame, text="Flow Diagram:", font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # Canvas for flow visualization (increased height for vertical stacking)
        flow_canvas = tk.Canvas(flow_frame, height=300, bg="white", relief=tk.SUNKEN, bd=1)
        flow_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Matched rules section
        rules_frame = ttk.Frame(paned)
        paned.add(rules_frame, weight=2)
        
        ttk.Label(rules_frame, text="Matched Rules (in evaluation order):", 
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # Create container for results table and scrollbars
        results_container = ttk.Frame(rules_frame)
        results_container.pack(fill=tk.BOTH, expand=True)
        
        # Results table (created as child of results_container, not rules_frame)
        columns = ("Line", "Type", "Action", "Protocol", "Rule")
        results_tree = ttk.Treeview(results_container, columns=columns, show="headings", height=5)
        
        results_tree.heading("Line", text="Line")
        results_tree.heading("Type", text="Type")
        results_tree.heading("Action", text="Action")
        results_tree.heading("Protocol", text="Protocol")
        results_tree.heading("Rule", text="Rule Details")
        
        results_tree.column("Line", width=50, stretch=False)
        results_tree.column("Type", width=100, stretch=False)
        results_tree.column("Action", width=70, stretch=False)
        results_tree.column("Protocol", width=70, stretch=False)
        results_tree.column("Rule", width=550, stretch=True)
        
        # Configure color tags
        results_tree.tag_configure("pass", foreground="#2E7D32")
        results_tree.tag_configure("drop", foreground="#D32F2F")
        results_tree.tag_configure("reject", foreground="#7B1FA2")
        results_tree.tag_configure("alert", foreground="#1976D2")
        results_tree.tag_configure("final", background="#FFFF99")
        
        # Vertical scrollbar
        results_scrollbar = ttk.Scrollbar(results_container, orient=tk.VERTICAL, command=results_tree.yview)
        results_tree.configure(yscrollcommand=results_scrollbar.set)
        
        # Horizontal scrollbar for long rules
        results_h_scrollbar = ttk.Scrollbar(results_container, orient=tk.HORIZONTAL, command=results_tree.xview)
        results_tree.configure(xscrollcommand=results_h_scrollbar.set)
        
        # Grid layout
        results_tree.grid(row=0, column=0, sticky="nsew")
        results_scrollbar.grid(row=0, column=1, sticky="ns")
        results_h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        results_container.grid_rowconfigure(0, weight=1)
        results_container.grid_columnconfigure(0, weight=1)
        
        # Bind double-click to jump to rule
        results_tree.bind("<Double-1>", lambda e: self._on_results_double_click(e, results_tree, dialog))
        
        # Final action display (create here so final_label exists for test button)
        final_frame = ttk.Frame(main_frame)
        final_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(final_frame, text="Final Action:", font=("TkDefaultFont", 11, "bold")).pack(side=tk.LEFT, padx=5)
        final_label = ttk.Label(final_frame, text="(not tested yet)", 
                               font=("TkDefaultFont", 11, "bold"))
        final_label.pack(side=tk.LEFT, padx=5)
        
        # Now configure the test button command (test_button was created earlier, now we configure it)
        test_button.config(command=lambda: self.run_flow_test(src_ip_var.get(), src_port_var.get(),
                                                               dst_ip_var.get(), dst_port_var.get(),
                                                               protocol_var.get(), direction_var.get(),
                                                               results_tree, flow_canvas, final_label,
                                                               url_var.get()))
        
        # Close button
        ttk.Button(main_frame, text="Close", command=dialog.destroy).pack()
    
    def run_flow_test(self, src_ip, src_port, dst_ip, dst_port, protocol, direction,
                     results_tree, flow_canvas, final_label, url=None):
        """Run flow test and update results display"""
        try:
            # Validate inputs
            if not src_ip or not dst_ip:
                messagebox.showerror("Validation Error", "Source and destination IP addresses are required.")
                return
            
            try:
                import ipaddress
                ipaddress.ip_address(src_ip)
                ipaddress.ip_address(dst_ip)
            except ValueError as e:
                messagebox.showerror("Validation Error", f"Invalid IP address: {str(e)}")
                return
            
            # Validate ports
            if src_port.lower() != 'any':
                try:
                    port_num = int(src_port)
                    if not (1 <= port_num <= 65535):
                        messagebox.showerror("Validation Error", "Source port must be between 1 and 65535 or 'any'.")
                        return
                except ValueError:
                    messagebox.showerror("Validation Error", "Source port must be a number or 'any'.")
                    return
            
            if dst_port.lower() != 'any':
                try:
                    port_num = int(dst_port)
                    if not (1 <= port_num <= 65535):
                        messagebox.showerror("Validation Error", "Destination port must be between 1 and 65535 or 'any'.")
                        return
                except ValueError:
                    messagebox.showerror("Validation Error", "Destination port must be a number or 'any'.")
                    return
            
            # Validate URL for HTTP/TLS protocols
            if protocol.lower() in ['http', 'tls', 'https']:
                if not url or not url.strip():
                    messagebox.showerror("Validation Error", 
                                       f"{protocol.upper()} protocol requires a URL/Domain. "
                                       "Please enter a domain like 'www.example.com' or 'www.example.com/path'.")
                    return
            
            # Create FlowTester instance
            from flow_tester import FlowTester
            flow_tester = FlowTester(self.parent.rules, self.parent.variables, self.parent.rule_analyzer)
            
            # Run the test
            results = flow_tester.test_flow(src_ip, src_port, dst_ip, dst_port, protocol, direction, url)
            
            # Store results and results_tree for diagram access
            self.parent._last_flow_test_results = results
            self.parent._flow_test_results_tree = results_tree
            
            # Clear previous results
            results_tree.delete(*results_tree.get_children())
            flow_canvas.delete("all")
            
            # Display flow diagram with results context (including matched rule info)
            self._draw_flow_diagram(flow_canvas, results['flow_steps'], results['final_action'], results.get('final_rule'))
            
            # Display matched rules in evaluation order (combine action rules and alert rules)
            all_matches = results['matched_rules'] + results['alert_rules']
            
            if all_matches:
                # Sort by line number to show in evaluation order
                all_matches.sort(key=lambda m: m['line'])
                
                for match in all_matches:
                    rule = match['rule']
                    
                    # Extract rule details (everything after protocol and direction)
                    # Format: src_net src_port direction dst_net dst_port (content)
                    rule_details = f"{rule.src_net} {rule.src_port} {rule.direction} {rule.dst_net} {rule.dst_port}"
                    if rule.content:
                        rule_details += f" ({rule.content})"
                    
                    # Only use action color tag (no yellow highlight)
                    tags = [match['action'].lower()]
                    
                    results_tree.insert("", tk.END, 
                                      values=(match['line'], match['type'], match['action'].upper(), 
                                             rule.protocol.upper(), rule_details),
                                      tags=tuple(tags))
            else:
                # No matches
                results_tree.insert("", tk.END, values=("", "", "", "", "No rules matched this flow"))
            
            # Display final action
            final_action = results['final_action']
            if final_action == 'PASS':
                final_label.config(text="ALLOWED", foreground="#2E7D32")
            elif final_action in ['DROP', 'REJECT']:
                final_label.config(text="BLOCKED", foreground="#D32F2F")
            elif final_action == 'NO_RULES':
                final_label.config(text="NO RULES TO EVALUATE", foreground="#FF6600")
            elif 'no matching rules' in final_action.lower():
                final_label.config(text="UNDETERMINED (no matching rules)", foreground="#FF6600")
            else:
                final_label.config(text=final_action, foreground="#000000")
                
        except Exception as e:
            messagebox.showerror("Flow Test Error", f"An error occurred during flow testing:\n\n{str(e)}\n\nPlease check your inputs and try again.")
            import traceback
            print(f"Flow test error: {traceback.format_exc()}")
    
    def _draw_flow_diagram(self, canvas, flow_steps, final_action=None, final_rule=None):
        """Draw enhanced visual flow diagram with rule-to-step mapping
        
        Args:
            canvas: Canvas widget to draw on
            flow_steps: List of flow step dictionaries
            final_action: Final action result (e.g., 'PASS', 'DROP', 'REJECT')
            final_rule: The final matched rule info (includes rule object)
        """
        canvas.delete("all")
        
        # Store references for hover functionality
        if not hasattr(self, '_canvas_hover_data'):
            self._canvas_hover_data = {}
        self._canvas_hover_data['canvas'] = canvas
        self._canvas_hover_data['arrow_to_line'] = {}
        self._canvas_hover_data['line_to_arrows'] = {}
        
        if not flow_steps:
            return
        
        # Calculate canvas dimensions
        canvas.update_idletasks()
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        
        if width <= 1:
            width = 900
        if height <= 1:
            height = 400  # Increased for vertical stacking
        
        # Layout parameters
        margin = 60
        box_width = 120
        box_height = 50
        
        # Calculate positions for source and destination boxes
        src_x = margin + box_width // 2
        dst_x = width - margin - box_width // 2
        
        # Draw source box (on left)
        src_y = height // 2
        canvas.create_rectangle(src_x - box_width//2, src_y - box_height//2,
                              src_x + box_width//2, src_y + box_height//2,
                              fill="#E3F2FD", outline="#1976D2", width=2)
        canvas.create_text(src_x, src_y, text="Source", font=("TkDefaultFont", 11, "bold"))
        
        # Add source address below box
        if flow_steps:
            src_addr = flow_steps[0].get('from', '')
            canvas.create_text(src_x, src_y + box_height//2 + 15, 
                             text=src_addr, font=("TkDefaultFont", 8))
        
        # Draw destination box (on right)
        dst_y = height // 2
        canvas.create_rectangle(dst_x - box_width//2, dst_y - box_height//2,
                              dst_x + box_width//2, dst_y + box_height//2,
                              fill="#E8F5E9", outline="#2E7D32", width=2)
        canvas.create_text(dst_x, dst_y, text="Destination", font=("TkDefaultFont", 11, "bold"))
        
        # Add destination address below box
        if flow_steps:
            dst_addr = flow_steps[0].get('to', '')
            canvas.create_text(dst_x, dst_y + box_height//2 + 15,
                             text=dst_addr, font=("TkDefaultFont", 8))
        
        # Get results from parent's last flow test (stored during run_flow_test)
        results = getattr(self.parent, '_last_flow_test_results', None)
        if not results:
            # No results available - just show source and destination boxes (already drawn)
            return
        
        # Build list of arrows to draw (TCP handshake steps + matched rules)
        arrows_to_draw = []
        
        # Get all matched rules (action rules + alert rules)
        all_matched = results.get('matched_rules', []) + results.get('alert_rules', [])
        step_mapping = results.get('step_rule_mapping', {})
        
        # If no rules matched, don't draw any arrows - just show source/destination boxes
        if not all_matched:
            return
        
        # TCP and application layer protocols over TCP (HTTP, TLS) use handshake + established phases
        if results.get('protocol') in ['tcp', 'http', 'tls', 'https']:
            # Show individual handshake steps (SYN, SYN-ACK, ACK) then established
            handshake_rules = [m for m in all_matched if m.get('phase') == 'handshake']
            established_rules = [m for m in all_matched if m.get('phase') == 'established']
            
            # TCP handshake steps with their matching rules (use first handshake rule for all 3 steps)
            handshake_match = handshake_rules[0] if handshake_rules else None
            
            # Check if handshake was blocked (DROP or REJECT)
            handshake_blocked = (handshake_match and 
                                handshake_match['action'].lower() in ['drop', 'reject'])
            
            # Step 1: SYN (->)
            arrows_to_draw.append({
                'type': 'tcp_syn',
                'match': handshake_match,
                'description': 'SYN',
                'direction': '->',
                'step_name': 'TCP SYN'
            })
            
            # Only show SYN-ACK and ACK if handshake was NOT blocked
            if not handshake_blocked:
                # Step 2: SYN-ACK (<-)
                arrows_to_draw.append({
                    'type': 'tcp_synack',
                    'match': handshake_match,  # Same rule (stateful)
                    'description': 'SYN-ACK',
                    'direction': '<-',
                    'step_name': 'TCP SYN-ACK'
                })
                
                # Step 3: ACK (->)
                arrows_to_draw.append({
                    'type': 'tcp_ack',
                    'match': handshake_match,  # Same rule (stateful)
                    'description': 'ACK',
                    'direction': '->',
                    'step_name': 'TCP ACK'
                })
                
                # Step 4+: Established phase rules (sorted by line number to match table order)
                # Only show if handshake succeeded
                established_rules_sorted = sorted(established_rules, key=lambda m: m['line'])
                
                protocol_name = results.get('protocol', 'tcp').upper()
                
                # For TLS/HTTPS, show detailed TLS handshake steps
                if protocol_name in ['TLS', 'HTTPS'] and established_rules_sorted:
                    # Find the first action rule (pass/drop/reject) - not alert
                    action_match = next((m for m in established_rules_sorted if m['action'].lower() != 'alert'), None)
                    
                    if action_match:
                        # Add alert rules that come BEFORE the action rule (by line number)
                        for match in established_rules_sorted:
                            if match['action'].lower() == 'alert' and match['line'] < action_match['line']:
                                arrows_to_draw.append({
                                    'type': 'alert',
                                    'match': match,
                                    'description': 'Alert',
                                    'direction': '->',
                                    'step_name': 'Alert Rule'
                                })
                        
                        # Check if TLS connection is blocked (DROP or REJECT)
                        tls_blocked = action_match['action'].lower() in ['drop', 'reject']
                        
                        # Show TLS ClientHello (always shown)
                        arrows_to_draw.append({
                            'type': 'tls_client_hello',
                            'match': action_match,
                            'description': 'ClientHello',
                            'direction': '->',
                            'step_name': 'TLS ClientHello'
                        })
                        
                        # Only show ServerHello and Encrypted Data if TLS was NOT blocked
                        if not tls_blocked:
                            arrows_to_draw.append({
                                'type': 'tls_server_hello',
                                'match': action_match,
                                'description': 'ServerHello',
                                'direction': '<-',
                                'step_name': 'TLS ServerHello'
                            })
                            
                            arrows_to_draw.append({
                                'type': 'tls_data',
                                'match': action_match,
                                'description': 'Encrypted Data',
                                'direction': '->',
                                'step_name': 'Application Data'
                            })
                        
                        # Add alert rules that come AFTER the action rule (by line number)
                        for match in established_rules_sorted:
                            if match['action'].lower() == 'alert' and match['line'] > action_match['line']:
                                arrows_to_draw.append({
                                    'type': 'alert',
                                    'match': match,
                                    'description': 'Alert',
                                    'direction': '->',
                                    'step_name': 'Alert Rule'
                                })
                    else:
                        # No action rule, just show all alert rules
                        for match in established_rules_sorted:
                            if match['action'].lower() == 'alert':
                                arrows_to_draw.append({
                                    'type': 'alert',
                                    'match': match,
                                    'description': 'Alert',
                                    'direction': '->',
                                    'step_name': 'Alert Rule'
                                })
                else:
                    # For HTTP and TCP, show single arrow per matched rule
                    for match in established_rules_sorted:
                        if protocol_name == 'HTTP':
                            desc = 'HTTP Data' if match['action'].lower() != 'alert' else 'Alert'
                        else:
                            desc = 'Established' if match['action'].lower() != 'alert' else 'Alert'
                        
                        arrows_to_draw.append({
                            'type': 'established',
                            'match': match,
                            'description': desc,
                            'direction': '->',
                            'step_name': f'{protocol_name} Connection' if match['action'].lower() != 'alert' else 'Alert Rule'
                        })
        elif all_matched:
            # Non-TCP protocols (IP, ICMP, UDP): show one arrow per matched rule
            all_phase_rules = [m for m in all_matched if m.get('phase') == 'all']
            for match in all_phase_rules:
                arrows_to_draw.append({
                    'type': 'single',
                    'match': match,
                    'description': results.get('protocol', 'IP').upper(),
                    'direction': '->',
                    'step_name': f"{results.get('protocol', 'IP').upper()} Packet"
                })
        else:
            # No matched rules - don't draw any arrows
            # Just show the source and destination boxes (already drawn)
            pass
        
        # Draw arrows vertically stacked (reduce spacing to fit more arrows)
        arrow_height = 30  # Vertical spacing between arrows (reduced for TLS handshake)
        start_y = max(60, (height - len(arrows_to_draw) * arrow_height) // 2)
        
        for i, arrow_info in enumerate(arrows_to_draw):
            y_pos = start_y + i * arrow_height
            match = arrow_info['match']
            arrow_direction = arrow_info.get('direction', '->')
            step_desc = arrow_info.get('description', '')
            
            if match:
                action = match['action'].lower()
                line_num = match['line']
                is_alert = (action == 'alert')
                is_final = (final_rule and match['line'] == final_rule['line'])
                
                # Determine arrow color based on rule action (match rule table colors)
                if is_alert:
                    arrow_color = "#1976D2"  # Blue for alerts
                    arrow_dash = (5, 3)  # Dashed line
                    arrow_width = 2
                elif action == 'pass':
                    arrow_color = "#2E7D32"  # Green for pass
                    arrow_dash = ()
                    arrow_width = 3 if is_final else 2
                elif action == 'reject':
                    arrow_color = "#7B1FA2"  # Purple for reject
                    arrow_dash = ()
                    arrow_width = 3 if is_final else 2
                elif action == 'drop':
                    arrow_color = "#D32F2F"  # Red for drop
                    arrow_dash = ()
                    arrow_width = 3 if is_final else 2
                else:
                    arrow_color = "#424242"  # Gray for others
                    arrow_dash = ()
                    arrow_width = 2
                
                # Draw arrow based on direction
                arrow_start_x = src_x + box_width//2 + 10
                arrow_end_x = dst_x - box_width//2 - 10
                
                if arrow_direction == '<-':
                    # Reverse direction for SYN-ACK
                    arrow_start_x, arrow_end_x = arrow_end_x, arrow_start_x
                
                # For drop/reject, arrow is cut in half to show flow stopped
                if action in ['drop', 'reject'] and arrow_direction == '->':
                    arrow_end_x = src_x + (dst_x - src_x) // 2
                
                # Create arrow with tags for hover
                arrow_tag = f"arrow_{line_num}_{i}"
                arrow_id = canvas.create_line(
                    arrow_start_x, y_pos, arrow_end_x, y_pos,
                    arrow=tk.LAST, width=arrow_width, fill=arrow_color,
                    dash=arrow_dash, tags=arrow_tag
                )
                
                # Store mapping for hover
                self._canvas_hover_data['arrow_to_line'][arrow_tag] = line_num
                if line_num not in self._canvas_hover_data['line_to_arrows']:
                    self._canvas_hover_data['line_to_arrows'][line_num] = []
                self._canvas_hover_data['line_to_arrows'][line_num].append(arrow_tag)
                
                # Draw visual indicators at arrow endpoint based on rule action
                actual_end_x = arrow_end_x
                if arrow_direction == '->':
                    if action == 'pass':
                        # Green checkmark for pass rules
                        self._draw_checkmark(canvas, actual_end_x + 5, y_pos, arrow_tag)
                    elif action in ['drop', 'reject']:
                        # Red X for drop/reject rules
                        self._draw_x_mark(canvas, actual_end_x + 10, y_pos, arrow_tag)
                    # Alert rules: no visual indicator (dashed line is sufficient)
                
                # Draw step description above arrow (e.g., "SYN", "SYN-ACK", "ACK")
                mid_x = (arrow_start_x + arrow_end_x) // 2
                canvas.create_text(mid_x, y_pos - 15,
                                 text=f"{step_desc} (Line {line_num})",
                                 font=("TkDefaultFont", 9),
                                 fill=arrow_color, tags=arrow_tag)
            else:
                # Generic arrow (no matching rule)
                arrow_color = "#999999"
                arrow_id = canvas.create_line(
                    src_x + box_width//2 + 10, y_pos,
                    dst_x - box_width//2 - 10, y_pos,
                    arrow=tk.LAST, width=2, fill=arrow_color
                )
                canvas.create_text((src_x + dst_x) // 2, y_pos - 15,
                                 text=arrow_info['description'],
                                 font=("TkDefaultFont", 8), fill=arrow_color)
        
        # Bind hover events
        self._setup_canvas_hover_bindings(canvas)
    
    def _draw_simple_arrows(self, canvas, flow_steps, src_x, dst_x, src_y, box_width):
        """Draw simple horizontal arrows when no rule mapping available"""
        arrow_spacing = 30
        start_y = src_y - (len(flow_steps) * arrow_spacing) // 2
        
        for i, step in enumerate(flow_steps):
            y_pos = start_y + i * arrow_spacing
            description = step.get('description', '')
            
            canvas.create_line(src_x + box_width//2 + 10, y_pos,
                             dst_x - box_width//2 - 10, y_pos,
                             arrow=tk.LAST, width=2, fill="#424242")
            canvas.create_text((src_x + dst_x) // 2, y_pos - 15,
                             text=description, font=("TkDefaultFont", 8))
    
    def _draw_checkmark(self, canvas, x, y, tag):
        """Draw a green checkmark at specified position"""
        # Checkmark shape
        points = [
            x - 6, y,
            x - 2, y + 4,
            x + 6, y - 4
        ]
        canvas.create_line(points, width=3, fill="#2E7D32",
                         capstyle=tk.ROUND, joinstyle=tk.ROUND, tags=tag)
    
    def _draw_x_mark(self, canvas, x, y, tag):
        """Draw a red X at specified position"""
        # X mark (two crossing lines)
        size = 6
        canvas.create_line(x - size, y - size, x + size, y + size,
                         width=3, fill="#D32F2F", tags=tag)
        canvas.create_line(x - size, y + size, x + size, y - size,
                         width=3, fill="#D32F2F", tags=tag)
    
    def _draw_info_icon(self, canvas, x, y, tag):
        """Draw a blue info icon at specified position"""
        # Circle
        radius = 6
        canvas.create_oval(x - radius, y - radius, x + radius, y + radius,
                         outline="#1976D2", width=2, fill="white", tags=tag)
        # 'i' letter
        canvas.create_text(x, y, text="i", font=("TkDefaultFont", 10, "bold"),
                         fill="#1976D2", tags=tag)
    
    def _setup_canvas_hover_bindings(self, canvas):
        """Setup hover event bindings for canvas arrows"""
        def on_canvas_hover(event):
            # Find which arrow is being hovered
            items = canvas.find_overlapping(event.x - 5, event.y - 5,
                                           event.x + 5, event.y + 5)
            
            # Clear any previous highlights
            self._clear_canvas_highlights(canvas)
            
            for item in items:
                tags = canvas.gettags(item)
                for tag in tags:
                    if tag.startswith('arrow_'):
                        line_num = self._canvas_hover_data.get('arrow_to_line', {}).get(tag)
                        if line_num:
                            # Highlight only line items (not text) on canvas
                            item_type = canvas.type(item)
                            if item_type == 'line':
                                canvas.itemconfig(item, width=4)
                            # Highlight rule in results table
                            self._highlight_rule_in_results(line_num)
                        break
        
        def on_canvas_leave(event):
            self._clear_canvas_highlights(canvas)
        
        canvas.bind("<Motion>", on_canvas_hover)
        canvas.bind("<Leave>", on_canvas_leave)
    
    def _clear_canvas_highlights(self, canvas):
        """Clear all arrow highlights on canvas"""
        for arrow_tag in self._canvas_hover_data.get('arrow_to_line', {}).keys():
            # Reset arrow width to normal - only for line items
            try:
                # Find all items with this tag
                items = canvas.find_withtag(arrow_tag)
                for item in items:
                    if canvas.type(item) == 'line':
                        canvas.itemconfig(item, width=2)
            except:
                pass
    
    def _highlight_rule_in_results(self, line_num):
        """Highlight corresponding rule in results table"""
        # This will be called from canvas hover
        # The results_tree reference should be stored during flow test
        results_tree = getattr(self.parent, '_flow_test_results_tree', None)
        if not results_tree:
            return
        
        # Find and select the item with matching line number
        for item in results_tree.get_children():
            values = results_tree.item(item, 'values')
            if values and str(values[0]) == str(line_num):
                results_tree.selection_set(item)
                results_tree.see(item)
                break
    
    def _on_results_double_click(self, event, results_tree, test_dialog):
        """Handle double-click on results table to jump to rule in main editor
        
        Args:
            event: Click event
            results_tree: The results treeview widget
            test_dialog: The test flow dialog window
        """
        # Get the clicked item
        item = results_tree.identify_row(event.y)
        if not item:
            return
        
        # Get the line number from the clicked item
        values = results_tree.item(item, 'values')
        if not values or not values[0]:
            return
        
        try:
            line_num = int(values[0])
        except (ValueError, TypeError):
            return
        
        # Close the test dialog
        test_dialog.destroy()
        
        # Jump to the rule in the main editor
        # Convert line number to 0-based index
        rule_index = line_num - 1
        
        # Get all items in main tree
        all_items = self.parent.tree.get_children()
        
        if rule_index < len(all_items):
            target_item = all_items[rule_index]
            # Clear current selection
            self.parent.tree.selection_remove(self.parent.tree.selection())
            # Select and focus the target rule
            self.parent.tree.selection_set(target_item)
            self.parent.tree.focus(target_item)
            self.parent.tree.see(target_item)
            # Ensure main window is visible
            self.parent.root.lift()
            self.parent.root.focus_force()
