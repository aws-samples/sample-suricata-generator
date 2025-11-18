import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
from typing import List, Dict, Optional

from suricata_rule import SuricataRule


class StatefulRuleImporter:
    """Import AWS Network Firewall Stateful Rule Groups from describe-rule-group JSON output
    
    Handles parsing of AWS Network Firewall rule group JSON format and conversion
    to Suricata rules with proper variable mapping and SID conflict resolution.
    """
    
    def __init__(self, parent_app):
        """Initialize with reference to parent application
        
        Args:
            parent_app: Reference to main SuricataRuleGenerator instance
        """
        self.parent = parent_app
    
    def import_standard_rule_group(self):
        """Import a standard rule group from AWS describe-rule-group JSON file"""
        # Check for unsaved changes
        if self.parent.modified:
            save_result = self.parent.ask_save_changes()
            if save_result is False:
                # User chose not to save, continue with loading
                pass
            elif save_result is None:
                # User cancelled, abort operation
                return
            elif save_result is True:
                # User saved successfully, continue with loading
                pass
        
        # Open file dialog to select JSON file
        filename = filedialog.askopenfilename(
            title="Select AWS Rule Group JSON File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            # Load and parse the JSON file
            with open(filename, 'r', encoding='utf-8') as f:
                rule_group_data = json.load(f)
            
            # Parse the rule group
            parsed_data = self.parse_rule_group_json(rule_group_data)
            
            # If parsing returned None, a specific error was already shown, so just return
            if not parsed_data:
                return
            
            # Show preview dialog and get user choices
            confirm_import, run_analyzer = self.show_import_preview_dialog(parsed_data, filename)
            
            if confirm_import:
                # User confirmed, proceed with import
                self.apply_import(parsed_data)
                
                # Run rule analyzer if requested
                if run_analyzer:
                    self.parent.review_rules()
                
        except FileNotFoundError:
            messagebox.showerror("File Not Found", f"File not found: {filename}")
        except PermissionError:
            messagebox.showerror("Permission Error", f"Cannot read file: {filename}")
        except json.JSONDecodeError as e:
            messagebox.showerror("JSON Parse Error", f"Invalid JSON format: {str(e)}")
        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import rule group: {str(e)}")
    
    def parse_rule_group_json(self, json_data: dict) -> Optional[Dict]:
        """Parse AWS Network Firewall rule group JSON
        
        Args:
            json_data: Parsed JSON from describe-rule-group command
            
        Returns:
            Dictionary with parsed data or None if parsing fails
        """
        try:
            # Navigate to RuleGroup section
            rule_group = json_data.get('RuleGroup', {})
            
            # Extract metadata
            rule_group_response = json_data.get('RuleGroupResponse', {})
            rule_group_name = rule_group_response.get('RuleGroupName', 'Imported Rule Group')
            description = rule_group_response.get('Description', '')
            
            # Validate Type if RuleGroupResponse is present
            if rule_group_response:
                rule_group_type = rule_group_response.get('Type', '')
                if rule_group_type and rule_group_type != 'STATEFUL':
                    messagebox.showerror(
                        "Invalid Rule Group Type",
                        f"This importer only supports STATEFUL rule groups.\n\n"
                        f"The selected rule group has Type: {rule_group_type}\n\n"
                        f"Please select a STATEFUL rule group JSON file."
                    )
                    return None
            
            # Parse variables
            variables = self.parse_rule_variables(rule_group.get('RuleVariables', {}))
            
            # Parse rules
            rules_source = rule_group.get('RulesSource', {})
            
            # Check for StatefulRules (5-tuple format)
            if 'StatefulRules' in rules_source:
                rules = self.parse_stateful_rules(rules_source['StatefulRules'])
            # Check for RulesString (Suricata format) - though this is less common for imports
            elif 'RulesString' in rules_source:
                rules = self.parse_rules_string(rules_source['RulesString'])
            else:
                messagebox.showwarning("No Rules Found", "No rules found in the rule group JSON.")
                return None
            
            return {
                'name': rule_group_name,
                'description': description,
                'rules': rules,
                'variables': variables,
                'original_json': json_data
            }
            
        except KeyError as e:
            messagebox.showerror("Parse Error", f"Missing required field in JSON: {str(e)}")
            return None
        except Exception as e:
            messagebox.showerror("Parse Error", f"Failed to parse rule group: {str(e)}")
            return None
    
    def parse_rule_variables(self, rule_variables: dict) -> dict:
        """Parse RuleVariables section (IPSets and PortSets)
        
        Args:
            rule_variables: RuleVariables dictionary from JSON
            
        Returns:
            Dictionary of variables with $ prefix for use in Suricata
        """
        variables = {}
        
        # Parse IPSets
        ip_sets = rule_variables.get('IPSets', {})
        for var_name, var_data in ip_sets.items():
            definition = var_data.get('Definition', [])
            # Add $ prefix and join with commas
            variables[f'${var_name}'] = ','.join(definition)
        
        # Parse PortSets
        port_sets = rule_variables.get('PortSets', {})
        for var_name, var_data in port_sets.items():
            definition = var_data.get('Definition', [])
            # Add $ prefix and join with commas
            variables[f'${var_name}'] = ','.join(definition)
        
        return variables
    
    def parse_stateful_rules(self, stateful_rules: List[dict]) -> List[SuricataRule]:
        """Parse StatefulRules array (5-tuple format)
        
        Args:
            stateful_rules: List of StatefulRule dictionaries
            
        Returns:
            List of SuricataRule objects
        """
        rules = []
        
        for rule_data in stateful_rules:
            try:
                # Parse header (5-tuple)
                header = rule_data.get('Header', {})
                action = rule_data.get('Action', 'PASS').lower()
                
                # Convert AWS format to Suricata format
                protocol = header.get('Protocol', 'TCP').lower()
                src_net = self.convert_network_field(header.get('Source', 'ANY'))
                src_port = self.convert_port_field(header.get('SourcePort', 'ANY'))
                dst_net = self.convert_network_field(header.get('Destination', 'ANY'))
                dst_port = self.convert_port_field(header.get('DestinationPort', 'ANY'))
                direction = self.convert_direction(header.get('Direction', 'FORWARD'))
                
                # Parse RuleOptions
                rule_options = rule_data.get('RuleOptions', [])
                msg, sid, rev, content = self.parse_rule_options(rule_options)
                
                # Create SuricataRule object
                rule = SuricataRule(
                    action=action,
                    protocol=protocol,
                    src_net=src_net,
                    src_port=src_port,
                    dst_net=dst_net,
                    dst_port=dst_port,
                    message=msg,
                    content=content,
                    sid=sid,
                    rev=rev,
                    direction=direction
                )
                
                rules.append(rule)
                
            except Exception as e:
                # Log error but continue parsing other rules
                print(f"Warning: Failed to parse rule: {str(e)}")
                continue
        
        return rules
    
    def parse_rules_string(self, rules_string: str) -> List[SuricataRule]:
        """Parse RulesString format (raw Suricata rules)
        
        Args:
            rules_string: Raw Suricata rules as string
            
        Returns:
            List of SuricataRule objects
        """
        rules = []
        lines = rules_string.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                # Blank line
                blank_rule = SuricataRule()
                blank_rule.is_blank = True
                rules.append(blank_rule)
            elif line.startswith('#'):
                # Comment line
                comment_rule = SuricataRule()
                comment_rule.is_comment = True
                comment_rule.comment_text = line
                rules.append(comment_rule)
            else:
                # Parse as Suricata rule
                rule = SuricataRule.from_string(line)
                if rule:
                    rules.append(rule)
        
        return rules
    
    def parse_rule_options(self, rule_options: List[dict]) -> tuple:
        """Parse RuleOptions array into message, sid, rev, and content
        
        Args:
            rule_options: List of RuleOption dictionaries
            
        Returns:
            Tuple of (message, sid, rev, content)
        """
        msg = ""
        sid = 100
        rev = 1
        content_parts = []
        
        for option in rule_options:
            keyword = option.get('Keyword', '')
            settings = option.get('Settings', [])
            
            if keyword == 'msg':
                # Extract message, removing quotes if present
                if settings:
                    msg = settings[0].strip('"')
            elif keyword == 'sid':
                # Extract SID
                if settings:
                    try:
                        sid = int(settings[0])
                    except ValueError:
                        sid = 100
            elif keyword == 'rev':
                # Extract revision
                if settings:
                    try:
                        rev = int(settings[0])
                    except ValueError:
                        rev = 1
            else:
                # All other keywords become part of content
                if settings:
                    # Format as "keyword:value1,value2,..."
                    setting_str = ','.join(str(s) for s in settings)
                    content_parts.append(f"{keyword}:{setting_str}")
                else:
                    # Keyword with no settings
                    content_parts.append(keyword)
        
        # Join content parts with semicolons
        content = '; '.join(content_parts)
        
        return msg, sid, rev, content
    
    def convert_network_field(self, value: str) -> str:
        """Convert AWS network field to Suricata format
        
        Args:
            value: AWS network value (e.g., 'ANY', '10.0.0.0/16', '$HOME_NET')
            
        Returns:
            Suricata-formatted network value
        """
        if value == 'ANY':
            return 'any'
        # Variables in AWS format already have $ prefix, keep as-is
        return value
    
    def convert_port_field(self, value: str) -> str:
        """Convert AWS port field to Suricata format
        
        Args:
            value: AWS port value (e.g., 'ANY', '443', '$SSL')
            
        Returns:
            Suricata-formatted port value
        """
        if value == 'ANY':
            return 'any'
        # Variables in AWS format already have $ prefix, keep as-is
        return value
    
    def convert_direction(self, value: str) -> str:
        """Convert AWS direction to Suricata format
        
        Args:
            value: AWS direction value ('FORWARD' or 'ANY')
            
        Returns:
            Suricata direction ('->' or '<>')
        """
        if value == 'FORWARD':
            return '->'
        elif value == 'ANY':
            return '<>'
        # Default to forward
        return '->'
    
    def show_import_preview_dialog(self, parsed_data: dict, filename: str) -> tuple:
        """Show preview dialog before importing
        
        Args:
            parsed_data: Parsed rule group data
            filename: Source JSON filename
            
        Returns:
            Tuple of (confirm_import: bool, run_analyzer: bool)
        """
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Import Stateful Rule Group - Preview")
        dialog.geometry("700x600")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 50, self.parent.root.winfo_rooty() + 50))
        
        result = [False]
        run_analyzer_var = tk.BooleanVar(value=True)  # Checked by default
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title
        title_label = ttk.Label(main_frame, text="Import Preview", 
                               font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 10))
        
        # File info
        info_frame = ttk.LabelFrame(main_frame, text="Rule Group Information")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, text=f"Source File:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(info_frame, text=filename, font=("TkDefaultFont", 9)).grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        ttk.Label(info_frame, text=f"Rule Group Name:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(info_frame, text=parsed_data['name'], font=("TkDefaultFont", 9, "bold")).grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        
        if parsed_data['description']:
            ttk.Label(info_frame, text=f"Description:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
            desc_label = ttk.Label(info_frame, text=parsed_data['description'], 
                                  font=("TkDefaultFont", 9), wraplength=500)
            desc_label.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        
        # Statistics
        rules_count = len(parsed_data['rules'])
        vars_count = len(parsed_data['variables'])
        
        stats_frame = ttk.LabelFrame(main_frame, text="Import Summary")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(stats_frame, text=f"Rules to import: {rules_count}", 
                 font=("TkDefaultFont", 10)).pack(anchor=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, text=f"Variables to import: {vars_count}", 
                 font=("TkDefaultFont", 10)).pack(anchor=tk.W, padx=10, pady=5)
        
        # Check for SID conflicts
        conflict_info = self.check_sid_conflicts(parsed_data['rules'])
        if conflict_info['has_conflicts']:
            ttk.Label(stats_frame, 
                     text=f"⚠️ SID conflicts detected: {len(conflict_info['conflicts'])} rules will be auto-renumbered", 
                     font=("TkDefaultFont", 9), foreground="orange").pack(anchor=tk.W, padx=10, pady=5)
        
        # Rules preview
        preview_frame = ttk.LabelFrame(main_frame, text="Rules Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create text widget for preview
        text_widget = tk.Text(preview_frame, wrap=tk.WORD, font=("Consolas", 9), height=10)
        scrollbar = ttk.Scrollbar(preview_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Show first 10 rules
        for i, rule in enumerate(parsed_data['rules'][:10]):
            text_widget.insert(tk.END, f"[{i+1}] {rule.to_string()}\n")
        
        if len(parsed_data['rules']) > 10:
            text_widget.insert(tk.END, f"\n... and {len(parsed_data['rules']) - 10} more rules")
        
        text_widget.config(state=tk.DISABLED)
        
        # Warning message
        warning_frame = ttk.Frame(main_frame)
        warning_frame.pack(fill=tk.X, pady=(0, 10))
        
        warning_label = ttk.Label(warning_frame, 
                                 text="⚠️ This will clear all current rules and variables. Make sure you've saved any changes.",
                                 font=("TkDefaultFont", 9, "bold"),
                                 foreground="red",
                                 wraplength=650)
        warning_label.pack()
        
        # Analyzer checkbox
        analyzer_frame = ttk.Frame(main_frame)
        analyzer_frame.pack(fill=tk.X, pady=(0, 10))
        
        analyzer_checkbox = ttk.Checkbutton(analyzer_frame, 
                                           text="Run rule analyzer after import to check for conflicts",
                                           variable=run_analyzer_var)
        analyzer_checkbox.pack(side=tk.LEFT)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def on_import():
            result[0] = True
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Import", command=on_import).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT)
        
        dialog.wait_window()
        return (result[0], run_analyzer_var.get())
    
    def create_metadata_comments(self, json_data: dict) -> List[SuricataRule]:
        """Create comment lines from RuleGroupResponse metadata
        
        Args:
            json_data: Complete JSON data including RuleGroupResponse
            
        Returns:
            List of comment SuricataRule objects for metadata
        """
        comments = []
        
        # Check if RuleGroupResponse exists
        rule_group_response = json_data.get('RuleGroupResponse', {})
        if not rule_group_response:
            return comments
        
        # Extract metadata fields
        arn = rule_group_response.get('RuleGroupArn', '')
        name = rule_group_response.get('RuleGroupName', '')
        group_id = rule_group_response.get('RuleGroupId', '')
        description = rule_group_response.get('Description', '')
        
        # Create header comment
        header_comment = SuricataRule()
        header_comment.is_comment = True
        header_comment.comment_text = "# Original Rule Group attributes:"
        comments.append(header_comment)
        
        # Add ARN if present
        if arn:
            arn_comment = SuricataRule()
            arn_comment.is_comment = True
            arn_comment.comment_text = f"#   RuleGroupArn: {arn}"
            comments.append(arn_comment)
        
        # Add Name if present
        if name:
            name_comment = SuricataRule()
            name_comment.is_comment = True
            name_comment.comment_text = f"#   RuleGroupName: {name}"
            comments.append(name_comment)
        
        # Add ID if present
        if group_id:
            id_comment = SuricataRule()
            id_comment.is_comment = True
            id_comment.comment_text = f"#   RuleGroupId: {group_id}"
            comments.append(id_comment)
        
        # Add Description if present
        if description:
            desc_comment = SuricataRule()
            desc_comment.is_comment = True
            desc_comment.comment_text = f"#   Description: {description}"
            comments.append(desc_comment)
        
        # Add blank line after metadata
        if comments:
            blank_rule = SuricataRule()
            blank_rule.is_blank = True
            comments.append(blank_rule)
        
        return comments
    
    def check_sid_conflicts(self, new_rules: List[SuricataRule]) -> dict:
        """Check for duplicate SIDs within the imported rules
        
        Since import forces a new file, we only check for duplicates within
        the imported JSON itself, not against existing rules in editor.
        
        Args:
            new_rules: List of rules to import
            
        Returns:
            Dictionary with conflict information
        """
        # Get all SIDs from the imported rules
        new_sids = [rule.sid for rule in new_rules 
                   if not getattr(rule, 'is_comment', False) 
                   and not getattr(rule, 'is_blank', False)]
        
        # Find duplicates within the imported rules
        seen_sids = set()
        duplicate_sids = []
        for sid in new_sids:
            if sid in seen_sids:
                duplicate_sids.append(sid)
            else:
                seen_sids.add(sid)
        
        return {
            'has_conflicts': len(duplicate_sids) > 0,
            'conflicts': duplicate_sids,
            'existing_sids': set(),  # Not checking against existing rules
            'new_sids': new_sids
        }
    
    def apply_import(self, parsed_data: dict):
        """Apply the import, replacing all current rules and variables
        
        Args:
            parsed_data: Parsed rule group data to import
        """
        # Check for duplicate SIDs within the imported JSON
        rules_to_import = parsed_data['rules']
        conflict_info = self.check_sid_conflicts(rules_to_import)
        
        if conflict_info['has_conflicts']:
            # Auto-renumber duplicate SIDs within imported rules
            # Find max SID in imported rules to start renumbering from
            imported_sids = [rule.sid for rule in rules_to_import 
                           if not getattr(rule, 'is_comment', False) 
                           and not getattr(rule, 'is_blank', False)]
            max_sid = max(imported_sids) if imported_sids else 99
            next_sid = max_sid + 1
            
            for rule in rules_to_import:
                if (not getattr(rule, 'is_comment', False) and 
                    not getattr(rule, 'is_blank', False)):
                    if rule.sid in conflict_info['conflicts']:
                        rule.sid = next_sid
                        next_sid += 1
        
        # Disable change tracking for new content operations
        self.parent.tracking_enabled = False
        self.parent.tracking_menu_var.set(False)
        
        # Clear current rules and variables
        self.parent.rules.clear()
        self.parent.variables.clear()
        self.parent.has_header = False
        self.parent.created_timestamp = None
        self.parent.pending_history.clear()
        
        # Create metadata comments from RuleGroupResponse if available
        metadata_comments = self.create_metadata_comments(parsed_data.get('original_json', {}))
        
        # Insert metadata comments at the beginning of rules
        if metadata_comments:
            rules_to_import = metadata_comments + rules_to_import
        
        # Import new rules (including metadata comments)
        self.parent.rules = rules_to_import
        
        # Import new variables directly
        imported_vars = parsed_data['variables']
        
        # Set the variables in parent
        for var_name, var_value in imported_vars.items():
            self.parent.variables[var_name] = var_value
        
        # Update UI - refresh table first
        self.parent.refresh_table(preserve_selection=False)
        
        # Detect any additional variables used in rules that weren't in the JSON
        # but preserve the imported variable definitions
        detected_vars = set()
        for rule in self.parent.rules:
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            if rule.src_net.startswith(('$', '@')):
                detected_vars.add(rule.src_net)
            if rule.dst_net.startswith(('$', '@')):
                detected_vars.add(rule.dst_net)
            if rule.src_port.startswith(('$', '@')):
                detected_vars.add(rule.src_port)
            if rule.dst_port.startswith(('$', '@')):
                detected_vars.add(rule.dst_port)
        
        detected_vars.discard('$EXTERNAL_NET')
        
        # Add any detected variables that weren't imported (keep imported values intact)
        for var in detected_vars:
            if var not in self.parent.variables:
                if var == '$HOME_NET':
                    self.parent.variables[var] = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
                else:
                    self.parent.variables[var] = ""
        
        # Refresh variables table
        # Note: Clicking on Variables tab will trigger auto_detect_variables, but it now
        # preserves variables with definitions even if not used in rules
        self.parent.refresh_variables_table()
        
        # Force UI update
        self.parent.root.update_idletasks()
        
        self.parent.current_file = None
        self.parent.modified = True
        self.parent.update_status_bar()
        self.parent.root.title(f"Suricata Rule Generator - {parsed_data['name']}")
        
        # Set up rule editor for new rule insertion
        self.parent.ui_manager.show_rule_editor()
        self.parent.set_default_editor_values()
        
        # Show success message
        messagebox.showinfo("Import Complete", 
                          f"Successfully imported {len(rules_to_import)} rules and {len(parsed_data['variables'])} variables from '{parsed_data['name']}'.")
