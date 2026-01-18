import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, List
import time

from suricata_rule import SuricataRule

# Optional boto3 import with graceful degradation
HAS_BOTO3 = False
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    boto3 = None
    ClientError = None
    NoCredentialsError = None


class DomainListImporter:
    """Handle AWS Domain List rule group imports
    
    Provides functionality to import Domain List rule groups directly from AWS
    Network Firewall, converting them to Suricata rules with the bulk domain
    import dialog.
    """
    
    def __init__(self, app_instance):
        """Initialize with reference to parent application
        
        Args:
            app_instance: Reference to main SuricataRuleGenerator instance
        """
        self.app = app_instance
    
    def show_import_source_dialog(self) -> Optional[str]:
        """Show dialog to select import source
        
        Returns:
            'file' - Import from text file
            'aws' - Import from AWS
            None - User cancelled
        """
        dialog = tk.Toplevel(self.app.root)
        dialog.title("Import Domain List")
        dialog.geometry("500x300")
        dialog.transient(self.app.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.app.root.winfo_rootx() + 250,
            self.app.root.winfo_rooty() + 200
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(main_frame, text="Import Domain List",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 20))
        
        # Source selection
        ttk.Label(main_frame, text="Select Import Source:",
                 font=("TkDefaultFont", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        source_var = tk.StringVar(value='file')
        
        # Option 1: Text file
        file_radio = ttk.Radiobutton(
            main_frame,
            text="Import from text file",
            variable=source_var,
            value='file'
        )
        file_radio.pack(anchor=tk.W, padx=20)
        
        ttk.Label(
            main_frame,
            text="Choose a local text file with one domain per line",
            font=("TkDefaultFont", 9),
            foreground="#666666"
        ).pack(anchor=tk.W, padx=40, pady=(2, 15))
        
        # Option 2: AWS
        aws_radio = ttk.Radiobutton(
            main_frame,
            text="Import from AWS Domain List Rule Group",
            variable=source_var,
            value='aws'
        )
        aws_radio.pack(anchor=tk.W, padx=20)
        
        aws_info = ttk.Label(
            main_frame,
            text="Browse and import from AWS Network Firewall",
            font=("TkDefaultFont", 9),
            foreground="#666666"
        )
        aws_info.pack(anchor=tk.W, padx=40, pady=(2, 5))
        
        # Check boto3 availability
        if not HAS_BOTO3:
            aws_radio.config(state='disabled')
            ttk.Label(
                main_frame,
                text="Requires boto3 - run: pip install boto3",
                font=("TkDefaultFont", 9),
                foreground="#999999"
            ).pack(anchor=tk.W, padx=40)
        
        # Buttons
        result = [None]
        
        def on_continue():
            result[0] = source_var.get()
            dialog.destroy()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(20, 0))
        
        ttk.Button(button_frame, text="Continue",
                  command=on_continue, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel",
                  command=dialog.destroy, width=10).pack(side=tk.LEFT, padx=5)
        
        dialog.wait_window()
        return result[0]
    
    def browse_aws_domain_lists(self, region: str = None) -> Optional[dict]:
        """Show browser dialog for AWS Domain List rule groups
        
        Args:
            region: AWS region (optional, uses default if not specified)
            
        Returns:
            dict with rule group details or None if cancelled
        """
        if not HAS_BOTO3:
            messagebox.showerror("boto3 Required", 
                "boto3 is required for AWS import.\n\n"
                "Install with: pip install boto3")
            return None
        
        # Initialize boto3 client
        try:
            if region:
                nfw_client = boto3.client('network-firewall', region_name=region)
            else:
                nfw_client = boto3.client('network-firewall')
                region = nfw_client.meta.region_name
        except NoCredentialsError:
            messagebox.showerror("AWS Credentials Not Found",
                "AWS credentials are not configured. To use this feature, you need to:\n\n"
                "1. Install AWS CLI: https://aws.amazon.com/cli/\n"
                "2. Run: aws configure\n"
                "3. Enter your Access Key ID and Secret Access Key\n\n"
                "Alternative: Set environment variables:\n"
                "• AWS_ACCESS_KEY_ID\n"
                "• AWS_SECRET_ACCESS_KEY\n"
                "• AWS_DEFAULT_REGION")
            return None
        except Exception as e:
            messagebox.showerror("AWS Connection Error",
                f"Failed to connect to AWS:\n\n{str(e)}\n\n"
                "Please check your AWS credentials configuration.")
            return None
        
        # Create browser dialog
        dialog = tk.Toplevel(self.app.root)
        dialog.title("AWS Network Firewall - Select Domain List Rule Group")
        dialog.geometry("900x600")
        dialog.transient(self.app.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.app.root.winfo_rootx() + 100,
            self.app.root.winfo_rooty() + 100
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Region and search controls frame (on same line)
        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Region selector
        ttk.Label(controls_frame, text="Region:").pack(side=tk.LEFT, padx=(0, 5))
        
        # All AWS standard commercial regions (matches existing Import/Export features)
        aws_regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'ca-central-1', 'ca-west-1',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-central-2',
            'eu-north-1', 'eu-south-1', 'eu-south-2',
            'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2',
            'ap-southeast-3', 'ap-southeast-4', 'ap-northeast-1', 'ap-northeast-2',
            'ap-northeast-3', 'ap-east-1',
            'sa-east-1',
            'me-south-1', 'me-central-1',
            'af-south-1',
            'il-central-1'
        ]
        
        selected_region_var = tk.StringVar(value=region)
        region_combo = ttk.Combobox(
            controls_frame,
            textvariable=selected_region_var,
            values=aws_regions,
            state="readonly",
            width=20
        )
        region_combo.pack(side=tk.LEFT, padx=(0, 20))
        
        # Search controls (on same line as region)
        search_frame = ttk.Frame(controls_frame)
        search_frame.pack(side=tk.LEFT)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        # Search functionality
        def on_search(*args):
            search_text = search_var.get().lower()
            for item in tree.get_children():
                values = tree.item(item, "values")
                if values:
                    name = values[0].lower()
                    if search_text in name:
                        tree.reattach(item, "", tree.index(item))
                    else:
                        tree.detach(item)
            
            # If search is empty, show all
            if not search_text:
                for item in tree.get_children(""):
                    try:
                        tree.reattach(item, "", tree.index(item))
                    except:
                        pass
        
        search_var.trace_add('write', on_search)
        
        def clear_search():
            search_var.set("")
        
        # Add search and refresh buttons
        ttk.Button(search_frame, text="🔍", width=3, command=lambda: on_search()).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(search_frame, text="Clear", command=clear_search).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(search_frame, text="↻ Refresh", command=lambda: load_rule_groups()).pack(side=tk.LEFT)
        
        # Treeview for rule groups (using grid layout like stateful importer)
        tree_container = ttk.Frame(main_frame)
        tree_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        columns = ("Name", "Type")
        tree = ttk.Treeview(tree_container, columns=columns, show="tree headings",
                           selectmode="extended")
        
        tree.heading("#0", text="")
        tree.heading("Name", text="Name ▲")
        tree.heading("Type", text="Type")
        
        tree.column("#0", width=30, stretch=False)
        tree.column("Name", width=400, stretch=True)
        tree.column("Type", width=150, stretch=False)
        
        # Scrollbars (using grid layout)
        v_scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        
        # Configure tags for styling
        tree.tag_configure("disabled", foreground="#999999")
        tree.tag_configure("details", font=("TkDefaultFont", 9), foreground="#666666")
        
        # Status label
        status_label = ttk.Label(main_frame, text="Loading rule groups...",
                                font=("TkDefaultFont", 9))
        status_label.pack(pady=(0, 10))
        
        # Store rule group data
        rule_groups_data = {}
        selected_rule_group = [None]
        
        def load_rule_groups():
            """Load rule groups from AWS with lazy loading"""
            try:
                # Clear tree
                for item in tree.get_children():
                    tree.delete(item)
                
                # Show loading dialog
                loading_dialog = tk.Toplevel(dialog)
                loading_dialog.title("Loading")
                loading_dialog.geometry("300x100")
                loading_dialog.transient(dialog)
                loading_dialog.grab_set()
                loading_dialog.geometry("+%d+%d" % (
                    dialog.winfo_rootx() + 300,
                    dialog.winfo_rooty() + 250
                ))
                
                ttk.Label(loading_dialog, text="Loading rule groups from AWS...").pack(pady=30)
                loading_dialog.update()
                
                # List all rule groups
                response = nfw_client.list_rule_groups(Type='STATEFUL')
                rule_groups = response.get('RuleGroups', [])
                
                loading_dialog.destroy()
                
                # Add all STATEFUL rule groups to tree (with dummy child to show expand triangle)
                for rg in rule_groups:
                    parent = tree.insert("", tk.END, text="",
                                       values=(rg['Name'], "STATEFUL"))
                    
                    # Add dummy child to show expand triangle
                    tree.insert(parent, tk.END, text="", values=("Loading...", ""))
                    
                    # Store basic data
                    rule_groups_data[parent] = {
                        'name': rg['Name'],
                        'arn': rg['Arn'],
                        'capacity': rg.get('Capacity'),
                        'details_loaded': False
                    }
                
                # Update status
                status_label.config(text=f"Region: {selected_region_var.get()} | {len(rule_groups)} STATEFUL rule groups found")
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code == 'AccessDeniedException':
                    messagebox.showerror(
                        "Insufficient AWS Permissions",
                        "Your AWS credentials don't have permission to list rule groups.\n\n"
                        "Required IAM permissions:\n"
                        "• network-firewall:ListRuleGroups\n"
                        "• network-firewall:DescribeRuleGroup\n\n"
                        "Please contact your AWS administrator.")
                else:
                    messagebox.showerror("AWS Error", f"Failed to list rule groups:\n\n{str(e)}")
                status_label.config(text="Error loading rule groups")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load rule groups:\n\n{str(e)}")
                status_label.config(text="Error loading rule groups")
        
        def on_tree_expand(event):
            """Handle expansion - fetch details on demand"""
            item = tree.focus()
            if not item or item not in rule_groups_data:
                return
            
            data = rule_groups_data[item]
            
            # Check if details already loaded
            if data.get('details_loaded'):
                return
            
            # Fetch full details from AWS
            try:
                details = nfw_client.describe_rule_group(
                    RuleGroupArn=data['arn'],
                    Type='STATEFUL'
                )
                
                rg_data = details['RuleGroup']
                rules_source = rg_data.get('RulesSource', {})
                rg_response = details.get('RuleGroupResponse', {})
                
                # Remove dummy child first
                for child in tree.get_children(item):
                    tree.delete(child)
                
                # Determine if this is a Domain List
                if 'RulesSourceList' in rules_source:
                    # Domain List - GOOD
                    rules_source_list = rules_source['RulesSourceList']
                    
                    # Update tree item to show it's a Domain List
                    tree.item(item, values=(data['name'], "Domain List"))
                    
                    # Get capacity from describe response (list_rule_groups doesn't include it)
                    actual_capacity = rg_response.get('Capacity', 'Unknown')
                    
                    # Store full data
                    data.update({
                        'capacity': actual_capacity,
                        'description': rg_response.get('Description', ''),
                        'domains': rules_source_list.get('Targets', []),
                        'target_types': rules_source_list.get('TargetTypes', []),
                        'generated_rules_type': rules_source_list.get('GeneratedRulesType', 'ALLOWLIST'),
                        'details_loaded': True,
                        'is_domain_list': True,
                        'region': selected_region_var.get()
                    })
                    
                    # Add detail rows (similar to stateful importer)
                    detail_text = (
                        f"    Capacity: {actual_capacity}  |  "
                        f"Domains: {len(rules_source_list.get('Targets', []))}  |  "
                        f"Targets: {', '.join(data['target_types'])}  |  "
                        f"Action: {data['generated_rules_type']}"
                    )
                    tree.insert(item, tk.END, text="", values=(detail_text, ""), tags=("details",))
                    
                    if data['description']:
                        desc_text = f"    Description: {data['description']}"
                        tree.insert(item, tk.END, text="", values=(desc_text, ""), tags=("details",))
                    
                    arn_text = f"    ARN: {data['arn']}"
                    tree.insert(item, tk.END, text="", values=(arn_text, ""), tags=("details",))
                
                else:
                    # NOT a Domain List
                    if 'StatefulRules' in rules_source:
                        format_type = "Stateful (5-tuple)"
                    elif 'RulesString' in rules_source:
                        format_type = "Stateful (Suricata)"
                    else:
                        format_type = "Stateful (Unknown)"
                    
                    # Update tree item and gray out
                    tree.item(item, values=(data['name'], format_type), tags=("disabled",))
                    
                    # Mark as loaded but not importable
                    data['details_loaded'] = True
                    data['is_domain_list'] = False
                    
                    # Add informational child rows
                    info_text = "    Not a Domain List - Use 'Import Stateful Rule Group' instead"
                    tree.insert(item, tk.END, text="", values=(info_text, ""), tags=("disabled",))
            
            except Exception as e:
                messagebox.showerror("Error", 
                    f"Failed to load details for {data['name']}:\n\n{str(e)}")
        
        def on_tree_select(event):
            """Handle selection - supports multiple selections"""
            selections = tree.selection()
            if not selections:
                selected_rule_group[0] = []
                return
            
            # Filter out detail rows and collect parent items
            valid_selections = []
            for item in selections:
                # Check if this is a detail row
                parent = tree.parent(item)
                if parent:
                    # This is a detail row - skip it
                    continue
                
                # Check if disabled (non-Domain List that was already expanded)
                if "disabled" in tree.item(item, 'tags'):
                    # Silently skip disabled items - validation will happen on Import click
                    continue
                
                # Valid selection - add to list
                if item in rule_groups_data:
                    valid_selections.append(item)
            
            # Store list of selected rule groups (may include both valid and invalid)
            # Import button will validate and show error if needed
            selected_rule_group[0] = [rule_groups_data[item] for item in valid_selections]
        
        def on_region_change(event):
            """Handle region change"""
            new_region = selected_region_var.get()
            nonlocal nfw_client
            nfw_client = boto3.client('network-firewall', region_name=new_region)
            load_rule_groups()
        
        # Bind events
        tree.bind('<<TreeviewSelect>>', on_tree_select)
        tree.bind('<<TreeviewOpen>>', on_tree_expand)
        region_combo.bind('<<ComboboxSelected>>', on_region_change)
        
        # Initial load
        dialog.update()
        load_rule_groups()
        
        # Buttons
        def on_import():
            if not selected_rule_group[0]:
                messagebox.showwarning("No Selection",
                    "Please select one or more Domain List rule groups to import.")
                return
            
            # Check if list (multiple) or dict (single - backward compatibility)
            selections = selected_rule_group[0]
            if isinstance(selections, dict):
                # Single selection - use existing workflow
                selections = [selections]
            
            # Fetch details for all selections that need loading
            all_rule_groups = []
            for data in selections:
                if not data.get('details_loaded'):
                    # Details not loaded yet - fetch them now
                    try:
                        details = nfw_client.describe_rule_group(
                            RuleGroupArn=data['arn'],
                            Type='STATEFUL'
                        )
                        
                        rg_data = details['RuleGroup']
                        rules_source = rg_data.get('RulesSource', {})
                        rg_response = details.get('RuleGroupResponse', {})
                        
                        # Check if this is a Domain List
                        if 'RulesSourceList' in rules_source:
                            # Domain List - GOOD
                            rules_source_list = rules_source['RulesSourceList']
                            
                            # Update stored data
                            data.update({
                                'capacity': rg_response.get('Capacity', 'Unknown'),
                                'description': rg_response.get('Description', ''),
                                'domains': rules_source_list.get('Targets', []),
                                'target_types': rules_source_list.get('TargetTypes', []),
                                'generated_rules_type': rules_source_list.get('GeneratedRulesType', 'ALLOWLIST'),
                                'details_loaded': True,
                                'is_domain_list': True,
                                'region': selected_region_var.get()
                            })
                            
                            all_rule_groups.append(data)
                        else:
                            # NOT a Domain List
                            messagebox.showerror("Cannot Import",
                                f"The rule group '{data['name']}' is not a Domain List type.\n\n"
                                "Only Domain List type rule groups can be imported with this feature.\n\n"
                                "Please select only Domain List rule groups.")
                            return
                        
                    except Exception as e:
                        messagebox.showerror("Error",
                            f"Failed to load rule group details for '{data['name']}':\n\n{str(e)}")
                        return
                else:
                    # Details already loaded - verify it's a Domain List
                    if not data.get('is_domain_list'):
                        messagebox.showerror("Cannot Import",
                            f"The rule group '{data['name']}' is not a Domain List type.\n\n"
                            "Only Domain List type rule groups can be imported with this feature.\n\n"
                            "Please select only Domain List rule groups.")
                        return
                    
                    all_rule_groups.append(data)
            
            # Show appropriate preview dialog
            if len(all_rule_groups) == 1:
                # Single selection - use existing preview
                if self.show_import_preview(all_rule_groups[0]):
                    dialog.destroy()
            else:
                # Multiple selections - use multi-preview
                if self.show_import_preview_multi(all_rule_groups):
                    dialog.destroy()
        
        def show_help():
            self.app.ui_manager.show_aws_setup_help(default_tab='iam')
        
        def on_cancel():
            # Clear selection before closing
            selected_rule_group[0] = None
            dialog.destroy()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Help",
                  command=show_help).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Refresh",
                  command=load_rule_groups).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel",
                  command=on_cancel).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Import",
                  command=on_import).pack(side=tk.RIGHT, padx=(0, 5))
        
        dialog.wait_window()
        
        # Return list of valid Domain Lists (empty list if none selected)
        if selected_rule_group[0]:
            # Could be list or dict (backward compatibility)
            if isinstance(selected_rule_group[0], list):
                # Return list of rule groups (could be single or multiple)
                valid_groups = [rg for rg in selected_rule_group[0] if rg.get('is_domain_list')]
                return valid_groups if valid_groups else None
            elif isinstance(selected_rule_group[0], dict) and selected_rule_group[0].get('is_domain_list'):
                # Single dict - wrap in list for consistency
                return [selected_rule_group[0]]
        
        return None
    
    def show_import_preview(self, rule_group_data: dict) -> bool:
        """Show preview of Domain List before importing
        
        Args:
            rule_group_data: Dict with domain list details
            
        Returns:
            True if user confirms import, False otherwise
        """
        dialog = tk.Toplevel(self.app.root)
        dialog.title("Import Preview - Domain List Rule Group")
        dialog.geometry("700x700")
        dialog.transient(self.app.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.app.root.winfo_rootx() + 150,
            self.app.root.winfo_rooty() + 100
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(main_frame, text="Import Preview - Domain List Rule Group",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 15))
        
        # Metadata frame
        meta_frame = ttk.LabelFrame(main_frame, text="Rule Group Metadata")
        meta_frame.pack(fill=tk.X, pady=(0, 15))
        
        meta_text = f"""Rule Group: {rule_group_data['name']}
ARN: {rule_group_data['arn']}
Region: {rule_group_data.get('region', 'Unknown')}
Capacity: {rule_group_data['capacity']}
Description: {rule_group_data['description']}

Domain List Configuration:
• Action: {rule_group_data['generated_rules_type']}
• Target Types: {', '.join(rule_group_data['target_types'])}
• Evaluation Order: DNSORDER (alphabetical)
• Domain Count: {len(rule_group_data['domains'])}"""
        
        ttk.Label(meta_frame, text=meta_text,
                 font=("Consolas", 9), justify=tk.LEFT).pack(padx=10, pady=10)
        
        # Domains preview frame
        domains_frame = ttk.LabelFrame(main_frame, text="Domain Preview")
        domains_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Domains text widget
        domains_text = tk.Text(domains_frame, height=12, wrap=tk.WORD,
                              font=("Consolas", 9), state=tk.DISABLED)
        domains_scrollbar = ttk.Scrollbar(domains_frame, orient=tk.VERTICAL,
                                         command=domains_text.yview)
        domains_text.configure(yscrollcommand=domains_scrollbar.set)
        
        domains_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        domains_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Populate domains preview
        domains_text.config(state=tk.NORMAL)
        domains = rule_group_data['domains']
        domains_text.insert(tk.END, f"First 10 Domains:\n")
        for i, domain in enumerate(domains[:10]):
            domains_text.insert(tk.END, f"• {domain}\n")
        
        if len(domains) > 10:
            domains_text.insert(tk.END, f"... and {len(domains) - 10} more domains\n")
        
        domains_text.config(state=tk.DISABLED)
        
        # Import note frame
        note_frame = ttk.Frame(main_frame)
        note_frame.pack(fill=tk.X, pady=(0, 15))
        
        note_text = ("Import Action:\n"
                    "These domains will be passed to the Bulk Domain Import dialog\n"
                    "where you can configure rule generation options.\n\n"
                    "Note: Domain List rule groups use DNSORDER evaluation (alphabetical).\n"
                    "After import, domains will be converted to STRICT_ORDER Suricata\n"
                    "rules and can be reordered as needed.")
        
        ttk.Label(note_frame, text=note_text,
                 font=("TkDefaultFont", 9), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Buttons
        result = [False]
        
        def on_import():
            result[0] = True
            dialog.destroy()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Cancel",
                  command=dialog.destroy).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Import",
                  command=on_import).pack(side=tk.RIGHT, padx=(0, 5))
        
        dialog.wait_window()
        return result[0]
    
    def show_import_preview_multi(self, rule_groups_list: List[dict]) -> bool:
        """Show preview for multiple Domain List rule groups
        
        Args:
            rule_groups_list: List of dicts with domain list details
            
        Returns:
            True if user confirms import, False otherwise
        """
        dialog = tk.Toplevel(self.app.root)
        dialog.title("Import Preview - Multiple Domain List Rule Groups")
        dialog.geometry("750x750")
        dialog.transient(self.app.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.app.root.winfo_rootx() + 150,
            self.app.root.winfo_rooty() + 50
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(main_frame, text=f"Import Preview - {len(rule_groups_list)} Domain List Rule Groups",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 15))
        
        # Combined summary frame
        summary_frame = ttk.LabelFrame(main_frame, text="Combined Summary")
        summary_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Calculate totals
        total_domains = sum(len(rg['domains']) for rg in rule_groups_list)
        actions = set(rg['generated_rules_type'] for rg in rule_groups_list)
        all_target_types = set()
        for rg in rule_groups_list:
            all_target_types.update(rg['target_types'])
        
        # Build summary text
        summary_text = f"Total Rule Groups: {len(rule_groups_list)}\n"
        summary_text += f"Total Domains: {total_domains}\n"
        summary_text += f"Combined Target Types: {', '.join(sorted(all_target_types))}\n"
        
        # Handle action conflicts
        if len(actions) > 1:
            summary_text += f"\n⚠️  Mixed Actions Detected: {', '.join(sorted(actions))}\n"
            summary_text += "Default action will be based on first rule group.\n"
            summary_text += "You can override in the Bulk Domain Import dialog."
        else:
            summary_text += f"Action: {list(actions)[0]}"
        
        ttk.Label(summary_frame, text=summary_text,
                 font=("Consolas", 9), justify=tk.LEFT,
                 foreground="blue" if len(actions) > 1 else "black").pack(padx=10, pady=10)
        
        # Rule groups list frame
        rg_frame = ttk.LabelFrame(main_frame, text="Rule Groups to Import")
        rg_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Rule groups text widget with scrollbar
        rg_text = tk.Text(rg_frame, height=15, wrap=tk.WORD,
                         font=("Consolas", 9), state=tk.DISABLED)
        rg_scrollbar = ttk.Scrollbar(rg_frame, orient=tk.VERTICAL,
                                     command=rg_text.yview)
        rg_text.configure(yscrollcommand=rg_scrollbar.set)
        
        rg_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        rg_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Populate rule groups list
        rg_text.config(state=tk.NORMAL)
        for i, rg in enumerate(rule_groups_list, 1):
            rg_text.insert(tk.END, f"{i}. {rg['name']}\n")
            rg_text.insert(tk.END, f"   Action: {rg['generated_rules_type']}  |  ")
            rg_text.insert(tk.END, f"Domains: {len(rg['domains'])}  |  ")
            rg_text.insert(tk.END, f"Targets: {', '.join(rg['target_types'])}\n")
            if rg['description']:
                rg_text.insert(tk.END, f"   Description: {rg['description']}\n")
            rg_text.insert(tk.END, f"   Region: {rg.get('region', 'Unknown')}\n")
            if i < len(rule_groups_list):
                rg_text.insert(tk.END, "\n")
        
        rg_text.config(state=tk.DISABLED)
        
        # Import note frame
        note_frame = ttk.Frame(main_frame)
        note_frame.pack(fill=tk.X, pady=(0, 15))
        
        note_text = ("Import Action:\n"
                    "Domains from all selected rule groups will be combined and passed\n"
                    "to the Bulk Domain Import dialog where you can configure rule\n"
                    "generation options.\n\n"
                    "Note: Duplicate domains across rule groups will be automatically\n"
                    "removed by the consolidation algorithm.")
        
        ttk.Label(note_frame, text=note_text,
                 font=("TkDefaultFont", 9), justify=tk.LEFT).pack(anchor=tk.W)
        
        # Buttons
        result = [False]
        
        def on_import():
            result[0] = True
            dialog.destroy()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Cancel",
                  command=dialog.destroy).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Import",
                  command=on_import).pack(side=tk.RIGHT, padx=(0, 5))
        
        dialog.wait_window()
        return result[0]
    
    def import_from_aws_multi(self, rule_groups_list: List[dict]):
        """Import multiple Domain Lists from AWS and combine them
        
        Args:
            rule_groups_list: List of dicts containing domain list details from AWS
        """
        # Combine all domains from all rule groups
        all_domains = []
        for rg in rule_groups_list:
            all_domains.extend(rg['domains'])
        
        # Normalize AWS wildcard domains before consolidation
        normalized_domains = []
        for domain in all_domains:
            if domain.startswith('.'):
                # Strip leading dot from AWS wildcard
                normalized_domains.append(domain[1:])
            else:
                # Keep domain as-is
                normalized_domains.append(domain)
        
        # Determine combined action (use first, warn if mixed)
        actions = set(rg['generated_rules_type'] for rg in rule_groups_list)
        default_action = 'pass' if rule_groups_list[0]['generated_rules_type'] == 'ALLOWLIST' else 'drop'
        
        # Determine combined protocols (union of all target types)
        all_target_types = set()
        for rg in rule_groups_list:
            all_target_types.update(rg['target_types'])
        
        protocols = []
        if 'HTTP_HOST' in all_target_types:
            protocols.append('http')
        if 'TLS_SNI' in all_target_types:
            protocols.append('tls')
        
        # If no target types specified, default to both
        if not protocols:
            protocols = ['http', 'tls']
        
        # Build source description for UI
        source_description = f"AWS Domain List Rule Groups ({len(rule_groups_list)} combined)"
        
        # Build metadata comment listing all sources
        metadata_comment = f"# Imported from {len(rule_groups_list)} AWS Domain List Rule Groups\n"
        for rg in rule_groups_list:
            metadata_comment += f"# - {rg['name']} ({rg['generated_rules_type']}, {len(rg['domains'])} domains)\n"
        
        metadata_comment += f"# Combined Target Types: {', '.join(sorted(all_target_types))}\n"
        
        if len(actions) > 1:
            metadata_comment += f"# Note: Mixed actions detected ({', '.join(sorted(actions))}), defaulting to {default_action.upper()}\n"
        
        metadata_comment += "# Original Evaluation: DNSORDER (alphabetical)\n"
        metadata_comment += "# Converted to: STRICT_ORDER (rule file order)\n"
        metadata_comment += "# Note: Leading dots stripped for consolidation (*.domain intent preserved)\n"
        metadata_comment += "# Note: Duplicates across rule groups automatically removed by consolidation\n"
        
        # Pass to Bulk Domain Import dialog
        self.app.domain_importer.show_bulk_import_dialog(
            domains_list=normalized_domains,
            default_action=default_action,
            source_description=source_description,
            metadata_comment=metadata_comment,
            protocols=protocols,
            aws_target_types=sorted(all_target_types)
        )
    
    def import_from_aws(self, rule_group_data: dict):
        """Import Domain List from AWS and open Bulk Domain Import dialog
        
        Args:
            rule_group_data: Dict containing domain list details from AWS
        """
        # Extract domains
        raw_domains = rule_group_data['domains']
        
        # CRITICAL: Normalize AWS wildcard domains before consolidation
        normalized_domains = []
        for domain in raw_domains:
            if domain.startswith('.'):
                # Strip leading dot from AWS wildcard
                normalized_domains.append(domain[1:])
            else:
                # Keep domain as-is
                normalized_domains.append(domain)
        
        # Map AWS action to Suricata action
        aws_action = rule_group_data['generated_rules_type']
        default_action = 'pass' if aws_action == 'ALLOWLIST' else 'drop'
        
        # Determine protocols based on target types
        target_types = rule_group_data['target_types']
        protocols = []
        if 'HTTP_HOST' in target_types:
            protocols.append('http')
        if 'TLS_SNI' in target_types:
            protocols.append('tls')
        
        # If no target types specified, default to both
        if not protocols:
            protocols = ['http', 'tls']
        
        # Build source description for UI
        source_description = f"AWS Domain List Rule Group ({rule_group_data['name']})"
        
        # Add metadata comment
        metadata_comment = (
            f"# Imported from AWS Domain List Rule Group\n"
            f"# Rule Group: {rule_group_data['name']}\n"
            f"# ARN: {rule_group_data['arn']}\n"
            f"# Original Action: {aws_action}\n"
            f"# Target Types: {', '.join(target_types)}\n"
            f"# Original Evaluation: DNSORDER (alphabetical)\n"
            f"# Converted to: STRICT_ORDER (rule file order)\n"
            f"# Note: Leading dots stripped for consolidation (*.domain intent preserved)\n"
        )
        
        # Pass to Bulk Domain Import dialog
        self.app.domain_importer.show_bulk_import_dialog(
            domains_list=normalized_domains,
            default_action=default_action,
            source_description=source_description,
            metadata_comment=metadata_comment,
            protocols=protocols,
            aws_target_types=target_types
        )
