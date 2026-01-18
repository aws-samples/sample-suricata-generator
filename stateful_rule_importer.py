import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
from typing import List, Dict, Optional
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


class AWSRuleGroupBrowser:
    """Browser dialog for AWS Network Firewall rule groups
    
    Provides a UI for browsing, searching, and selecting AWS Network Firewall
    rule groups directly from AWS account without requiring manual CLI exports.
    """
    
    def __init__(self, parent_app):
        """Initialize browser with reference to parent application
        
        Args:
            parent_app: Reference to main SuricataRuleGenerator instance
        """
        self.parent = parent_app
        self.cached_rule_groups = None
        self.cache_timestamp = None
        self.cache_ttl = 300  # 5 minutes
        self.expanded_details = {}  # Cache expanded rule group details
        self.selected_region = None  # Currently selected AWS region
        
        # All AWS standard commercial regions (excludes China and GovCloud)
        self.aws_regions = [
            # US Regions
            'us-east-1',      # US East (N. Virginia)
            'us-east-2',      # US East (Ohio)
            'us-west-1',      # US West (N. California)
            'us-west-2',      # US West (Oregon)
            # Canada Regions
            'ca-central-1',   # Canada (Central)
            'ca-west-1',      # Canada (Calgary)
            # Europe Regions
            'eu-west-1',      # Europe (Ireland)
            'eu-west-2',      # Europe (London)
            'eu-west-3',      # Europe (Paris)
            'eu-central-1',   # Europe (Frankfurt)
            'eu-central-2',   # Europe (Zurich)
            'eu-north-1',     # Europe (Stockholm)
            'eu-south-1',     # Europe (Milan)
            'eu-south-2',     # Europe (Spain)
            # Asia Pacific Regions
            'ap-south-1',     # Asia Pacific (Mumbai)
            'ap-south-2',     # Asia Pacific (Hyderabad)
            'ap-southeast-1', # Asia Pacific (Singapore)
            'ap-southeast-2', # Asia Pacific (Sydney)
            'ap-southeast-3', # Asia Pacific (Jakarta)
            'ap-southeast-4', # Asia Pacific (Melbourne)
            'ap-northeast-1', # Asia Pacific (Tokyo)
            'ap-northeast-2', # Asia Pacific (Seoul)
            'ap-northeast-3', # Asia Pacific (Osaka)
            'ap-east-1',      # Asia Pacific (Hong Kong)
            # South America Regions
            'sa-east-1',      # South America (São Paulo)
            # Middle East Regions
            'me-south-1',     # Middle East (Bahrain)
            'me-central-1',   # Middle East (UAE)
            # Africa Regions
            'af-south-1',     # Africa (Cape Town)
            # Israel Regions
            'il-central-1',   # Israel (Tel Aviv)
        ]
    
    def browse_and_select(self) -> Optional[Dict]:
        """Show browse dialog and return selected rule group data
        
        Returns:
            Dict with rule group data or None if cancelled
        """
        # Create browse dialog
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Browse AWS Rule Groups")
        dialog.geometry("800x600")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 100,
            self.parent.root.winfo_rooty() + 50
        ))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Region and search controls frame
        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Region selector
        ttk.Label(controls_frame, text="Region:").pack(side=tk.LEFT, padx=(0, 5))
        
        # Get default region from boto3
        try:
            session = boto3.Session()
            default_region = session.region_name or 'us-east-1'
        except:
            default_region = 'us-east-1'
        
        self.selected_region = default_region
        region_var = tk.StringVar(value=default_region)
        region_combo = ttk.Combobox(controls_frame, textvariable=region_var, 
                                    values=self.aws_regions, state="readonly", width=20)
        region_combo.pack(side=tk.LEFT, padx=(0, 20))
        
        # Region change handler
        def on_region_change(event):
            # Update selected region
            self.selected_region = region_var.get()
            # Clear cache since we're switching regions
            self.cached_rule_groups = None
            self.cache_timestamp = None
            self.expanded_details.clear()
            # Reload rule groups for new region
            load_rule_groups()
        
        region_combo.bind('<<ComboboxSelected>>', on_region_change)
        
        # Search controls (on same line as region)
        search_frame = ttk.Frame(controls_frame)
        search_frame.pack(side=tk.LEFT)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        # Search functionality (client-side filtering)
        def on_search(*args):
            self._filter_tree(tree, search_var.get())
        
        search_var.trace_add('write', on_search)
        
        def clear_search():
            search_var.set("")
        
        ttk.Button(search_frame, text="🔍", width=3, command=lambda: on_search()).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(search_frame, text="Clear", command=clear_search).pack(side=tk.LEFT, padx=(0, 10))
        
        def refresh_list():
            # Clear cache and reload
            self.cached_rule_groups = None
            self.cache_timestamp = None
            self.expanded_details.clear()
            load_rule_groups()
        
        ttk.Button(search_frame, text="↻ Refresh", command=refresh_list).pack(side=tk.LEFT)
        
        # Treeview for rule groups
        tree_container = ttk.Frame(main_frame)
        tree_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        columns = ("Name", "Type")
        tree = ttk.Treeview(tree_container, columns=columns, show="tree headings", selectmode="browse")
        
        tree.heading("#0", text="", command=lambda: None)  # Hidden but needed for expand/collapse
        tree.heading("Name", text="Name ▲", command=lambda: self._sort_tree(tree, "Name", False))
        tree.heading("Type", text="Type", command=lambda: self._sort_tree(tree, "Type", False))
        
        tree.column("#0", width=30, stretch=False)  # For expand/collapse triangle
        tree.column("Name", width=400, stretch=True)
        tree.column("Type", width=150, stretch=False)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        
        # Configure tags for styling
        tree.tag_configure("stateful", foreground="#000000")
        tree.tag_configure("stateless", foreground="#999999")
        tree.tag_configure("details", font=("TkDefaultFont", 9), foreground="#666666")
        tree.tag_configure("warning", font=("TkDefaultFont", 9), foreground="#CC6600")  # Darker orange for better readability
        
        # Status footer
        status_label = ttk.Label(main_frame, text="", font=("TkDefaultFont", 9))
        status_label.pack(fill=tk.X, pady=(0, 10))
        
        # Selected display
        selected_label = ttk.Label(main_frame, text="Selected: (none)", font=("TkDefaultFont", 9))
        selected_label.pack(fill=tk.X, pady=(0, 10))
        
        # Store selection
        selected_data = [None]
        rule_groups_data = []
        
        def on_tree_select(event):
            """Handle tree selection"""
            selection = tree.selection()
            if not selection:
                selected_label.config(text="Selected: (none)")
                selected_data[0] = None
                return
            
            item = selection[0]
            values = tree.item(item, "values")
            
            # Check if this is a detail row or main row
            parent = tree.parent(item)
            if parent:
                # This is a detail row - select the parent instead
                tree.selection_set(parent)
                return
            
            # Check if this is a STATELESS rule group
            if len(values) >= 2 and values[1] == "STATELESS":
                # Don't allow selection of STATELESS
                tree.selection_remove(item)
                selected_label.config(text="Selected: (none)")
                selected_data[0] = None
                messagebox.showinfo("Cannot Select", "Only STATEFUL rule groups can be imported.")
                return
            
            # Find the rule group data
            rg_name = values[0] if values else None
            if rg_name:
                for rg in rule_groups_data:
                    if rg['name'] == rg_name and rg['type'] == 'STATEFUL':
                        selected_label.config(text=f"Selected: {rg_name}")
                        selected_data[0] = rg
                        break
        
        tree.bind("<<TreeviewSelect>>", on_tree_select)
        
        def on_tree_expand(event):
            """Handle expand event to load details on demand"""
            item = tree.focus()
            if not item:
                return
            
            # Check if this has the dummy "Loading..." child
            children = tree.get_children(item)
            if children:
                # Check if it's the dummy child
                first_child_values = tree.item(children[0], "values")
                if first_child_values and first_child_values[0] != "Loading...":
                    # Already has real children, don't reload
                    return
            
            values = tree.item(item, "values")
            if not values:
                return
            
            rg_name = values[0]
            rg_type = values[1]
            
            # Only expand STATEFUL rule groups
            if rg_type != "STATEFUL":
                return
            
            # Find rule group data
            rg_data = None
            for rg in rule_groups_data:
                if rg['name'] == rg_name and rg['type'] == rg_type:
                    rg_data = rg
                    break
            
            if not rg_data:
                return
            
            # Load details if not cached
            if rg_name not in self.expanded_details:
                self._load_rule_group_details(rg_data, tree, item)
            else:
                # Use cached details
                self._display_cached_details(tree, item, self.expanded_details[rg_name])
        
        tree.bind("<<TreeviewOpen>>", on_tree_expand)
        
        def load_rule_groups():
            """Load rule groups from AWS"""
            # Check cache first
            if self._is_cache_valid():
                rule_groups = self.cached_rule_groups
            else:
                # Show progress dialog
                progress_dialog = tk.Toplevel(dialog)
                progress_dialog.title("Loading Rule Groups")
                progress_dialog.geometry("350x100")
                progress_dialog.transient(dialog)
                progress_dialog.grab_set()
                progress_dialog.resizable(False, False)
                
                # Center on parent
                progress_dialog.geometry("+%d+%d" % (
                    dialog.winfo_rootx() + 200,
                    dialog.winfo_rooty() + 200
                ))
                
                ttk.Label(progress_dialog, text="Loading rule groups from AWS...",
                         font=("TkDefaultFont", 10)).pack(pady=20)
                progress_bar = ttk.Progressbar(progress_dialog, mode='indeterminate', length=300)
                progress_bar.pack(pady=10)
                progress_bar.start(10)
                
                dialog.update()
                progress_dialog.update()
                
                try:
                    # Fetch rule groups from AWS
                    rule_groups = self._fetch_rule_groups()
                    progress_dialog.destroy()
                    
                except NoCredentialsError:
                    progress_dialog.destroy()
                    messagebox.showerror(
                        "AWS Credentials Not Found",
                        "AWS credentials are not configured. To use this feature, you need to:\n\n"
                        "1. Install AWS CLI: https://aws.amazon.com/cli/\n"
                        "2. Run: aws configure\n"
                        "3. Enter your Access Key ID and Secret Access Key\n\n"
                        "Alternative: Set environment variables:\n"
                        "• AWS_ACCESS_KEY_ID\n"
                        "• AWS_SECRET_ACCESS_KEY\n"
                        "• AWS_DEFAULT_REGION"
                    )
                    dialog.destroy()
                    return
                
                except ClientError as e:
                    progress_dialog.destroy()
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    if error_code == 'AccessDeniedException':
                        messagebox.showerror(
                            "Insufficient AWS Permissions",
                            "Your AWS credentials don't have permission to list rule groups.\n\n"
                            "Required IAM permissions:\n"
                            "• network-firewall:ListRuleGroups\n"
                            "• network-firewall:DescribeRuleGroup\n\n"
                            "Please contact your AWS administrator to grant these permissions."
                        )
                    else:
                        messagebox.showerror("AWS Error", f"Failed to list rule groups:\n\n{str(e)}")
                    dialog.destroy()
                    return
                
                except Exception as e:
                    progress_dialog.destroy()
                    if "timeout" in str(e).lower():
                        messagebox.showerror(
                            "Connection Timeout",
                            "Cannot connect to AWS Network Firewall service.\n\n"
                            "Please check:\n"
                            "• Internet connection is active\n"
                            "• Firewall/proxy allows AWS API access\n"
                            "• Selected region is correct"
                        )
                    else:
                        messagebox.showerror("Error", f"Failed to load rule groups:\n\n{str(e)}")
                    dialog.destroy()
                    return
            
            # Clear tree
            tree.delete(*tree.get_children())
            rule_groups_data.clear()
            
            if not rule_groups:
                messagebox.showinfo(
                    "No Rule Groups Found",
                    "No rule groups found in your account for the default region.\n\n"
                    "This could mean:\n"
                    "• No rule groups exist in this region\n"
                    "• You don't have permissions to view them\n"
                    "• Check AWS credentials are configured correctly"
                )
                dialog.destroy()
                return
            
            # Populate tree
            stateful_count = 0
            stateless_count = 0
            
            for rg in rule_groups:
                rg_type = rg['type']
                tag = "stateful" if rg_type == "STATEFUL" else "stateless"
                
                # Insert with empty text in #0 column (will show triangle if expandable)
                item = tree.insert("", tk.END, text="", values=(rg['name'], rg_type), tags=(tag,))
                
                # Only STATEFUL rule groups are expandable
                if rg_type == "STATEFUL":
                    # Add a dummy child to show expand triangle (will be replaced on expand)
                    tree.insert(item, tk.END, text="", values=("Loading...", ""))
                    stateful_count += 1
                else:
                    stateless_count += 1
                
                rule_groups_data.append(rg)
            
            # Update status - include region information
            status_label.config(
                text=f"Region: {self.selected_region} | Showing {len(rule_groups)} rule groups "
                     f"({stateful_count} STATEFUL selectable, {stateless_count} STATELESS disabled)"
            )
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def on_preview():
            if not selected_data[0]:
                messagebox.showwarning("No Selection", "Please select a rule group to import.")
                return
            
            # Add selected region to the returned data
            selected_data[0]['region'] = self.selected_region
            dialog.destroy()
        
        def on_cancel():
            # Clear selection before closing to ensure import is cancelled
            selected_data[0] = None
            dialog.destroy()
        
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Preview Import >", command=on_preview).pack(side=tk.RIGHT)
        
        # Load rule groups
        load_rule_groups()
        
        # Wait for dialog
        dialog.wait_window()
        
        return selected_data[0]
    
    def _is_cache_valid(self) -> bool:
        """Check if cached data is still valid"""
        if not self.cached_rule_groups or not self.cache_timestamp:
            return False
        
        elapsed = (time.time() - self.cache_timestamp)
        return elapsed < self.cache_ttl
    
    def _fetch_rule_groups(self) -> List[Dict]:
        """Fetch rule groups from AWS using selected region
        
        Returns:
            List of rule group dictionaries
        """
        if not HAS_BOTO3:
            raise ImportError("boto3 is required for AWS import")
        
        # Create client with selected region (or default if not set)
        region = self.selected_region if self.selected_region else None
        client = boto3.client('network-firewall', region_name=region)
        
        rule_groups = []
        
        # Fetch STATEFUL rule groups
        response_stateful = client.list_rule_groups(
            Scope='ACCOUNT',
            Type='STATEFUL',
            MaxResults=100
        )
        
        for rg in response_stateful.get('RuleGroups', []):
            rule_groups.append({
                'name': rg['Name'],
                'arn': rg['Arn'],
                'type': 'STATEFUL'
            })
        
        # Fetch STATELESS rule groups (for display only)
        response_stateless = client.list_rule_groups(
            Scope='ACCOUNT',
            Type='STATELESS',
            MaxResults=100
        )
        
        for rg in response_stateless.get('RuleGroups', []):
            rule_groups.append({
                'name': rg['Name'],
                'arn': rg['Arn'],
                'type': 'STATELESS'
            })
        
        # Sort by name
        rule_groups.sort(key=lambda x: x['name'])
        
        # Cache the results
        self.cached_rule_groups = rule_groups
        self.cache_timestamp = time.time()
        
        return rule_groups
    
    def _filter_tree(self, tree, search_text):
        """Filter tree items by search text (client-side)"""
        search_lower = search_text.lower()
        
        for item in tree.get_children():
            values = tree.item(item, "values")
            if values:
                name = values[0].lower()
                if search_lower in name:
                    tree.item(item, tags=tree.item(item, "tags"))  # Show
                else:
                    tree.detach(item)  # Hide
        
        # If search is empty, show all
        if not search_text:
            for item in tree.get_children(""):
                tree.reattach(item, "", tree.index(item))
    
    def _sort_tree(self, tree, column, reverse):
        """Sort tree by column"""
        items = [(tree.set(item, column), item) for item in tree.get_children("")]
        items.sort(reverse=reverse)
        
        for index, (val, item) in enumerate(items):
            tree.move(item, "", index)
        
        # Update heading with sort indicator
        for col in tree["columns"]:
            if col == column:
                indicator = " ▼" if reverse else " ▲"
                tree.heading(col, text=col + indicator,
                           command=lambda c=col, r=reverse: self._sort_tree(tree, c, not r))
            else:
                tree.heading(col, text=col,
                           command=lambda c=col: self._sort_tree(tree, c, False))
    
    def _load_rule_group_details(self, rg_data, tree, item):
        """Load rule group details on expand (lazy loading)"""
        # Show progress dialog
        progress_dialog = tk.Toplevel(self.parent.root)
        progress_dialog.title("Loading Rule Group Details")
        progress_dialog.geometry("350x100")
        progress_dialog.transient(tree.winfo_toplevel())
        progress_dialog.grab_set()
        progress_dialog.resizable(False, False)
        
        # Center on parent
        parent_window = tree.winfo_toplevel()
        progress_dialog.geometry("+%d+%d" % (
            parent_window.winfo_rootx() + 200,
            parent_window.winfo_rooty() + 200
        ))
        
        ttk.Label(progress_dialog, text=f"Retrieving details for\n{rg_data['name']}...",
                 font=("TkDefaultFont", 10)).pack(pady=10)
        progress_bar = ttk.Progressbar(progress_dialog, mode='indeterminate', length=300)
        progress_bar.pack(pady=10)
        progress_bar.start(10)
        
        tree.winfo_toplevel().update()
        progress_dialog.update()
        
        try:
            # Fetch details from AWS using selected region
            region = self.selected_region if self.selected_region else None
            client = boto3.client('network-firewall', region_name=region)
            response = client.describe_rule_group(
                RuleGroupArn=rg_data['arn'],
                Type='STATEFUL'
            )
            
            # Extract details
            rg_response = response.get('RuleGroupResponse', {})
            rule_group = response.get('RuleGroup', {})
            
            # Count rules and determine format
            rules_source = rule_group.get('RulesSource', {})
            if 'StatefulRules' in rules_source:
                rule_count = len(rules_source['StatefulRules'])
                rule_format = 'Standard (5-tuple)'
            elif 'RulesString' in rules_source:
                rule_count = len([line for line in rules_source['RulesString'].split('\n') if line.strip() and not line.strip().startswith('#')])
                rule_format = 'Suricata'
            else:
                rule_count = 0
                rule_format = 'Unknown'
            
            details = {
                'capacity': rg_response.get('Capacity', 'Unknown'),
                'rule_count': rule_count,
                'last_modified': rg_response.get('LastModifiedTime', 'Unknown'),
                'description': rg_response.get('Description', ''),
                'format': rule_format,
                'associations': rg_response.get('NumberOfAssociations', 0)
            }
            
            # Cache details
            self.expanded_details[rg_data['name']] = details
            
            progress_dialog.destroy()
            
            # Display details
            self._display_cached_details(tree, item, details)
            
        except Exception as e:
            progress_dialog.destroy()
            messagebox.showerror("Error", f"Failed to load details:\n\n{str(e)}")
            # Remove dummy child
            for child in tree.get_children(item):
                tree.delete(child)
    
    def _display_cached_details(self, tree, item, details):
        """Display cached details in tree"""
        # Remove dummy/old children
        for child in tree.get_children(item):
            tree.delete(child)
        
        # Format last modified
        last_mod = details['last_modified']
        if isinstance(last_mod, str):
            last_mod_str = last_mod[:10]  # Just date part
        else:
            try:
                last_mod_str = last_mod.strftime('%Y-%m-%d')
            except:
                last_mod_str = str(last_mod)
        
        # Add detail rows - include format information
        detail_text = (
            f"    Capacity: {details['capacity']}  |  "
            f"Rules: {details['rule_count']}  |  "
            f"Format: {details['format']}  |  "
            f"Modified: {last_mod_str}"
        )
        
        detail_item = tree.insert(item, tk.END, text="", values=(detail_text, ""), tags=("details",))
        
        # Add firewall associations info
        associations = details.get('associations', 0)
        if associations > 0:
            assoc_text = f"    ⚠️  Attached to {associations} firewall policy/policies"
            tree.insert(item, tk.END, text="", values=(assoc_text, ""), tags=("warning",))
        else:
            assoc_text = f"    Not attached to any firewall policies"
            tree.insert(item, tk.END, text="", values=(assoc_text, ""), tags=("details",))
        
        if details['description']:
            desc_text = f"    Description: {details['description']}"
            tree.insert(item, tk.END, text="", values=(desc_text, ""), tags=("details",))


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
        self.aws_browser = AWSRuleGroupBrowser(parent_app) if HAS_BOTO3 else None
    
    def import_standard_rule_group(self):
        """Import a standard rule group - check for unsaved changes first, then show options dialog"""
        # Check for unsaved changes BEFORE showing import options dialog
        if self.parent.modified:
            save_result = self.parent.ask_save_changes()
            if not save_result:
                return  # User clicked Cancel or save failed - abort import
            # If True (saved successfully or user chose No), continue with import
        
        # Show import options dialog
        import_source = self._show_import_options_dialog()
        
        if not import_source:
            return  # User cancelled
        
        if import_source == 'json':
            # Use existing JSON file import (no longer needs to check for unsaved changes)
            self._import_from_json_file()
        elif import_source == 'aws':
            # Use new AWS direct import (no longer needs to check for unsaved changes)
            self._import_from_aws()
    
    def _show_import_options_dialog(self) -> Optional[str]:
        """Show dialog to choose import source
        
        Returns:
            'json' for JSON file, 'aws' for AWS direct, None for cancel
        """
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Import Stateful Rule Group")
        dialog.geometry("580x280")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 200,
            self.parent.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        ttk.Label(main_frame, text="Choose Import Source:",
                 font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W, pady=(0, 15))
        
        # Radio buttons
        source_var = tk.StringVar(value='json')
        
        # Option 1: JSON file
        json_frame = ttk.Frame(main_frame)
        json_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Radiobutton(json_frame, text="Import from JSON File", 
                       variable=source_var, value='json').pack(anchor=tk.W)
        ttk.Label(json_frame, 
                 text="Export a rule group using AWS CLI and import the\nJSON file",
                 font=("TkDefaultFont", 9), foreground="#666666").pack(anchor=tk.W, padx=(25, 0))
        
        # Option 2: AWS
        aws_frame = ttk.Frame(main_frame)
        aws_frame.pack(fill=tk.X, pady=(0, 10))
        
        aws_radio = ttk.Radiobutton(aws_frame, text="Import from AWS",
                                    variable=source_var, value='aws')
        aws_radio.pack(anchor=tk.W)
        
        if HAS_BOTO3:
            ttk.Label(aws_frame,
                     text="Connect to AWS and browse rule groups directly",
                     font=("TkDefaultFont", 9), foreground="#666666").pack(anchor=tk.W, padx=(25, 0))
        else:
            aws_radio.config(state='disabled')
            ttk.Label(aws_frame,
                     text="Requires boto3 - run: pip install boto3",
                     font=("TkDefaultFont", 9), foreground="#999999").pack(anchor=tk.W, padx=(25, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(15, 0))
        
        result = [None]
        
        def on_help():
            # Open existing Help > AWS Setup
            self.parent.ui_manager.show_aws_setup_help()
        
        def on_ok():
            result[0] = source_var.get()
            dialog.destroy()
        
        ttk.Button(button_frame, text="Help", command=on_help).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        
        dialog.wait_window()
        return result[0]
    
    def _import_from_json_file(self):
        """Import from JSON file (existing functionality)"""
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
            
            if not parsed_data:
                return
            
            # Show preview dialog and get user choices
            confirm_import, run_analyzer = self.show_import_preview_dialog(parsed_data, filename)
            
            if confirm_import:
                self.apply_import(parsed_data)
                
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
    
    def _import_from_aws(self):
        """Import from AWS (new functionality)"""
        if not HAS_BOTO3:
            messagebox.showerror("boto3 Required", "boto3 is required for AWS import")
            return
        
        # Show browse dialog
        selected_rg = self.aws_browser.browse_and_select()
        
        if not selected_rg:
            return  # User cancelled
        
        # Fetch full rule group data (pass region along)
        try:
            rule_group_data = self._fetch_rule_group_data(selected_rg['arn'], selected_rg.get('region'))
            
            # Parse the rule group
            parsed_data = self.parse_rule_group_json(rule_group_data)
            
            if not parsed_data:
                return
            
            # Show preview dialog (modified for AWS source)
            confirm_import, run_analyzer = self.show_import_preview_dialog(parsed_data, source="AWS")
            
            if confirm_import:
                self.apply_import(parsed_data)
                
                if run_analyzer:
                    self.parent.review_rules()
                
        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import rule group from AWS:\n\n{str(e)}")
    
    def _fetch_rule_group_data(self, arn: str, region: Optional[str] = None) -> Dict:
        """Fetch complete rule group data from AWS
        
        Args:
            arn: Rule group ARN
            region: AWS region (optional, uses default if not specified)
            
        Returns:
            Dict with rule group data in describe-rule-group format
        """
        if not HAS_BOTO3:
            raise ImportError("boto3 is required for AWS import")
        
        client = boto3.client('network-firewall', region_name=region)
        
        response = client.describe_rule_group(
            RuleGroupArn=arn,
            Type='STATEFUL'
        )
        
        return response
    
    def import_from_aws_data(self, rule_group_data: Dict, run_analyzer: bool = False):
        """Import rule group from AWS data (for programmatic use)
        
        Args:
            rule_group_data: Rule group data from describe_rule_group
            run_analyzer: Whether to run rule analyzer after import
        """
        # Parse the rule group
        parsed_data = self.parse_rule_group_json(rule_group_data)
        
        if not parsed_data:
            return
        
        # Apply import
        self.apply_import(parsed_data)
        
        if run_analyzer:
            self.parent.review_rules()
    
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
            
            # Parse variables (IPSets and PortSets from RuleVariables)
            variables = self.parse_rule_variables(rule_group.get('RuleVariables', {}))
            
            # Parse IP set references (managed IP sets referenced by ARN)
            reference_sets = self.parse_reference_sets(rule_group.get('ReferenceSets', {}))
            
            # Merge reference sets into variables
            variables.update(reference_sets)
            
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
    
    def parse_reference_sets(self, reference_sets: dict) -> dict:
        """Parse ReferenceSets section (IP set references)
        
        IP set references are AWS VPC Managed Prefix Lists that are referenced by ARN.
        These use the @ prefix (not $) and the value is the ARN itself.
        
        Args:
            reference_sets: ReferenceSets dictionary from JSON
            
        Returns:
            Dictionary of variables with @ prefix and ARN values
        """
        variables = {}
        
        # Parse IPSetReferences
        ip_set_references = reference_sets.get('IPSetReferences', {})
        for var_name, var_data in ip_set_references.items():
            reference_arn = var_data.get('ReferenceArn', '')
            # Add @ prefix (not $) and use the ARN as the value
            variables[f'@{var_name}'] = reference_arn
        
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
        from constants import SuricataConstants
        
        msg = ""
        sid = SuricataConstants.SID_MIN
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
                        sid = SuricataConstants.SID_MIN
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
    
    def show_import_preview_dialog(self, parsed_data: dict, source) -> tuple:
        """Show preview dialog before importing
        
        Args:
            parsed_data: Parsed rule group data
            source: Source identifier (filename string or "AWS")
            
        Returns:
            Tuple of (confirm_import: bool, run_analyzer: bool)
        """
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Import Stateful Rule Group - Preview")
        dialog.geometry("700x850")
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
        
        # Show source (AWS or file path)
        if source == "AWS":
            ttk.Label(info_frame, text=f"Source:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
            ttk.Label(info_frame, text="AWS Network Firewall", font=("TkDefaultFont", 9)).grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
            
            # Show ARN if available
            original_json = parsed_data.get('original_json', {})
            rg_response = original_json.get('RuleGroupResponse', {})
            if rg_response.get('RuleGroupArn'):
                ttk.Label(info_frame, text=f"ARN:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
                ttk.Label(info_frame, text=rg_response['RuleGroupArn'], font=("TkDefaultFont", 9)).grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
                next_row = 2
            else:
                next_row = 1
        else:
            ttk.Label(info_frame, text=f"Source File:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
            ttk.Label(info_frame, text=source, font=("TkDefaultFont", 9)).grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
            next_row = 1
        
        ttk.Label(info_frame, text=f"Rule Group Name:").grid(row=next_row, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(info_frame, text=parsed_data['name'], font=("TkDefaultFont", 9, "bold")).grid(row=next_row, column=1, sticky=tk.W, padx=10, pady=5)
        
        if parsed_data['description']:
            next_row += 1
            ttk.Label(info_frame, text=f"Description:").grid(row=next_row, column=0, sticky=tk.W, padx=10, pady=5)
            desc_label = ttk.Label(info_frame, text=parsed_data['description'], 
                                  font=("TkDefaultFont", 9), wraplength=500)
            desc_label.grid(row=next_row, column=1, sticky=tk.W, padx=10, pady=5)
        
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
        
        ttk.Label(stats_frame,
                 text="✓ Ready to import (will create new file)",
                 font=("TkDefaultFont", 9), foreground="#2E7D32").pack(anchor=tk.W, padx=10, pady=5)
        
        # Metadata comments notice
        ttk.Label(stats_frame,
                 text="Metadata Comments: These metadata details will be preserved\n"
                      "as header comments in the imported file:\n"
                      "  • Rule Group ARN\n"
                      "  • Rule Group Name\n"
                      "  • Rule Group ID\n"
                      "  • Description",
                 font=("TkDefaultFont", 8), foreground="#666666",
                 justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=5)
        
        # Rules preview
        preview_frame = ttk.LabelFrame(main_frame, text="Rules Preview (first 10)")
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
        
        # Variables preview (optional section - only show if variables exist)
        if parsed_data['variables']:
            vars_preview_frame = ttk.LabelFrame(main_frame, text="Variables Preview")
            vars_preview_frame.pack(fill=tk.X, pady=(0, 10))
            
            vars_text = tk.Text(vars_preview_frame, wrap=tk.WORD, font=("Consolas", 9), height=4)
            vars_text.pack(fill=tk.X, padx=5, pady=5)
            
            # Show first 10 variables
            var_items = list(parsed_data['variables'].items())[:10]
            for var_name, var_value in var_items:
                # Truncate long values
                display_value = var_value[:60] + "..." if len(var_value) > 60 else var_value
                vars_text.insert(tk.END, f"{var_name} = {display_value}\n")
            
            if len(parsed_data['variables']) > 10:
                vars_text.insert(tk.END, f"... and {len(parsed_data['variables']) - 10} more variables")
            
            vars_text.config(state=tk.DISABLED)
        
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
