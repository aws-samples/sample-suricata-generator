import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import urllib.request
import urllib.error
import re
from typing import List, Optional, Dict

from suricata_rule import SuricataRule


class ToolTip:
    """Simple tooltip widget that shows on hover"""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)
    
    def show_tooltip(self, event=None):
        if self.tooltip_window or not self.text:
            return
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                        background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                        font=("TkDefaultFont", 8))
        label.pack()
    
    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

def create_tooltip(widget, text):
    """Helper function to create a tooltip for a widget"""
    return ToolTip(widget, text)


class DomainImporter:
    """Domain import functionality for Suricata Rule Generator
    
    Handles bulk domain import, AWS template loading, and domain rule generation.
    """
    
    def __init__(self, parent_app):
        """Initialize with reference to parent application"""
        self.parent = parent_app
    
    def import_domains(self):
        """Import domains from a text file and create bulk rules"""
        filename = filedialog.askopenfilename(
            title="Select Domain List File",
            filetypes=[("Text files", "*.txt"), ("Suricata files", "*.suricata"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f.readlines() if line.strip()]
            
            if not domains:
                messagebox.showwarning("Warning", "No domains found in the file.")
                return
            
            # Show bulk import dialog
            self.show_bulk_import_dialog(domains)
            
        except FileNotFoundError:
            messagebox.showerror("File Not Found", f"Domain file not found: {filename}")
        except PermissionError:
            messagebox.showerror("Permission Error", f"Cannot read domain file: {filename}")
        except UnicodeDecodeError:
            messagebox.showerror("File Encoding Error", f"Cannot read domain file due to encoding issues: {filename}\n\nPlease ensure the file is saved in UTF-8 format.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read domain file: {str(e)}")
    
    def show_bulk_import_dialog(self, domains: List[str]):
        """Show dialog for bulk domain import configuration"""
        # Check current selection state to determine insertion position
        selection = self.parent.tree.selection()
        insert_index = None
        insertion_text = "Rules will be appended to end"
        
        if selection:
            if len(selection) > 1:
                # Multiple selection - show warning and abort
                messagebox.showwarning("Selection Error", 
                    "Please select only one rule to specify insertion position, or clear selection to append to end.")
                return False
            
            # Single selection - check if it's the placeholder
            selected_item = selection[0]
            if selected_item == self.parent.placeholder_item:
                # Placeholder selected - treat as no selection (append to end)
                insert_index = None
                insertion_text = "Rules will be appended to end"
            else:
                # Real rule selected - insert at this position
                insert_index = self.parent.tree.index(selected_item)
                insertion_text = f"Rules will be inserted at line {insert_index + 1}"
        
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Bulk Domain Import")
        dialog.geometry("500x650")  # Increased height for additional features and info labels
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 50, self.parent.root.winfo_rooty() + 50))
        
        result = [False]
        
        # Domain list preview
        ttk.Label(dialog, text=f"Found {len(domains)} domains:").pack(pady=5)
        
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        domain_listbox = tk.Listbox(list_frame, height=8)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=domain_listbox.yview)
        domain_listbox.configure(yscrollcommand=scrollbar.set)
        
        for domain in domains[:20]:  # Show first 20 domains
            domain_listbox.insert(tk.END, domain)
        if len(domains) > 20:
            domain_listbox.insert(tk.END, f"... and {len(domains) - 20} more")
        
        domain_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configuration options
        config_frame = ttk.LabelFrame(dialog, text="Rule Configuration")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Action selection
        ttk.Label(config_frame, text="Action:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        action_var = tk.StringVar(value="pass")
        action_combo = ttk.Combobox(config_frame, textvariable=action_var,
                                   values=["pass", "drop", "reject"], state="readonly")
        action_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Starting SID
        ttk.Label(config_frame, text="Starting SID:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        max_sid = max([rule.sid for rule in self.parent.rules], default=99)
        suggested_sid = max_sid + 1
        sid_var = tk.StringVar(value=str(suggested_sid))
        ttk.Entry(config_frame, textvariable=sid_var, width=10).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Message template
        ttk.Label(config_frame, text="Message Template:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        message_var = tk.StringVar(value="Alert and pass traffic to domain {domain}")
        message_entry = ttk.Entry(config_frame, textvariable=message_var, width=40)
        message_entry.grid(row=2, column=1, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # Alert on pass option (left side)
        alert_on_pass_var = tk.BooleanVar(value=True)
        alert_on_pass_checkbox = ttk.Checkbutton(config_frame, text="Alert on pass", 
                                                 variable=alert_on_pass_var)
        alert_on_pass_checkbox.grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        
        # Strict domain list option (right side)
        strict_domain_var = tk.BooleanVar(value=False)
        strict_domain_checkbox = ttk.Checkbutton(config_frame, text="Strict domain list", 
                                                 variable=strict_domain_var)
        strict_domain_checkbox.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Create tooltips for checkboxes
        create_tooltip(alert_on_pass_checkbox, 
                      "Adds 'alert' keyword to pass rules for logging\n(only applies to 'pass' action)")
        create_tooltip(strict_domain_checkbox, 
                      "Matches only exact domain (no subdomains)\nusing startswith/endswith keywords")
        
        # Rule count preview frame
        preview_frame = ttk.Frame(config_frame)
        preview_frame.grid(row=4, column=0, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # Rule count labels
        standard_count_label = ttk.Label(preview_frame, text="", font=("TkDefaultFont", 8))
        standard_count_label.pack(anchor=tk.W)
        
        consolidation_count_label = ttk.Label(preview_frame, text="", font=("TkDefaultFont", 8), foreground="green")
        consolidation_count_label.pack(anchor=tk.W)
        
        # Info label
        info_label = ttk.Label(config_frame, text="", font=("TkDefaultFont", 8))
        info_label.grid(row=5, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # Insertion position feedback
        position_frame = ttk.LabelFrame(dialog, text="Insertion Position")
        position_frame.pack(fill=tk.X, padx=10, pady=5)
        
        position_label = ttk.Label(position_frame, text=insertion_text, font=("TkDefaultFont", 9, "bold"))
        position_label.pack(pady=5)
        
        # Function to update rule count preview and UI state
        def update_rule_count_preview():
            """Update the rule count preview based on current settings"""
            try:
                action = action_var.get()
                alert_on_pass = alert_on_pass_var.get()
                strict_domain = strict_domain_var.get()
                
                # Update message template based on action and alert settings
                current_message = message_var.get()
                # Only update if it's still a default template (contains {domain})
                if "{domain}" in current_message:
                    if action == "pass":
                        if alert_on_pass:
                            message_var.set("Alert and pass traffic to domain {domain}")
                        else:
                            message_var.set("Pass traffic to domain {domain}")
                    elif action == "drop":
                        message_var.set("Domain drop rule for {domain}")
                    elif action == "reject":
                        message_var.set("Domain reject rule for {domain}")
                    else:
                        message_var.set("Domain rule for {domain}")
                
                # Update checkbox state based on action
                if action == "pass":
                    alert_on_pass_checkbox.config(state="normal")
                else:
                    alert_on_pass_checkbox.config(state="disabled")
                
                # Update info text based on action and alert setting
                if action == "pass":
                    if alert_on_pass:
                        info_text = "For 'pass' action: Creates Pass rules with alert keyword (2 rules per domain)\nFor other actions: Creates single rules (2 rules per domain)"
                        rules_per_domain = 2
                    else:
                        info_text = "For 'pass' action: Creates Alert + Pass rule pairs (4 rules per domain)\nFor other actions: Creates single rules (2 rules per domain)"
                        rules_per_domain = 4
                else:
                    info_text = "For 'pass' action: Creates Pass rules (2 rules per domain)\nFor other actions: Creates single rules (2 rules per domain)"
                    rules_per_domain = 2
                info_label.config(text=info_text)
                
                # Calculate standard rule count (without consolidation)
                standard_total = len(domains) * rules_per_domain
                
                # Check if consolidation will be applied
                if not strict_domain:
                    # Domain consolidation mode (strict mode disabled)
                    consolidation = self.consolidate_domains(domains)
                    consolidated_count = len(consolidation['consolidated_groups'])
                    individual_count = len(consolidation['individual_domains'])
                    total_domains_after = consolidated_count + individual_count
                    total_rules = total_domains_after * rules_per_domain
                    
                    if consolidated_count > 0:
                        # Consolidation is possible
                        consolidated_domain_count = sum(len(g['children']) for g in consolidation['consolidated_groups'])
                        savings = standard_total - total_rules
                        
                        standard_count_label.config(text=f"Standard (no consolidation): {standard_total} rules ({len(domains)} domains × {rules_per_domain} rules each)")
                        
                        # Build smart preview text
                        preview_text = f"With consolidation: {total_rules} rules - Saves {savings} rules!\n"
                        preview_text += f"• {consolidated_count} parent domain(s) cover {consolidated_domain_count} domain(s)\n"
                        preview_text += f"• {individual_count} individual domain(s) (no siblings)"
                        
                        # Show up to 3 consolidation group details
                        if len(consolidation['consolidated_groups']) <= 3:
                            preview_text += "\n\nConsolidation details:"
                            for group in consolidation['consolidated_groups']:
                                children_preview = ', '.join(group['children'][:3])
                                if len(group['children']) > 3:
                                    children_preview += f" (+{len(group['children'])-3} more)"
                                preview_text += f"\n  • {group['parent']} ← {children_preview}"
                        elif len(consolidation['consolidated_groups']) > 3:
                            preview_text += f"\n\n({consolidated_count} consolidation groups - first 3 shown in comment after import)"
                        
                        consolidation_count_label.config(text=preview_text, foreground="green")
                    else:
                        # No consolidation possible
                        standard_count_label.config(text=f"With consolidation: {standard_total} rules ({len(domains)} domains × {rules_per_domain} rules each)")
                        consolidation_count_label.config(text="No consolidation possible - all domains are unique", foreground="gray")
                else:
                    # Strict mode enabled - no consolidation
                    standard_count_label.config(text=f"Strict mode (no consolidation): {standard_total} rules ({len(domains)} domains × {rules_per_domain} rules each)")
                    consolidation_count_label.config(text="")
                    
            except Exception as e:
                # Fallback for any errors during preview calculation
                standard_count_label.config(text=f"Rule count: {len(domains)} domains")
                consolidation_count_label.config(text="")
        
        # Bind events to update preview
        action_combo.bind('<<ComboboxSelected>>', lambda e: update_rule_count_preview())
        alert_on_pass_checkbox.config(command=update_rule_count_preview)
        strict_domain_checkbox.config(command=update_rule_count_preview)
        
        # Initial preview update
        update_rule_count_preview()
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def on_import():
            try:
                start_sid = int(sid_var.get())
                action = action_var.get()
                message_template = message_var.get()
                alert_on_pass = alert_on_pass_var.get()
                strict_domain = strict_domain_var.get()
                
                # Close the import dialog first
                dialog.destroy()
                
                # Create progress dialog
                progress_dialog = tk.Toplevel(self.parent.root)
                progress_dialog.title("Importing Domains")
                progress_dialog.geometry("400x120")
                progress_dialog.transient(self.parent.root)
                progress_dialog.grab_set()
                progress_dialog.resizable(False, False)
                
                # Center the progress dialog
                progress_dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 200, self.parent.root.winfo_rooty() + 200))
                
                # Progress frame
                progress_frame = ttk.Frame(progress_dialog)
                progress_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
                
                # Status label
                status_label = ttk.Label(progress_frame, text=f"Processing {len(domains)} domains...")
                status_label.pack(pady=(0, 10))
                
                # Progress bar
                progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=350)
                progress_bar.pack(pady=(0, 10))
                
                # Progress text label
                progress_text = ttk.Label(progress_frame, text="0%")
                progress_text.pack()
                
                # Force dialog to display
                progress_dialog.update()
                
                # Generate rules for each domain with consolidation
                new_rules = self.generate_domain_rules(domains, action, start_sid, message_template, alert_on_pass, strict_domain,
                                                       progress_bar, progress_text, progress_dialog)
                
                # Close progress dialog
                progress_dialog.destroy()
                
                # Calculate domain SID ranges for history tracking
                domain_details = []
                current_sid = start_sid
                # Calculate rules per domain based on action and alert_on_pass
                if action == "pass" and not alert_on_pass:
                    rules_per_domain = 4  # Alert + Pass for TLS and HTTP
                else:
                    rules_per_domain = 2  # Standard: 2 rules per domain
                
                for domain in domains:
                    end_sid = current_sid + rules_per_domain - 1
                    domain_details.append({'domain': domain, 'start_sid': current_sid, 'end_sid': end_sid})
                    current_sid += rules_per_domain
                
                # Save state for undo
                self.parent.save_undo_state()
                
                # Determine insertion line for history tracking
                history_line = insert_index + 1 if insert_index is not None else len(self.parent.rules) + 1
                
                # Add history entry with detailed domain information
                self.parent.add_history_entry('domain_import', {
                    'count': len(new_rules), 
                    'domains': len(domains), 
                    'action': action,
                    'domain_details': domain_details,
                    'start_sid': start_sid,
                    'end_sid': current_sid - 1,
                    'line': history_line
                })
                
                # Insert rules at determined position
                if insert_index is not None:
                    # Insert at specific position
                    for i, rule in enumerate(new_rules):
                        self.parent.rules.insert(insert_index + i, rule)
                else:
                    # Append to end (original behavior)
                    self.parent.rules.extend(new_rules)
                self.parent.refresh_table()
                self.parent.modified = True
                # Auto-detect variables after domain import
                self.parent.auto_detect_variables()
                self.parent.update_status_bar()
                
                result[0] = True
                dialog.destroy()
                
                messagebox.showinfo("Success", f"Successfully imported {len(new_rules)} rules for {len(domains)} domains.")
                
            except ValueError:
                messagebox.showerror("Input Error", "Starting SID must be a valid number.")
            except OverflowError:
                messagebox.showerror("Input Error", "Starting SID is too large.")
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import domains: {str(e)}")
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Import", command=on_import).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT)
        
        dialog.wait_window()
        return result[0]
    
    def consolidate_domains(self, domains: List[str]) -> Dict:
        """Consolidate domains to their most specific common parent
        
        Analyzes a list of domains and groups them by finding the most specific parent
        that covers the maximum number of related domains. Uses a scoring system to
        prioritize more specific parents over less specific ones.
        
        Args:
            domains: List of domain names to analyze
            
        Returns:
            Dictionary with:
            - 'consolidated_groups': List of dicts with 'parent' and 'children' keys
            - 'individual_domains': List of domains that don't have siblings
            
        Example:
            Input: ['one.two.server.com', 'three.server.com', 'server.com', 'four.server.com']
            Output: {
                'consolidated_groups': [
                    {'parent': 'server.com', 'children': ['one.two.server.com', 'three.server.com', 'server.com', 'four.server.com']}
                ],
                'individual_domains': []
            }
        """
        if not domains:
            return {'consolidated_groups': [], 'individual_domains': []}
        
        # Build parent-child relationships for all domains
        parent_to_all_children = {}
        
        for domain in domains:
            parts = domain.lower().split('.')
            # Consider all possible parents including the domain itself
            # Start from i=0 to include the domain as its own parent (for cases like server.appstate.edu in input)
            # Only consider parents with 2+ parts (skip TLDs like .com, .org)
            for i in range(0, len(parts) - 1):  # -1 to skip TLD-only parents, 0 to include domain itself
                parent = '.'.join(parts[i:])
                # Skip if parent would be just a TLD
                if len(parent.split('.')) < 2:
                    continue
                if parent not in parent_to_all_children:
                    parent_to_all_children[parent] = set()
                parent_to_all_children[parent].add(domain)
        
        # For each set of children, find the MOST specific parent that covers them all
        # Group parents by the exact set of children they cover
        children_set_to_parents = {}
        for parent, children in parent_to_all_children.items():
            # Skip if fewer than 2 children
            if len(children) < 2:
                continue
            
            # If parent is in its own children set AND it's in the input domains,
            # this means the parent domain itself is in the input list
            # We should include it in consolidation (e.g., server.appstate.edu with its subdomains)
            # Don't skip this case - it's valid for consolidation
            
            # Create a frozenset for use as dictionary key
            children_key = frozenset(children)
            
            if children_key not in children_set_to_parents:
                children_set_to_parents[children_key] = []
            children_set_to_parents[children_key].append(parent)
        
        # Filter out subset groups - only keep maximal (largest) groups
        # Sort children sets by size (largest first) to process supersets before subsets
        sorted_children_sets = sorted(children_set_to_parents.items(), 
                                      key=lambda x: len(x[0]), 
                                      reverse=True)
        
        maximal_groups = {}
        for children_set, parent_list in sorted_children_sets:
            # Check if this set is a subset of any larger set we've already kept
            is_subset = False
            for kept_set in maximal_groups.keys():
                if children_set < kept_set:  # children_set is a proper subset of kept_set
                    is_subset = True
                    break
            
            if not is_subset:
                maximal_groups[children_set] = parent_list
        
        # For each maximal group, pick the MOST specific (longest) parent
        consolidated_groups = []
        processed_domains = set()
        
        for children_set, parent_list in maximal_groups.items():
            # Get the most specific parent (the one with most parts)
            most_specific_parent = max(parent_list, key=lambda x: len(x.split('.')))
            
            # Get children that are in the original input and not yet processed
            # Use set to avoid duplicates, then convert to sorted list
            children_in_input = set(c for c in children_set if c in domains and c not in processed_domains)
            
            # If the parent itself is in the input, add it too
            if most_specific_parent in domains and most_specific_parent not in processed_domains:
                children_in_input.add(most_specific_parent)
            
            # Only consolidate if we have 2+ domains to group
            if len(children_in_input) >= 2:
                consolidated_groups.append({
                    'parent': most_specific_parent,
                    'children': sorted(list(children_in_input))
                })
                processed_domains.update(children_in_input)
        
        # Collect individual domains
        individual_domains = [d for d in domains if d not in processed_domains]
        
        return {
            'consolidated_groups': consolidated_groups,
            'individual_domains': sorted(individual_domains)
        }
    
    def generate_domain_rules(self, domains: List[str], action: str, start_sid: int, message_template: str, alert_on_pass: bool = True, strict_domain: bool = False, progress_bar=None, progress_text=None, progress_dialog=None) -> List[SuricataRule]:
        """Generate Suricata rules for a list of domains based on specified action
        
        For 'pass' action: Creates Pass rules with optional alert keyword (2 rules per domain)
        For other actions: Creates single rules (2 rules per domain - TLS and HTTP)
        
        Args:
            domains: List of domain names to create rules for
            action: Rule action (pass, drop, reject, alert)
            start_sid: Starting SID number for rule generation
            message_template: Template string with {domain} placeholder
            alert_on_pass: Whether to add alert keyword to pass rules
            strict_domain: Whether to use strict domain matching (exact match only, no subdomains)
            progress_bar: Optional progress bar widget to update
            progress_text: Optional progress text label to update
            progress_dialog: Optional progress dialog to update
        
        Returns:
            List of SuricataRule objects ready for insertion
        """
        # Apply domain consolidation when strict mode is disabled
        consolidation = None
        if not strict_domain:
            consolidation = self.consolidate_domains(domains)
            # Build list of domains to process (consolidated parents + individuals)
            domains_to_process = [group['parent'] for group in consolidation['consolidated_groups']]
            domains_to_process.extend(consolidation['individual_domains'])
        else:
            # Strict mode: process all domains individually
            domains_to_process = domains
        
        rules = []
        current_sid = start_sid
        total_domains = len(domains_to_process)
        
        # Add consolidation summary comment if consolidation occurred
        if consolidation and len(consolidation['consolidated_groups']) > 0:
            summary_rule = SuricataRule()
            summary_rule.is_comment = True
            consolidated_count = sum(len(g['children']) for g in consolidation['consolidated_groups'])
            summary_rule.comment_text = f"# Domain consolidation: {len(domains)} domains consolidated to {len(domains_to_process)} rules ({consolidated_count} consolidated, {len(consolidation['individual_domains'])} individual)"
            rules.append(summary_rule)
        
        for idx, domain in enumerate(domains_to_process):
            # Update progress bar if provided
            if progress_bar is not None and progress_text is not None and progress_dialog is not None:
                progress = (idx / total_domains) * 100
                progress_bar['value'] = progress
                progress_text.config(text=f"{int(progress)}% ({idx}/{total_domains} domains)")
                progress_dialog.update()
            
            domain_rules = []
            
            if action == "pass":
                # Pass action with optional alert keyword to log and allow traffic
                
                if alert_on_pass:
                    # Generate TLS message from template
                    domain_display = domain if strict_domain else f"*.{domain}"
                    if message_template == "Alert and pass traffic to domain {domain}":
                        # Default template - use default message
                        pass_tls_message = f"Alert and pass TLS traffic to domain {domain_display}"
                    else:
                        # Custom template - inject TLS into the message
                        pass_tls_message = message_template.replace("{domain}", domain_display).replace("traffic", "TLS traffic")
                    
                    if strict_domain:
                        pass_tls_content = f'flow:to_server; tls.sni; content:"{domain}"; startswith; endswith; nocase; alert'
                    else:
                        pass_tls_content = f'flow:to_server; tls.sni; dotprefix; content:".{domain}"; endswith; nocase; alert'
                    
                    pass_tls_rule = SuricataRule(
                        action="pass",
                        protocol="tls",
                        src_net="$HOME_NET",
                        src_port="any",
                        dst_net="any",
                        dst_port="any",
                        message=pass_tls_message,
                        content=pass_tls_content,
                        sid=current_sid
                    )
                    domain_rules.append(pass_tls_rule)
                    current_sid += 1
                    
                    # Generate HTTP message from template
                    domain_display = domain if strict_domain else f"*.{domain}"
                    if message_template == "Alert and pass traffic to domain {domain}":
                        # Default template - use default message
                        pass_http_message = f"Alert and pass HTTP traffic to domain {domain_display}"
                    else:
                        # Custom template - inject HTTP into the message
                        pass_http_message = message_template.replace("{domain}", domain_display).replace("traffic", "HTTP traffic")
                    
                    if strict_domain:
                        pass_http_content = f'flow:to_server; http.host; content:"{domain}"; startswith; endswith; nocase; alert'
                    else:
                        pass_http_content = f'flow:to_server; http.host; dotprefix; content:".{domain}"; endswith; nocase; alert'
                    
                    pass_http_rule = SuricataRule(
                        action="pass",
                        protocol="http",
                        src_net="$HOME_NET",
                        src_port="any",
                        dst_net="any",
                        dst_port="any",
                        message=pass_http_message,
                        content=pass_http_content,
                        sid=current_sid
                    )
                    domain_rules.append(pass_http_rule)
                    current_sid += 1
                    
                else:
                    # Create separate alert and pass rules
                    domain_display = domain if strict_domain else f"*.{domain}"
                    
                    # Alert TLS rule
                    if message_template == "Pass traffic to domain {domain}":
                        alert_tls_message = f"Alert for TLS traffic to domain {domain_display}"
                    else:
                        alert_tls_message = message_template.replace("{domain}", domain_display).replace("traffic", "TLS traffic").replace("Pass", "Alert for")
                    
                    if strict_domain:
                        alert_tls_content = f'flow:to_server; tls.sni; content:"{domain}"; startswith; endswith; nocase'
                    else:
                        alert_tls_content = f'flow:to_server; tls.sni; dotprefix; content:".{domain}"; endswith; nocase'
                    
                    alert_tls_rule = SuricataRule(
                        action="alert",
                        protocol="tls",
                        src_net="$HOME_NET",
                        src_port="any",
                        dst_net="any",
                        dst_port="any",
                        message=alert_tls_message,
                        content=alert_tls_content,
                        sid=current_sid
                    )
                    domain_rules.append(alert_tls_rule)
                    current_sid += 1
                    
                    # Pass TLS rule
                    if message_template == "Pass traffic to domain {domain}":
                        pass_tls_message = f"Pass TLS traffic to domain {domain_display}"
                    else:
                        pass_tls_message = message_template.replace("{domain}", domain_display).replace("traffic", "TLS traffic")
                    
                    if strict_domain:
                        pass_tls_content = f'flow:to_server; tls.sni; content:"{domain}"; startswith; endswith; nocase'
                    else:
                        pass_tls_content = f'flow:to_server; tls.sni; dotprefix; content:".{domain}"; endswith; nocase'
                    
                    pass_tls_rule = SuricataRule(
                        action="pass",
                        protocol="tls",
                        src_net="$HOME_NET",
                        src_port="any",
                        dst_net="any",
                        dst_port="any",
                        message=pass_tls_message,
                        content=pass_tls_content,
                        sid=current_sid
                    )
                    domain_rules.append(pass_tls_rule)
                    current_sid += 1
                    
                    # Alert HTTP rule
                    if message_template == "Pass traffic to domain {domain}":
                        alert_http_message = f"Alert for HTTP traffic to domain {domain_display}"
                    else:
                        alert_http_message = message_template.replace("{domain}", domain_display).replace("traffic", "HTTP traffic").replace("Pass", "Alert for")
                    
                    if strict_domain:
                        alert_http_content = f'flow:to_server; http.host; content:"{domain}"; startswith; endswith; nocase'
                    else:
                        alert_http_content = f'flow:to_server; http.host; dotprefix; content:".{domain}"; endswith; nocase'
                    
                    alert_http_rule = SuricataRule(
                        action="alert",
                        protocol="http",
                        src_net="$HOME_NET",
                        src_port="any",
                        dst_net="any",
                        dst_port="any",
                        message=alert_http_message,
                        content=alert_http_content,
                        sid=current_sid
                    )
                    domain_rules.append(alert_http_rule)
                    current_sid += 1
                    
                    # Pass HTTP rule
                    if message_template == "Pass traffic to domain {domain}":
                        pass_http_message = f"Pass HTTP traffic to domain {domain_display}"
                    else:
                        pass_http_message = message_template.replace("{domain}", domain_display).replace("traffic", "HTTP traffic")
                    
                    if strict_domain:
                        pass_http_content = f'flow:to_server; http.host; content:"{domain}"; startswith; endswith; nocase'
                    else:
                        pass_http_content = f'flow:to_server; http.host; dotprefix; content:".{domain}"; endswith; nocase'
                    
                    pass_http_rule = SuricataRule(
                        action="pass",
                        protocol="http",
                        src_net="$HOME_NET",
                        src_port="any",
                        dst_net="any",
                        dst_port="any",
                        message=pass_http_message,
                        content=pass_http_content,
                        sid=current_sid
                    )
                    domain_rules.append(pass_http_rule)
                    current_sid += 1
                
            else:
                # Generate single rules for TLS and HTTP (drop/reject/alert)
                
                # TLS rule - check if using default or custom template
                domain_display = domain if strict_domain else f"*.{domain}"
                if action == "drop" and message_template == "Domain drop rule for {domain}":
                    tls_message = f"Domain drop rule for {domain_display}"
                elif action == "reject" and message_template == "Domain reject rule for {domain}":
                    tls_message = f"Domain reject rule for {domain_display}"
                else:
                    # Use custom template or non-drop/reject action
                    tls_message = message_template.replace("{domain}", domain_display)
                
                if strict_domain:
                    tls_content = f'flow:to_server; tls.sni; content:"{domain}"; startswith; endswith; nocase'
                else:
                    tls_content = f'flow:to_server; tls.sni; dotprefix; content:".{domain}"; endswith; nocase'
                tls_rule = SuricataRule(
                    action=action,
                    protocol="tls",
                    src_net="$HOME_NET",
                    src_port="any",
                    dst_net="any",
                    dst_port="any",
                    message=tls_message,
                    content=tls_content,
                    sid=current_sid
                )
                domain_rules.append(tls_rule)
                current_sid += 1
                
                # HTTP rule - check if using default or custom template
                domain_display = domain if strict_domain else f"*.{domain}"
                if action == "drop" and message_template == "Domain drop rule for {domain}":
                    http_message = f"Domain drop rule for {domain_display}"
                elif action == "reject" and message_template == "Domain reject rule for {domain}":
                    http_message = f"Domain reject rule for {domain_display}"
                else:
                    # Use custom template or non-drop/reject action
                    http_message = message_template.replace("{domain}", domain_display)
                
                if strict_domain:
                    http_content = f'flow:to_server; http.host; content:"{domain}"; startswith; endswith; nocase'
                else:
                    http_content = f'flow:to_server; http.host; dotprefix; content:".{domain}"; endswith; nocase'
                http_rule = SuricataRule(
                    action=action,
                    protocol="http",
                    src_net="$HOME_NET",
                    src_port="any",
                    dst_net="any",
                    dst_port="any",
                    message=http_message,
                    content=http_content,
                    sid=current_sid
                )
                domain_rules.append(http_rule)
                current_sid += 1
            
            rules.extend(domain_rules)
        
        # Update progress to 100% when done
        if progress_bar is not None and progress_text is not None and progress_dialog is not None:
            progress_bar['value'] = 100
            progress_text.config(text=f"100% (Complete)")
            progress_dialog.update()
        
        return rules
    
    def load_aws_template(self):
        """Load AWS best practices Suricata rules template from website"""
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
        
        try:
            # Show loading message
            loading_dialog = tk.Toplevel(self.parent.root)
            loading_dialog.title("Loading")
            loading_dialog.geometry("300x100")
            loading_dialog.transient(self.parent.root)
            loading_dialog.grab_set()
            loading_dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 200, self.parent.root.winfo_rooty() + 200))
            
            ttk.Label(loading_dialog, text="Fetching AWS best practices rules...").pack(pady=30)
            loading_dialog.update()
            
            # Load AWS template using FileManager
            self.parent.rules, self.parent.variables = self.parent.file_manager.load_aws_template()
            
            loading_dialog.destroy()
            
            # Disable change tracking for new content operations
            self.parent.tracking_enabled = False
            self.parent.tracking_menu_var.set(False)
            
            # Update UI without preserving selection to enable click-to-insert
            self.parent.refresh_table(preserve_selection=False)
            self.parent.current_file = None
            self.parent.modified = True  # Mark as modified since template was loaded
            self.parent.selected_rule_index = None
            self.parent.has_header = False  # AWS templates don't get headers
            self.parent.created_timestamp = None
            self.parent.auto_detect_variables()
            self.parent.root.title("Suricata Rule Generator - AWS Best Practices Template")
            
            # Set up rule editor for new rule insertion
            self.parent.ui_manager.show_rule_editor()
            self.parent.set_default_editor_values()
            
            messagebox.showinfo("Success", f"Successfully loaded {len(self.parent.rules)} rules from AWS best practices template.")
            
        except urllib.error.HTTPError as e:
            if 'loading_dialog' in locals():
                loading_dialog.destroy()
            messagebox.showerror("HTTP Error", f"Failed to fetch AWS template (HTTP {e.code}): {str(e)}")
        except urllib.error.URLError as e:
            if 'loading_dialog' in locals():
                loading_dialog.destroy()
            messagebox.showerror("Network Error", f"Failed to fetch AWS template: {str(e)}")
        except Exception as e:
            if 'loading_dialog' in locals():
                loading_dialog.destroy()
            messagebox.showerror("Template Error", f"Failed to load AWS template: {str(e)}")
    
    def insert_domain_rule(self):
        """Insert domain rules at selected position"""
        selection = self.parent.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a position to insert the domain rules.")
            return
        
        # Get the index of selected item
        selected_item = selection[0]
        insert_index = self.parent.tree.index(selected_item)
        
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Insert Domain Rule")
        dialog.geometry("450x320")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.parent.root.winfo_rootx() + 50, self.parent.root.winfo_rooty() + 50))
        
        result = [False]
        domain_var = tk.StringVar()
        message_var = tk.StringVar(value="Domain allow rule for {domain}")
        alert_on_pass_var = tk.BooleanVar(value=True)
        strict_domain_var = tk.BooleanVar(value=False)
        
        # Domain input
        ttk.Label(dialog, text="Domain:").pack(pady=5)
        domain_entry = ttk.Entry(dialog, textvariable=domain_var, width=40)
        domain_entry.pack(pady=5)
        domain_entry.focus()
        
        # Message template
        ttk.Label(dialog, text="Message Template:").pack(pady=(10, 5))
        ttk.Entry(dialog, textvariable=message_var, width=40).pack(pady=5)
        
        # Checkboxes frame (for side-by-side layout)
        checkboxes_frame = ttk.Frame(dialog)
        checkboxes_frame.pack(pady=5)
        
        # Alert on pass option (left side)
        alert_on_pass_checkbox = ttk.Checkbutton(checkboxes_frame, text="Alert on pass", 
                                                 variable=alert_on_pass_var)
        alert_on_pass_checkbox.pack(side=tk.LEFT, padx=10)
        
        # Strict domain list option (right side)
        strict_domain_checkbox = ttk.Checkbutton(checkboxes_frame, text="Strict domain list", 
                                                 variable=strict_domain_var)
        strict_domain_checkbox.pack(side=tk.LEFT, padx=10)
        
        # Create tooltips for checkboxes
        create_tooltip(alert_on_pass_checkbox, 
                      "Adds 'alert' keyword to pass rules for logging")
        create_tooltip(strict_domain_checkbox, 
                      "Matches only exact domain (no subdomains)\nusing startswith/endswith keywords")
        
        # Info label
        def update_info_text():
            domain = domain_var.get().strip()
            domain_display = domain if domain else "example.com"
            strict = strict_domain_var.get()
            
            # Determine domain matching behavior
            if strict:
                domain_match = f"(exact match only: {domain_display})"
            else:
                domain_match = f"(allows *.{domain_display})"
            
            if alert_on_pass_var.get():
                info_text = f"This will create 2 rules: Pass TLS (with alert) → Pass HTTP (with alert)\n{domain_match}"
            else:
                info_text = f"This will create 4 rules: Alert TLS → Pass TLS → Alert HTTP → Pass HTTP\n{domain_match}"
            info_label.config(text=info_text)
        
        info_label = ttk.Label(dialog, text="", font=("TkDefaultFont", 8))
        info_label.pack(pady=10)
        
        # Bind checkboxes to update info text
        alert_on_pass_checkbox.config(command=update_info_text)
        strict_domain_checkbox.config(command=update_info_text)
        domain_entry.bind('<KeyRelease>', lambda e: update_info_text())
        update_info_text()  # Set initial text
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def on_insert():
            domain = domain_var.get().strip()
            if not domain:
                messagebox.showerror("Error", "Please enter a domain name.")
                return
            
            # Get next available SID
            max_sid = max([rule.sid for rule in self.parent.rules], default=99)
            start_sid = max_sid + 1
            
            # Generate domain rules
            alert_on_pass = alert_on_pass_var.get()
            strict_domain = strict_domain_var.get()
            new_rules = self.generate_domain_rules([domain], "pass", start_sid, message_var.get(), alert_on_pass, strict_domain)
            
            # Save state for undo
            self.parent.save_undo_state()
            
            # Insert rules at selected position
            for i, rule in enumerate(new_rules):
                self.parent.rules.insert(insert_index + i, rule)
            
            self.parent.refresh_table()
            self.parent.modified = True
            # Auto-detect variables after domain rule insertion
            self.parent.auto_detect_variables()
            self.parent.update_status_bar()
            
            result[0] = True
            dialog.destroy()
            
            # Calculate correct rule count based on alert_on_pass setting
            rule_count = len(new_rules)
            messagebox.showinfo("Success", f"Successfully inserted {rule_count} rules for domain '{domain}' at line {insert_index + 1}.")
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Insert", command=on_insert).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT)
        
        # Bind Enter key to insert
        dialog.bind('<Return>', lambda e: on_insert())
        
        dialog.wait_window()
        return result[0]
