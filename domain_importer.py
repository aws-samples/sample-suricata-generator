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
        
        # PCRE Optimization option
        pcre_var = tk.BooleanVar(value=False)
        pcre_checkbox = ttk.Checkbutton(config_frame, text="Use PCRE optimization to reduce rule count", 
                                       variable=pcre_var)
        pcre_checkbox.grid(row=3, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # PCRE info label
        pcre_info_text = "Analyzes domains for patterns and groups similar domains into PCRE rules when possible"
        pcre_info_label = ttk.Label(config_frame, text=pcre_info_text, font=("TkDefaultFont", 8), foreground="blue")
        pcre_info_label.grid(row=4, column=0, columnspan=3, sticky=tk.W, padx=20, pady=(0, 5))
        
        # Alert on pass option (left side)
        alert_on_pass_var = tk.BooleanVar(value=True)
        alert_on_pass_checkbox = ttk.Checkbutton(config_frame, text="Alert on pass", 
                                                 variable=alert_on_pass_var)
        alert_on_pass_checkbox.grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
        
        # Strict domain list option (right side)
        strict_domain_var = tk.BooleanVar(value=False)
        strict_domain_checkbox = ttk.Checkbutton(config_frame, text="Strict domain list", 
                                                 variable=strict_domain_var)
        strict_domain_checkbox.grid(row=5, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Create tooltips for checkboxes
        create_tooltip(alert_on_pass_checkbox, 
                      "Adds 'alert' keyword to pass rules for logging\n(only applies to 'pass' action)")
        create_tooltip(strict_domain_checkbox, 
                      "Matches only exact domain (no subdomains)\nusing startswith/endswith keywords")
        
        # Rule count preview frame (now at row 6, right after checkboxes)
        preview_frame = ttk.Frame(config_frame)
        preview_frame.grid(row=6, column=0, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # Rule count labels
        standard_count_label = ttk.Label(preview_frame, text="", font=("TkDefaultFont", 8))
        standard_count_label.pack(anchor=tk.W)
        
        pcre_count_label = ttk.Label(preview_frame, text="", font=("TkDefaultFont", 8), foreground="green")
        pcre_count_label.pack(anchor=tk.W)
        
        # Info label
        info_label = ttk.Label(config_frame, text="", font=("TkDefaultFont", 8))
        info_label.grid(row=7, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
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
                use_pcre = pcre_var.get()
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
                
                # Update checkbox state based on action and PCRE
                if action == "pass":
                    alert_on_pass_checkbox.config(state="normal")
                else:
                    alert_on_pass_checkbox.config(state="disabled")
                
                # Disable strict domain when PCRE is enabled
                if use_pcre:
                    strict_domain_checkbox.config(state="disabled")
                else:
                    strict_domain_checkbox.config(state="normal")
                
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
                
                # Check if consolidation or PCRE optimization will be applied
                if use_pcre:
                    # PCRE optimization mode
                    standard_count_label.config(text=f"Standard approach: {standard_total} rules ({len(domains)} domains × {rules_per_domain} rules each)")
                    
                    # Analyze domains for PCRE optimization
                    pcre_analysis = self.analyze_domains_for_pcre(domains)
                    optimized_domain_groups = pcre_analysis['optimized_groups']
                    individual_domains = pcre_analysis['individual_domains']
                    
                    # Calculate optimized rule count
                    pcre_group_rules = len(optimized_domain_groups) * rules_per_domain
                    individual_rules = len(individual_domains) * rules_per_domain
                    pcre_total = pcre_group_rules + individual_rules
                    
                    # Show optimization results
                    if pcre_total < standard_total:
                        savings = standard_total - pcre_total
                        pcre_count_label.config(
                            text=f"PCRE optimized: {pcre_total} rules ({len(optimized_domain_groups)} PCRE groups + {len(individual_domains)} individual) - Saves {savings} rules!",
                            foreground="green"
                        )
                    else:
                        pcre_count_label.config(
                            text=f"PCRE analysis: No optimization possible with current domains (would still create {pcre_total} rules)",
                            foreground="orange"
                        )
                elif not strict_domain:
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
                        
                        pcre_count_label.config(text=preview_text, foreground="green")
                    else:
                        # No consolidation possible
                        standard_count_label.config(text=f"With consolidation: {standard_total} rules ({len(domains)} domains × {rules_per_domain} rules each)")
                        pcre_count_label.config(text="No consolidation possible - all domains are unique", foreground="gray")
                else:
                    # Strict mode enabled - no consolidation
                    standard_count_label.config(text=f"Strict mode (no consolidation): {standard_total} rules ({len(domains)} domains × {rules_per_domain} rules each)")
                    pcre_count_label.config(text="")
                    
            except Exception as e:
                # Fallback for any errors during preview calculation
                standard_count_label.config(text=f"Rule count: {len(domains)} domains")
                pcre_count_label.config(text="")
        
        # Bind events to update preview
        action_combo.bind('<<ComboboxSelected>>', lambda e: update_rule_count_preview())
        pcre_checkbox.config(command=update_rule_count_preview)
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
                use_pcre = pcre_var.get()
                alert_on_pass = alert_on_pass_var.get()
                strict_domain = strict_domain_var.get() and not use_pcre  # Disable strict if PCRE is enabled
                
                # Generate rules for each domain (with optional PCRE optimization)
                if use_pcre:
                    new_rules = self.generate_domain_rules_with_pcre(domains, action, start_sid, message_template, alert_on_pass)
                else:
                    new_rules = self.generate_domain_rules(domains, action, start_sid, message_template, alert_on_pass, strict_domain)
                
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
        
        Analyzes a list of domains and groups them by their longest common suffix.
        Only consolidates when 2 or more domains share a common parent.
        
        Args:
            domains: List of domain names to analyze
            
        Returns:
            Dictionary with:
            - 'consolidated_groups': List of dicts with 'parent' and 'children' keys
            - 'individual_domains': List of domains that don't have siblings
            
        Example:
            Input: ['windows.microsoft.com', 'office.microsoft.com', 'google.com']
            Output: {
                'consolidated_groups': [
                    {'parent': 'microsoft.com', 'children': ['windows.microsoft.com', 'office.microsoft.com']}
                ],
                'individual_domains': ['google.com']
            }
        """
        if not domains:
            return {'consolidated_groups': [], 'individual_domains': []}
        
        # Build parent-child relationships for all domains
        parent_to_all_children = {}
        
        for domain in domains:
            parts = domain.lower().split('.')
            # Only consider parents with 2+ parts (skip TLDs like .com, .org)
            for i in range(1, len(parts) - 1):  # -1 to skip TLD-only parents
                parent = '.'.join(parts[i:])
                if parent not in parent_to_all_children:
                    parent_to_all_children[parent] = set()
                parent_to_all_children[parent].add(domain)
        
        # Find the LEAST specific (shortest) parent that covers 2+ domains
        # This ensures we consolidate to microsoft.com rather than prod.do.dsp.mp.microsoft.com
        consolidated_groups = []
        processed_domains = set()
        
        # Sort by number of parts (ascending) - LEAST specific first
        sorted_parents = sorted(parent_to_all_children.keys(),
                               key=lambda x: len(x.split('.')),
                               reverse=False)
        
        for parent in sorted_parents:
            all_children = parent_to_all_children[parent]
            # Get unprocessed children
            available_children = [c for c in all_children if c not in processed_domains]
            
            # Need at least 2 domains to consolidate
            if len(available_children) >= 2:
                # Don't consolidate if the parent itself is in the child list
                # In that case, wait for a less specific parent
                if parent in available_children:
                    continue
                
                # Check if any children are also in the input domain list
                # If so, include the parent domain too
                children_in_input = [c for c in available_children if c in domains]
                if parent in domains:
                    children_in_input.append(parent)
                
                # Only consolidate if we have 2+ domains to group
                if len(children_in_input) >= 2:
                    consolidated_groups.append({
                        'parent': parent,
                        'children': sorted(children_in_input)
                    })
                    processed_domains.update(children_in_input)
        
        # Collect individual domains
        individual_domains = [d for d in domains if d not in processed_domains]
        
        return {
            'consolidated_groups': consolidated_groups,
            'individual_domains': sorted(individual_domains)
        }
    
    def generate_domain_rules(self, domains: List[str], action: str, start_sid: int, message_template: str, alert_on_pass: bool = True, strict_domain: bool = False) -> List[SuricataRule]:
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
        # Add consolidation summary comment if consolidation occurred
        if consolidation and len(consolidation['consolidated_groups']) > 0:
            summary_rule = SuricataRule()
            summary_rule.is_comment = True
            consolidated_count = sum(len(g['children']) for g in consolidation['consolidated_groups'])
            summary_rule.comment_text = f"# Domain consolidation: {len(domains)} domains consolidated to {len(domains_to_process)} rules ({consolidated_count} consolidated, {len(consolidation['individual_domains'])} individual)"
            rules.append(summary_rule)
        
        for domain in domains_to_process:
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
        
        return rules
    
    def analyze_domains_for_pcre(self, domains):
        """Analyze domains for PCRE optimization opportunities
        
        Returns a dictionary with:
        - optimized_groups: List of domain groups that can be optimized with PCRE
        - individual_domains: List of domains that don't fit into groups
        """
        domain_groups = {}
        tld_groups = {}
        individual_domains = []
        
        # First pass: Group domains by root domain (subdomains of same domain)
        for domain in domains:
            domain_parts = domain.lower().split('.')
            if len(domain_parts) >= 2:
                root_domain = '.'.join(domain_parts[-2:])  # Get last two parts (domain.tld)
                
                if root_domain not in domain_groups:
                    domain_groups[root_domain] = []
                domain_groups[root_domain].append(domain)
            else:
                individual_domains.append(domain)
        
        # Second pass: Group domains by domain name with different TLDs
        domain_name_groups = {}
        remaining_domains = []
        
        for root_domain, group_domains in domain_groups.items():
            if len(group_domains) > 1:
                # Multiple subdomains - already optimizable, keep as is
                remaining_domains.extend(group_domains)
            else:
                # Single domain - check for TLD variations
                domain_parts = root_domain.split('.')
                if len(domain_parts) == 2:
                    domain_name = domain_parts[0]  # e.g., "microsoft" from "microsoft.com"
                    tld = domain_parts[1]  # e.g., "com" from "microsoft.com"
                    
                    if domain_name not in domain_name_groups:
                        domain_name_groups[domain_name] = {}
                        domain_name_groups[domain_name]['domains'] = []
                        domain_name_groups[domain_name]['tlds'] = []
                    
                    domain_name_groups[domain_name]['domains'].extend(group_domains)
                    domain_name_groups[domain_name]['tlds'].append(tld)
                else:
                    remaining_domains.extend(group_domains)
        
        optimized_groups = []
        
        # Process subdomain groups (existing logic)
        for root_domain, group_domains in domain_groups.items():
            if len(group_domains) > 1:
                optimized_groups.append({
                    'pattern': f'.*\\.{re.escape(root_domain)}',
                    'domains': group_domains,
                    'description': f"Subdomain group for *.{root_domain} ({len(group_domains)} domains)",
                    'type': 'subdomain'
                })
        
        # Process TLD variation groups (new logic)
        for domain_name, group_info in domain_name_groups.items():
            if len(group_info['tlds']) > 1:
                # Multiple TLDs for same domain name - can optimize with PCRE
                tlds = sorted(set(group_info['tlds']))  # Remove duplicates and sort
                tld_pattern = '|'.join(re.escape(tld) for tld in tlds)
                pattern = f'{re.escape(domain_name)}\\.({tld_pattern})'
                
                optimized_groups.append({
                    'pattern': pattern,
                    'domains': group_info['domains'],
                    'description': f"TLD group for {domain_name}.({','.join(tlds)}) ({len(group_info['domains'])} domains)",
                    'type': 'tld_variation'
                })
            else:
                # Single TLD - no optimization benefit
                individual_domains.extend(group_info['domains'])
        
        return {
            'optimized_groups': optimized_groups,
            'individual_domains': individual_domains
        }
    
    def generate_domain_rules_with_pcre(self, domains, action, start_sid, message_template, alert_on_pass=True):
        """Generate domain rules with PCRE optimization
        
        This method analyzes the domain list and creates PCRE-based rules where beneficial,
        falling back to individual domain rules where PCRE doesn't provide optimization.
        
        Each PCRE group still requires the same rule structure:
        - Pass action: 2 rules per group (Pass TLS + Pass HTTP, with optional alert keyword)
        - Other actions: 2 rules per group (TLS rule + HTTP rule)
        """
        # Analyze domains for PCRE opportunities
        pcre_analysis = self.analyze_domains_for_pcre(domains)
        optimized_groups = pcre_analysis['optimized_groups']
        individual_domains = pcre_analysis['individual_domains']
        
        rules = []
        current_sid = start_sid
        
        # Generate PCRE rules for optimized groups
        for group in optimized_groups:
            pattern = group['pattern']
            group_domains = group['domains']
            group_description = group['description']
            
            # Add comment describing the PCRE group
            comment_rule = SuricataRule()
            comment_rule.is_comment = True
            comment_rule.comment_text = f"# PCRE optimized {group_description}: {', '.join(group_domains)}"
            rules.append(comment_rule)
            
            # Generate PCRE rules for this group
            pcre_rules = self.generate_pcre_group_rules(pattern, group_domains, action, current_sid, message_template, alert_on_pass)
            rules.extend(pcre_rules)
            
            # Update SID counter (2 rules for all actions)
            rules_per_group = 2
            current_sid += rules_per_group
        
        # Generate individual rules for domains that don't benefit from PCRE
        if individual_domains:
            if optimized_groups:
                # Add separator comment if we have both PCRE groups and individual domains
                separator_rule = SuricataRule()
                separator_rule.is_comment = True
                separator_rule.comment_text = f"# Individual domain rules (no PCRE optimization available)"
                rules.append(separator_rule)
            
            individual_rules = self.generate_domain_rules(individual_domains, action, current_sid, message_template, alert_on_pass)
            rules.extend(individual_rules)
        
        return rules
    
    def generate_pcre_group_rules(self, pattern, group_domains, action, start_sid, message_template, alert_on_pass=True):
        """Generate PCRE-based rules for a group of domains
        
        Args:
            pattern: PCRE pattern to match (e.g., '.*\\.google\\.com')
            group_domains: List of domains this pattern covers
            action: Rule action (pass, drop, reject, alert)
            start_sid: Starting SID for this group
            message_template: Message template
            alert_on_pass: Whether to add alert keyword to pass rules
            
        Returns:
            List of SuricataRule objects using PCRE matching
        """
        rules = []
        current_sid = start_sid
        
        # Create descriptive group name for messages
        if len(group_domains) > 1:
            # Extract root domain from pattern for cleaner messages
            # Convert pattern like '.*\\.google\\.com' back to 'google.com'
            root_domain = pattern.replace('.*\\.', '').replace('\\', '')
            group_name = f"*.{root_domain}"
            domain_list = ', '.join(group_domains)
        else:
            group_name = group_domains[0]
            domain_list = group_domains[0]
        
        if action == "pass":
            # Pass action with optional alert keyword to log and allow traffic
            
            # Pass TLS rule with PCRE and optional alert keyword
            if alert_on_pass:
                pass_tls_message = f"Alert and pass TLS traffic to domain group {group_name}"
                pass_tls_content = f'flow:to_server; tls.sni; pcre:"/{pattern}/i"; alert'
            else:
                pass_tls_message = f"Pass TLS traffic to domain group {group_name}"
                pass_tls_content = f'flow:to_server; tls.sni; pcre:"/{pattern}/i"'
            
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
            rules.append(pass_tls_rule)
            current_sid += 1
            
            # Pass HTTP rule with PCRE and optional alert keyword
            if alert_on_pass:
                pass_http_message = f"Alert and pass HTTP traffic to domain group {group_name}"
                pass_http_content = f'flow:to_server; http.host; pcre:"/{pattern}/i"; alert'
            else:
                pass_http_message = f"Pass HTTP traffic to domain group {group_name}"
                pass_http_content = f'flow:to_server; http.host; pcre:"/{pattern}/i"'
            
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
            rules.append(pass_http_rule)
            current_sid += 1
            
        else:
            # Generate PCRE rules for TLS and HTTP (drop/reject/alert)
            
            # TLS rule with PCRE
            if action == "drop":
                tls_message = f"Domain drop rule for {group_name}"
            elif action == "reject":
                tls_message = f"Domain reject rule for {group_name}"
            else:
                tls_message = message_template.replace("{domain}", group_name)
            
            tls_content = f'flow:to_server; tls.sni; pcre:"/{pattern}/i"'
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
            rules.append(tls_rule)
            current_sid += 1
            
            # HTTP rule with PCRE
            if action == "drop":
                http_message = f"Domain drop rule for {group_name}"
            elif action == "reject":
                http_message = f"Domain reject rule for {group_name}"
            else:
                http_message = message_template.replace("{domain}", group_name)
            
            http_content = f'flow:to_server; http.host; pcre:"/{pattern}/i"'
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
            rules.append(http_rule)
            current_sid += 1
        
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
