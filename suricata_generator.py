import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import re
import os
import ipaddress
from typing import List, Dict, Optional, Tuple
import urllib.request
import urllib.error

from suricata_rule import SuricataRule
from rule_analyzer import RuleAnalyzer
from file_manager import FileManager
from domain_importer import DomainImporter
from stateful_rule_importer import StatefulRuleImporter
from search_manager import SearchManager
from ui_manager import UIManager
from flow_tester import FlowTester
from rule_filter import RuleFilter
from template_manager import TemplateManager
from constants import SuricataConstants
from version import get_main_version
from security_validator import security_validator, validate_rule_input, validate_file_operation

class SuricataRuleGenerator:
    """Main application class for the Suricata Rule Generator GUI"""
    def __init__(self):
        # Initialize main window
        self.root = tk.Tk()
        self.root.title("Suricata Rule Generator for AWS Network Firewall")
        self.root.geometry("1220x900")
        
        # Application state variables
        self.rules: List[SuricataRule] = []  # List of all rules
        self.current_file = None  # Currently opened file path
        self.modified = False  # Track if changes need saving
        self.selected_rule_index = None  # Index of currently selected rule
        self.undo_state = None  # Previous state for undo functionality
        self.placeholder_item = None  # Placeholder row for new rule insertion
        self.variables = {}  # Dictionary to store network variables
        self.clipboard = []  # Clipboard for copy/paste functionality
        self.has_header = False  # Whether file has our header
        self.created_timestamp = None  # Original creation timestamp
        self.tracking_enabled = False  # Whether change tracking is enabled
        self.pending_history = []  # Pending history entries to write on save
        self.config_file = self.get_safe_config_path()  # User config file
        self.rule_analyzer = RuleAnalyzer()  # Rule analysis engine
        self.file_manager = FileManager()  # File operations manager
        self.domain_importer = DomainImporter(self)  # Domain import functionality
        self.stateful_rule_importer = StatefulRuleImporter(self)  # Stateful rule group import functionality
        self.search_manager = SearchManager(self)  # Search functionality manager
        self.ui_manager = UIManager(self)  # UI components manager
        self.rule_filter = RuleFilter()  # Rule filtering manager
        self.template_manager = TemplateManager()  # Template management for rule generation
        
        # Load user configuration
        self.load_config()
        
        # Build the user interface
        self.ui_manager.setup_ui()
        
        
        # Always start with blank canvas - don't auto-load default rules or create headers
        self.refresh_table()
        self.ui_manager.show_rule_editor()
        self.set_default_editor_values()
        self.add_placeholder_row()  # Show placeholder by default
    
    def auto_detect_variables(self):
        """Auto-detect variables from current rules and populate Variables tab
        
        Scans all rules for network variables (starting with $ or @) and adds them
        to the variables dictionary with sensible defaults. HOME_NET gets RFC1918
        private address space by default. $EXTERNAL_NET is ignored as it's implicitly
        defined by AWS Network Firewall as the inverse of $HOME_NET.
        
        Also removes variables that are no longer used in any rules.
        """
        detected_vars = set()
        
        # PHASE 1: Scan all rules to detect which variables are actually being used
        # This ensures we only create/maintain variables that are referenced in the ruleset
        for rule in self.rules:
            # Skip non-rule lines (comments and blank lines don't have network/port fields)
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            
            # Check network fields for variable references ($HOME_NET, @ALLOW_LIST, etc.)
            if rule.src_net.startswith(('$', '@')):
                detected_vars.add(rule.src_net)
            if rule.dst_net.startswith(('$', '@')):
                detected_vars.add(rule.dst_net)
            
            # Check port fields for variable references ($WEB_PORTS, etc.)
            # Note: @ variables not allowed for ports per AWS Network Firewall requirements
            if rule.src_port.startswith(('$', '@')):
                detected_vars.add(rule.src_port)
            if rule.dst_port.startswith(('$', '@')):
                detected_vars.add(rule.dst_port)
        
        # Keep $EXTERNAL_NET in detected_vars if it's used, so we can define it properly
        # detected_vars.discard('$EXTERNAL_NET')  # Don't discard - we'll handle it below
        
        # PHASE 2: Clean up unused variables (but preserve variables with definitions)
        # Remove variables that are:
        # 1. Not used in any rules AND
        # 2. Have no definition (empty or whitespace only)
        # Keep variables that have definitions even if not currently used (user may add them soon)
        # Always keep $EXTERNAL_NET and $HOME_NET (core variables)
        current_vars = list(self.variables.keys())  # Copy keys since we're modifying dict
        for var in current_vars:
            if var not in detected_vars and var not in ['$EXTERNAL_NET', '$HOME_NET']:
                # Extract definition (handle both new dict format and legacy string format)
                var_def = self.variables[var].get("definition", "") if isinstance(self.variables[var], dict) else self.variables[var]
                if not var_def.strip():
                    # Variable is unused and has no definition - safe to remove
                    del self.variables[var]
                # If variable has a definition, keep it even if not currently used in rules
        
        # PHASE 3: Create new variables with sensible defaults
        # For each detected variable that doesn't exist yet, create it with appropriate defaults
        for var in detected_vars:
            if var not in self.variables:
                if var == '$HOME_NET':
                    # Default to RFC1918 private address space
                    # AWS Network Firewall requires brackets for multiple CIDRs
                    self.variables[var] = {
                        "definition": "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]",
                        "description": ""
                    }
                elif var == '$EXTERNAL_NET':
                    # Will be auto-defined in Phase 4 based on $HOME_NET
                    # This ensures $EXTERNAL_NET is always the inverse of $HOME_NET
                    pass
                else:
                    # Unknown variable - create with empty definition for user to fill in
                    self.variables[var] = {
                        "definition": "",
                        "description": ""
                    }
        
        # PHASE 4: Auto-define $EXTERNAL_NET as the inverse of $HOME_NET
        # AWS Network Firewall best practice: $EXTERNAL_NET should be the negation of $HOME_NET
        # This prevents policy conflicts where rules for $HOME_NET and $EXTERNAL_NET overlap
        # Example: If $HOME_NET=[10.0.0.0/8,172.16.0.0/12], then $EXTERNAL_NET=[!10.0.0.0/8,!172.16.0.0/12]
        if '$HOME_NET' in self.variables:
            # Extract $HOME_NET definition (handle both new dict format and legacy string format)
            home_net_data = self.variables['$HOME_NET']
            if isinstance(home_net_data, dict):
                home_net_def = home_net_data.get("definition", "")
            else:
                home_net_def = home_net_data
            
            if home_net_def.strip():
                # Generate $EXTERNAL_NET as negation of $HOME_NET using helper method
                external_net_def = self._negate_cidr_list(home_net_def)
                self.variables['$EXTERNAL_NET'] = {
                    "definition": external_net_def,
                    "description": "Auto-defined as negation of $HOME_NET"
                }
        
        # Refresh variables table display
        self.refresh_variables_table()
    
    def _negate_cidr_list(self, cidr_list: str) -> str:
        """Negate a CIDR list to create the inverse definition
        
        Converts $HOME_NET CIDRs to their negation for $EXTERNAL_NET.
        Examples:
        - "10.0.0.0/8" -> "!10.0.0.0/8"
        - "[10.0.0.0/8,172.16.0.0/12]" -> "[!10.0.0.0/8,!172.16.0.0/12]"
        
        Args:
            cidr_list: CIDR specification string
            
        Returns:
            Negated CIDR specification string
        """
        cidr_list = cidr_list.strip()
        
        # Handle bracketed lists
        if cidr_list.startswith('[') and cidr_list.endswith(']'):
            # Extract inner content
            inner_content = cidr_list[1:-1]
            # Split by comma and negate each CIDR
            cidrs = [cidr.strip() for cidr in inner_content.split(',')]
            negated_cidrs = []
            for cidr in cidrs:
                if cidr and not cidr.startswith('!'):
                    negated_cidrs.append(f'!{cidr}')
                else:
                    # Already negated or empty, keep as is
                    negated_cidrs.append(cidr)
            return f"[{','.join(negated_cidrs)}]"
        else:
            # Single CIDR - just prepend with !
            if not cidr_list.startswith('!'):
                return f'!{cidr_list}'
            else:
                return cidr_list
    
    def refresh_variables_table(self):
        """Refresh the variables table display"""
        # Clear existing items
        for item in self.variables_tree.get_children():
            self.variables_tree.delete(item)
        
        # Configure grey tag for $EXTERNAL_NET
        self.variables_tree.tag_configure("external_net", foreground="#808080")
        
        # Analyze variable usage to determine correct types
        variable_usage = self.file_manager.analyze_variable_usage(self.rules)
        
        # Add variables to table with usage-based type detection
        for var, var_data in sorted(self.variables.items()):
            var_type = self.file_manager.get_variable_type_from_usage(var, variable_usage)
            
            # Extract definition and description from new dict format (with backward compatibility)
            if isinstance(var_data, dict):
                definition = var_data.get("definition", "")
                description = var_data.get("description", "")
            else:
                # Legacy format: string value (backward compatibility)
                definition = var_data
                description = ""
            
            # If variable has a definition but shows as "IP Set", check if it's actually a port definition
            if var_type == "IP Set" and definition and var.startswith('$'):
                # Try to infer if this is actually a port set by checking the definition format
                if self.ui_manager._looks_like_port_definition(definition):
                    var_type = "Port Set"
            
            if var == '$EXTERNAL_NET':
                # Show actual definition if auto-generated, otherwise show as managed by AWS
                if definition.strip():
                    # We have an auto-generated definition - show it with grey formatting
                    item = self.variables_tree.insert("", tk.END, values=(var, var_type, definition, description), tags=("external_net",))
                else:
                    # No definition - show as managed by AWS
                    display_definition = "(auto-defined by AWS Network Firewall)"
                    auto_description = "Automatically managed by AWS"
                    item = self.variables_tree.insert("", tk.END, values=(var, var_type, display_definition, auto_description), tags=("external_net",))
            else:
                item = self.variables_tree.insert("", tk.END, values=(var, var_type, definition, description))
    
    def get_variable_type(self, var_name):
        """Determine variable type based on usage context"""
        # Use the file manager's sophisticated type detection
        variable_usage = self.file_manager.analyze_variable_usage(self.rules)
        return self.file_manager.get_variable_type_from_usage(var_name, variable_usage)
    
    
    def validate_cidr_list(self, cidr_list):
        """Validate CIDR list with bracket requirement for multiple values
        
        AWS Network Firewall requires brackets for multiple CIDR blocks.
        Accepts formats like: 
        - Single CIDR: 192.168.1.0/24
        - Multiple CIDRs: [192.168.1.0/24,192.168.2.0/24]
        - With negation: [192.168.1.0/24,!172.16.0.0/12]
        
        Args:
            cidr_list: CIDR specification string
        
        Returns:
            bool: True if format and CIDR blocks are valid
        """
        if not cidr_list.strip():
            return True  # Empty is valid
        
        cidr_spec = cidr_list.strip()
        
        # Check if contains comma (multiple values)
        if ',' in cidr_spec:
            # Multiple values MUST be enclosed in brackets
            if not (cidr_spec.startswith('[') and cidr_spec.endswith(']')):
                return False  # Multiple CIDRs require brackets
            # Remove brackets and validate contents
            inner_content = cidr_spec[1:-1].strip()
            cidrs = [cidr.strip() for cidr in inner_content.split(',')]
        elif cidr_spec.startswith('[') and cidr_spec.endswith(']'):
            # Bracketed single value is also valid
            inner_content = cidr_spec[1:-1].strip()
            cidrs = [inner_content]
        else:
            # Single CIDR without brackets
            cidrs = [cidr_spec]
        
        # Validate each CIDR block
        for cidr in cidrs:
            if not cidr:
                return False  # Empty CIDR not valid
            if cidr.startswith('!'):
                cidr = cidr[1:]  # Remove negation for validation
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                return False
        return True
    
    def validate_port_list(self, port_list):
        """Validate comma-separated port list with support for ranges and negation
        
        Suricata requires port ranges and complex port specifications to be enclosed in brackets.
        Accepts formats like: 80, [443,8080:8090], [80:100,!85], any, $WEB_PORTS
        
        Args:
            port_list: Port specification string
        
        Returns:
            bool: True if all port specifications are valid
        """
        if not port_list.strip():
            return True  # Empty is valid
        
        port_spec = port_list.strip()
        
        # Handle 'any' keyword
        if port_spec.lower() == 'any':
            return True  # 'any' is always valid
        
        # Handle port variables starting with $ (only $ variables allowed for ports)
        if port_spec.startswith('$'):
            # Check for double prefix ($$) which is invalid
            if port_spec.startswith('$$'):
                return False
            # Valid variable format: $ followed by alphanumeric/underscore characters
            if len(port_spec) > 1 and port_spec[1:].replace('_', '').isalnum():
                return True
            else:
                return False
        
        # Reject @ variables for ports (AWS Network Firewall requirement)
        if port_spec.startswith('@'):
            return False  # @REFERENCE variables not allowed for ports
        
        # Check if this is a bracketed specification
        if port_spec.startswith('[') and port_spec.endswith(']'):
            # Remove brackets and validate the contents
            inner_content = port_spec[1:-1].strip()
            return self._validate_bracketed_port_content(inner_content)
        
        # Check if this is a single port number (allowed without brackets)
        try:
            port_num = int(port_spec)
            return 1 <= port_num <= 65535
        except ValueError:
            pass
        
        # Check if this contains range operators or commas (requires brackets)
        if ':' in port_spec or ',' in port_spec or '!' in port_spec:
            return False  # Ranges and complex specs require brackets
        
        # If we get here, it's an invalid specification
        return False
    
    def _validate_bracketed_port_content(self, content):
        """Validate the content inside port brackets
        
        Args:
            content: The content inside the brackets
            
        Returns:
            bool: True if the bracketed content is valid
        """
        if not content.strip():
            return False  # Empty brackets not valid
        
        # Split by commas to handle multiple port specs
        port_specs = [spec.strip() for spec in content.split(',')]
        
        for spec in port_specs:
            if not spec:
                continue  # Skip empty specs
            
            # Handle negation
            if spec.startswith('!'):
                spec = spec[1:].strip()
                if not spec:
                    return False  # Empty negation not valid
                
                # Check if negated spec is 'any'
                if spec.lower() == 'any':
                    continue  # !any is valid
                
                # Check if negated spec is a variable (only $ allowed)
                if spec.startswith('$'):
                    # Validate variable format
                    if spec.startswith('$$'):
                        return False  # Double $$ prefix invalid
                    if len(spec) > 1 and spec[1:].replace('_', '').isalnum():
                        continue  # !$VARIABLE is valid
                    else:
                        return False  # Invalid variable format
                if spec.startswith('@'):
                    return False  # !@VARIABLE not allowed for ports
            
            # Handle 'any' keyword
            if spec.lower() == 'any':
                continue
            
            # Handle variables (only $ allowed)
            if spec.startswith('$'):
                # Validate variable format
                if spec.startswith('$$'):
                    return False  # Double $$ prefix invalid
                if len(spec) > 1 and spec[1:].replace('_', '').isalnum():
                    continue  # $VARIABLE is valid
                else:
                    return False  # Invalid variable format
            if spec.startswith('@'):
                return False  # @ variables not allowed for ports
            
            # Handle port ranges (e.g., 8080:8090)
            if ':' in spec:
                try:
                    start, end = spec.split(':', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                        return False
                except ValueError:
                    return False
            else:
                # Single port validation
                try:
                    port_num = int(spec)
                    if not (1 <= port_num <= 65535):
                        return False
                except ValueError:
                    return False
        
        return True
    
    
    
    def calculate_rule_statistics(self, actual_rules=None):
        """Calculate comprehensive rule statistics for colored status bar display
        
        Analyzes all rules to provide real-time statistics including:
        - Action counts (pass, drop, reject, alert) for colored labels
        - SID range (min/max) for capacity planning
        - Undefined variables count for configuration warnings
        - Protocol distribution for rule composition analysis
        - Unique reference sets count for IP Set References tracking
        
        Args:
            actual_rules: Pre-filtered list of actual rules (optional)
        
        Returns:
            dict: Comprehensive statistics dictionary with nested categories
        """
        stats = {
            'actions': {'pass': 0, 'drop': 0, 'reject': 0, 'alert': 0},
            'protocols': {'dcerpc': 0, 'dhcp': 0, 'dns': 0, 'ftp': 0, 'http': 0, 'http2': 0, 'icmp': 0, 'ikev2': 0, 'imap': 0, 'ip': 0, 'krb5': 0, 'msn': 0, 'ntp': 0, 'quic': 0, 'smb': 0, 'smtp': 0, 'ssh': 0, 'tcp': 0, 'tftp': 0, 'tls': 0, 'udp': 0, 'other': 0},
            'sid_range': {'min': None, 'max': None},
            'undefined_vars': 0,
            'reference_sets': 0
        }
        stats = {
            'actions': {'pass': 0, 'drop': 0, 'reject': 0, 'alert': 0},
            'protocols': {protocol: 0 for protocol in SuricataConstants.SUPPORTED_PROTOCOLS},
            'sid_range': {'min': None, 'max': None},
            'undefined_vars': 0,
            'reference_sets': 0
        }
        stats['protocols']['other'] = 0  # Add 'other' category for unsupported protocols
        
        sids = []
        used_vars = set()
        
        # Use provided actual_rules or filter if not provided
        rules_to_analyze = actual_rules if actual_rules is not None else [r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        for rule in rules_to_analyze:
                # Action counts
                action = rule.action.lower()
                if action in stats['actions']:
                    stats['actions'][action] += 1
                
                # Protocol counts
                protocol = rule.protocol.lower()
                if protocol in stats['protocols']:
                    stats['protocols'][protocol] += 1
                else:
                    stats['protocols']['other'] += 1
                
                # SID tracking
                sids.append(rule.sid)
                
                # Variable usage
                if rule.src_net.startswith(('$', '@')):
                    used_vars.add(rule.src_net)
                if rule.dst_net.startswith(('$', '@')):
                    used_vars.add(rule.dst_net)
                if rule.src_port.startswith(('$', '@')):
                    used_vars.add(rule.src_port)
                if rule.dst_port.startswith(('$', '@')):
                    used_vars.add(rule.dst_port)
        
        # Calculate SID range
        if sids:
            stats['sid_range']['min'] = min(sids)
            stats['sid_range']['max'] = max(sids)
        
        # Count undefined variables (exclude $EXTERNAL_NET as it's implicitly defined by AWS Network Firewall)
        undefined_vars = []
        for var in used_vars:
            if var not in self.variables:
                undefined_vars.append(var)
            else:
                # Handle both old string format and new dict format for backward compatibility
                var_data = self.variables[var]
                if isinstance(var_data, dict):
                    var_def = var_data.get("definition", "")
                else:
                    var_def = var_data
                if not var_def.strip():
                    undefined_vars.append(var)
        undefined_vars = [var for var in undefined_vars if var != '$EXTERNAL_NET']
        stats['undefined_vars'] = len(undefined_vars)
        
        # Count unique reference sets (variables starting with @)
        reference_sets = [var for var in used_vars if var.startswith('@')]
        stats['reference_sets'] = len(reference_sets)
        
        return stats
    
    def update_status_bar(self, displayed_count=None):
        """Update status bar with capacity, colored action counts, and warnings
        
        Displays comprehensive status information including:
        - Rule capacity count for AWS Network Firewall planning
        - Colored action count labels (green/red/purple/blue) OR filter info if filters active
        - SID range information for uniqueness tracking
        - Undefined variables warnings in orange
        - Search status when active
        - File modification status
        - Filter status when filters are active
        
        Args:
            displayed_count: Number of rules displayed (for filter info), None if no filtering
        """
        # Cache filtered rules to avoid repeated filtering
        actual_rules = [r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        capacity = len(actual_rules)
        
        # Get rule action statistics using cached rules
        stats = self.calculate_rule_statistics(actual_rules)
        
        # Update main status text (capacity and file status)
        status_text = f"Capacity: {capacity}"
        
        # Add file status
        if self.modified:
            status_text += " | Modified"
        elif self.current_file:
            status_text += " | Ready"
        else:
            status_text += " | New"
        
        # Add tracking status if relevant
        if self.tracking_enabled:
            status_text += " | Tracking: ON"
        
        # Add search status if active
        search_status = self.search_manager.get_search_status()
        if search_status:
            status_text += f" | {search_status}"
        
        self.status_label.config(text=status_text)
        
        # Update additional info labels
        if capacity > 0:
            # SID range info
            if stats['sid_range']['min'] and stats['sid_range']['max']:
                self.sid_label.config(text=f" | SIDs: {stats['sid_range']['min']}-{stats['sid_range']['max']}")
                self.sid_label.pack(side=tk.LEFT, pady=2)
            else:
                self.sid_label.pack_forget()
            
            # Undefined variables warning
            if stats['undefined_vars'] > 0:
                self.vars_label.config(text=f" | {stats['undefined_vars']} undefined vars")
                self.vars_label.pack(side=tk.LEFT, pady=2)
            else:
                self.vars_label.pack_forget()
        else:
            self.sid_label.pack_forget()
            self.vars_label.pack_forget()
        
        # Check if filters are active and handle status bar display accordingly
        filters_active = self.rule_filter.is_active()
        
        if filters_active and displayed_count is not None:
            # Filters are active - show filter information
            # Hide action count labels (they'll be replaced by filter info)
            self.pass_label.pack_forget()
            self.drop_label.pack_forget()
            self.reject_label.pack_forget()
            self.alert_label.pack_forget()
            
            # Show filter status label with count and description
            total_rules = len(self.rules)
            filter_desc = self.rule_filter.get_filter_description()
            
            # Create filter status text
            filter_text = f" | Showing {displayed_count} of {total_rules} rules"
            if filter_desc:
                filter_text += f" | Filters: {filter_desc}"
            
            # Use filter_label (will be created in ui_manager) with same color as SID label
            if hasattr(self, 'filter_label'):
                self.filter_label.config(text=filter_text)
                self.filter_label.pack(side=tk.LEFT, pady=2)
        else:
            # No filters active - show normal action count labels
            if hasattr(self, 'filter_label'):
                self.filter_label.pack_forget()
            
            # Update colored action count labels
            if capacity > 0:
                actions = stats['actions']
                # Show colored labels with counts
                if actions['pass'] > 0:
                    self.pass_label.config(text=f" | Pass: {actions['pass']}")
                    self.pass_label.pack(side=tk.LEFT, pady=2)
                else:
                    self.pass_label.pack_forget()
                
                if actions['drop'] > 0:
                    self.drop_label.config(text=f" | Drop: {actions['drop']}")
                    self.drop_label.pack(side=tk.LEFT, pady=2)
                else:
                    self.drop_label.pack_forget()
                
                if actions['reject'] > 0:
                    self.reject_label.config(text=f" | Reject: {actions['reject']}")
                    self.reject_label.pack(side=tk.LEFT, pady=2)
                else:
                    self.reject_label.pack_forget()
                
                if actions['alert'] > 0:
                    self.alert_label.config(text=f" | Alert: {actions['alert']}")
                    self.alert_label.pack(side=tk.LEFT, pady=2)
                else:
                    self.alert_label.pack_forget()
            else:
                # Hide all colored labels when no rules
                self.pass_label.pack_forget()
                self.drop_label.pack_forget()
                self.reject_label.pack_forget()
                self.alert_label.pack_forget()
        
        # Update IP Set References count label (always show as requested)
        reference_count = stats['reference_sets']
        self.refs_label.config(text=f" | IP Set References: {reference_count}/5")
        self.refs_label.pack(side=tk.LEFT, pady=2)
    
    def get_safe_config_path(self):
        """Get safe config file path with validation"""
        import tempfile
        try:
            home_dir = os.path.expanduser("~")
            if os.path.isdir(home_dir) and os.access(home_dir, os.W_OK):
                return os.path.join(home_dir, ".suricata_generator_config.json")
        except (OSError, ValueError):
            pass
        return os.path.join(tempfile.gettempdir(), "suricata_generator_config.json")
    
    def load_config(self):
        """Load user configuration from file"""
        # Always start with tracking disabled
        self.tracking_enabled = False
    
    def save_config(self):
        """Save user configuration to file"""
        try:
            import json
            config = {
                'tracking_enabled': self.tracking_enabled
            }
            # Ensure config directory exists
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
        except PermissionError:
            pass  # Cannot write to config directory - continue without saving
        except OSError:
            pass  # File system error - continue without saving
        except (TypeError, ValueError):
            pass  # Other errors - continue without saving
    
    def toggle_tracking(self):
        """Toggle change tracking on/off"""
        self.tracking_enabled = self.tracking_menu_var.get()
        self.save_config()
        
        # If enabling tracking, add header
        if self.tracking_enabled and not self.has_header:
            self.rules = self.file_manager.create_header(self.rules)
            self.has_header = True
            self.refresh_table()
            self.modified = True
        
        # Update status bar to show tracking state
        self.update_status_bar()
        
        # Show confirmation message
        status = "enabled" if self.tracking_enabled else "disabled"
        messagebox.showinfo("Change Tracking", f"Change tracking has been {status}.")
    
    def check_and_enable_existing_tracking(self):
        """Check for existing history file and auto-enable tracking if found"""
        if not self.current_file:
            return
            
        history_filename = self.current_file.replace('.suricata', '.history')
        if not history_filename.endswith('.history'):
            history_filename += '.history'
            
        if os.path.exists(history_filename):
            try:
                # Enable change tracking
                self.tracking_enabled = True
                self.tracking_menu_var.set(True)
                
                # Update status bar to show tracking state
                self.update_status_bar()
                
                # Refresh history display if tab exists
                if hasattr(self, 'history_text'):
                    self.ui_manager.refresh_history_display()
                    
            except (OSError, IOError, json.JSONDecodeError):
                # If there's an error, just continue without tracking
                pass
    
    def add_history_entry(self, action, details=None, count=None):
        """Add entry to pending history (only if tracking enabled)"""
        if not self.tracking_enabled:
            return
        
        import datetime
        
        # Count current rules for before/after tracking
        rule_count = len([r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)])
        
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'version': self.get_version_number(),
            'action': action,
            'rule_count_before': rule_count
        }
        
        if details:
            entry['details'] = details
        if count is not None:
            entry['count'] = count
        
        self.pending_history.append(entry)
    

    
    def load_rules_from_file(self, filename: str):
        """Load rules from a .suricata file and companion .var file if it exists"""
        try:
            if not os.path.exists(filename):
                raise FileNotFoundError(f"File not found: {filename}")
            
            if not os.access(filename, os.R_OK):
                raise PermissionError(f"Cannot read file: {filename}")
            
            self.rules, self.variables, self.has_header, self.created_timestamp = self.file_manager.load_rules_from_file(filename)
            self.refresh_table()
            self.auto_detect_variables()
            
        except FileNotFoundError as e:
            messagebox.showerror("File Not Found", str(e))
        except PermissionError as e:
            messagebox.showerror("Permission Error", str(e))
        except UnicodeDecodeError as e:
            messagebox.showerror("File Encoding Error", f"Cannot read file due to encoding issues: {filename}\n\nPlease ensure the file is saved in UTF-8 format.")
        except Exception as e:
            messagebox.showerror("Error Loading File", f"Failed to load rules from {filename}:\n\n{str(e)}")
    

    def refresh_table(self, preserve_selection=True):
        """Refresh the rules table display with current rule data
        
        Rebuilds the entire table with color coding and proper formatting.
        Handles comments, blank lines, and regular rules with appropriate styling.
        Applies active filters to hide non-matching rules.
        
        Args:
            preserve_selection: Whether to restore selection after refresh
        """
        # Clear search results when table is refreshed
        self.search_manager.close_search()
        
        # Preserve current selection to restore after refresh (only if requested)
        selection = self.tree.selection()
        selected_index = None
        if selection and preserve_selection:
            selected_index = self.tree.index(selection[0])
        
        # Clear all existing table items including any placeholder
        self.tree.delete(*self.tree.get_children())
        self.placeholder_item = None
        
        # Track displayed count for filter status
        displayed_count = 0
        
        # Populate table with current rules (apply filtering)
        for i, rule in enumerate(self.rules):
            line_num = i + 1
            
            # Apply filter - skip rules that don't match
            if not self.rule_filter.matches(rule):
                continue
            
            displayed_count += 1
            
            # Handle different rule types with appropriate display
            # IMPORTANT: Always provide 5 values to match column structure (even when SIG Type hidden)
            if getattr(rule, 'is_blank', False):
                # Blank line - show line number only, all other columns empty
                values = (line_num, "", "", "", "")
                tag = ""
            elif getattr(rule, 'is_comment', False):
                # Comment line - show in first few columns, comment text in last column
                values = (line_num, "", "COMMENT", "", rule.comment_text)
                tag = "comment"
            else:
                # Regular Suricata rule - Line, SigType, Action, Protocol, and combined Rule Data
                if rule.original_options:
                    # Use original options to maintain exact formatting
                    options_str = f"({rule.original_options};)" if not rule.original_options.endswith(';') else f"({rule.original_options})"
                else:
                    # Fallback: reconstruct options if original not available
                    options_parts = []
                    if rule.message:
                        options_parts.append(f'msg:"{rule.message}"')
                    if rule.content:
                        options_parts.append(rule.content)
                    options_parts.append(f'sid:{rule.sid}')
                    options_parts.append(f'rev:{rule.rev}')
                    options_str = f"({'; '.join(options_parts)};)" if options_parts else ""
                
                # Format combined rule data: source src_port direction destination dst_port (options)
                rule_data = f"{rule.src_net} {rule.src_port} {rule.direction} {rule.dst_net} {rule.dst_port} {options_str}"
                
                # Calculate SIG type for this rule (if classification available)
                sig_type_label = ""
                if hasattr(self, 'show_sigtype_var') and self.show_sigtype_var.get():
                    detailed_type = self.rule_analyzer.get_detailed_suricata_rule_type(rule)
                    sig_type_label = self.rule_analyzer.get_display_label_for_type(detailed_type)
                
                # Always use 5-column format to match table structure
                values = (
                    line_num,
                    sig_type_label,
                    rule.action,
                    rule.protocol,
                    rule_data
                )
                # Apply color coding based on action type
                tag = f"action_{rule.action}" if rule.action in ["pass", "alert", "drop", "reject"] else ""
            
            # Insert row into table with appropriate styling
            item = self.tree.insert("", tk.END, values=values, tags=(tag,))
            
            # Restore selection if this was the previously selected item and preservation is enabled
            if selected_index is not None and i == selected_index and preserve_selection:
                self.tree.selection_set(item)
        
        # Force UI update to ensure changes are visible
        self.root.update()
        self.root.update_idletasks()
        
        # Update status bar after table refresh (pass displayed_count for filter info)
        self.update_status_bar(displayed_count=displayed_count)
    
    def move_rule_up(self):
        """Move selected rule up by one position"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to move.")
            return
        
        # Get ACTUAL line number from tree (critical when filters active)
        selected_item = selection[0]
        values = self.tree.item(selected_item, 'values')
        if values and values[0]:
            rule_index = int(values[0]) - 1  # Convert 1-based to 0-based
        else:
            messagebox.showerror("Error", "Could not determine rule position.")
            return
        
        # Bounds check
        if rule_index < 0 or rule_index >= len(self.rules):
            messagebox.showerror("Error", f"Invalid rule position: {rule_index + 1}")
            return
        
        if rule_index == 0:
            messagebox.showinfo("Info", "Rule is already at the top.")
            return
        
        # Save state for undo
        self.save_undo_state()
        
        # Add history entry
        self.add_history_entry('rule_moved', {'direction': 'up', 'from_line': rule_index + 1, 'to_line': rule_index})
        
        # Swap rules
        self.rules[rule_index], self.rules[rule_index - 1] = self.rules[rule_index - 1], self.rules[rule_index]
        self.refresh_table()
        
        # Reselect the moved rule
        items = self.tree.get_children()
        if rule_index - 1 < len(items):
            self.tree.selection_set(items[rule_index - 1])
        
        self.modified = True
        self.update_status_bar()
    
    def move_rule_down(self):
        """Move selected rule down by one position"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to move.")
            return
        
        # Get ACTUAL line number from tree (critical when filters active)
        selected_item = selection[0]
        values = self.tree.item(selected_item, 'values')
        if values and values[0]:
            rule_index = int(values[0]) - 1  # Convert 1-based to 0-based
        else:
            messagebox.showerror("Error", "Could not determine rule position.")
            return
        
        if rule_index >= len(self.rules) - 1:
            messagebox.showinfo("Info", "Rule is already at the bottom.")
            return
        
        # Save state for undo
        self.save_undo_state()
        
        # Add history entry
        self.add_history_entry('rule_moved', {'direction': 'down', 'from_line': rule_index + 1, 'to_line': rule_index + 2})
        
        # Swap rules
        self.rules[rule_index], self.rules[rule_index + 1] = self.rules[rule_index + 1], self.rules[rule_index]
        self.refresh_table()
        
        # Reselect the moved rule
        items = self.tree.get_children()
        if rule_index + 1 < len(items):
            self.tree.selection_set(items[rule_index + 1])
        
        self.modified = True
        self.update_status_bar()
    
    def get_next_available_sid(self, start_sid: int = 100) -> int:
        """Get the next available SID in the range 100-999999999"""
        used_sids = {rule.sid for rule in self.rules}
        
        for sid in range(start_sid, 1000000000):
            if sid not in used_sids:
                return sid
        
        # If no SID available in range, return the start_sid (will trigger validation error)
        return start_sid
    
    def validate_unique_sid(self, sid: int, exclude_index: int = -1) -> bool:
        """Check if SID is unique (excluding the rule at exclude_index)"""
        for i, rule in enumerate(self.rules):
            # Skip comment and blank rules as they don't have meaningful SIDs
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            if i != exclude_index and rule.sid == sid:
                return False
        return True
    
    def validate_total_rule_length(self, rule: SuricataRule) -> bool:
        """Validate total rule length including expanded variables (AWS limit: 8,192 chars)
        
        AWS Network Firewall has a hard limit of 8,192 characters per Suricata rule,
        INCLUDING the expanded variable values. This validation expands all variables
        and checks the total length.
        
        Args:
            rule: SuricataRule object to validate
            
        Returns:
            bool: True if rule length is valid, False otherwise
        """
        # Get rule string
        rule_string = rule.to_string()
        
        # Expand all variables to their actual values
        for var_name, var_data in self.variables.items():
            if isinstance(var_data, dict):
                definition = var_data.get("definition", "")
            else:
                definition = var_data
            
            # Replace variable with its definition
            if definition:
                rule_string = rule_string.replace(var_name, definition)
        
        # Check total length
        total_length = len(rule_string)
        
        if total_length > 8192:
            messagebox.showerror(
                "AWS Network Firewall Quota Violation",
                f"Rule length exceeds AWS Network Firewall limit!\n\n"
                f"Total length (with variables expanded): {total_length} characters\n"
                f"AWS limit: 8,192 characters\n\n"
                f"Please reduce the rule length by:\n"
                f"• Shortening the message text\n"
                f"• Reducing content keywords\n"
                f"• Simplifying variable definitions\n"
                f"• Using shorter variable names"
            )
            return False
        
        # Warn if approaching limit (within 500 characters)
        if total_length > 7692:
            messagebox.showwarning(
                "Rule Length Warning",
                f"Rule length is approaching AWS Network Firewall limit!\n\n"
                f"Current length: {total_length} characters\n"
                f"AWS limit: 8,192 characters\n"
                f"Remaining: {8192 - total_length} characters\n\n"
                f"Consider reducing rule complexity to stay within limits."
            )
        
        return True
    
    def validate_ip_set_references(self, new_rule: Optional[SuricataRule] = None, 
                                   exclude_index: int = -1) -> bool:
        """Validate total IP Set References don't exceed 5 (AWS limit)
        
        AWS Network Firewall allows maximum 5 IP Set References (@ variables)
        per rule group. This validation counts existing references and checks
        if adding/modifying a rule would exceed this limit.
        
        Args:
            new_rule: Optional new rule being added/modified
            exclude_index: Index of rule being modified (to exclude from count)
            
        Returns:
            bool: True if IP Set Reference count is valid, False otherwise
        """
        # Collect all IP Set References (@ variables) from current rules
        reference_sets = set()
        
        for i, rule in enumerate(self.rules):
            # Skip comment and blank rules
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            
            # Skip the rule being modified
            if i == exclude_index:
                continue
            
            # Check source network
            if rule.src_net.startswith('@'):
                reference_sets.add(rule.src_net)
            
            # Check destination network
            if rule.dst_net.startswith('@'):
                reference_sets.add(rule.dst_net)
        
        # If we're adding/modifying a rule, include its references
        if new_rule:
            if new_rule.src_net.startswith('@'):
                reference_sets.add(new_rule.src_net)
            if new_rule.dst_net.startswith('@'):
                reference_sets.add(new_rule.dst_net)
        
        # Check if we exceed the limit
        total_references = len(reference_sets)
        
        if total_references > 5:
            # Build list of references for error message
            ref_list = '\n'.join([f"  • {ref}" for ref in sorted(reference_sets)])
            
            messagebox.showerror(
                "AWS Network Firewall Quota Violation",
                f"IP Set References exceed AWS Network Firewall limit!\n\n"
                f"Total IP Set References: {total_references}\n"
                f"AWS limit: 5 per rule group\n\n"
                f"Current references:\n{ref_list}\n\n"
                f"To fix this issue:\n"
                f"• Consolidate multiple IP sets into fewer sets\n"
                f"• Use $ variables instead of @ references where possible\n"
                f"• Remove unused IP Set References from rules"
            )
            return False
        
        # Warn if at limit (5 references)
        if total_references == 5:
            ref_list = '\n'.join([f"  • {ref}" for ref in sorted(reference_sets)])
            messagebox.showwarning(
                "IP Set Reference Limit Reached",
                f"You have reached the AWS Network Firewall limit!\n\n"
                f"Total IP Set References: 5 (at maximum)\n\n"
                f"Current references:\n{ref_list}\n\n"
                f"Cannot add more IP Set References (@) without\n"
                f"removing or consolidating existing ones."
            )
        
        return True
    
    def validate_network_field(self, value: str, field_name: str) -> bool:
        """Validate network field (source/dest network) with full Suricata CIDR range support"""
        value = value.strip()
        
        # Allow 'any'
        if value.lower() == 'any':
            return True
        
        # Validate simple variables using the helper that checks for proper format
        if (value.startswith('$') or value.startswith('@')) and not value.startswith(('$[', '@[')) and '[' not in value:
            # Use the validation helper to ensure proper variable format (no $$, @@, etc.)
            return self._validate_single_network_item(value, field_name, show_error=True)
        
        # Check if it's a bracketed group expression
        if value.startswith('[') and value.endswith(']'):
            return self._validate_network_group(value[1:-1], field_name)
        
        # Check if it's a negated expression
        if value.startswith('!'):
            negated_value = value[1:].strip()
            if negated_value.startswith('[') and negated_value.endswith(']'):
                # Negated group: ![1.1.1.1, 1.1.1.2]
                return self._validate_network_group(negated_value[1:-1], field_name)
            else:
                # Simple negation: !192.168.1.0/24 or !$HOME_NET
                return self._validate_single_network_item(negated_value, field_name)
        
        # Check if it's a simple CIDR or single IP
        if self._validate_single_network_item(value, field_name, show_error=False):
            return True
        
        # If none of the above, it's invalid
        messagebox.showerror("Network Validation Error", 
            f"{field_name} must be one of:\n" +
            "• 'any'\n" +
            "• Variable: $HOME_NET or @REFERENCE_SET\n" +
            "• Single CIDR: 192.168.1.0/24\n" +
            "• Negation: !192.168.1.0/24 or !$HOME_NET\n" +
            "• Group: [10.0.0.0/24, !10.0.0.5]\n" +
            "• Variable group: [$EXTERNAL_NET, !$HOME_NET]\n" +
            "• Negated group: ![1.1.1.1, 1.1.1.2]")
        return False
    
    def _validate_network_group(self, group_content: str, field_name: str) -> bool:
        """Validate the contents of a network group [item1, item2, ...]"""
        if not group_content.strip():
            messagebox.showerror("Network Validation Error", 
                f"{field_name} contains empty brackets. Groups must contain at least one network specification.")
            return False
        
        # Split by commas and validate each item
        items = [item.strip() for item in group_content.split(',')]
        
        for item in items:
            if not item:
                messagebox.showerror("Network Validation Error", 
                    f"{field_name} contains empty item in group. Remove extra commas.")
                return False
            
            # Handle negated items within group
            if item.startswith('!'):
                item = item[1:].strip()
                if not item:
                    messagebox.showerror("Network Validation Error", 
                        f"{field_name} contains empty negation in group.")
                    return False
            
            # Validate the individual item
            if not self._validate_single_network_item(item, field_name, show_error=True):
                return False
        
        return True
    
    def _validate_single_network_item(self, value: str, field_name: str, show_error: bool = True) -> bool:
        """Validate a single network item (CIDR, IP, or variable)"""
        value = value.strip()
        
        # Allow 'any'
        if value.lower() == 'any':
            return True
        
        # Validate variables - must start with exactly one $ or @ followed by valid characters
        if value.startswith('$') or value.startswith('@'):
            # Check for double prefix ($$, @@) which is invalid
            if value.startswith('$$') or value.startswith('@@'):
                if show_error:
                    messagebox.showerror("Network Validation Error", 
                        f"Invalid variable in {field_name}: '{value}'\n\n" +
                        "Variables must start with exactly one $ or @ character (e.g., $HOME_NET, @REFERENCE_SET)")
                return False
            
            # Valid variable format: $ or @ followed by alphanumeric/underscore characters
            # Pattern: ^[$@][A-Za-z0-9_]+$
            if len(value) > 1 and value[1:].replace('_', '').isalnum():
                return True
            else:
                if show_error:
                    messagebox.showerror("Network Validation Error", 
                        f"Invalid variable format in {field_name}: '{value}'\n\n" +
                        "Variables must be alphanumeric with underscores (e.g., $HOME_NET, @MY_SET_1)")
                return False
        
        # Check if it's a valid CIDR or IP
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            if show_error:
                messagebox.showerror("Network Validation Error", 
                    f"Invalid network specification in {field_name}: '{value}'\n\n" +
                    "Must be a valid IP address or CIDR block (e.g., 192.168.1.0/24)")
            return False
    
    def validate_port_field(self, value: str, field_name: str) -> bool:
        """Validate port field (source/dest port)"""
        value = value.strip()
        
        # Allow 'any'
        if value.lower() == 'any':
            return True
        
        # AWS Network Firewall requires port variables to use $ prefix only
        if value.startswith('$'):
            return True
        
        # Reject @ prefix for port variables (AWS Network Firewall compatibility)
        if value.startswith('@'):
            messagebox.showerror("AWS Network Firewall Validation Error", 
                f"{field_name} contains an invalid variable prefix.\n\n" +
                "AWS Network Firewall requires port variables to use $ prefix only.\n" +
                f"Change '{value}' to use $ prefix instead (e.g., ${value[1:]}).")
            return False
        
        # Validate using existing port list validation logic
        if not self.validate_port_list(value):
            messagebox.showerror("Port Validation Error", 
                f"{field_name} must be:\n" +
                "- 'any'\n" +
                "- A port variable starting with $ (e.g., $WEB_PORTS)\n" +
                "- A valid port number (1-65535)\n" +
                "- Port ranges and lists MUST use brackets:\n" +
                "  • Port range: [8080:8090]\n" +
                "  • Multiple ports: [80,443,8080]\n" +
                "  • Complex specs: [80:100,!85]\n\n" +
                "Suricata syntax requires brackets for all port ranges and complex port specifications.")
            return False
        
        return True
    
    def add_rule(self):
        """Add a new rule"""
        # Ask for line number
        max_line = len(self.rules) + 1
        line_num = simpledialog.askinteger(
            "Add Rule", 
            f"Enter line number (1-{max_line}):", 
            minvalue=1, 
            maxvalue=max_line,
            initialvalue=max_line
        )
        
        if line_num is None:
            return
        
        # Convert to 0-based index
        insert_index = line_num - 1
        
        # Auto-generate SID
        max_sid = max([rule.sid for rule in self.rules], default=99)
        next_sid = max_sid + 1
        
        # Create a new rule with default values (protocol-based content)
        default_protocol = "tcp"
        default_content = "" if default_protocol.lower() in ["udp", "icmp"] else "flow: to_server"
        
        new_rule = SuricataRule(
            action="pass",
            protocol=default_protocol,
            src_net="$HOME_NET",
            src_port="any",
            dst_net="$EXTERNAL_NET",
            dst_port="any",
            message="",
            content=default_content,
            sid=next_sid
        )
        
        # Show edit dialog with new rule
        updated_rule = self.show_edit_rule_dialog("Add Rule", new_rule)
        if updated_rule:
            if self.validate_unique_sid(updated_rule.sid):
                if insert_index >= len(self.rules):
                    self.rules.append(updated_rule)
                else:
                    self.rules.insert(insert_index, updated_rule)
                self.refresh_table()
                self.modified = True
                messagebox.showinfo("Success", f"Rule added at line {line_num} successfully.")
            else:
                messagebox.showerror("Error", f"SID {updated_rule.sid} is already in use. Please choose a different SID.")
    
    def insert_rule(self):
        """Insert a new rule at selected position"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a position to insert the rule.")
            return
        
        # Get the actual line number from tree (important when filters are active)
        selected_item = selection[0]
        values = self.tree.item(selected_item, 'values')
        if values and values[0]:
            # Convert 1-based line number to 0-based index
            insert_index = int(values[0]) - 1
        else:
            messagebox.showerror("Error", "Could not determine insert position.")
            return
        
        # Auto-generate SID
        max_sid = max([rule.sid for rule in self.rules], default=99)
        next_sid = max_sid + 1
        
        # Create a new rule with default values (protocol-based content)
        default_protocol = "tcp"
        default_content = "" if default_protocol.lower() in ["udp", "icmp"] else "flow: to_server"
        
        new_rule = SuricataRule(
            action="pass",
            protocol=default_protocol,
            src_net="$HOME_NET",
            src_port="any",
            dst_net="any",
            dst_port="any",
            message="",
            content=default_content,
            sid=next_sid
        )
        
        # Show edit dialog with new rule
        updated_rule = self.show_edit_rule_dialog("Insert Rule", new_rule)
        if updated_rule:
            if self.validate_unique_sid(updated_rule.sid):
                # Save state for undo
                self.save_undo_state()
                
                # Add history entry with simplified rule information
                rule_details = {
                    'line': insert_index + 1, 
                    'rule_text': updated_rule.to_string()
                }
                self.add_history_entry('rule_added', rule_details)
                
                self.rules.insert(insert_index, updated_rule)
                self.refresh_table()
                self.modified = True
                messagebox.showinfo("Success", f"Rule inserted at line {insert_index + 1} successfully.")
            else:
                messagebox.showerror("Error", f"SID {updated_rule.sid} is already in use. Please choose a different SID.")
    
    def edit_selected_rule(self):
        """Edit the selected rule"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to edit.")
            return
        
        # Get ACTUAL line number from tree (critical when filters active)
        selected_item = selection[0]
        values = self.tree.item(selected_item, 'values')
        if values and values[0]:
            rule_index = int(values[0]) - 1  # Convert 1-based to 0-based
        else:
            messagebox.showerror("Error", "Could not determine rule position.")
            return
        
        rule = self.rules[rule_index]
        
        # Check if this is a comment and handle appropriately
        if getattr(rule, 'is_comment', False):
            # Show comment edit dialog
            updated_comment = self.show_edit_comment_dialog("Edit Comment", rule.comment_text)
            if updated_comment is not None:
                # Save state for undo
                self.save_undo_state()
                
                # Update the comment
                rule.comment_text = updated_comment
                self.refresh_table()
                self.modified = True
                messagebox.showinfo("Success", f"Comment at line {rule_index + 1} updated successfully.")
        elif getattr(rule, 'is_blank', False):
            # Blank lines can't be edited
            messagebox.showinfo("Info", "Blank lines cannot be edited.")
        else:
            # Show regular rule edit dialog
            updated_rule = self.show_edit_rule_dialog("Edit Rule", rule)
            if updated_rule:
                if self.validate_unique_sid(updated_rule.sid, rule_index):
                    # Capture detailed changes for history logging
                    original_rule = self.rules[rule_index]
                    changes = self.compare_rules_for_changes(original_rule, updated_rule)
                    
                    # Check if ONLY the message field changed (for filtering out message-only changes)
                    message_only_change = (
                        original_rule.action == updated_rule.action and
                        original_rule.protocol == updated_rule.protocol and
                        original_rule.src_net == updated_rule.src_net and
                        original_rule.src_port == updated_rule.src_port and
                        original_rule.direction == updated_rule.direction and
                        original_rule.dst_net == updated_rule.dst_net and
                        original_rule.dst_port == updated_rule.dst_port and
                        original_rule.content == updated_rule.content and
                        original_rule.sid == updated_rule.sid and
                        original_rule.message != updated_rule.message
                    )
                    
                    # Skip tracking if only message changed
                    if message_only_change:
                        # Still update the rule but don't track the change
                        self.rules[rule_index] = updated_rule
                        self.refresh_table()
                        self.modified = True
                        self.auto_detect_variables()
                        self.update_status_bar()
                        messagebox.showinfo("Success", f"Rule at line {rule_index + 1} updated successfully.")
                        return
                    
                    # Save state for undo
                    self.save_undo_state()
                    
                    # Add history entry with detailed change information
                    history_details = {
                        'line': rule_index + 1, 
                        'rule_text': updated_rule.to_string(),
                        'action': updated_rule.action,
                        'sid': updated_rule.sid,
                        'message': updated_rule.message
                    }
                    
                    # Include detailed changes if any were captured
                    if changes:
                        history_details['changes'] = changes
                    
                    self.add_history_entry('rule_modified', history_details)
                    
                    self.rules[rule_index] = updated_rule
                    self.refresh_table()
                    self.modified = True
                    # Auto-detect variables after rule changes
                    self.auto_detect_variables()
                    self.update_status_bar()
                    messagebox.showinfo("Success", f"Rule at line {rule_index + 1} updated successfully.")
                else:
                    messagebox.showerror("Error", f"SID {updated_rule.sid} is already in use. Please choose a different SID.")
    
    def delete_selected_rule(self):
        """Delete the selected rule(s)"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select one or more rules to delete.")
            return
        
        count = len(selection)
        rule_text = "rule" if count == 1 else "rules"
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the {count} selected {rule_text}?"):
            # Save state for undo
            self.save_undo_state()
            
            # Get ACTUAL indices using line numbers from tree (critical when filters active)
            indices = []
            for item in selection:
                values = self.tree.item(item, 'values')
                if values and values[0]:
                    # Convert 1-based line number to 0-based index
                    actual_index = int(values[0]) - 1
                    indices.append(actual_index)
            
            # Capture complete rule details before deletion
            deleted_rules = []
            for index in indices:
                if index < len(self.rules):
                    rule = self.rules[index]
                    if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False):
                        deleted_rules.append({
                            'line': index + 1, 
                            'rule_text': rule.to_string()
                        })
            
            # Add history entries for each deleted rule
            for rule_info in deleted_rules:
                self.add_history_entry('rule_deleted', rule_info)
            
            # Sort indices in reverse order to delete from end to beginning
            indices.sort(reverse=True)
            
            # Delete rules in reverse order to maintain correct indices
            for index in indices:
                del self.rules[index]
            
            self.refresh_table()
            self.modified = True
            # Don't call update_status_bar() here - refresh_table() already called it with proper displayed_count
    
    
    def create_rule_from_form(self, show_errors=True) -> Optional[SuricataRule]:
        """Create a SuricataRule object from form data"""
        try:
            sid_str = self.sid_var.get().strip()
            if not sid_str:
                if show_errors:
                    messagebox.showerror("Error", "SID is required.")
                return None
            
            sid = int(sid_str)
            if not (SuricataConstants.SID_MIN <= sid <= SuricataConstants.SID_MAX):
                if show_errors:
                    messagebox.showerror("Error", f"SID must be between {SuricataConstants.SID_MIN} and {SuricataConstants.SID_MAX}.")
                return None
            
            # Get rev value (should be set from UI or default to 1)
            rev_str = self.rev_var.get().strip() if hasattr(self, 'rev_var') and self.rev_var.get().strip() else "1"
            try:
                rev = int(rev_str)
                if rev < 1:
                    rev = 1
            except (ValueError, AttributeError):
                rev = 1
            
            return SuricataRule(
                action=self.action_var.get(),
                protocol=self.protocol_var.get(),
                src_net=self.src_net_var.get(),
                src_port=self.src_port_var.get(),
                dst_net=self.dst_net_var.get(),
                dst_port=self.dst_port_var.get(),
                message=self.message_var.get(),
                content=self.content_var.get().rstrip(';'),
                sid=sid,
                rev=rev
            )
        except (ValueError, AttributeError):
            if show_errors:
                messagebox.showerror("Error", "SID must be a valid number.")
            return None
    

    

    

    
    def new_file(self):
        """Create a new file"""
        if self.modified and not self.ask_save_changes():
            return
        
        # Disable change tracking for new content operations
        self.tracking_enabled = False
        self.tracking_menu_var.set(False)
        
        self.rules.clear()
        self.variables.clear()
        self.has_header = False
        self.created_timestamp = None
        self.pending_history.clear()
        
        # Create header for new files only if tracking enabled
        if self.tracking_enabled:
            self.create_header()
            self.add_history_entry('file_created')
        
        self.refresh_table()
        self.auto_detect_variables()
        self.current_file = None
        self.modified = False
        self.update_status_bar()
        self.root.title("Suricata Rule Generator for AWS Network Firewall")
        
        # Force UI update to reset scrollbar state
        self.root.update_idletasks()
        
        # Show rule editor with default values and add placeholder for new rule insertion
        self.ui_manager.show_rule_editor()
        self.set_default_editor_values()
        self.selected_rule_index = len(self.rules)  # Set to insert after header if present
        self.add_placeholder_row()  # Show placeholder by default
    
    def open_file(self):
        """Open an existing .suricata file"""
        if self.modified and not self.ask_save_changes():
            return
        
        # Check for unsaved pending history changes
        if self.tracking_enabled and self.pending_history:
            if not self.ask_save_pending_changes():
                return
        
        filename = filedialog.askopenfilename(
            title="Open Suricata Rules File",
            filetypes=[("Suricata files", "*.suricata"), ("All files", "*.*")]
        )
        
        if filename:
            # Clear pending history from previous file
            self.pending_history.clear()
            
            self.load_rules_from_file(filename)
            self.current_file = filename
            self.modified = False
            self.selected_rule_index = None
            
            # Check for existing history file and auto-enable tracking
            self.check_and_enable_existing_tracking()
            
            self.update_status_bar()
            # Refresh table without preserving selection to enable click-to-insert
            self.refresh_table(preserve_selection=False)
            self.root.title(f"Suricata Rule Generator - {os.path.basename(filename)}")
            # Set up rule editor for new rule insertion
            self.ui_manager.show_rule_editor()
            self.set_default_editor_values()
    
    def save_file(self):
        """Save the current file"""
        if not self.current_file:
            return self.save_as_file()
        
        return self.save_rules_to_file(self.current_file)
    
    def save_as_file(self):
        """Save the file with a new name"""
        filename = filedialog.asksaveasfilename(
            title="Save Suricata Rules File",
            defaultextension=".suricata",
            filetypes=[("Suricata files", "*.suricata"), ("All files", "*.*")]
        )
        
        if filename:
            if self.save_rules_to_file(filename):
                self.current_file = filename
                self.root.title(f"Suricata Rule Generator - {os.path.basename(filename)}")
                return True
        return False
    
    def save_rules_to_file(self, filename: str) -> bool:
        """Save rules to a file with variable validation and atomic save process"""
        try:
            # Validate filename
            if not filename or not filename.strip():
                raise ValueError("Filename cannot be empty")
            
            # Check directory permissions
            directory = os.path.dirname(os.path.abspath(filename))
            if not os.path.exists(directory):
                raise FileNotFoundError(f"Directory does not exist: {directory}")
            
            if not os.access(directory, os.W_OK):
                raise PermissionError(f"Cannot write to directory: {directory}")
            
            success = self.file_manager.save_rules_to_file(
                filename, self.rules, self.variables, 
                self.has_header, self.tracking_enabled, self.pending_history
            )
            
            if success:
                if self.tracking_enabled and self.pending_history:
                    self.pending_history.clear()
                
                self.modified = False
                self.update_status_bar()
                messagebox.showinfo("Success", f"Rules saved to {filename}")
                return True
            
        except ValueError as e:
            messagebox.showerror("Validation Error", str(e))
        except FileNotFoundError as e:
            messagebox.showerror("Directory Error", str(e))
        except PermissionError as e:
            messagebox.showerror("Permission Error", str(e))
        except OSError as e:
            messagebox.showerror("File System Error", f"Cannot save file: {str(e)}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save rules to {filename}:\n\n{str(e)}")
        
        return False
    
    

    

    

    
    
    
    def copy_selected_rules(self):
        """Copy selected rules to clipboard"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select one or more rules to copy.")
            return
        
        # Get selected rule indices - use line numbers from tree when filters active
        indices = []
        for item in selection:
            # Get the line number from the first column (actual line number in file)
            values = self.tree.item(item, 'values')
            if values and values[0]:
                # Convert 1-based line number to 0-based index
                actual_index = int(values[0]) - 1
                indices.append(actual_index)
        
        internal_rules = []  # Rules with new SIDs for internal clipboard
        original_rules = []  # Rules with original SIDs for system clipboard
        
        for index in sorted(indices):
            if index < len(self.rules):
                rule = self.rules[index]
                
                # Create copies for both clipboards
                if getattr(rule, 'is_comment', False):
                    # Comments - same for both clipboards
                    internal_rule = SuricataRule()
                    internal_rule.is_comment = True
                    internal_rule.comment_text = rule.comment_text
                    internal_rules.append(internal_rule)
                    original_rules.append(rule)  # Use original rule object
                elif getattr(rule, 'is_blank', False):
                    # Blank lines - same for both clipboards
                    internal_rule = SuricataRule()
                    internal_rule.is_blank = True
                    internal_rules.append(internal_rule)
                    original_rules.append(rule)  # Use original rule object
                else:
                    # Regular rules - different SIDs for each clipboard
                    # Internal clipboard: new SID to avoid conflicts
                    max_sid = max([r.sid for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)], default=99)
                    new_sid = max_sid + len(internal_rules) + 1
                    
                    internal_rule = SuricataRule(
                        action=rule.action,
                        protocol=rule.protocol,
                        src_net=rule.src_net,
                        src_port=rule.src_port,
                        dst_net=rule.dst_net,
                        dst_port=rule.dst_port,
                        message=rule.message,
                        content=rule.content,
                        sid=new_sid,
                        direction=rule.direction,
                        original_options=rule.original_options
                    )
                    internal_rules.append(internal_rule)
                    original_rules.append(rule)  # Use original rule object with original SID
        
        # Store internal clipboard (with new SIDs for conflict-free pasting)
        self.clipboard = internal_rules
        
        # Copy to system clipboard (with original SIDs as displayed in table)
        rule_strings = []
        for rule in original_rules:
            if getattr(rule, 'is_comment', False):
                rule_strings.append(rule.comment_text)
            elif getattr(rule, 'is_blank', False):
                rule_strings.append('')
            else:
                rule_strings.append(rule.to_string())
        
        clipboard_text = '\n'.join(rule_strings)
        self.root.clipboard_clear()
        self.root.clipboard_append(clipboard_text)
        
        # Track what we last copied so we can detect external clipboard content
        self._last_copied_text = clipboard_text
        
        # Enable paste button
        if hasattr(self, 'paste_button'):
            self.paste_button.config(state="normal")
        
        # Copy operations are not tracked - only paste operations are tracked for better usefulness
        count = len(internal_rules)
        
        rule_text = "rule" if count == 1 else "rules"
        messagebox.showinfo("Copy", f"Copied {count} {rule_text} to clipboard.")
    
    def get_system_clipboard_content(self) -> Optional[str]:
        """Safely get content from system clipboard"""
        try:
            content = self.root.clipboard_get()
            return content
        except tk.TclError:
            return None  # No clipboard content or access denied
    
    
    def parse_clipboard_text(self, clipboard_text: str) -> List[SuricataRule]:
        """Parse clipboard text into SuricataRule objects with auto-conversion for port brackets"""
        rules = []
        lines = clipboard_text.strip().split('\n')
        
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
                # Auto-convert port ranges to bracket format before parsing
                corrected_line = self.file_manager._auto_correct_port_brackets(line)
                
                # Try to parse as Suricata rule
                parsed_rule = SuricataRule.from_string(corrected_line)
                if parsed_rule:
                    # If rule doesn't have rev keyword, set default rev=1
                    if not re.search(r'rev:\d+', corrected_line):
                        parsed_rule.rev = 1
                    
                    # Normalize keyword ordering immediately (WYSIWYG behavior)
                    # Reconstruct original_options with msg first for consistent display
                    options_parts = []
                    if parsed_rule.message:
                        options_parts.append(f'msg:"{parsed_rule.message}"')
                    if parsed_rule.content:
                        content_cleaned = parsed_rule.content.rstrip(';')
                        options_parts.append(content_cleaned)
                    options_parts.append(f'sid:{parsed_rule.sid}')
                    options_parts.append(f'rev:{parsed_rule.rev}')
                    parsed_rule.original_options = '; '.join(options_parts)
                    
                    # Validate the parsed rule has valid syntax
                    validation_errors = []
                    
                    # Validate action
                    if parsed_rule.action.lower() not in SuricataConstants.SUPPORTED_ACTIONS:
                        validation_errors.append(f"invalid action '{parsed_rule.action}'")
                    
                    # Validate protocol
                    if parsed_rule.protocol.lower() not in SuricataConstants.SUPPORTED_PROTOCOLS:
                        validation_errors.append(f"invalid protocol '{parsed_rule.protocol}'")
                    
                    # Validate source network (silent validation for paste)
                    if not self._validate_single_network_item(parsed_rule.src_net, "Source Network", show_error=False):
                        validation_errors.append(f"invalid source network '{parsed_rule.src_net}'")
                    
                    # Validate destination network (silent validation for paste)
                    if not self._validate_single_network_item(parsed_rule.dst_net, "Dest Network", show_error=False):
                        validation_errors.append(f"invalid destination network '{parsed_rule.dst_net}'")
                    
                    # Validate source port (suppress messagebox errors during validation)
                    if not self.validate_port_list(parsed_rule.src_port):
                        validation_errors.append(f"invalid source port '{parsed_rule.src_port}'")
                    
                    # Validate destination port (suppress messagebox errors during validation)
                    if not self.validate_port_list(parsed_rule.dst_port):
                        validation_errors.append(f"invalid destination port '{parsed_rule.dst_port}'")
                    
                    # If there are validation errors, comment out the rule
                    if validation_errors:
                        error_rule = SuricataRule()
                        error_rule.is_comment = True
                        error_summary = ', '.join(validation_errors)
                        error_rule.comment_text = f"# [VALIDATION ERROR: {error_summary}] {corrected_line}"
                        rules.append(error_rule)
                    else:
                        # Valid rule - add it
                        rules.append(parsed_rule)
                else:
                    # Malformed rule - insert as comment with error note
                    error_rule = SuricataRule()
                    error_rule.is_comment = True
                    error_rule.comment_text = f"# [PARSE ERROR] {corrected_line}"
                    rules.append(error_rule)
        
        return rules
    
    
    def assign_safe_sids(self, new_rules: List[SuricataRule]) -> None:
        """Assign safe SIDs to avoid conflicts with existing rules"""
        existing_sids = {rule.sid for rule in self.rules 
                         if not getattr(rule, 'is_comment', False) 
                         and not getattr(rule, 'is_blank', False)}
        
        next_sid = max(existing_sids, default=99) + 1
        
        for rule in new_rules:
            if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False):
                while next_sid in existing_sids:
                    next_sid += 1
                
                rule.sid = next_sid
                # Update original_options to reflect new SID
                if rule.original_options:
                    import re
                    rule.original_options = re.sub(r'sid:\d+', f'sid:{next_sid}', rule.original_options)
                existing_sids.add(next_sid)
                next_sid += 1

    def paste_rules(self):
        """Paste rules from clipboard at selected position or end"""
        # Determine paste position using ACTUAL line numbers (critical when filters active)
        selection = self.tree.selection()
        if selection:
            selected_item = selection[0]
            values = self.tree.item(selected_item, 'values')
            if values and values[0]:
                # Convert 1-based line number to 0-based index, then +1 for "after"
                paste_index = int(values[0])
            else:
                paste_index = len(self.rules)  # Fallback to end if can't determine position
        else:
            paste_index = len(self.rules)  # At end if no selection
        
        # Enhanced clipboard logic - check both internal and system clipboard
        rules_to_paste = []
        source = "internal"
        
        # Get system clipboard content first to compare
        system_content = self.get_system_clipboard_content()
        
        # Check if we should prefer system clipboard over internal clipboard
        use_system_clipboard = False
        
        if system_content and system_content.strip():
            # Check if system clipboard has different content than what we last copied
            if hasattr(self, '_last_copied_text'):
                # If system clipboard content is different from our last copy, prefer system
                if system_content.strip() != self._last_copied_text.strip():
                    use_system_clipboard = True
            else:
                # No record of last copy, check if system content looks like rules
                if any(keyword in system_content.lower() for keyword in ['alert', 'drop', 'pass', 'reject', 'sid:', '->', 'tcp', 'udp', 'http']):
                    use_system_clipboard = True
        
        if use_system_clipboard and system_content:
            # Use system clipboard for external rules
            rules_to_paste = self.parse_clipboard_text(system_content)
            if rules_to_paste:
                # Assign safe SIDs to avoid conflicts
                self.assign_safe_sids(rules_to_paste)
                source = "external"
        elif self.clipboard:
            # Use internal clipboard - but still need to create deep copies and reassign SIDs
            import copy
            rules_to_paste = []
            
            # Generate new SIDs for internal clipboard rules to prevent conflicts (original behavior)
            max_sid = max([rule.sid for rule in self.rules if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False)], default=99)
            next_sid = max_sid + 1
            
            for rule in self.clipboard:
                rule_copy = copy.deepcopy(rule)
                
                # Assign new SID for non-comment/non-blank rules (restore original behavior)
                if not getattr(rule_copy, 'is_comment', False) and not getattr(rule_copy, 'is_blank', False):
                    rule_copy.sid = next_sid
                    # Update original_options with new SID
                    if rule_copy.original_options:
                        import re
                        rule_copy.original_options = re.sub(r'sid:\d+', f'sid:{next_sid}', rule_copy.original_options)
                    next_sid += 1
                
                rules_to_paste.append(rule_copy)
            source = "internal"
        elif system_content:
            # Fallback to system clipboard even if it doesn't look like rules
            rules_to_paste = self.parse_clipboard_text(system_content)
            if rules_to_paste:
                # Assign safe SIDs to avoid conflicts
                self.assign_safe_sids(rules_to_paste)
                source = "external"
        
        if not rules_to_paste:
            messagebox.showwarning("Warning", "No rules in clipboard to paste.")
            return
        
        # Validate port fields in pasted rules before inserting
        invalid_rules = []
        for i, rule in enumerate(rules_to_paste):
            # Skip comments and blank lines
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            
            # Validate source and destination ports
            if not self.validate_port_list(rule.src_port):
                invalid_rules.append(f"Rule {i+1}: Invalid source port '{rule.src_port}'")
            if not self.validate_port_list(rule.dst_port):
                invalid_rules.append(f"Rule {i+1}: Invalid destination port '{rule.dst_port}'")
        
        # If there are invalid port fields, show error and cancel paste
        if invalid_rules:
            error_msg = "Cannot paste rules with invalid port fields:\n\n" + "\n".join(invalid_rules[:5])
            if len(invalid_rules) > 5:
                error_msg += f"\n... and {len(invalid_rules) - 5} more validation errors"
            error_msg += "\n\nPlease fix the port fields in the source and try again."
            messagebox.showerror("Port Validation Error", error_msg)
            return
        
        # Save state for undo
        self.save_undo_state()
        
        # Add history entry for paste operation
        count = len(rules_to_paste)
        # Collect details about pasted rules for better tracking
        pasted_rules_details = []
        for rule in rules_to_paste:
            if getattr(rule, 'is_comment', False):
                pasted_rules_details.append({'type': 'comment', 'text': rule.comment_text[:50] + '...' if len(rule.comment_text) > 50 else rule.comment_text})
            elif getattr(rule, 'is_blank', False):
                pasted_rules_details.append({'type': 'blank'})
            else:
                pasted_rules_details.append({'type': 'rule', 'action': rule.action, 'sid': rule.sid, 'message': rule.message[:30] + '...' if len(rule.message) > 30 else rule.message})
        
        self.add_history_entry('rules_pasted', {'line': paste_index + 1, 'count': count, 'rules': pasted_rules_details})
        
        # Insert rules from clipboard
        for i, rule in enumerate(rules_to_paste):
            self.rules.insert(paste_index + i, rule)
        
        self.refresh_table()
        self.modified = True
        # Auto-detect variables after paste operation
        self.auto_detect_variables()
        self.update_status_bar()
        
        # Show appropriate success message based on source
        rule_text = "rule" if count == 1 else "rules"
        source_text = " from external source" if source == "external" else ""
        
        # Use paste_index which was calculated before table refresh
        if paste_index < len(self.rules) - count:  # If we pasted before the end
            position_text = f"after line {paste_index}"
        else:
            position_text = "at end of file"
        
        messagebox.showinfo("Paste", f"Pasted {count} {rule_text}{source_text} {position_text}.")
    
    def deselect_item(self, item):
        """Deselect a tree item"""
        try:
            self.tree.selection_remove(item)
            self.selected_rule_index = None
            self.ui_manager.hide_all_editor_fields()
        except tk.TclError:
            pass
    

    
    def on_closing(self):
        """Handle application closing"""
        if self.modified and not self.ask_save_changes():
            return
        self.root.destroy()

    def export_file(self):
        """Export rules as Terraform or CloudFormation template"""
        if not self.rules:
            messagebox.showwarning("Warning", "No rules to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export Infrastructure Template",
            initialfile="network-firewall-rules.tf",
            filetypes=[
                ("Terraform files", "*.tf"),
                ("CloudFormation templates", "*.cft")
            ],
            defaultextension=".tf"
        )
        
        if filename:
            # Determine export format based on file extension
            if filename.lower().endswith('.tf'):
                export_format = "terraform"
            elif filename.lower().endswith('.cft'):
                export_format = "cloudformation"
            else:
                messagebox.showerror("Error", "Unsupported file format. Please use .tf or .cft extension.")
                return
            
            # Generate and save the export file
            if export_format == "terraform":
                content = self.file_manager.generate_terraform_template(self.rules, self.variables)
            else:  # cloudformation
                content = self.file_manager.generate_cloudformation_template(self.rules, self.variables)
                
                # AWS CloudFormation Quota Validation (Priority 1 & 2)
                # Validate CloudFormation template size against AWS limits
                template_size = len(content.encode('utf-8'))
                rule_count = len([r for r in self.rules if not getattr(r, 'is_comment', False) 
                                 and not getattr(r, 'is_blank', False)])
                
                # Check against 1 MB S3 limit (hard limit)
                if template_size > 1048576:  # 1 MB
                    messagebox.showerror(
                        "CloudFormation Template Too Large",
                        f"CloudFormation template size: {template_size:,} bytes ({template_size/1024/1024:.2f} MB)\n"
                        f"AWS S3 limit: 1,048,576 bytes (1 MB)\n\n"
                        f"Your template with {rule_count} rules exceeds the maximum "
                        f"CloudFormation template size.\n\n"
                        f"This template cannot be deployed to AWS.\n\n"
                        f"Solutions:\n"
                        f"• Reduce rule count (currently {rule_count} rules)\n"
                        f"• Use Terraform export instead (no size limits)\n"
                        f"• Split rules into multiple rule groups"
                    )
                    return
                
                # Check against 51.2 KB direct API limit (requires S3)
                elif template_size > 51200:  # 51.2 KB
                    response = messagebox.askyesno(
                        "CloudFormation Template Requires S3",
                        f"CloudFormation template size: {template_size:,} bytes ({template_size/1024:.1f} KB)\n"
                        f"Direct API limit: 51,200 bytes (51.2 KB)\n\n"
                        f"⚠️ This template is too large for direct API deployment.\n"
                        f"You MUST upload it to S3 before deploying.\n\n"
                        f"Deployment steps:\n"
                        f"1. Upload template to S3 bucket\n"
                        f"2. Deploy using S3 URL:\n"
                        f"   aws cloudformation create-stack --template-url s3://...\n\n"
                        f"S3 limit: 1,048,576 bytes (1 MB)\n"
                        f"Your template: {template_size:,} bytes ({(template_size/1048576)*100:.1f}% of S3 limit)\n\n"
                        f"Continue with export?\n"
                        f"(Template will be saved but requires S3 upload before deployment)"
                    )
                    if not response:
                        return
                
                # Warn if approaching 51.2 KB limit but still safe for direct API
                elif template_size > 45000:  # Within 6 KB of limit
                    messagebox.showwarning(
                        "CloudFormation Template Approaching Size Limit",
                        f"CloudFormation template size: {template_size:,} bytes ({template_size/1024:.1f} KB)\n"
                        f"Direct API limit: 51,200 bytes (51.2 KB)\n"
                        f"Remaining: {51200 - template_size:,} bytes\n\n"
                        f"Your template is approaching the direct API size limit.\n"
                        f"Consider using Terraform export for larger rule sets."
                    )
            
            try:
                # Validate directory permissions before writing
                directory = os.path.dirname(os.path.abspath(filename))
                if not os.path.exists(directory):
                    raise FileNotFoundError(f"Directory does not exist: {directory}")
                
                if not os.access(directory, os.W_OK):
                    raise PermissionError(f"Cannot write to directory: {directory}")
                
                # Use newline='' to prevent Python from converting \n to \r\n on Windows
                # This ensures Unix line endings (LF) are preserved in the exported file
                with open(filename, 'w', encoding='utf-8', newline='') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Successfully exported {export_format.title()} template to {filename}")
            except FileNotFoundError as e:
                messagebox.showerror("Directory Error", str(e))
            except PermissionError as e:
                messagebox.showerror("Permission Error", str(e))
            except OSError as e:
                messagebox.showerror("File System Error", f"Cannot write export file: {str(e)}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export {export_format} template to {filename}:\n\n{str(e)}")
    

    
    def get_version_number(self) -> str:
        """Get current version number"""
        return get_main_version()
    
    
    
    def ask_save_changes(self) -> bool:
        """Ask user if they want to save changes"""
        if not self.modified:
            return True
        
        result = messagebox.askyesnocancel("Save Changes", "Do you want to save changes before continuing?")
        if result is True:
            return self.save_file()
        elif result is False:
            return True
        else:  # Cancel
            return False
    
    def ask_save_pending_changes(self) -> bool:
        """Ask user if they want to save pending history changes"""
        if not self.pending_history:
            return True
        
        result = messagebox.askyesnocancel("Save Pending Changes", 
            "You have unsaved change history. Do you want to save the current file to preserve the change history before continuing?")
        if result is True:
            return self.save_file()
        elif result is False:
            return True
        else:  # Cancel
            return False
    

    
    def show_edit_comment_dialog(self, title: str, comment_text: str) -> Optional[str]:
        """Show a dialog for editing comment text"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("600x150")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(True, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        result = [None]
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Comment label
        ttk.Label(main_frame, text="Comment text:").pack(anchor=tk.W, pady=(0, 5))
        
        # Comment entry - extract just the comment part without the # prefix
        display_text = comment_text
        if comment_text.startswith('#'):
            display_text = comment_text[1:].lstrip()
        
        comment_var = tk.StringVar(value=display_text)
        comment_entry = ttk.Entry(main_frame, textvariable=comment_var, width=80)
        comment_entry.pack(fill=tk.X, pady=(0, 10))
        comment_entry.focus()
        comment_entry.select_range(0, tk.END)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def on_ok():
            updated_text = comment_var.get().strip()
            # Ensure the comment starts with # and a space
            if updated_text:
                if not updated_text.startswith('#'):
                    updated_text = f"# {updated_text}"
                elif updated_text.startswith('#') and len(updated_text) > 1 and updated_text[1] != ' ':
                    updated_text = f"# {updated_text[1:]}"
            else:
                updated_text = "#"
            
            result[0] = updated_text
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT)
        
        # Bind Enter key
        dialog.bind('<Return>', lambda e: on_ok())
        
        dialog.wait_window()
        return result[0]
    
    def show_edit_rule_dialog(self, title: str, rule: SuricataRule) -> Optional[SuricataRule]:
        """Show a dialog for editing all rule fields"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("500x450")
        dialog.transient(self.root)
        dialog.grab_set()
        
        result = [None]
        
        # Create variables
        action_var = tk.StringVar(value=rule.action)
        protocol_var = tk.StringVar(value=rule.protocol)
        src_net_var = tk.StringVar(value=rule.src_net)
        src_port_var = tk.StringVar(value=rule.src_port)
        dst_net_var = tk.StringVar(value=rule.dst_net)
        dst_port_var = tk.StringVar(value=rule.dst_port)
        message_var = tk.StringVar(value=rule.message)
        content_var = tk.StringVar(value=rule.content)
        sid_var = tk.StringVar(value=str(rule.sid))
        rev_var = tk.StringVar(value=str(rule.rev))
        
        # Form frame
        form_frame = ttk.Frame(dialog)
        form_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        row = 0
        # Action and Protocol
        ttk.Label(form_frame, text="Action:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        action_combo = ttk.Combobox(form_frame, textvariable=action_var, values=["pass", "alert", "drop", "reject"], state="readonly", width=12)
        action_combo.grid(row=row, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Protocol:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        protocol_combo = ttk.Combobox(form_frame, textvariable=protocol_var, values=SuricataConstants.SUPPORTED_PROTOCOLS, state="readonly", width=12)
        protocol_combo.grid(row=row, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Add protocol change callback to update content field for new rules
        def on_dialog_protocol_change(event):
            protocol = protocol_var.get().lower()
            # Only auto-update content if this is a new rule with default content
            current_content = content_var.get()
            if current_content in ["flow: to_server", ""]:
                if protocol in ["udp", "icmp"]:
                    content_var.set("")
                else:
                    content_var.set("flow: to_server")
        
        protocol_combo.bind('<<ComboboxSelected>>', on_dialog_protocol_change)
        
        # Source Network and Port
        row += 1
        ttk.Label(form_frame, text="Source Network:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(form_frame, textvariable=src_net_var, width=15).grid(row=row, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Source Port:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(form_frame, textvariable=src_port_var, width=15).grid(row=row, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Destination Network and Port
        row += 1
        ttk.Label(form_frame, text="Dest Network:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(form_frame, textvariable=dst_net_var, width=15).grid(row=row, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Dest Port:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(form_frame, textvariable=dst_port_var, width=15).grid(row=row, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Message
        row += 1
        ttk.Label(form_frame, text="Message:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        message_entry = ttk.Entry(form_frame, textvariable=message_var, width=50)
        message_entry.grid(row=row, column=1, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=2)
        
        # Content
        row += 1
        ttk.Label(form_frame, text="Content:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(form_frame, textvariable=content_var, width=50).grid(row=row, column=1, columnspan=3, sticky=tk.W+tk.E, padx=5, pady=2)
        
        # SID and REV
        row += 1
        ttk.Label(form_frame, text="SID:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(form_frame, textvariable=sid_var, width=15).grid(row=row, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(form_frame, text="Rev:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(form_frame, textvariable=rev_var, width=5, state="readonly").grid(row=row, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Configure column weights
        form_frame.columnconfigure(1, weight=1)
        form_frame.columnconfigure(3, weight=1)
        
        # Focus on message field
        message_entry.focus()
        message_entry.select_range(0, tk.END)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def on_ok():
            try:
                # Validate rule inputs for security
                try:
                    validate_rule_input(
                        message=message_var.get(),
                        content=content_var.get()
                    )
                except ValueError as e:
                    messagebox.showerror("Security Validation Error", str(e))
                    return
                
                sid = int(sid_var.get().strip())
                if not (SuricataConstants.SID_MIN <= sid <= SuricataConstants.SID_MAX):
                    messagebox.showerror("Error", f"SID must be between {SuricataConstants.SID_MIN} and {SuricataConstants.SID_MAX}.")
                    return
                
                # Validate port fields
                if not self.validate_port_field(src_port_var.get(), "Source Port"):
                    return
                if not self.validate_port_field(dst_port_var.get(), "Dest Port"):
                    return
                
                # Check if any non-message fields changed to determine if rev should increment
                original_rule = rule
                fields_changed = (
                    original_rule.action != action_var.get() or
                    original_rule.protocol != protocol_var.get() or
                    original_rule.src_net != src_net_var.get() or
                    original_rule.src_port != src_port_var.get() or
                    original_rule.dst_net != dst_net_var.get() or
                    original_rule.dst_port != dst_port_var.get() or
                    original_rule.content != content_var.get() or
                    original_rule.sid != sid
                )
                
                # Increment rev if any non-message fields changed
                new_rev = rule.rev + 1 if fields_changed else rule.rev
                
                updated_rule = SuricataRule(
                    action=action_var.get(),
                    protocol=protocol_var.get(),
                    src_net=src_net_var.get(),
                    src_port=src_port_var.get(),
                    dst_net=dst_net_var.get(),
                    dst_port=dst_port_var.get(),
                    message=message_var.get(),
                    content=content_var.get().rstrip(';'),
                    sid=sid,
                    rev=new_rev
                )
                result[0] = updated_rule
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "SID must be a valid number.")
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key
        dialog.bind('<Return>', lambda e: on_ok())
        
        dialog.wait_window()
        return result[0]
    
    
    def clear_editor_fields(self):
        """Clear all editor fields"""
        self.action_var.set("pass")
        self.protocol_var.set("tcp")
        self.src_net_var.set("$HOME_NET")
        self.src_port_var.set("any")
        self.dst_net_var.set("$EXTERNAL_NET")
        self.dst_port_var.set("any")
        self.message_var.set("")
        self.content_var.set("")
        self.sid_var.set("")
        self.comment_var.set("")
        self.ui_manager.hide_all_editor_fields()
    
    def set_default_editor_values(self):
        """Set default values in editor fields for new file"""
        self.action_var.set("pass")
        protocol = self.protocol_var.get()
        self.protocol_var.set("tcp")
        self.src_net_var.set("$HOME_NET")
        self.src_port_var.set("any")
        self.direction_var.set("->")
        self.dst_net_var.set("any")
        self.dst_port_var.set("any")
        self.message_var.set("")
        
        # Set Content Keywords based on protocol - empty for udp/icmp, "flow: to_server" for others
        current_protocol = self.protocol_var.get().lower()
        if current_protocol in ["udp", "icmp"]:
            self.content_var.set("")
        else:
            self.content_var.set("flow: to_server")
        
        self.sid_var.set("100")
        if hasattr(self, 'rev_var'):
            self.rev_var.set("1")
    
    def save_rule_changes(self):
        """Save changes from editor fields to the selected rule or insert new rule
        
        Handles both editing existing rules and inserting new rules from the editor.
        Performs validation for SID uniqueness and network field formats.
        Supports comments, regular rules, and blank lines.
        """
        # Handle insertion of new rules when index is at or beyond current rules
        if (self.selected_rule_index is not None and 
            (self.selected_rule_index >= len(self.rules) or len(self.rules) == 0)):
            self.insert_new_rule_from_editor()
            return
        
        # Validate that a rule is selected
        if self.selected_rule_index is None:
            messagebox.showwarning("Warning", "No rule selected to save changes.")
            return
        
        # Store line number early (before any operations that might clear selected_rule_index)
        updated_line_num = self.selected_rule_index + 1
        
        rule = self.rules[self.selected_rule_index]
        
        # Handle blank lines - replace with new rule
        if getattr(rule, 'is_blank', False):
            # Blank line selected - replace it with a new rule
            try:
                # Validate rule inputs for security
                try:
                    validate_rule_input(
                        message=self.message_var.get(),
                        content=self.content_var.get()
                    )
                except ValueError as e:
                    messagebox.showerror("Security Validation Error", str(e))
                    return
                
                # Validate SID
                sid_str = self.sid_var.get().strip()
                if not sid_str:
                    messagebox.showerror("Error", "SID is required.")
                    return
                
                sid = int(sid_str)
                if not (SuricataConstants.SID_MIN <= sid <= SuricataConstants.SID_MAX):
                    messagebox.showerror("Error", f"SID must be between {SuricataConstants.SID_MIN} and {SuricataConstants.SID_MAX}.")
                    return
                
                # Validate network fields
                if not self.validate_network_field(self.src_net_var.get(), "Source Network"):
                    return
                if not self.validate_network_field(self.dst_net_var.get(), "Dest Network"):
                    return
                
                # Validate port fields
                if not self.validate_port_field(self.src_port_var.get(), "Source Port"):
                    return
                if not self.validate_port_field(self.dst_port_var.get(), "Dest Port"):
                    return
                
                # Create new rule from editor fields
                options_parts = []
                if self.message_var.get():
                    options_parts.append(f'msg:"{self.message_var.get()}"')
                if self.content_var.get():
                    content_cleaned = self.content_var.get().rstrip(';')
                    options_parts.append(content_cleaned)
                options_parts.append(f'sid:{sid}')
                options_parts.append(f'rev:1')
                original_options = '; '.join(options_parts)
                
                new_rule = SuricataRule(
                    action=self.action_var.get(),
                    protocol=self.protocol_var.get(),
                    src_net=self.src_net_var.get(),
                    src_port=self.src_port_var.get(),
                    dst_net=self.dst_net_var.get(),
                    dst_port=self.dst_port_var.get(),
                    message=self.message_var.get(),
                    content=self.content_var.get(),
                    sid=sid,
                    direction=self.direction_var.get(),
                    original_options=original_options
                )
                
                # AWS Network Firewall Quota Validation (Priority 1 & 2)
                # Validate total rule length with variable expansion
                if not self.validate_total_rule_length(new_rule):
                    return
                
                # Validate IP Set References don't exceed 5
                if not self.validate_ip_set_references(new_rule, exclude_index=self.selected_rule_index):
                    return
                
                # Save state for undo
                self.save_undo_state()
                
                # Add history entry
                rule_details = {
                    'line': self.selected_rule_index + 1, 
                    'rule_text': new_rule.to_string()
                }
                self.add_history_entry('rule_added', rule_details)
                
                # Replace the blank line with the new rule
                self.rules[self.selected_rule_index] = new_rule
                
                # Refresh and auto-detect variables
                self.refresh_table()
                self.modified = True
                self.auto_detect_variables()
                self.update_status_bar()
                
                messagebox.showinfo("Success", f"Rule added at line {updated_line_num} successfully.")
                
            except ValueError:
                messagebox.showerror("Error", "SID must be a valid number.")
            return
        
        if getattr(rule, 'is_comment', False):
            # Validate comment text for security
            try:
                validate_rule_input(comment=self.comment_var.get())
            except ValueError as e:
                messagebox.showerror("Security Validation Error", str(e))
                return
            
            # Save state for undo
            self.save_undo_state()
            
            # Save comment
            rule.comment_text = self.comment_var.get()
            self.refresh_table()
            self.modified = True
            self.update_status_bar()
            
            # Reselect the updated comment
            items = self.tree.get_children()
            if self.selected_rule_index is not None and self.selected_rule_index < len(items):
                self.tree.selection_set(items[self.selected_rule_index])
            
            messagebox.showinfo("Success", f"Comment at line {updated_line_num} updated successfully.")
        else:
            # Save rule
            try:
                # Validate rule inputs for security
                try:
                    validate_rule_input(
                        message=self.message_var.get(),
                        content=self.content_var.get()
                    )
                except ValueError as e:
                    messagebox.showerror("Security Validation Error", str(e))
                    return
                
                # Validate SID
                sid_str = self.sid_var.get().strip()
                if not sid_str:
                    messagebox.showerror("Error", "SID is required.")
                    return
                
                sid = int(sid_str)
                if not (SuricataConstants.SID_MIN <= sid <= SuricataConstants.SID_MAX):
                    messagebox.showerror("Error", f"SID must be between {SuricataConstants.SID_MIN} and {SuricataConstants.SID_MAX}.")
                    return
                
                # Check for duplicate SID (excluding current rule)
                if not self.validate_unique_sid(sid, self.selected_rule_index):
                    messagebox.showerror("Error", f"SID {sid} is already in use. Please choose a different SID.")
                    return
                
                # Validate network fields
                if not self.validate_network_field(self.src_net_var.get(), "Source Network"):
                    return
                if not self.validate_network_field(self.dst_net_var.get(), "Dest Network"):
                    return
                
                # Validate port fields
                if not self.validate_port_field(self.src_port_var.get(), "Source Port"):
                    return
                if not self.validate_port_field(self.dst_port_var.get(), "Dest Port"):
                    return
                
                # Check if any non-message fields changed to determine if rev should increment
                original_rule = self.rules[self.selected_rule_index]
                fields_changed = (
                    original_rule.action != self.action_var.get() or
                    original_rule.protocol != self.protocol_var.get() or
                    original_rule.src_net != self.src_net_var.get() or
                    original_rule.src_port != self.src_port_var.get() or
                    original_rule.dst_net != self.dst_net_var.get() or
                    original_rule.dst_port != self.dst_port_var.get() or
                    original_rule.content != self.content_var.get() or
                    original_rule.sid != sid
                )
                
                # Check if ONLY the message field changed (for filtering out message-only changes)
                message_only_change = (
                    not fields_changed and 
                    original_rule.message != self.message_var.get()
                )
                
                # Skip tracking if only message changed
                if message_only_change:
                    # Still update the rule but don't track the change
                    new_rev = original_rule.rev  # Don't increment rev for message-only changes
                    
                    # Create updated rule - reconstruct original_options from editor fields for message-only changes too
                    options_parts = []
                    if self.message_var.get():
                        options_parts.append(f'msg:"{self.message_var.get()}"')
                    if self.content_var.get():
                        # Strip trailing semicolon from content to prevent double semicolons
                        content_cleaned = self.content_var.get().rstrip(';')
                        options_parts.append(content_cleaned)
                    options_parts.append(f'sid:{sid}')
                    options_parts.append(f'rev:{new_rev}')
                    new_original_options = '; '.join(options_parts)
                    
                    updated_rule = SuricataRule(
                        action=self.action_var.get(),
                        protocol=self.protocol_var.get(),
                        src_net=self.src_net_var.get(),
                        src_port=self.src_port_var.get(),
                        dst_net=self.dst_net_var.get(),
                        dst_port=self.dst_port_var.get(),
                        message=self.message_var.get(),
                        content=self.content_var.get(),
                        sid=sid,
                        direction=self.direction_var.get(),
                        original_options=new_original_options,
                        rev=new_rev
                    )
                    
                    # Update the rule in the list without tracking
                    self.rules[self.selected_rule_index] = updated_rule
                    self.refresh_table()
                    self.modified = True
                    self.auto_detect_variables()
                    self.update_status_bar()
                    
                    # Reselect the updated rule
                    items = self.tree.get_children()
                    if self.selected_rule_index is not None and self.selected_rule_index < len(items):
                        self.tree.selection_set(items[self.selected_rule_index])
                    
                    messagebox.showinfo("Success", f"Rule at line {self.selected_rule_index + 1} updated successfully.")
                    return
                
                # Increment rev if any non-message fields changed
                new_rev = original_rule.rev + 1 if fields_changed else original_rule.rev
                
                # Create updated rule - reconstruct original_options from editor fields
                options_parts = []
                if self.message_var.get():
                    options_parts.append(f'msg:"{self.message_var.get()}"')
                if self.content_var.get():
                    # Strip trailing semicolon from content to prevent double semicolons
                    content_cleaned = self.content_var.get().rstrip(';')
                    options_parts.append(content_cleaned)
                options_parts.append(f'sid:{sid}')
                options_parts.append(f'rev:{new_rev}')
                new_original_options = '; '.join(options_parts)
                
                updated_rule = SuricataRule(
                    action=self.action_var.get(),
                    protocol=self.protocol_var.get(),
                    src_net=self.src_net_var.get(),
                    src_port=self.src_port_var.get(),
                    dst_net=self.dst_net_var.get(),
                    dst_port=self.dst_port_var.get(),
                    message=self.message_var.get(),
                    content=self.content_var.get(),
                    sid=sid,
                    direction=self.direction_var.get(),
                    original_options=new_original_options,
                    rev=new_rev
                )
                
                # AWS Network Firewall Quota Validation (Priority 1 & 2)
                # Validate total rule length with variable expansion
                if not self.validate_total_rule_length(updated_rule):
                    return
                
                # Validate IP Set References don't exceed 5
                if not self.validate_ip_set_references(updated_rule, exclude_index=self.selected_rule_index):
                    return
                
                # Save state for undo
                self.save_undo_state()
                
                # Capture detailed changes for history logging
                original_rule = self.rules[self.selected_rule_index]
                changes = self.compare_rules_for_changes(original_rule, updated_rule)
                
                # Add history entry with detailed change information
                history_details = {
                    'line': self.selected_rule_index + 1, 
                    'rule_text': updated_rule.to_string(),
                    'action': updated_rule.action,
                    'sid': updated_rule.sid,
                    'message': updated_rule.message
                }
                
                # Include detailed changes if any were captured
                if changes:
                    history_details['changes'] = changes
                
                self.add_history_entry('rule_modified', history_details)
                
                # Store line number before refresh (for message and reselection)
                updated_line_num = self.selected_rule_index + 1
                
                # Update the rule in the list
                self.rules[self.selected_rule_index] = updated_rule
                
                # Check if rule matches current filters
                filters_active = self.rule_filter.is_active()
                rule_matches_filters = self.rule_filter.matches(updated_rule)
                
                # If filters are active and updated rule doesn't match, clear filters
                if filters_active and not rule_matches_filters:
                    self.ui_manager.clear_filters()
                    messagebox.showinfo("Success", 
                        f"Rule at line {updated_line_num} updated successfully.\n\n" +
                        "Note: Filters were cleared because the updated rule no longer matches the active filter criteria.")
                    return
                
                self.refresh_table()
                self.modified = True
                # Auto-detect variables after rule changes
                self.auto_detect_variables()
                self.update_status_bar()
                
                # Reselect the updated rule
                items = self.tree.get_children()
                if self.selected_rule_index is not None and self.selected_rule_index < len(items):
                    self.tree.selection_set(items[self.selected_rule_index])
                
                messagebox.showinfo("Success", f"Rule at line {updated_line_num} updated successfully.")
                
            except ValueError:
                messagebox.showerror("Error", "SID must be a valid number.")
    
    def compare_rules_for_changes(self, original_rule, updated_rule):
        """Compare two rules and return detailed information about what changed
        
        Args:
            original_rule: The original SuricataRule object
            updated_rule: The updated SuricataRule object
            
        Returns:
            dict: Dictionary containing detailed change information
        """
        changes = {}
        
        # Compare each field and track changes (exclude rev changes per user requirements)
        if original_rule.action != updated_rule.action:
            changes['action'] = {'from': original_rule.action, 'to': updated_rule.action}
        
        if original_rule.protocol != updated_rule.protocol:
            changes['protocol'] = {'from': original_rule.protocol, 'to': updated_rule.protocol}
        
        if original_rule.src_net != updated_rule.src_net:
            changes['src_net'] = {'from': original_rule.src_net, 'to': updated_rule.src_net}
        
        if original_rule.src_port != updated_rule.src_port:
            changes['src_port'] = {'from': original_rule.src_port, 'to': updated_rule.src_port}
        
        if original_rule.direction != updated_rule.direction:
            changes['direction'] = {'from': original_rule.direction, 'to': updated_rule.direction}
        
        if original_rule.dst_net != updated_rule.dst_net:
            changes['dst_net'] = {'from': original_rule.dst_net, 'to': updated_rule.dst_net}
        
        if original_rule.dst_port != updated_rule.dst_port:
            changes['dst_port'] = {'from': original_rule.dst_port, 'to': updated_rule.dst_port}
        
        if original_rule.message != updated_rule.message:
            changes['message'] = {'from': original_rule.message, 'to': updated_rule.message}
        
        if original_rule.content != updated_rule.content:
            changes['content'] = {'from': original_rule.content, 'to': updated_rule.content}
        
        if original_rule.sid != updated_rule.sid:
            changes['sid'] = {'from': original_rule.sid, 'to': updated_rule.sid}
        
        # Note: rev changes are intentionally excluded from change tracking per user requirements
        
        return changes
    
    def save_undo_state(self):
        """Save current state for undo functionality"""
        import copy
        self.undo_state = copy.deepcopy(self.rules)
    
    def undo_last_change(self):
        """Undo the last change made to the rules"""
        if self.undo_state is None:
            messagebox.showinfo("Undo", "No changes to undo.")
            return
        
        # Add history entry for the undo action (before restoring state)
        current_rule_count = len([r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)])
        
        # Restore the previous state
        self.rules = self.undo_state
        self.undo_state = None
        
        # Calculate rule count after undo for tracking
        undone_rule_count = len([r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)])
        
        # Add history entry for the undo operation
        self.add_history_entry('undo_performed', {
            'rules_before': current_rule_count,
            'rules_after': undone_rule_count,
            'rules_changed': abs(undone_rule_count - current_rule_count)
        })
        
        self.refresh_table()
        self.modified = True
        self.update_status_bar()
    
    def on_tree_click(self, event):
        """Handle clicks on the tree to manage rule selection and insertion
        
        This method handles three types of clicks:
        1. Empty area clicks - show placeholder for new rule insertion
        2. Placeholder clicks - set up editor for new rule creation
        3. Existing rule clicks - select rule or toggle selection for copy/paste workflow
        """
        # Determine if click is on an existing item or empty area
        item = self.tree.identify_row(event.y)
        if not item:
            # Click in empty area below rules - just clear selection and hide editor
            self.tree.selection_remove(self.tree.selection())  # Clear any selection
            if not self.placeholder_item:  # Only add if doesn't exist
                self.add_placeholder_row()  # Add placeholder
            self.selected_rule_index = None  # Clear selection
            self.ui_manager.hide_all_editor_fields()  # Hide editor for empty area clicks
        elif item == self.placeholder_item:
            # Click on placeholder - keep it and set up for new rule insertion
            self.tree.selection_remove(self.tree.selection())  # Clear any selection
            self.selected_rule_index = len(self.rules)  # Set insertion point
            self.ui_manager.show_rule_editor()  # Show editor fields
            self.set_default_editor_values()  # Populate with defaults
            # Auto-generate next available SID for convenience
            max_sid = max([rule.sid for rule in self.rules], default=99)
            self.sid_var.set(str(max_sid + 1))
        else:
            # Check if clicking on already selected item to toggle selection
            current_selection = self.tree.selection()
            if len(current_selection) == 1 and current_selection[0] == item:
                # Toggle off - deselect the item and schedule deselection after event processing
                # Use after_idle to avoid conflict with TreeviewSelect event
                self.root.after_idle(lambda: self.deselect_item(item))
                return
            
            # Click on existing rule - clean up placeholder only if it exists
            if self.placeholder_item:
                self.remove_placeholder_row()
    
    def insert_new_rule_from_editor(self):
        """Insert a new rule from the editor fields"""
        try:
            # Validate rule inputs for security
            try:
                validate_rule_input(
                    message=self.message_var.get(),
                    content=self.content_var.get()
                )
            except ValueError as e:
                messagebox.showerror("Security Validation Error", str(e))
                return
            
            # Validate SID
            sid_str = self.sid_var.get().strip()
            if not sid_str:
                messagebox.showerror("Error", "SID is required.")
                return
            
            sid = int(sid_str)
            if not (SuricataConstants.SID_MIN <= sid <= SuricataConstants.SID_MAX):
                messagebox.showerror("Error", f"SID must be between {SuricataConstants.SID_MIN} and {SuricataConstants.SID_MAX}.")
                return
            
            # Validate network fields
            if not self.validate_network_field(self.src_net_var.get(), "Source Network"):
                return
            if not self.validate_network_field(self.dst_net_var.get(), "Dest Network"):
                return
            
            # Validate port fields
            if not self.validate_port_field(self.src_port_var.get(), "Source Port"):
                return
            if not self.validate_port_field(self.dst_port_var.get(), "Dest Port"):
                return
            
            # Create new rule from editor fields
            options_parts = []
            if self.message_var.get():
                options_parts.append(f'msg:"{self.message_var.get()}"')
            if self.content_var.get():
                # Strip trailing semicolon from content to prevent double semicolons
                content_cleaned = self.content_var.get().rstrip(';')
                options_parts.append(content_cleaned)
            options_parts.append(f'sid:{sid}')
            options_parts.append(f'rev:1')
            original_options = '; '.join(options_parts)
            
            new_rule = SuricataRule(
                action=self.action_var.get(),
                protocol=self.protocol_var.get(),
                src_net=self.src_net_var.get(),
                src_port=self.src_port_var.get(),
                dst_net=self.dst_net_var.get(),
                dst_port=self.dst_port_var.get(),
                message=self.message_var.get(),
                content=self.content_var.get(),
                sid=sid,
                direction=self.direction_var.get(),
                original_options=original_options
            )
            
            # AWS Network Firewall Quota Validation (Priority 1 & 2)
            # Validate total rule length with variable expansion
            if not self.validate_total_rule_length(new_rule):
                return
            
            # Validate IP Set References don't exceed 5
            if not self.validate_ip_set_references(new_rule):
                return
            
            # Save state for undo
            self.save_undo_state()
            
            # Add history entry with simplified rule information
            rule_details = {
                'line': self.selected_rule_index + 1, 
                'rule_text': new_rule.to_string()
            }
            self.add_history_entry('rule_added', rule_details)
            
            # Insert the rule
            self.rules.insert(self.selected_rule_index, new_rule)
            
            # If filters are active and new rule doesn't match, temporarily clear filters so user can see their new rule
            filters_were_active = self.rule_filter.is_active()
            if filters_were_active and not self.rule_filter.matches(new_rule):
                # Clear filters temporarily
                self.ui_manager.clear_filters()
                messagebox.showinfo("Success", 
                    f"Rule inserted successfully at line {self.selected_rule_index + 1}.\n\n" +
                    "Note: Filters were cleared because the new rule didn't match the active filter criteria.")
            else:
                self.refresh_table(preserve_selection=False)
                messagebox.showinfo("Success", f"Rule inserted successfully. Click below the last rule to add another.")
            
            self.modified = True
            # Auto-detect variables after rule insertion
            self.auto_detect_variables()
            
            # Clear selection and set up for next insertion
            self.tree.selection_remove(self.tree.selection())
            
            # Remove existing placeholder first, then add new one
            self.remove_placeholder_row()
            self.add_placeholder_row()
            self.selected_rule_index = len(self.rules)  # Set to end for next insertion
            
            # Set up editor for next rule with new SID
            self.set_default_editor_values()
            max_sid = max([rule.sid for rule in self.rules], default=99)
            self.sid_var.set(str(max_sid + 1))
            
        except ValueError:
            messagebox.showerror("Error", "SID must be a valid number.")
    
    def insert_comment(self):
        """Insert a comment at selected position or end"""
        selection = self.tree.selection()
        if selection:
            # Get the actual line number from tree (important when filters are active)
            selected_item = selection[0]
            values = self.tree.item(selected_item, 'values')
            if values and values[0]:
                # Convert 1-based line number to 0-based index
                insert_index = int(values[0]) - 1
            else:
                messagebox.showerror("Error", "Could not determine insert position.")
                return
        else:
            insert_index = len(self.rules)
        
        # Create custom dialog for comment input
        dialog = tk.Toplevel(self.root)
        dialog.title("Insert Comment")
        dialog.geometry("800x120")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(True, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        result = [None]
        
        # Label
        ttk.Label(dialog, text="Enter comment text:").pack(pady=10)
        
        # Text entry
        comment_var = tk.StringVar(value="<insert comment here>")
        entry = ttk.Entry(dialog, textvariable=comment_var, width=100)
        entry.pack(fill=tk.X, padx=10, pady=5)
        entry.focus()
        entry.select_range(0, tk.END)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def on_ok():
            result[0] = comment_var.get()
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key
        dialog.bind('<Return>', lambda e: on_ok())
        
        dialog.wait_window()
        
        if result[0] is not None:
            # Validate comment text for security
            try:
                validate_rule_input(comment=result[0])
            except ValueError as e:
                messagebox.showerror("Security Validation Error", str(e))
                return
            
            # Save state for undo
            self.save_undo_state()
            
            # Create comment rule
            comment_rule = SuricataRule()
            comment_rule.is_comment = True
            comment_rule.comment_text = f"# {result[0]}"
            
            # Insert comment
            self.rules.insert(insert_index, comment_rule)
            self.refresh_table()
            self.modified = True
            self.update_status_bar()
            
            messagebox.showinfo("Success", f"Comment inserted at line {insert_index + 1} successfully.")
    
    def add_placeholder_row(self):
        """Add a placeholder row at the end for new rule insertion"""
        if self.placeholder_item:
            return  # Already exists
        
        line_num = len(self.rules) + 1
        values = (line_num, "", "", "<click to add rule>")
        self.placeholder_item = self.tree.insert("", tk.END, values=values, tags=("comment",))
        
        # Force UI update to ensure placeholder is visible
        self.root.update_idletasks()
    
    def on_column_resize(self, event):
        """Handle column resize events to restore placeholder row"""
        self.restore_placeholder_if_needed()
    
    def on_tree_configure(self, event):
        """Handle tree configure events (including after redraw) to restore placeholder"""
        # Use after_idle to avoid duplicate placeholders during rapid events
        self.root.after_idle(self.restore_placeholder_if_needed)
    
    def restore_placeholder_if_needed(self):
        """Restore placeholder row if conditions are met"""
        if len(self.rules) > 0 and not self.placeholder_item:
            # Only restore if placeholder doesn't exist
            self.root.after_idle(self.add_placeholder_row)
    
    def on_double_click(self, event):
        """Handle double-click events on tree items"""
        item = self.tree.identify_row(event.y)
        if item == self.placeholder_item:
            # Double-click on placeholder - show insert rule dialog
            self.insert_rule()
        else:
            # Double-click on regular rule - show edit dialog
            self.edit_selected_rule()
    
    def on_key_down(self, event):
        """Handle Down arrow key to navigate to placeholder when at last rule"""
        # Only handle if the tree has focus
        if self.root.focus_get() != self.tree:
            return
        
        selection = self.tree.selection()
        if not selection or not self.placeholder_item:
            return
        
        selected_item = selection[0]
        all_items = self.tree.get_children()
        
        # If we have rules and a placeholder
        if len(all_items) >= 2:
            # Check if we're on the last actual rule (not the placeholder)
            last_rule_item = all_items[-2]  # Second to last (placeholder is last)
            if selected_item == last_rule_item:
                # Move to placeholder
                self.tree.selection_set(self.placeholder_item)
                self.tree.focus(self.placeholder_item)
                return 'break'
    
    def on_key_end(self, event):
        """Handle End key to navigate to placeholder"""
        # Only handle if the tree has focus
        if self.root.focus_get() != self.tree:
            return
        
        if self.placeholder_item:
            self.tree.selection_set(self.placeholder_item)
            self.tree.focus(self.placeholder_item)
            self.tree.see(self.placeholder_item)  # Scroll to show the placeholder
            return 'break'
    
    def on_key_home(self, event):
        """Handle Home key to navigate to first line"""
        # Only handle if the tree has focus
        if self.root.focus_get() != self.tree:
            return
        
        all_items = self.tree.get_children()
        if all_items:
            first_item = all_items[0]
            self.tree.selection_set(first_item)
            self.tree.focus(first_item)
            self.tree.see(first_item)  # Scroll to show the first item
            return 'break'
    
    def on_delete_key(self, event):
        """Handle Delete key - only delete rules when tree view has focus"""
        # Only delete rules if the tree view has focus
        if self.root.focus_get() == self.tree:
            self.delete_selected_rule()
        # If focus is elsewhere (like text entry fields), let the default behavior handle it
    
    def select_all_rules(self):
        """Select all rules in the tree (excludes placeholder)"""
        # Clear any existing selection first
        self.tree.selection_remove(self.tree.selection())
        
        all_items = self.tree.get_children()
        if all_items:
            # Filter out placeholder item if it exists
            items_to_select = [item for item in all_items if item != self.placeholder_item]
            if items_to_select:
                # Add each item to selection
                for item in items_to_select:
                    self.tree.selection_add(item)
                # Focus on first selected item
                self.tree.focus(items_to_select[0])
    
    def remove_placeholder_row(self):
        """Remove the placeholder row if it exists"""
        if self.placeholder_item:
            try:
                self.tree.delete(self.placeholder_item)
            except tk.TclError:
                pass  # Item may already be deleted
            self.placeholder_item = None
    
    def on_space_key(self, event):
        """Handle Space key - only toggle rules when tree view has focus"""
        # Only toggle rules if the tree view has focus
        if self.root.focus_get() == self.tree:
            self.toggle_rule_disabled()
            return 'break'  # Prevent default space behavior
        # If focus is elsewhere, let the default behavior handle it
    
    def toggle_rule_disabled(self):
        """Toggle selected rules between enabled (rule) and disabled (comment) state"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select one or more rules to toggle.")
            return
        
        # Save state for undo
        self.save_undo_state()
        
        # Get ACTUAL indices using line numbers from tree (critical when filters active)
        indices = []
        for item in selection:
            values = self.tree.item(item, 'values')
            if values and values[0]:
                # Convert 1-based line number to 0-based index
                actual_index = int(values[0]) - 1
                indices.append(actual_index)
        
        # Track changes for history
        enabled_rules = []
        disabled_rules = []
        
        # Process each selected rule
        for index in indices:
            if index < len(self.rules):
                rule = self.rules[index]
                
                if getattr(rule, 'is_comment', False):
                    # Try to convert comment back to rule if it contains directional indicators
                    comment_text = rule.comment_text.strip()
                    if comment_text.startswith('# '):
                        potential_rule_text = comment_text[2:]  # Remove "# "
                        
                        # Check if it contains directional indicators
                        if any(direction in potential_rule_text for direction in ['->', '<>']):
                            try:
                                # Try to parse it back into a rule
                                restored_rule = SuricataRule.from_string(potential_rule_text)
                                if restored_rule:
                                    self.rules[index] = restored_rule
                                    enabled_rules.append({
                                        'line': index + 1,
                                        'action': restored_rule.action,
                                        'sid': restored_rule.sid,
                                        'message': restored_rule.message
                                    })
                            except:
                                # If parsing fails, leave as comment
                                pass
                elif getattr(rule, 'is_blank', False):
                    # Skip blank lines
                    continue
                else:
                    # Convert rule to comment (disable)
                    comment_rule = SuricataRule()
                    comment_rule.is_comment = True
                    comment_rule.comment_text = f"# {rule.to_string()}"
                    self.rules[index] = comment_rule
                    disabled_rules.append({
                        'line': index + 1,
                        'action': rule.action,
                        'sid': rule.sid,
                        'message': rule.message
                    })
        
        # Add history entries for tracking
        if enabled_rules:
            self.add_history_entry('rules_enabled', {'count': len(enabled_rules), 'rules': enabled_rules})
        if disabled_rules:
            self.add_history_entry('rules_disabled', {'count': len(disabled_rules), 'rules': disabled_rules})
        
        # Refresh table and update status
        self.refresh_table()
        self.modified = True
        self.update_status_bar()
        
        # Show feedback message
        count = len([i for i in indices if i < len(self.rules)])
        rule_text = "rule" if count == 1 else "rules"
        messagebox.showinfo("Toggle Complete", f"Toggled {count} {rule_text} between enabled/disabled state.")
    
    def on_ctrl_g_key(self, event):
        """Handle Ctrl+G key - only show dialog when tree view has focus"""
        # Only show dialog if the tree view has focus
        if self.root.focus_get() == self.tree:
            self.show_jump_to_line_dialog()
            return 'break'  # Prevent default behavior
        # If focus is elsewhere, let the default behavior handle it
    
    def show_jump_to_line_dialog(self):
        """Show dialog to jump to a specific line number"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Go to Line")
        dialog.geometry("300x120")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 200, self.root.winfo_rooty() + 200))
        
        # Calculate total lines (including comments and blanks)
        total_lines = len(self.rules)
        if self.placeholder_item:
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
                    if self.placeholder_item:
                        self.tree.selection_set(self.placeholder_item)
                        self.tree.focus(self.placeholder_item)
                        self.tree.see(self.placeholder_item)
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
    

    

    
    def show_sid_management(self):
        """Show SID Management dialog for bulk SID renumbering"""
        if not self.rules:
            messagebox.showinfo("SID Management", "No rules to manage.")
            return
        
        # Determine which rules to work with - selected rules or all rules
        selection = self.tree.selection()
        if selection:
            # Use selected rules - get ACTUAL indices using line numbers (critical when filters active)
            selected_indices = []
            for item in selection:
                values = self.tree.item(item, 'values')
                if values and values[0]:
                    selected_indices.append(int(values[0]) - 1)  # Convert 1-based to 0-based
            
            selected_rules = [self.rules[i] for i in selected_indices if i < len(self.rules)]
            actual_rules = [r for r in selected_rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
            scope_default = "selected"
        else:
            # Use all rules
            actual_rules = [r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
            scope_default = "all"
        
        if not actual_rules:
            messagebox.showinfo("SID Management", "No rules with SIDs to manage.")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("SID Management")
        dialog.geometry("600x650")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 100, self.root.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title
        title_label = ttk.Label(main_frame, text="Bulk SID Renumbering", font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Current SID info
        current_sids = [r.sid for r in actual_rules]
        min_sid = min(current_sids)
        max_sid = max(current_sids)
        info_frame = ttk.LabelFrame(main_frame, text="Current SID Information")
        info_frame.pack(fill=tk.X, pady=(0, 15))
        
        scope_text = "Selected Rules" if scope_default == "selected" else "All Rules"
        ttk.Label(info_frame, text=f"Scope: {scope_text}").pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(info_frame, text=f"Total Rules: {len(actual_rules)}").pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(info_frame, text=f"Current SID Range: {min_sid} - {max_sid}").pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(info_frame, text=f"SID Gaps: {max_sid - min_sid + 1 - len(actual_rules)}").pack(anchor=tk.W, padx=10, pady=(2, 10))
        
        # Renumbering options
        options_frame = ttk.LabelFrame(main_frame, text="Renumbering Options")
        options_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Starting SID
        start_frame = ttk.Frame(options_frame)
        start_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(start_frame, text="Starting SID:").pack(side=tk.LEFT)
        start_var = tk.StringVar(value="100")
        start_entry = ttk.Entry(start_frame, textvariable=start_var, width=10)
        start_entry.pack(side=tk.LEFT, padx=(10, 0))
        
        # Increment
        increment_frame = ttk.Frame(options_frame)
        increment_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(increment_frame, text="Increment:").pack(side=tk.LEFT)
        increment_var = tk.StringVar(value="10")
        increment_entry = ttk.Entry(increment_frame, textvariable=increment_var, width=10)
        increment_entry.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(increment_frame, text="(gap between SIDs)", font=("TkDefaultFont", 8)).pack(side=tk.LEFT, padx=(5, 0))
        
        # Scope options
        scope_frame = ttk.LabelFrame(main_frame, text="Scope")
        scope_frame.pack(fill=tk.X, pady=(0, 15))
        
        scope_var = tk.StringVar(value=scope_default)
        
        # Create radio buttons with conditional state
        all_radio = ttk.Radiobutton(scope_frame, text="All rules", variable=scope_var, value="all")
        all_radio.pack(anchor=tk.W, padx=10, pady=2)
        
        selected_radio = ttk.Radiobutton(scope_frame, text="Selected rules only", variable=scope_var, value="selected")
        selected_radio.pack(anchor=tk.W, padx=10, pady=2)
        
        # Disable appropriate options based on selection state
        if selection:  # Rules are selected
            all_radio.config(state="disabled")
        else:  # No rules selected
            selected_radio.config(state="disabled")
        
        # Action type scope with dropdown
        action_frame = ttk.Frame(scope_frame)
        action_frame.pack(fill=tk.X, padx=10, pady=2)
        
        action_radio = ttk.Radiobutton(action_frame, text="Rules by action type:", variable=scope_var, value="action")
        action_radio.pack(side=tk.LEFT)
        
        # Get available actions from current rules
        all_rules = [r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        available_actions = sorted(list(set(r.action for r in all_rules)))
        
        action_var = tk.StringVar(value=available_actions[0] if available_actions else "pass")
        action_combo = ttk.Combobox(action_frame, textvariable=action_var, values=available_actions, 
                                   state="readonly", width=10)
        action_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        # Conflict check section
        conflict_frame = ttk.Frame(main_frame)
        conflict_frame.pack(fill=tk.X, pady=(0, 10))
        
        check_button = ttk.Button(conflict_frame, text="Check for Conflicts")
        check_button.pack(side=tk.LEFT)
        
        conflict_status = ttk.Label(conflict_frame, text="", font=("TkDefaultFont", 9))
        conflict_status.pack(side=tk.LEFT, padx=(10, 0))
        
        # Preview section
        preview_frame = ttk.LabelFrame(main_frame, text="Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        preview_text = tk.Text(preview_frame, height=8, wrap=tk.WORD, font=("Consolas", 9))
        preview_scrollbar = ttk.Scrollbar(preview_frame, orient=tk.VERTICAL, command=preview_text.yview)
        preview_text.configure(yscrollcommand=preview_scrollbar.set)
        
        preview_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        preview_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Update preview function (placeholder)
        def update_preview():
            preview_text.delete(1.0, tk.END)
            try:
                start_sid = int(start_var.get())
                increment = int(increment_var.get())
                scope = scope_var.get()
                
                preview_text.insert(tk.END, f"Preview: Starting SID {start_sid}, increment {increment}\n")
                
                # Determine which rules to preview based on scope
                if scope == "all":
                    preview_rules = actual_rules
                    preview_text.insert(tk.END, f"Scope: All rules\n\n")
                elif scope == "selected":
                    preview_rules = actual_rules  # actual_rules already filtered for selected
                    preview_text.insert(tk.END, f"Scope: Selected rules\n\n")
                elif scope == "action":
                    selected_action = action_var.get()
                    all_rules_for_action = [r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
                    preview_rules = [r for r in all_rules_for_action if r.action == selected_action]
                    preview_text.insert(tk.END, f"Scope: {selected_action.upper()} rules only ({len(preview_rules)} rules)\n\n")
                else:
                    preview_rules = []
                
                # Show first few examples
                rules_to_show = preview_rules[:5]
                current_sid = start_sid
                
                for i, rule in enumerate(rules_to_show):
                    old_sid = rule.sid
                    preview_text.insert(tk.END, f"Rule {i+1}: SID {old_sid} → {current_sid} ({rule.action})\n")
                    current_sid += increment
                
                if len(preview_rules) > 5:
                    preview_text.insert(tk.END, f"... and {len(preview_rules) - 5} more rules\n")
                elif len(preview_rules) == 0:
                    preview_text.insert(tk.END, "No rules match the selected scope\n")
                    
            except ValueError:
                preview_text.insert(tk.END, "Invalid input values")
        
        # Conflict detection function
        def check_conflicts():
            try:
                start_sid = int(start_var.get())
                increment = int(increment_var.get())
                scope = scope_var.get()
                
                # Get all actual rules (non-comment, non-blank)
                all_actual_rules = [r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
                
                # Determine which rules would be renumbered based on scope
                if scope == "all":
                    rules_to_renumber = all_actual_rules
                elif scope == "selected":
                    rules_to_renumber = actual_rules
                elif scope == "action":
                    selected_action = action_var.get()
                    rules_to_renumber = [r for r in all_actual_rules if r.action == selected_action]
                else:
                    rules_to_renumber = []
                
                # Get SIDs of rules that would be renumbered (to exclude from conflict check)
                renumber_sids = set(r.sid for r in rules_to_renumber)
                
                # Get SIDs of all existing rules that would NOT be renumbered
                existing_sids = set(r.sid for r in all_actual_rules if r.sid not in renumber_sids)
                
                # Calculate new SIDs and check for conflicts
                conflicts = []
                current_sid = start_sid
                for i, rule in enumerate(rules_to_renumber):
                    if current_sid in existing_sids:
                        # Find the conflicting rule
                        conflicting_rule = next(r for r in all_actual_rules if r.sid == current_sid and r.sid not in renumber_sids)
                        rule_line = self.rules.index(conflicting_rule) + 1
                        conflicts.append((current_sid, rule_line))
                    current_sid += increment
                
                # Update status display
                if conflicts:
                    conflict_status.config(text=f"⚠️ {len(conflicts)} conflicts detected", foreground="orange")
                    show_conflict_dialog(conflicts, start_sid, increment)
                else:
                    conflict_status.config(text="✅ No conflicts", foreground="green")
                    
            except ValueError:
                conflict_status.config(text="❌ Invalid input values", foreground="red")
        
        # Conflict resolution dialog
        def show_conflict_dialog(conflicts, start_sid, increment):
            conflict_dialog = tk.Toplevel(dialog)
            conflict_dialog.title("SID Conflicts Detected")
            conflict_dialog.geometry("500x350")
            conflict_dialog.transient(dialog)
            conflict_dialog.grab_set()
            
            # Center on parent dialog
            conflict_dialog.geometry("+%d+%d" % (dialog.winfo_rootx() + 50, dialog.winfo_rooty() + 50))
            
            main_cf = ttk.Frame(conflict_dialog)
            main_cf.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
            
            # Warning header
            ttk.Label(main_cf, text="⚠️ SID Conflicts Detected", font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 10))
            
            # Conflict details
            details_frame = ttk.LabelFrame(main_cf, text="Conflicts")
            details_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
            
            details_text = tk.Text(details_frame, height=6, wrap=tk.WORD, font=("Consolas", 9))
            details_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=details_text.yview)
            details_text.configure(yscrollcommand=details_scroll.set)
            
            details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
            details_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
            
            # Show conflict details
            details_text.insert(tk.END, "The requested renumbering would create these conflicts:\n\n")
            for new_sid, rule_line in conflicts:
                details_text.insert(tk.END, f"• SID {new_sid} would be assigned to multiple rules (conflict with line {rule_line})\n")
            
            details_text.config(state=tk.DISABLED)
            
            # Resolution options
            resolution_frame = ttk.LabelFrame(main_cf, text="Choose Resolution")
            resolution_frame.pack(fill=tk.X, pady=(0, 15))
            
            resolution_var = tk.StringVar(value="skip")
            ttk.Radiobutton(resolution_frame, text="Skip conflicting SIDs (find next available)", 
                           variable=resolution_var, value="skip").pack(anchor=tk.W, padx=10, pady=2)
            
            # Calculate safe starting SID (beyond all existing SIDs that won't be renumbered)
            all_existing_sids = set(r.sid for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False))
            safe_start = max(all_existing_sids) + 10 if all_existing_sids else start_sid
            ttk.Radiobutton(resolution_frame, text=f"Start at SID {safe_start} (no conflicts)", 
                           variable=resolution_var, value="restart").pack(anchor=tk.W, padx=10, pady=2)
            
            ttk.Radiobutton(resolution_frame, text="Overwrite existing rules (⚠️ will modify other rules)", 
                           variable=resolution_var, value="overwrite").pack(anchor=tk.W, padx=10, pady=2)
            
            # Buttons
            button_cf = ttk.Frame(main_cf)
            button_cf.pack(fill=tk.X)
            
            def apply_resolution():
                """Apply the selected conflict resolution strategy"""
                resolution = resolution_var.get()
                if resolution == "restart":
                    # Update starting SID to safe value and refresh preview
                    start_var.set(str(safe_start))
                    update_preview()
                    conflict_resolution["strategy"] = "restart"
                elif resolution == "skip":
                    # Store strategy for Apply logic to handle
                    conflict_resolution["strategy"] = "skip"
                elif resolution == "overwrite":
                    # Store strategy for Apply logic to handle
                    conflict_resolution["strategy"] = "overwrite"
                
                conflict_dialog.destroy()
            
            ttk.Button(button_cf, text="Apply", command=apply_resolution).pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(button_cf, text="Cancel", command=conflict_dialog.destroy).pack(side=tk.RIGHT)
        
        # Function to clear conflict status when settings change
        def clear_conflict_status(*args):
            conflict_status.config(text="", foreground="black")
            update_preview()
        
        # Bind button command
        check_button.config(command=check_conflicts)
        
        # Bind update events to clear status and update preview
        start_var.trace('w', clear_conflict_status)
        increment_var.trace('w', clear_conflict_status)
        scope_var.trace('w', clear_conflict_status)
        action_var.trace('w', clear_conflict_status)
        
        # Initial preview
        update_preview()
        
        # Store conflict resolution strategy
        conflict_resolution = {"strategy": "none"}
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def on_apply():
            """Apply the SID renumbering with conflict resolution"""
            try:
                start_sid = int(start_var.get())
                increment = int(increment_var.get())
                scope = scope_var.get()
                
                # Validate input values
                if start_sid < SuricataConstants.SID_MIN or start_sid > SuricataConstants.SID_MAX:
                    messagebox.showerror("Error", f"Starting SID must be between {SuricataConstants.SID_MIN} and {SuricataConstants.SID_MAX}.")
                    return
                if increment < 1 or increment > 1000:
                    messagebox.showerror("Error", "Increment must be between 1 and 1000.")
                    return
                
                # Get all actual rules (non-comment, non-blank)
                all_actual_rules = [r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
                
                # Determine which rules to renumber based on scope
                if scope == "all":
                    rules_to_renumber = all_actual_rules
                    scope_description = "all rules"
                elif scope == "selected":
                    rules_to_renumber = actual_rules
                    scope_description = "selected rules"
                elif scope == "action":
                    selected_action = action_var.get()
                    rules_to_renumber = [r for r in all_actual_rules if r.action == selected_action]
                    scope_description = f"{selected_action} rules"
                else:
                    messagebox.showerror("Error", "Please select a valid scope.")
                    return
                
                if not rules_to_renumber:
                    messagebox.showwarning("Warning", "No rules found matching the selected scope.")
                    return
                
                # Final confirmation dialog
                rule_count = len(rules_to_renumber)
                confirm_msg = f"Apply SID renumbering to {rule_count} {scope_description}?\n\n"
                confirm_msg += f"Starting SID: {start_sid}\n"
                confirm_msg += f"Increment: {increment}\n\n"
                confirm_msg += "This operation can be undone with Ctrl+Z."
                
                if not messagebox.askyesno("Confirm SID Renumbering", confirm_msg):
                    return
                
                # Save state for undo functionality (critical for bulk operations)
                self.save_undo_state()
                
                # Close main dialog and show progress dialog
                dialog.destroy()
                
                # Create progress dialog
                progress_dialog = tk.Toplevel(self.root)
                progress_dialog.title("Renumbering SIDs")
                progress_dialog.geometry("400x120")
                progress_dialog.transient(self.root)
                progress_dialog.grab_set()
                progress_dialog.resizable(False, False)
                
                # Center the progress dialog
                progress_dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 200, self.root.winfo_rooty() + 200))
                
                # Progress frame
                progress_frame = ttk.Frame(progress_dialog)
                progress_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
                
                # Status label
                status_label = ttk.Label(progress_frame, text=f"Renumbering {rule_count} rules...")
                status_label.pack(pady=(0, 10))
                
                # Progress bar
                progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=350)
                progress_bar.pack(pady=(0, 10))
                
                # Progress text label
                progress_text = ttk.Label(progress_frame, text="0%")
                progress_text.pack()
                
                # Force dialog to display
                progress_dialog.update()
                
                # Apply the SID renumbering with conflict resolution
                current_sid = start_sid
                updated_count = 0
                all_existing_sids = set(r.sid for r in all_actual_rules)
                
                for idx, rule in enumerate(rules_to_renumber):
                    # Update progress bar
                    progress = ((idx + 1) / rule_count) * 100
                    progress_bar['value'] = progress
                    progress_text.config(text=f"{int(progress)}% ({idx + 1}/{rule_count} rules)")
                    progress_dialog.update()
                    # Handle conflict resolution strategies
                    if conflict_resolution["strategy"] == "skip":
                        # Skip conflicting SIDs - find next available
                        while current_sid in all_existing_sids and current_sid != rule.sid:
                            current_sid += 1
                            if current_sid > 999999999:  # Prevent infinite loop
                                messagebox.showerror("Error", "Cannot find available SID - reached maximum SID value.")
                                return
                    elif conflict_resolution["strategy"] == "overwrite":
                        # Overwrite existing SIDs - update conflicting rules first
                        existing_rule_with_sid = next((r for r in all_actual_rules if r.sid == current_sid and r != rule), None)
                        if existing_rule_with_sid:
                            # Find a safe SID for the displaced rule
                            safe_sid = max(all_existing_sids) + 1
                            existing_rule_with_sid.sid = safe_sid
                            if existing_rule_with_sid.original_options:
                                import re
                                existing_rule_with_sid.original_options = re.sub(r'sid:\d+', f'sid:{safe_sid}', existing_rule_with_sid.original_options)
                            all_existing_sids.add(safe_sid)
                            updated_count += 1
                    
                    # Only update if SID is actually changing
                    if rule.sid != current_sid:
                        # Remove old SID from tracking set
                        all_existing_sids.discard(rule.sid)
                        
                        # Update the rule's SID
                        rule.sid = current_sid
                        
                        # Update the original_options string to maintain proper formatting
                        if rule.original_options:
                            import re
                            rule.original_options = re.sub(r'sid:\d+', f'sid:{current_sid}', rule.original_options)
                        
                        # Add new SID to tracking set
                        all_existing_sids.add(current_sid)
                        updated_count += 1
                    
                    # Move to next SID for next rule
                    current_sid += increment
                
                # Close progress dialog
                progress_dialog.destroy()
                
                # Refresh the UI to show changes
                self.refresh_table()
                self.modified = True
                self.update_status_bar()
                
                # Show completion message
                if updated_count > 0:
                    messagebox.showinfo("SID Renumbering Complete", 
                                      f"Successfully renumbered {updated_count} of {rule_count} rules.\n\n"
                                      f"Use Ctrl+Z to undo if needed.")
                else:
                    messagebox.showinfo("SID Renumbering Complete", 
                                      "No SID changes were needed - all rules already had the target SIDs.")
                
            except ValueError as e:
                messagebox.showerror("Error", "Invalid input values. Please check Starting SID and Increment fields.")
            except ValueError as e:
                messagebox.showerror("Input Error", "Invalid input values. Please check Starting SID and Increment fields.")
            except OverflowError:
                messagebox.showerror("Input Error", "SID values are too large.")
            except Exception as e:
                messagebox.showerror("SID Management Error", f"An error occurred during SID renumbering: {str(e)}")
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Apply", command=on_apply).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT)
        
        # Focus on starting SID entry
        start_entry.focus()
        start_entry.select_range(0, tk.END)
    

    
    def analyze_advanced_editor_changes(self, original_rules, new_rules):
        """Analyze changes made in Advanced Editor and return summary
        
        Args:
            original_rules: List of rules before Advanced Editor
            new_rules: List of rules after Advanced Editor
            
        Returns:
            dict: Summary of changes with statistics and details
        """
        # Count actual rules (non-comment, non-blank)
        original_actual = [r for r in original_rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        new_actual = [r for r in new_rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        original_count = len(original_actual)
        new_count = len(new_actual)
        
        # Calculate basic statistics
        rules_added = new_count - original_count if new_count > original_count else 0
        rules_deleted = original_count - new_count if original_count > new_count else 0
        
        # Track modified rules by comparing SIDs
        original_sids = {r.sid: r for r in original_actual}
        new_sids = {r.sid: r for r in new_actual}
        
        rules_modified = 0
        for sid, new_rule in new_sids.items():
            if sid in original_sids:
                original_rule = original_sids[sid]
                # Check if rule content changed (excluding rev)
                if (original_rule.action != new_rule.action or
                    original_rule.protocol != new_rule.protocol or
                    original_rule.src_net != new_rule.src_net or
                    original_rule.src_port != new_rule.src_port or
                    original_rule.dst_net != new_rule.dst_net or
                    original_rule.dst_port != new_rule.dst_port or
                    original_rule.content != new_rule.content or
                    original_rule.message != new_rule.message):
                    rules_modified += 1
        
        # Calculate SID ranges
        original_sid_range = None
        new_sid_range = None
        if original_actual:
            original_sids_list = [r.sid for r in original_actual]
            original_sid_range = (min(original_sids_list), max(original_sids_list))
        if new_actual:
            new_sids_list = [r.sid for r in new_actual]
            new_sid_range = (min(new_sids_list), max(new_sids_list))
        
        # Calculate action distribution changes
        original_actions = {}
        for rule in original_actual:
            action = rule.action.lower()
            original_actions[action] = original_actions.get(action, 0) + 1
        
        new_actions = {}
        for rule in new_actual:
            action = rule.action.lower()
            new_actions[action] = new_actions.get(action, 0) + 1
        
        return {
            'rules_before': original_count,
            'rules_after': new_count,
            'rules_added': rules_added,
            'rules_deleted': rules_deleted,
            'rules_modified': rules_modified,
            'original_sid_range': original_sid_range,
            'new_sid_range': new_sid_range,
            'original_actions': original_actions,
            'new_actions': new_actions
        }
    
    def add_advanced_editor_history(self, change_summary):
        """Add history entry for Advanced Editor changes
        
        Implements hybrid approach: small changes (1-2 rules) are tracked individually
        with special marking, larger changes get a summary entry.
        
        Args:
            change_summary: Dictionary containing change statistics
        """
        if not self.tracking_enabled:
            return
        
        total_changes = (change_summary['rules_added'] + 
                        change_summary['rules_deleted'] + 
                        change_summary['rules_modified'])
        
        # For small changes (1-2 rules), track individually but mark as from Advanced Editor
        if total_changes <= 2:
            # Generate individual entries with special marking
            if change_summary['rules_added'] > 0:
                details = {
                    'count': change_summary['rules_added'],
                    'source': 'advanced_editor',
                    'rules_before': change_summary['rules_before'],
                    'rules_after': change_summary['rules_after']
                }
                self.add_history_entry('advanced_editor_rules_added', details)
            
            if change_summary['rules_deleted'] > 0:
                details = {
                    'count': change_summary['rules_deleted'],
                    'source': 'advanced_editor',
                    'rules_before': change_summary['rules_before'],
                    'rules_after': change_summary['rules_after']
                }
                self.add_history_entry('advanced_editor_rules_deleted', details)
            
            if change_summary['rules_modified'] > 0:
                details = {
                    'count': change_summary['rules_modified'],
                    'source': 'advanced_editor',
                    'rules_before': change_summary['rules_before'],
                    'rules_after': change_summary['rules_after']
                }
                self.add_history_entry('advanced_editor_rules_modified', details)
        else:
            # For larger changes, create a summary entry
            details = {
                'rules_before': change_summary['rules_before'],
                'rules_after': change_summary['rules_after'],
                'rules_added': change_summary['rules_added'],
                'rules_deleted': change_summary['rules_deleted'],
                'rules_modified': change_summary['rules_modified'],
                'net_change': change_summary['rules_after'] - change_summary['rules_before']
            }
            
            # Add SID range info if available
            if change_summary['original_sid_range']:
                details['original_sid_range'] = f"{change_summary['original_sid_range'][0]}-{change_summary['original_sid_range'][1]}"
            if change_summary['new_sid_range']:
                details['new_sid_range'] = f"{change_summary['new_sid_range'][0]}-{change_summary['new_sid_range'][1]}"
            
            # Add action distribution changes if significant
            if change_summary['original_actions'] or change_summary['new_actions']:
                details['action_changes'] = {
                    'before': change_summary['original_actions'],
                    'after': change_summary['new_actions']
                }
            
            self.add_history_entry('advanced_editor_bulk_changes', details)
    
    def _serialize_rule(self, rule):
        """Convert SuricataRule to JSON-serializable dict"""
        return {
            'is_blank': getattr(rule, 'is_blank', False),
            'is_comment': getattr(rule, 'is_comment', False),
            'comment_text': getattr(rule, 'comment_text', ''),
            'action': getattr(rule, 'action', ''),
            'protocol': getattr(rule, 'protocol', ''),
            'src_net': getattr(rule, 'src_net', ''),
            'src_port': getattr(rule, 'src_port', ''),
            'direction': getattr(rule, 'direction', ''),
            'dst_net': getattr(rule, 'dst_net', ''),
            'dst_port': getattr(rule, 'dst_port', ''),
            'message': getattr(rule, 'message', ''),
            'content': getattr(rule, 'content', ''),
            'sid': getattr(rule, 'sid', 0),
            'rev': getattr(rule, 'rev', 1),
            'original_options': getattr(rule, 'original_options', '')
        }
    
    def _deserialize_rule(self, rule_dict):
        """Convert JSON dict back to SuricataRule"""
        rule = SuricataRule()
        rule.is_blank = rule_dict.get('is_blank', False)
        rule.is_comment = rule_dict.get('is_comment', False)
        rule.comment_text = rule_dict.get('comment_text', '')
        rule.action = rule_dict.get('action', '')
        rule.protocol = rule_dict.get('protocol', '')
        rule.src_net = rule_dict.get('src_net', '')
        rule.src_port = rule_dict.get('src_port', '')
        rule.direction = rule_dict.get('direction', '')
        rule.dst_net = rule_dict.get('dst_net', '')
        rule.dst_port = rule_dict.get('dst_port', '')
        rule.message = rule_dict.get('message', '')
        rule.content = rule_dict.get('content', '')
        rule.sid = rule_dict.get('sid', 0)
        rule.rev = rule_dict.get('rev', 1)
        rule.original_options = rule_dict.get('original_options', '')
        return rule
    
    def show_advanced_editor(self):
        """Show the Advanced Editor (wxPython/Scintilla) via subprocess
        
        Launches advanced_editor.py as a separate process with wxPython/Scintilla.
        Includes graceful degradation for users without wxPython installed.
        """
        import subprocess
        import sys
        import tempfile
        import os
        import json
        
        # Check if wxPython is available by checking advanced_editor.py
        editor_path = os.path.join(os.path.dirname(__file__), 'advanced_editor.py')
        if not os.path.exists(editor_path):
            messagebox.showerror("Error", "Advanced editor file not found.")
            return
        
        # Save original state before opening editor
        original_rules = self.rules.copy()
        
        # Create temp files for data exchange
        temp_dir = tempfile.gettempdir()
        input_file = os.path.join(temp_dir, f'suricata_editor_input_{os.getpid()}.json')
        output_file = os.path.join(temp_dir, f'suricata_editor_output_{os.getpid()}.json')
        
        # Serialize rules and variables to JSON
        editor_data = {
            'rules': [self._serialize_rule(r) for r in self.rules],
            'variables': self.variables.copy(),
            'current_file': self.current_file,
            'tracking_enabled': self.tracking_enabled
        }
        
        try:
            # Write input data
            with open(input_file, 'w', encoding='utf-8') as f:
                json.dump(editor_data, f, indent=2)
            
            # Launch advanced editor as subprocess
            result = subprocess.run(
                [sys.executable, editor_path, input_file, output_file],
                capture_output=True,
                text=True
            )
            
            # Graceful degradation: Check for wxPython not installed error
            if 'wxPython not installed' in result.stderr or 'wxPython not installed' in result.stdout:
                messagebox.showerror(
                    "Advanced Editor Unavailable",
                    "The Advanced Editor requires wxPython for code folding support.\n\n"
                    "Install with: pip install wxPython\n\n"
                    "See README.md for platform-specific installation instructions."
                )
                return
            
            if result.returncode != 0:
                # Editor was cancelled or had error
                if result.returncode == 1:
                    # User clicked Cancel - this is normal
                    return
                else:
                    messagebox.showwarning(
                        "Advanced Editor",
                        "Editor encountered an error or was cancelled."
                    )
                    return
            
            # Read result if editor completed successfully
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    result_data = json.load(f)
                
                if result_data.get('ok'):
                    # Deserialize rules from result
                    edited_rules = [self._deserialize_rule(r) for r in result_data['rules']]
                    
                    # Analyze changes for history tracking
                    change_summary = self.analyze_advanced_editor_changes(original_rules, edited_rules)
                    if change_summary:
                        self.add_advanced_editor_history(change_summary)
                    
                    # Update rules and variables
                    self.rules = edited_rules
                    self.variables = result_data['variables'].copy()
                    
                    # Refresh UI
                    self.refresh_table()
                    self.auto_detect_variables()
                    self.modified = True
                    self.update_status_bar()
        
        except Exception as e:
            messagebox.showerror(
                "Advanced Editor Error",
                f"Failed to launch Advanced Editor:\n\n{str(e)}"
            )
        
        finally:
            # Cleanup temp files
            for temp_file in [input_file, output_file]:
                if os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except:
                        pass  # Best effort cleanup
    
    def show_about(self):
        """Show About dialog with version information and release notes from RELEASE_NOTES.md"""
        # Try to read release notes from file
        release_notes = self.load_release_notes()
        
        # Create custom dialog for better formatting
        dialog = tk.Toplevel(self.root)
        dialog.title("About Suricata Rule Generator")
        dialog.geometry("700x500")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 100, self.root.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Text widget with scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("TkDefaultFont", 9), 
                             state=tk.DISABLED, bg=dialog.cget('bg'))
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure text tags for formatting
        text_widget.tag_configure("bold", font=("TkDefaultFont", 9, "bold"))
        text_widget.tag_configure("hyperlink", foreground="blue", underline=True)
        text_widget.tag_configure("hyperlink_hover", foreground="purple", underline=True)
        
        # Insert text with formatting
        text_widget.config(state=tk.NORMAL)
        
        # Insert title
        text_widget.insert(tk.END, "Suricata Rule Generator for AWS Network Firewall\n")
        
        # Insert authors heading
        text_widget.insert(tk.END, "Authors:\n")
        
        # Insert Brian's author line with bolded name and hyperlink
        brian_name_start = text_widget.index(tk.INSERT)
        text_widget.insert(tk.END, "Brian Westmoreland")
        brian_name_end = text_widget.index(tk.INSERT)
        text_widget.tag_add("bold", brian_name_start, brian_name_end)
        
        text_widget.insert(tk.END, " (")
        
        brian_linkedin_start = text_widget.index(tk.INSERT)
        text_widget.insert(tk.END, "LinkedIn")
        brian_linkedin_end = text_widget.index(tk.INSERT)
        text_widget.tag_add("hyperlink", brian_linkedin_start, brian_linkedin_end)
        text_widget.tag_add("brian_linkedin", brian_linkedin_start, brian_linkedin_end)
        
        text_widget.insert(tk.END, ")\n")
        
        # Insert Jesse's author line with bolded name and hyperlink
        jesse_name_start = text_widget.index(tk.INSERT)
        text_widget.insert(tk.END, "Jesse Lepich")
        jesse_name_end = text_widget.index(tk.INSERT)
        text_widget.tag_add("bold", jesse_name_start, jesse_name_end)
        
        text_widget.insert(tk.END, " (")
        
        jesse_linkedin_start = text_widget.index(tk.INSERT)
        text_widget.insert(tk.END, "LinkedIn")
        jesse_linkedin_end = text_widget.index(tk.INSERT)
        text_widget.tag_add("hyperlink", jesse_linkedin_start, jesse_linkedin_end)
        text_widget.tag_add("jesse_linkedin", jesse_linkedin_start, jesse_linkedin_end)
        
        text_widget.insert(tk.END, ")\n")
        
        # Insert version (unbolded)
        text_widget.insert(tk.END, f"\nVersion {self.get_version_number()}")
        
        text_widget.insert(tk.END, "\n\n")
        
        # Insert release notes
        text_widget.insert(tk.END, f"{release_notes}\n\n")
        
        # Insert additional documentation info
        text_widget.insert(tk.END, 
            "For complete documentation and usage instructions,\n"
            "see the README.md file in the project directory.\n\n"
            "For complete release notes and version history,\n"
            "see the RELEASE_NOTES.md file in the project directory."
        )
        
        # Configure hyperlink behavior for Brian's LinkedIn
        def on_brian_hyperlink_click(event):
            import webbrowser
            webbrowser.open("https://www.linkedin.com/in/brian-westmoreland-b55b755/")
        
        # Configure hyperlink behavior for Jesse's LinkedIn
        def on_jesse_hyperlink_click(event):
            import webbrowser
            webbrowser.open("https://www.linkedin.com/in/jesselepich/")
        
        def on_hyperlink_enter(event):
            text_widget.config(cursor="hand2")
            text_widget.tag_configure("hyperlink", foreground="purple", underline=True)
        
        def on_hyperlink_leave(event):
            text_widget.config(cursor="")
            text_widget.tag_configure("hyperlink", foreground="blue", underline=True)
        
        # Bind hyperlink events for Brian's LinkedIn
        text_widget.tag_bind("brian_linkedin", "<Button-1>", on_brian_hyperlink_click)
        text_widget.tag_bind("brian_linkedin", "<Enter>", on_hyperlink_enter)
        text_widget.tag_bind("brian_linkedin", "<Leave>", on_hyperlink_leave)
        
        # Bind hyperlink events for Jesse's LinkedIn
        text_widget.tag_bind("jesse_linkedin", "<Button-1>", on_jesse_hyperlink_click)
        text_widget.tag_bind("jesse_linkedin", "<Enter>", on_hyperlink_enter)
        text_widget.tag_bind("jesse_linkedin", "<Leave>", on_hyperlink_leave)
        
        text_widget.config(state=tk.DISABLED)
        
        # OK button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        ttk.Button(button_frame, text="OK", command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Focus on OK button
        dialog.focus_set()
    
    def load_release_notes(self):
        """Load and parse release notes from RELEASE_NOTES.md file"""
        try:
            # Get the directory where the script is located
            script_dir = os.path.dirname(os.path.abspath(__file__))
            release_notes_path = os.path.join(script_dir, "RELEASE_NOTES.md")
            
            with open(release_notes_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract the first two versions (current and previous) for the About dialog
            lines = content.split('\n')
            release_text = "Release Notes:\n\n"
            version_count = 0
            
            for line in lines:
                if line.startswith('## Version') and version_count < 2:
                    version_count += 1
                    # Add blank line before second version for separation
                    if version_count > 1:
                        release_text += "\n"
                    release_text += line.replace('## ', '') + ":\n"
                elif line.startswith('### ') and version_count <= 2:
                    release_text += "\u2022 " + line.replace('### ', '') + "\n"
                elif line.startswith('- **') and version_count <= 2:
                    # Convert markdown bullet to unicode bullet
                    release_text += "  " + line.replace('- **', '\u2022 ').replace('**:', ':') + "\n"
                elif line.startswith('---') and version_count >= 2:
                    break
            
            return release_text.strip()
            
        except (OSError, IOError, UnicodeDecodeError):
            # Fallback if file can't be read
            return "Release Notes:\n\nUnable to load release notes from RELEASE_NOTES.md file."
    
    def review_rules(self):
        """Analyze rules for conflicts and shadowing issues"""
        if not self.rules:
            messagebox.showinfo("Analysis", "No rules to analyze.")
            return
        
        # Use variables from Variables tab, or get from user if none defined
        variables = dict(self.variables)  # Copy current variables
        
        # Check if we have undefined variables (handle both dict and string formats)
        undefined_vars = []
        for var, var_data in variables.items():
            if isinstance(var_data, dict):
                definition = var_data.get("definition", "")
            else:
                definition = var_data
            if not definition.strip():
                undefined_vars.append(var)
        
        if undefined_vars:
            # Show dialog to define missing variables
            additional_vars = self.get_variable_definitions(undefined_vars)
            if additional_vars is None:
                return  # User cancelled
            variables.update(additional_vars)
        
        # Filter actual rules for progress calculation
        actual_rules = [r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        # Create progress dialog
        progress_dialog = tk.Toplevel(self.root)
        progress_dialog.title("Analyzing Rules")
        progress_dialog.geometry("400x170")
        progress_dialog.transient(self.root)
        progress_dialog.grab_set()
        progress_dialog.resizable(False, False)
        
        # Center the progress dialog
        progress_dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 200, self.root.winfo_rooty() + 200))
        
        # Progress frame
        progress_frame = ttk.Frame(progress_dialog)
        progress_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Status label
        status_label = ttk.Label(progress_frame, text=f"Analyzing {len(actual_rules)} rules for conflicts...")
        status_label.pack(pady=(0, 10))
        
        # Progress bar
        progress_bar = ttk.Progressbar(progress_frame, mode='determinate', length=350)
        progress_bar.pack(pady=(0, 10))
        
        # Progress text label
        progress_text = ttk.Label(progress_frame, text="0%")
        progress_text.pack(pady=(0, 10))
        
        # Cancel button
        cancel_requested = [False]  # Use list to allow modification in nested function
        
        def on_cancel():
            cancel_requested[0] = True
            progress_dialog.destroy()
        
        cancel_button = ttk.Button(progress_frame, text="Cancel", command=on_cancel)
        cancel_button.pack()
        
        # Force dialog to display
        progress_dialog.update()
        
        # Perform analysis using the rule analyzer with progress updates
        conflicts = self.rule_analyzer.analyze_rule_conflicts(self.rules, variables, progress_bar, progress_text, progress_dialog, cancel_requested)
        
        # Close progress dialog if still open
        try:
            progress_dialog.destroy()
        except:
            pass  # Dialog may already be closed by cancel button
        
        # Only show results if analysis wasn't cancelled
        if not cancel_requested[0]:
            self.show_analysis_report(conflicts)
        else:
            messagebox.showinfo("Analysis Cancelled", "Rule analysis was cancelled by user.")
    
    def get_variable_definitions(self, undefined_vars=None):
        """Get CIDR definitions for undefined variables"""
        if undefined_vars is None:
            # Find all variables used in rules
            variables = set()
            for rule in self.rules:
                if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                    continue
                if rule.src_net.startswith('$') or rule.src_net.startswith('@'):
                    variables.add(rule.src_net)
                if rule.dst_net.startswith('$') or rule.dst_net.startswith('@'):
                    variables.add(rule.dst_net)
            undefined_vars = list(variables)
        
        if not undefined_vars:
            return {}  # No variables to define
        
        # Create dialog for variable definitions
        dialog = tk.Toplevel(self.root)
        dialog.title("Define Network Variables")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        result = [None]
        var_entries = {}
        
        # Instructions
        ttk.Label(dialog, text="Define CIDR ranges for network variables (leave blank to skip analysis):").pack(pady=10)
        
        # Scrollable frame for variables
        canvas = tk.Canvas(dialog)
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Add variable entry fields
        for var in sorted(undefined_vars):
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill=tk.X, padx=10, pady=2)
            
            ttk.Label(frame, text=f"{var}:", width=15).pack(side=tk.LEFT)
            entry = ttk.Entry(frame, width=30)
            entry.pack(side=tk.LEFT, padx=(5, 0))
            var_entries[var] = entry
            
            # Add common defaults
            if var in ['$HOME_NET', '$INTERNAL_NET']:
                entry.insert(0, "192.168.0.0/16")
            elif var in ['$EXTERNAL_NET', '$INTERNET']:
                entry.insert(0, "!192.168.0.0/16")
        
        canvas.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def on_ok():
            var_defs = {}
            for var, entry in var_entries.items():
                value = entry.get().strip()
                if value:
                    var_defs[var] = value
            result[0] = var_defs
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Analyze", command=on_ok).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT)
        
        dialog.wait_window()
        return result[0]
    


    
    def show_analysis_report(self, conflicts):
        """Show analysis results in a new window"""
        report_window = tk.Toplevel(self.root)
        report_window.title("Rule Analysis Report")
        report_window.geometry("900x600")
        report_window.transient(self.root)
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(report_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Generate report content
        report = self.generate_analysis_report(conflicts)
        text_widget.insert(tk.END, report)
        
        # Make read-only but allow selection and copying
        text_widget.config(state=tk.NORMAL)
        text_widget.bind("<Key>", lambda e: "break")  # Prevent typing
        text_widget.bind("<Button-1>", lambda e: text_widget.focus_set())  # Allow selection
        
        # Add right-click context menu for copying
        def show_context_menu(event):
            context_menu = tk.Menu(report_window, tearoff=0)
            context_menu.add_command(label="Copy", command=lambda: copy_selection())
            context_menu.add_command(label="Select All", command=lambda: text_widget.tag_add(tk.SEL, "1.0", tk.END))
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
        
        def copy_selection():
            try:
                selected_text = text_widget.selection_get()
                report_window.clipboard_clear()
                report_window.clipboard_append(selected_text)
            except tk.TclError:
                pass  # No selection
        
        text_widget.bind("<Button-3>", show_context_menu)  # Right-click
        
        # Buttons frame
        buttons_frame = ttk.Frame(report_window)
        buttons_frame.pack(pady=10)
        
        ttk.Button(buttons_frame, text="Save as HTML", command=lambda: self.save_report_html(conflicts)).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Save as PDF", command=lambda: self.save_report_pdf(conflicts)).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Close", command=report_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def generate_analysis_report(self, conflicts):
        """Generate formatted analysis report with timestamp and version info"""
        total_rules = len([r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)])
        return self.rule_analyzer.generate_analysis_report(conflicts, total_rules, self.current_file, self.get_version_number())
    
    def save_report_html(self, conflicts):
        """Save analysis report as HTML file"""
        filename = filedialog.asksaveasfilename(
            title="Save Analysis Report as HTML",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                html_content = self.generate_html_report(conflicts)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                messagebox.showinfo("Success", f"Report saved as {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save HTML report: {str(e)}")
    
    def save_report_pdf(self, conflicts):
        """Save analysis report as PDF file"""
        try:
            import webbrowser
            import tempfile
            import os
            
            # Generate HTML first
            html_content = self.generate_html_report(conflicts)
            
            # Create temporary HTML file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as temp_file:
                temp_file.write(html_content)
                temp_file.flush()  # Ensure content is written to disk before using file path
                temp_html_path = temp_file.name
            
            # Open in browser for user to print to PDF
            webbrowser.open('file://' + os.path.abspath(temp_html_path))
            messagebox.showinfo("PDF Export", "Report opened in browser. Use browser's Print > Save as PDF function to create PDF.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export PDF: {str(e)}")
    
    def generate_html_report(self, conflicts):
        """Generate HTML formatted analysis report"""
        total_rules = len([r for r in self.rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)])
        return self.rule_analyzer.generate_html_report(conflicts, total_rules, self.current_file, self.get_version_number())
    
    

    
    def find_first_rule_position(self) -> int:
        """Find the position of the first actual rule (after comments and blank lines)
        
        Returns:
            int: Index of first rule position (0-based)
        """
        for i, rule in enumerate(self.rules):
            # Skip comments and blank lines
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            # Found first actual rule
            return i
        
        # No rules found, insert at beginning
        return 0
    
    def deselect_item(self, item):
        """Deselect an item and update UI state"""
        self.tree.selection_remove(item)
        self.selected_rule_index = None
        self.ui_manager.hide_all_editor_fields()
    

    
    
    
    def show_template_dialog(self):
        """Show template selection dialog for inserting rules from templates"""
        # Check if template file exists and templates loaded
        if not self.template_manager.templates:
            messagebox.showwarning("Templates Unavailable", 
                "No templates found. Please ensure rule_templates.json exists in the program directory.")
            return
        
        # Create selection dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Insert Rules From Template")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 100, self.root.winfo_rooty() + 50))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title
        title_label = ttk.Label(main_frame, text="Insert Rules From Template", 
                               font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Category filter
        category_frame = ttk.Frame(main_frame)
        category_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(category_frame, text="Category:").pack(side=tk.LEFT, padx=(0, 5))
        category_var = tk.StringVar(value="All Categories")
        category_combo = ttk.Combobox(category_frame, textvariable=category_var,
                                     state="readonly", width=20)
        category_combo.pack(side=tk.LEFT)
        
        # Get all categories
        categories = self.template_manager.get_templates_by_category()
        category_list = ["All Categories"] + sorted(categories.keys())
        category_combo['values'] = category_list
        
        # Template list frame
        list_frame = ttk.LabelFrame(main_frame, text="Select Template")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Create listbox with scrollbar
        listbox_frame = ttk.Frame(list_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        templates_listbox = tk.Listbox(listbox_frame, font=("TkDefaultFont", 10))
        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=templates_listbox.yview)
        templates_listbox.configure(yscrollcommand=scrollbar.set)
        
        templates_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Store template IDs with listbox items
        template_ids = []
        
        def populate_templates(category_filter="All Categories"):
            """Populate template listbox based on category filter"""
            templates_listbox.delete(0, tk.END)
            template_ids.clear()
            
            if category_filter == "All Categories":
                # Show all templates grouped by category
                for category in sorted(categories.keys()):
                    # Add category header (non-selectable, just for display)
                    templates_listbox.insert(tk.END, f"▼ {category}")
                    templates_listbox.itemconfig(tk.END, {'bg': '#E0E0E0', 'fg': '#424242'})
                    
                    # Add templates under this category with icons
                    for template in sorted(categories[category], key=lambda t: t['name']):
                        icon = template.get('icon', '')
                        display_text = f"    {icon} {template['name']}" if icon else f"    {template['name']}"
                        templates_listbox.insert(tk.END, display_text)
                        template_ids.append(template['id'])
            else:
                # Show only templates in selected category with icons
                for template in sorted(categories[category_filter], key=lambda t: t['name']):
                    icon = template.get('icon', '')
                    display_text = f"{icon} {template['name']}" if icon else template['name']
                    templates_listbox.insert(tk.END, display_text)
                    template_ids.append(template['id'])
        
        # Initial population
        populate_templates()
        
        # Bind category change to repopulate
        category_combo.bind('<<ComboboxSelected>>', lambda e: populate_templates(category_var.get()))
        
        # Description frame
        desc_frame = ttk.Frame(main_frame)
        desc_frame.pack(fill=tk.X, pady=(0, 15))
        
        desc_text = tk.Text(desc_frame, height=4, wrap=tk.WORD, font=("TkDefaultFont", 9), 
                           relief=tk.FLAT, bg='white')
        desc_text.pack(fill=tk.X)
        desc_text.insert(tk.END, "Select a template from the list above.")
        desc_text.config(state=tk.DISABLED)
        
        # Update description when selection changes
        def on_template_select(event):
            selection = templates_listbox.curselection()
            if not selection:
                return
            
            selected_index = selection[0]
            # Check if this is a category header (grey background)
            try:
                bg_color = templates_listbox.itemcget(selected_index, 'bg')
                if bg_color == '#E0E0E0':
                    # Category header - ignore
                    return
            except:
                pass
            
            # Find corresponding template ID
            # Count actual template items before this selection (skip category headers)
            template_index = 0
            for i in range(selected_index + 1):
                try:
                    bg = templates_listbox.itemcget(i, 'bg')
                    if bg != '#E0E0E0':
                        template_index += 1
                except:
                    template_index += 1
            
            template_index -= 1  # Adjust for 0-based indexing
            
            if 0 <= template_index < len(template_ids):
                template_id = template_ids[template_index]
                template = self.template_manager.get_template(template_id)
                
                if template:
                    desc_text.config(state=tk.NORMAL)
                    desc_text.delete(1.0, tk.END)
                    # Add icon to description if available
                    icon = template.get('icon', '')
                    if icon:
                        desc_text.insert(tk.END, f"{icon} ")
                    desc_text.insert(tk.END, f"{template['description']}\n\n")
                    desc_text.insert(tk.END, f"Category: {template.get('category', 'Uncategorized')} | ")
                    desc_text.insert(tk.END, f"Complexity: {template.get('complexity', 'N/A').title()}")
                    desc_text.config(state=tk.DISABLED)
        
        templates_listbox.bind('<<ListboxSelect>>', on_template_select)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def on_next():
            """Handle Next button - show template-specific dialog"""
            selection = templates_listbox.curselection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a template first.")
                return
            
            selected_index = selection[0]
            # Check if this is a category header
            try:
                bg_color = templates_listbox.itemcget(selected_index, 'bg')
                if bg_color == '#E0E0E0':
                    messagebox.showwarning("Invalid Selection", "Please select a template, not a category header.")
                    return
            except:
                pass
            
            # Find template ID
            template_index = 0
            for i in range(selected_index + 1):
                try:
                    bg = templates_listbox.itemcget(i, 'bg')
                    if bg != '#E0E0E0':
                        template_index += 1
                except:
                    template_index += 1
            template_index -= 1
            
            if 0 <= template_index < len(template_ids):
                template_id = template_ids[template_index]
                dialog.destroy()
                self.show_template_application_dialog(template_id)
        
        ttk.Button(button_frame, text="Next >", command=on_next).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def show_template_application_dialog(self, template_id: str):
        """Show dialog for applying template with parameter collection
        
        Args:
            template_id: Template identifier
        """
        template = self.template_manager.get_template(template_id)
        if not template:
            messagebox.showerror("Error", "Template not found.")
            return
        
        # Check if template has parameters
        has_parameters = bool(template.get('parameters'))
        
        if has_parameters:
            # Show parameter collection dialog first
            parameters = self.show_template_parameters_dialog(template)
            if parameters is None:
                return  # User cancelled
            # Then show preview/apply dialog
            self.show_template_preview_dialog(template_id, parameters)
        else:
            # Policy template - show preview/apply dialog directly
            self.show_template_preview_dialog(template_id, {})
    
    def show_template_parameters_dialog(self, template):
        """Show dialog for collecting template parameters
        
        Args:
            template: Template dictionary
            
        Returns:
            Dict with parameter values or None if cancelled
        """
        dialog = tk.Toplevel(self.root)
        # Add icon to dialog title if available
        icon = template.get('icon', '')
        dialog_title = f"{icon} {template['name']}" if icon else template['name']
        dialog.title(dialog_title)
        dialog.geometry("900x720")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 200, self.root.winfo_rooty() + 100))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title with icon
        title_text = f"{icon} {template['name']}" if icon else template['name']
        title_label = ttk.Label(main_frame, text=title_text, 
                               font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 5))
        
        # Description
        desc_label = ttk.Label(main_frame, text=template['description'], 
                              font=("TkDefaultFont", 9), wraplength=550)
        desc_label.pack(pady=(0, 15))
        
        # Scrollable parameters frame (increased height for country tabs)
        canvas = tk.Canvas(main_frame, height=450)
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=canvas.yview)
        params_frame = ttk.Frame(canvas)
        
        params_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=params_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Store parameter widgets
        param_widgets = {}
        
        # Create UI for each parameter
        for param in template.get('parameters', []):
            param_type = param['type']
            param_name = param['name']
            
            # Parameter frame
            param_container = ttk.LabelFrame(params_frame, text=param.get('description', param_name))
            param_container.pack(fill=tk.X, padx=5, pady=10)
            
            if param_type == 'radio':
                # Radio button parameter
                var = tk.StringVar(value=param['options'][0]['value'])
                param_widgets[param_name] = var
                
                for option in param['options']:
                    ttk.Radiobutton(param_container, 
                                   text=option['label'],
                                   variable=var,
                                   value=option['value']).pack(anchor=tk.W, padx=10, pady=2)
            
            elif param_type == 'checkbox':
                # Checkbox parameter
                var = tk.BooleanVar(value=param.get('default', False))
                param_widgets[param_name] = var
                
                ttk.Checkbutton(param_container,
                               text=param.get('label', param_name),
                               variable=var).pack(anchor=tk.W, padx=10, pady=5)
            
            elif param_type == 'text_input':
                # Text input parameter
                var = tk.StringVar(value='')
                
                label_text = param.get('label', param_name)
                ttk.Label(param_container, text=label_text).pack(anchor=tk.W, padx=10, pady=(5, 2))
                
                entry = ttk.Entry(param_container, textvariable=var, width=50)
                entry.pack(fill=tk.X, padx=10, pady=(0, 5))
                
                # Store both var and entry widget for validation
                param_widgets[param_name] = {'var': var, 'entry': entry}
                
                if param.get('placeholder'):
                    entry.insert(0, param['placeholder'])
                    entry.config(foreground='grey')
                    
                    def on_focus_in(e, entry=entry, ph=param['placeholder']):
                        if entry.get() == ph:
                            entry.delete(0, tk.END)
                            entry.config(foreground='black')
                    
                    def on_focus_out(e, entry=entry, ph=param['placeholder']):
                        if not entry.get():
                            entry.insert(0, ph)
                            entry.config(foreground='grey')
                    
                    entry.bind('<FocusIn>', on_focus_in)
                    entry.bind('<FocusOut>', on_focus_out)
                
                # Add hint if available
                if param.get('description'):
                    ttk.Label(param_container, text=param['description'],
                             font=("TkDefaultFont", 8), foreground='#666666').pack(anchor=tk.W, padx=10, pady=(0, 5))
            
            elif param_type == 'multi_select_port':
                # Multi-select port parameter
                port_vars = {}
                param_widgets[param_name] = port_vars
                
                # Add Select All / None buttons
                button_frame = ttk.Frame(param_container)
                button_frame.pack(fill=tk.X, padx=10, pady=5)
                
                def select_all_ports():
                    for var in port_vars.values():
                        var.set(True)
                
                def select_none_ports():
                    for var in port_vars.values():
                        var.set(False)
                
                ttk.Button(button_frame, text="Select All", command=select_all_ports, width=10).pack(side=tk.LEFT, padx=(0, 5))
                ttk.Button(button_frame, text="None", command=select_none_ports, width=10).pack(side=tk.LEFT)
                
                # Create checkboxes for each port
                for option in param['options']:
                    var = tk.BooleanVar(value=option.get('default_checked', False))
                    port_vars[option['value']] = var
                    
                    # Format: "DNS (53) - DNS tunneling"
                    label_text = f"{option['label']}"
                    if option.get('description'):
                        label_text += f" - {option['description']}"
                    
                    ttk.Checkbutton(param_container, text=label_text, 
                                   variable=var).pack(anchor=tk.W, padx=10, pady=1)
            
            elif param_type == 'multi_select_protocol':
                # Multi-select protocol parameter
                protocol_vars = {}
                param_widgets[param_name] = protocol_vars
                
                # Add Select All / None buttons
                button_frame = ttk.Frame(param_container)
                button_frame.pack(fill=tk.X, padx=10, pady=5)
                
                def select_all_protocols():
                    for var in protocol_vars.values():
                        var.set(True)
                
                def select_none_protocols():
                    for var in protocol_vars.values():
                        var.set(False)
                
                ttk.Button(button_frame, text="Select All", command=select_all_protocols, width=10).pack(side=tk.LEFT, padx=(0, 5))
                ttk.Button(button_frame, text="None", command=select_none_protocols, width=10).pack(side=tk.LEFT)
                
                # Create checkboxes for each protocol
                for option in param['options']:
                    var = tk.BooleanVar(value=option.get('default_checked', False))
                    protocol_vars[option['value']] = var
                    
                    # Format: "TLS (HTTPS) - TCP/443"
                    transport = option.get('transport', 'tcp').upper()
                    port = option.get('port', 'any')
                    label_text = f"{option['label']} - {transport}/{port}"
                    if option.get('description'):
                        label_text += f" ({option['description']})"
                    
                    ttk.Checkbutton(param_container, text=label_text, 
                                   variable=var).pack(anchor=tk.W, padx=10, pady=1)
            
            elif param_type == 'multi_select_extension':
                # Multi-select file extension parameter
                extension_vars = {}
                param_widgets[param_name] = extension_vars
                
                # Add Select All / None buttons
                button_frame = ttk.Frame(param_container)
                button_frame.pack(fill=tk.X, padx=10, pady=5)
                
                def select_all_extensions():
                    for var in extension_vars.values():
                        var.set(True)
                
                def select_none_extensions():
                    for var in extension_vars.values():
                        var.set(False)
                
                ttk.Button(button_frame, text="Select All", command=select_all_extensions, width=10).pack(side=tk.LEFT, padx=(0, 5))
                ttk.Button(button_frame, text="None", command=select_none_extensions, width=10).pack(side=tk.LEFT)
                
                # Create checkboxes for each extension
                for option in param['options']:
                    var = tk.BooleanVar(value=option.get('default_checked', False))
                    extension_vars[option['value']] = var
                    
                    # Format: "Executable (.exe)"
                    label_text = option['label']
                    
                    ttk.Checkbutton(param_container, text=label_text, 
                                   variable=var).pack(anchor=tk.W, padx=10, pady=1)
            
            elif param_type == 'multi_select_method':
                # Multi-select HTTP method parameter
                method_vars = {}
                param_widgets[param_name] = method_vars
                
                # Add Select All / None buttons
                button_frame = ttk.Frame(param_container)
                button_frame.pack(fill=tk.X, padx=10, pady=5)
                
                def select_all_methods():
                    for var in method_vars.values():
                        var.set(True)
                
                def select_none_methods():
                    for var in method_vars.values():
                        var.set(False)
                
                ttk.Button(button_frame, text="Select All", command=select_all_methods, width=10).pack(side=tk.LEFT, padx=(0, 5))
                ttk.Button(button_frame, text="None", command=select_none_methods, width=10).pack(side=tk.LEFT)
                
                # Create checkboxes for each method
                for option in param['options']:
                    var = tk.BooleanVar(value=option.get('default_checked', False))
                    method_vars[option['value']] = var
                    
                    # Format: "PUT - Upload/modify resources"
                    label_text = f"{option['label']}"
                    if option.get('description'):
                        label_text += f" - {option['description']}"
                    
                    ttk.Checkbutton(param_container, text=label_text, 
                                   variable=var).pack(anchor=tk.W, padx=10, pady=1)
            
            elif param_type == 'multi_select_country':
                # Multi-select country parameter with dropdown and two-panel layout
                # Region selector frame
                selector_frame = ttk.Frame(param_container)
                selector_frame.pack(fill=tk.X, padx=10, pady=5)
                
                ttk.Label(selector_frame, text="Region:", font=("TkDefaultFont", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
                
                # Region dropdown
                region_var = tk.StringVar()
                
                # Group countries by region
                regions = {}
                for option in param['options']:
                    region = option.get('region', 'Other')
                    if region not in regions:
                        regions[region] = []
                    regions[region].append(option)
                
                region_list = ['Asia', 'Americas', 'Africa', 'Middle East', 'Europe', 'Oceania']
                # Only include regions that have countries
                region_list = [r for r in region_list if r in regions]
                region_var.set(region_list[0] if region_list else "")
                
                region_combo = ttk.Combobox(selector_frame, textvariable=region_var,
                                           values=region_list, state="readonly", width=20)
                region_combo.pack(side=tk.LEFT)
                
                # Country count label
                count_label = ttk.Label(selector_frame, text="", font=("TkDefaultFont", 8), foreground="#666666")
                count_label.pack(side=tk.LEFT, padx=(10, 0))
                
                # Two-panel layout
                panels_frame = ttk.Frame(param_container)
                panels_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
                
                # LEFT PANEL: Countries in selected region
                left_panel = ttk.LabelFrame(panels_frame, text="Countries in Selected Region")
                left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
                
                # Scrollable canvas for left panel
                left_canvas = tk.Canvas(left_panel)
                left_scrollbar = ttk.Scrollbar(left_panel, orient=tk.VERTICAL, command=left_canvas.yview)
                left_content = ttk.Frame(left_canvas)
                
                left_content.bind(
                    "<Configure>",
                    lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all"))
                )
                
                left_canvas.create_window((0, 0), window=left_content, anchor="nw")
                left_canvas.configure(yscrollcommand=left_scrollbar.set)
                
                left_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
                left_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
                
                # Enable mousewheel scrolling for left panel
                def on_left_mousewheel(event):
                    left_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                
                left_canvas.bind("<Enter>", lambda e: left_canvas.bind("<MouseWheel>", on_left_mousewheel))
                left_canvas.bind("<Leave>", lambda e: left_canvas.unbind("<MouseWheel>"))
                
                # RIGHT PANEL: Selected countries summary
                right_panel = ttk.LabelFrame(panels_frame, text="Selected Countries")
                right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(5, 0))
                right_panel.config(width=250)
                
                # Selected count label
                selected_count_label = ttk.Label(right_panel, text="0 selected", 
                                                font=("TkDefaultFont", 9, "bold"), foreground="#1976D2")
                selected_count_label.pack(pady=(5, 5))
                
                # Scrollable canvas for right panel
                right_canvas = tk.Canvas(right_panel, width=230)
                right_scrollbar = ttk.Scrollbar(right_panel, orient=tk.VERTICAL, command=right_canvas.yview)
                right_content = ttk.Frame(right_canvas)
                
                right_content.bind(
                    "<Configure>",
                    lambda e: right_canvas.configure(scrollregion=right_canvas.bbox("all"))
                )
                
                right_canvas.create_window((0, 0), window=right_content, anchor="nw")
                right_canvas.configure(yscrollcommand=right_scrollbar.set)
                
                right_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
                right_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
                
                # Enable mousewheel scrolling for right panel
                def on_right_mousewheel(event):
                    right_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
                
                right_canvas.bind("<Enter>", lambda e: right_canvas.bind("<MouseWheel>", on_right_mousewheel))
                right_canvas.bind("<Leave>", lambda e: right_canvas.unbind("<MouseWheel>"))
                
                # Global storage for selections across ALL regions
                selected_countries = {}  # {code: {'label': ..., 'region': ...}}
                
                # Store current region checkboxes
                current_checkboxes = {}
                
                def update_selected_panel():
                    """Update right panel showing all selected countries"""
                    # Clear existing items
                    for widget in right_content.winfo_children():
                        widget.destroy()
                    
                    # Update count
                    count = len(selected_countries)
                    selected_count_label.config(text=f"{count} selected")
                    
                    if not selected_countries:
                        ttk.Label(right_content, text="No countries selected",
                                 font=("TkDefaultFont", 8, "italic"), foreground="#666666").pack(padx=5, pady=20)
                        return
                    
                    # Show each selected country with remove button
                    for code in sorted(selected_countries.keys()):
                        country_info = selected_countries[code]
                        
                        # Create frame for this country
                        country_frame = ttk.Frame(right_content)
                        country_frame.pack(fill=tk.X, padx=5, pady=2)
                        
                        # Country label (name and code)
                        label_text = f"{country_info['label']} ({code})"
                        country_label = ttk.Label(country_frame, text=label_text, 
                                                 font=("TkDefaultFont", 8))
                        country_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
                        
                        # Remove button
                        def make_remove_command(c):
                            def remove():
                                del selected_countries[c]
                                # Update checkbox if in current region
                                if c in current_checkboxes:
                                    current_checkboxes[c].set(False)
                                # Refresh right panel
                                update_selected_panel()
                            return remove
                        
                        remove_btn = ttk.Button(country_frame, text="✕", width=2,
                                               command=make_remove_command(code))
                        remove_btn.pack(side=tk.RIGHT)
                
                def populate_region(region_name):
                    """Populate left panel with countries in selected region"""
                    # Clear existing checkboxes
                    for widget in left_content.winfo_children():
                        widget.destroy()
                    current_checkboxes.clear()
                    
                    # Get countries for this region
                    region_countries = regions.get(region_name, [])
                    
                    # Update count label
                    count_label.config(text=f"({len(region_countries)} countries)")
                    
                    if not region_countries:
                        ttk.Label(left_content, text="No countries in this region",
                                 font=("TkDefaultFont", 8, "italic")).pack(padx=10, pady=20)
                        return
                    
                    # Add checkbox for each country
                    for country in region_countries:
                        code = country['value']
                        label = country['label']
                        
                        # Check if already selected
                        is_selected = code in selected_countries
                        
                        var = tk.BooleanVar(value=is_selected)
                        current_checkboxes[code] = var
                        
                        # Format: "China (CN)"
                        label_text = f"{label} ({code})"
                        
                        # Checkbox with change handler
                        def make_checkbox_handler(c, lbl, rgn):
                            def on_change():
                                if current_checkboxes[c].get():
                                    # Add to selected
                                    selected_countries[c] = {
                                        'label': lbl,
                                        'region': rgn
                                    }
                                else:
                                    # Remove from selected
                                    if c in selected_countries:
                                        del selected_countries[c]
                                # Update right panel
                                update_selected_panel()
                            return on_change
                        
                        cb = ttk.Checkbutton(left_content, text=label_text, variable=var,
                                            command=make_checkbox_handler(code, label, region_name))
                        cb.pack(anchor=tk.W, padx=10, pady=1)
                
                # Populate initial region
                if region_list:
                    populate_region(region_list[0])
                
                # Bind region change event
                region_combo.bind('<<ComboboxSelected>>', lambda e: populate_region(region_var.get()))
                
                # Initial update of selected panel
                update_selected_panel()
                
                # Store the selected_countries dict in param_widgets for collection
                param_widgets[param_name] = selected_countries
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        result = [None]
        
        def on_next():
            """Validate and collect parameters"""
            params = {}
            
            # Validate and collect each parameter
            for param in template.get('parameters', []):
                param_name = param['name']
                param_type = param['type']
                
                if param_type == 'radio':
                    params[param_name] = param_widgets[param_name].get()
                
                elif param_type == 'checkbox':
                    params[param_name] = param_widgets[param_name].get()
                
                elif param_type == 'text_input':
                    entry_widget = param_widgets[param_name]['entry']
                    value = param_widgets[param_name]['var'].get()
                    
                    # Check if text is greyed out (placeholder still shown)
                    # Only treat as empty if it's the placeholder AND greyed out
                    if value == param.get('placeholder', '') and entry_widget.cget('foreground') == 'grey':
                        value = ''
                    
                    # Validate required
                    if param.get('required') and not value:
                        messagebox.showerror("Validation Error", 
                            f"{param.get('label', param_name)} is required.")
                        return
                    
                    # Validate pattern if specified
                    if value and param.get('pattern'):
                        import re
                        if not re.match(param['pattern'], value):
                            error_msg = param.get('validation_message', f"Invalid format for {param_name}")
                            messagebox.showerror("Validation Error", error_msg)
                            return
                    
                    # Validate length
                    if value:
                        if param.get('min_length') and len(value) < param['min_length']:
                            messagebox.showerror("Validation Error",
                                f"{param.get('label', param_name)} must be at least {param['min_length']} characters.")
                            return
                        if param.get('max_length') and len(value) > param['max_length']:
                            messagebox.showerror("Validation Error",
                                f"{param.get('label', param_name)} must be no more than {param['max_length']} characters.")
                            return
                    
                    params[param_name] = value
                
                elif param_type == 'multi_select_port':
                    # Collect selected ports
                    port_vars = param_widgets[param_name]
                    selected = [port_val for port_val, var in port_vars.items() if var.get()]
                    
                    # Validate minimum selections
                    min_selections = param.get('min_selections', 1)
                    if len(selected) < min_selections:
                        messagebox.showerror("Validation Error",
                            f"Please select at least {min_selections} port(s).")
                        return
                    
                    params[param_name] = selected
                
                elif param_type == 'multi_select_protocol':
                    # Collect selected protocols
                    protocol_vars = param_widgets[param_name]
                    selected = [protocol_val for protocol_val, var in protocol_vars.items() if var.get()]
                    
                    # Validate minimum selections
                    min_selections = param.get('min_selections', 1)
                    if len(selected) < min_selections:
                        messagebox.showerror("Validation Error",
                            f"Please select at least {min_selections} protocol(s).")
                        return
                    
                    params[param_name] = selected
                
                elif param_type == 'multi_select_extension':
                    # Collect selected file extensions
                    extension_vars = param_widgets[param_name]
                    selected = [ext_val for ext_val, var in extension_vars.items() if var.get()]
                    
                    # Validate minimum selections
                    min_selections = param.get('min_selections', 1)
                    if len(selected) < min_selections:
                        messagebox.showerror("Validation Error",
                            f"Please select at least {min_selections} file extension(s).")
                        return
                    
                    params[param_name] = selected
                
                elif param_type == 'multi_select_method':
                    # Collect selected HTTP methods
                    method_vars = param_widgets[param_name]
                    selected = [method_val for method_val, var in method_vars.items() if var.get()]
                    
                    # Validate minimum selections
                    min_selections = param.get('min_selections', 1)
                    if len(selected) < min_selections:
                        messagebox.showerror("Validation Error",
                            f"Please select at least {min_selections} HTTP method(s).")
                        return
                    
                    params[param_name] = selected
                
                elif param_type == 'multi_select_country':
                    # Collect selected countries from the global selected_countries dict
                    # (not from country_vars which are just the current region checkboxes)
                    selected = list(param_widgets[param_name].keys())
                    
                    # Validate minimum selections
                    min_selections = param.get('min_selections', 1)
                    if len(selected) < min_selections:
                        messagebox.showerror("Validation Error",
                            f"Please select at least {min_selections} country/countries.")
                        return
                    
                    params[param_name] = selected
            
            result[0] = params
            dialog.destroy()
        
        ttk.Button(button_frame, text="Next >", command=on_next).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        
        dialog.wait_window()
        return result[0]
    
    def show_template_preview_dialog(self, template_id: str, parameters: dict):
        """Show preview and apply dialog for template
        
        Args:
            template_id: Template identifier
            parameters: Collected parameter values
        """
        template = self.template_manager.get_template(template_id)
        if not template:
            messagebox.showerror("Error", "Template not found.")
            return
        
        # Create application dialog for policy template
        dialog = tk.Toplevel(self.root)
        # Add icon to dialog title if available
        icon = template.get('icon', '')
        dialog_title = f"{icon} {template['name']}" if icon else template['name']
        dialog.title(dialog_title)
        dialog.geometry("700x650")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 150, self.root.winfo_rooty() + 100))
        
        # Main frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Title and description with icon
        title_text = f"{icon} {template['name']}" if icon else template['name']
        title_label = ttk.Label(main_frame, text=title_text, 
                               font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 5))
        
        desc_label = ttk.Label(main_frame, text=template['description'], 
                              font=("TkDefaultFont", 9), wraplength=650)
        desc_label.pack(pady=(0, 15))
        
        # Test mode checkbox
        test_mode_var = tk.BooleanVar(value=False)
        test_mode_frame = ttk.Frame(main_frame)
        test_mode_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Checkbutton(test_mode_frame, text="Test Mode (use 'alert' action for all rules)",
                       variable=test_mode_var).pack(anchor=tk.W)
        ttk.Label(test_mode_frame, 
                 text="When enabled, all generated rules will use 'alert' action instead of their default actions.",
                 font=("TkDefaultFont", 8), foreground="#666666").pack(anchor=tk.W, padx=(20, 0))
        
        # Preview frame
        preview_frame = ttk.LabelFrame(main_frame, text="Rule Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        preview_text = tk.Text(preview_frame, wrap=tk.NONE, font=("Consolas", 9), height=12)
        preview_scrollbar = ttk.Scrollbar(preview_frame, orient=tk.VERTICAL, command=preview_text.yview)
        preview_h_scrollbar = ttk.Scrollbar(preview_frame, orient=tk.HORIZONTAL, command=preview_text.xview)
        preview_text.configure(yscrollcommand=preview_scrollbar.set, xscrollcommand=preview_h_scrollbar.set)
        
        preview_text.grid(row=0, column=0, sticky="nsew")
        preview_scrollbar.grid(row=0, column=1, sticky="ns")
        preview_h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        preview_frame.grid_rowconfigure(0, weight=1)
        preview_frame.grid_columnconfigure(0, weight=1)
        
        # SID entry frame
        sid_frame = ttk.Frame(main_frame)
        sid_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(sid_frame, text="Starting SID:").pack(side=tk.LEFT, padx=(0, 5))
        
        # Get suggested starting SID
        existing_sids = {r.sid for r in self.rules 
                        if not getattr(r, 'is_comment', False) 
                        and not getattr(r, 'is_blank', False)}
        suggested_sid = self.template_manager.get_suggested_starting_sid(template, existing_sids)
        
        sid_var = tk.StringVar(value=str(suggested_sid))
        sid_entry = ttk.Entry(sid_frame, textvariable=sid_var, width=10)
        sid_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Label(sid_frame, text=f"(Next available: {suggested_sid})", 
                 font=("TkDefaultFont", 8), foreground="#666666").pack(side=tk.LEFT)
        
        # Update preview function
        def update_preview():
            """Update preview based on test mode checkbox"""
            try:
                start_sid = int(sid_var.get())
                test_mode = test_mode_var.get()
                
                # Generate preview (use collected parameters)
                preview = self.template_manager.preview_rules(template_id, parameters, start_sid, test_mode)
                
                # Count rules to be generated (consider conditional rules and dual insertion)
                temp_rules = self.template_manager.apply_template(template_id, parameters, start_sid, test_mode)
                
                # Calculate rule count based on result type
                if isinstance(temp_rules, dict) and 'top_rules' in temp_rules:
                    # Dual insertion template
                    rule_count = len(temp_rules['top_rules']) + len(temp_rules['bottom_rules'])
                else:
                    # Standard template
                    rule_count = len(temp_rules)
                
                preview_text.config(state=tk.NORMAL)
                preview_text.delete(1.0, tk.END)
                preview_text.insert(tk.END, f"This will create {rule_count} rule(s):\n\n")
                preview_text.insert(tk.END, preview)
                
                # Add notes if available
                if template.get('notes'):
                    preview_text.insert(tk.END, f"\n\nNotes:\n{template['notes']}")
                
                preview_text.config(state=tk.DISABLED)
            except ValueError:
                preview_text.config(state=tk.NORMAL)
                preview_text.delete(1.0, tk.END)
                preview_text.insert(tk.END, "Invalid starting SID")
                preview_text.config(state=tk.DISABLED)
        
        # Initial preview
        update_preview()
        
        # Bind changes to update preview
        test_mode_var.trace('w', lambda *args: update_preview())
        sid_var.trace('w', lambda *args: update_preview())
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def on_apply():
            """Apply the template"""
            try:
                start_sid = int(sid_var.get())
                
                # Validate SID
                if not (SuricataConstants.SID_MIN <= start_sid <= SuricataConstants.SID_MAX):
                    messagebox.showerror("Error", 
                        f"Starting SID must be between {SuricataConstants.SID_MIN} and {SuricataConstants.SID_MAX}.")
                    return
                
                # Generate rules from template (use collected parameters)
                test_mode = test_mode_var.get()
                result = self.template_manager.apply_template(template_id, parameters, start_sid, test_mode)
                
                if not result:
                    messagebox.showerror("Error", "Failed to generate rules from template.")
                    return
                
                # Check if this is a dual insertion template
                if isinstance(result, dict) and 'top_rules' in result:
                    top_rules = result['top_rules']
                    bottom_rules = result['bottom_rules']
                    
                    if not top_rules and not bottom_rules:
                        messagebox.showerror("Error", "Failed to generate rules from template.")
                        return
                    
                    # Save undo state BEFORE making changes
                    self.save_undo_state()
                    
                    # Insert top rules at the beginning (after comments/blank lines)
                    if top_rules:
                        top_insert_position = self.find_first_rule_position()
                        
                        # Insert comment headers
                        comment1 = SuricataRule()
                        comment1.is_comment = True
                        comment1.comment_text = "# Silently allow TCP 3-way handshake to be setup by $HOME_NET clients"
                        self.rules.insert(top_insert_position, comment1)
                        
                        comment2 = SuricataRule()
                        comment2.is_comment = True
                        comment2.comment_text = "# Do not move this section, it's important that this be at the top of the entire firewall ruleset to reduce rule conflicts"
                        self.rules.insert(top_insert_position + 1, comment2)
                        
                        # Insert first 2 TCP handshake rules
                        self.rules.insert(top_insert_position + 2, top_rules[0])
                        self.rules.insert(top_insert_position + 3, top_rules[1])
                        
                        # Add blank line
                        blank1 = SuricataRule()
                        blank1.is_blank = True
                        self.rules.insert(top_insert_position + 4, blank1)
                        
                        # Add comment for JA3 rules
                        comment3 = SuricataRule()
                        comment3.is_comment = True
                        comment3.comment_text = "# Silently turn on JA3/S hash logging for all other tls alert rules (like sid:999991)"
                        self.rules.insert(top_insert_position + 5, comment3)
                        
                        # Insert remaining JA3 logging rules (rules 3 and 4)
                        self.rules.insert(top_insert_position + 6, top_rules[2])
                        self.rules.insert(top_insert_position + 7, top_rules[3])
                        
                        # Add comment indicating where user rules begin
                        comment4 = SuricataRule()
                        comment4.is_comment = True
                        comment4.comment_text = "# ---Insert user rules beginning here---"
                        self.rules.insert(top_insert_position + 8, comment4)
                        
                        # Add blank line after top rules section
                        blank2 = SuricataRule()
                        blank2.is_blank = True
                        self.rules.insert(top_insert_position + 9, blank2)
                    
                    # Insert bottom rules at the end
                    bottom_insert_position = len(self.rules)
                    for i, rule in enumerate(bottom_rules):
                        self.rules.insert(bottom_insert_position + i, rule)
                    
                    # Add change tracking entry
                    if self.tracking_enabled:
                        total_rules = len(top_rules) + len(bottom_rules)
                        self.add_history_entry('template_applied', {
                            'template_name': template['name'],
                            'rule_count': total_rules,
                            'top_rules_count': len(top_rules),
                            'bottom_rules_count': len(bottom_rules),
                            'test_mode': test_mode,
                            'insertion_type': 'dual'
                        })
                    
                    # Update UI
                    self.refresh_table()
                    self.auto_detect_variables()
                    self.modified = True
                    self.update_status_bar()
                    
                    # Close dialog and show success
                    dialog.destroy()
                    
                    total_rules = len(top_rules) + len(bottom_rules)
                    rule_text = "rule" if total_rules == 1 else "rules"
                    test_text = " (Test Mode)" if test_mode else ""
                    messagebox.showinfo("Template Applied", 
                        f"Successfully added {total_rules} {rule_text} from template{test_text}.\n\n"
                        f"• {len(top_rules)} rules inserted at TOP of file\n"
                        f"• {len(bottom_rules)} rules inserted at BOTTOM of file\n\n"
                        "Use Ctrl+Z to undo if needed.")
                else:
                    # Standard single insertion
                    template_rules = result
                    
                    # Determine insertion point
                    insertion_point = template.get('insertion_point')
                    if insertion_point == 'end':
                        insert_position = len(self.rules)
                    else:
                        # Insert at current position or after selected rule
                        if self.selected_rule_index is not None:
                            insert_position = self.selected_rule_index + 1
                        else:
                            insert_position = len(self.rules)
                    
                    # Save undo state BEFORE making changes
                    self.save_undo_state()
                    
                    # Insert rules atomically
                    for i, rule in enumerate(template_rules):
                        self.rules.insert(insert_position + i, rule)
                    
                    # Add change tracking entry
                    if self.tracking_enabled:
                        self.add_history_entry('template_applied', {
                            'template_name': template['name'],
                            'rule_count': len(template_rules),
                            'start_sid': template_rules[0].sid if template_rules else start_sid,
                            'end_sid': template_rules[-1].sid if template_rules else start_sid,
                            'test_mode': test_mode,
                            'insertion_point': insert_position + 1
                        })
                    
                    # Update UI
                    self.refresh_table()
                    self.auto_detect_variables()
                    self.modified = True
                    self.update_status_bar()
                    
                    # Close dialog and show success
                    dialog.destroy()
                    
                    rule_text = "rule" if len(template_rules) == 1 else "rules"
                    test_text = " (Test Mode)" if test_mode else ""
                    messagebox.showinfo("Template Applied", 
                        f"Successfully added {len(template_rules)} {rule_text} from template{test_text}.\n\n"
                        f"SID range: {template_rules[0].sid} - {template_rules[-1].sid}\n\n"
                        "Use Ctrl+Z to undo if needed.")
                
            except ValueError:
                messagebox.showerror("Error", "Starting SID must be a valid number.")
            except Exception as e:
                messagebox.showerror("Template Error", f"Failed to apply template:\n\n{str(e)}")
        
        ttk.Button(button_frame, text="Apply", command=on_apply).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def on_closing(self):
        """Handle application closing"""
        if self.modified and not self.ask_save_changes():
            return
        
        self.root.destroy()
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = SuricataRuleGenerator()
    app.run()
