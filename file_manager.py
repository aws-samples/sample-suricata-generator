"""
File Manager Module for Suricata Rule Generator

Handles all file I/O operations including:
- Loading/saving .suricata files
- Variable file management (.var files)
- History file management (.history files)
- Export functionality (Terraform/CloudFormation/AWS)
"""

import os
import json
import re
import urllib.request
import urllib.error
from typing import List, Optional
from tkinter import ttk, messagebox
import tkinter as tk
from suricata_rule import SuricataRule
from constants import SuricataConstants, SecurityConstants, ValidationMessages
from security_validator import validate_file_operation, security_validator
from version import get_main_version


class FileManager:
    """Manages all file operations for the Suricata Rule Generator"""
    
    def __init__(self):
        self.version = get_main_version()
    
    def load_rules_from_file(self, filename: str) -> tuple[List[SuricataRule], dict, bool, Optional[str]]:
        """Load rules from a .suricata file
        
        Returns:
            tuple: (rules_list, variables_dict, has_header, created_timestamp)
        """
        # Validate file operation for security
        validate_file_operation(filename, "read")
        
        rules = []
        variables = {}
        has_header = False
        created_timestamp = None
        
        try:
            with open(filename, 'r', encoding=SuricataConstants.DEFAULT_ENCODING) as f:
                lines = f.readlines()
            
            for line in lines:
                original_line = line.rstrip('\n\r')
                stripped_line = line.strip()
                
                if not stripped_line:
                    blank_rule = SuricataRule()
                    blank_rule.is_blank = True
                    rules.append(blank_rule)
                elif stripped_line.startswith('#'):
                    comment_rule = SuricataRule()
                    comment_rule.is_comment = True
                    comment_rule.comment_text = original_line
                    rules.append(comment_rule)
                else:
                    # Auto-convert port ranges to bracket format before parsing
                    corrected_line = self._auto_correct_port_brackets(stripped_line)
                    rule = SuricataRule.from_string(corrected_line)
                    if rule:
                        rules.append(rule)
            
            # Load companion .var file if it exists
            variables = self.load_variables_file(filename)
            
            # Check for existing header and extract timestamp
            has_header, created_timestamp = self.detect_header(rules)
            
            return rules, variables, has_header, created_timestamp
            
        except FileNotFoundError:
            raise Exception(f"File not found: {filename}")
        except PermissionError:
            raise Exception(f"Permission denied reading file: {filename}")
        except UnicodeDecodeError as e:
            raise Exception(f"File encoding error in {filename}. Please ensure the file is saved in UTF-8 format.")
        except Exception as e:
            raise Exception(f"Failed to load file {filename}: {str(e)}")
    
    def save_rules_to_file(self, filename: str, rules: List[SuricataRule], variables: dict, 
                          has_header: bool = False, tracking_enabled: bool = False, 
                          pending_history: List = None) -> bool:
        """Save rules to a .suricata file with validation"""
        
        # Check for duplicate SIDs
        sids = [rule.sid for rule in rules if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False)]
        duplicate_sids = [sid for sid in set(sids) if sids.count(sid) > 1]
        
        if duplicate_sids:
            raise ValueError(f"Duplicate SIDs found: {', '.join(map(str, duplicate_sids))}")
        
        # Check for reject actions on IP protocol rules (AWS Network Firewall restriction)
        invalid_ip_rules = []
        for i, rule in enumerate(rules):
            if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False):
                if rule.protocol.lower() == 'ip' and rule.action.lower() == 'reject':
                    line_num = i + 1
                    invalid_ip_rules.append(line_num)
        
        if invalid_ip_rules:
            lines_str = ', '.join(map(str, invalid_ip_rules))
            raise ValueError(f"AWS Network Firewall does not allow REJECT action on IP protocol rules. Invalid rules found at line(s): {lines_str}. Change action to 'drop' instead.")
        
        # Variable validation
        used_vars = self.scan_rules_for_variables(rules)
        
        # Handle both old format (string) and new format (dict) for validation
        undefined_vars = []
        for var in used_vars:
            if var not in variables:
                undefined_vars.append(var)
            else:
                var_data = variables[var]
                # Handle both old format (string) and new format (dict with definition/description)
                if isinstance(var_data, dict):
                    var_definition = var_data.get("definition", "")
                else:
                    var_definition = var_data  # Legacy format
                
                if not var_definition.strip():
                    undefined_vars.append(var)
        
        undefined_vars = [var for var in undefined_vars if var != '$EXTERNAL_NET']
        
        if undefined_vars:
            var_list = ', '.join(undefined_vars)
            raise ValueError(f"Rules reference undefined variables: {var_list}")
        
        try:
            # Update header if present and tracking enabled
            if has_header and tracking_enabled:
                self.update_header(rules)
            
            # Save the main .suricata file
            with open(filename, 'w', encoding='utf-8') as f:
                for rule in rules:
                    if getattr(rule, 'is_blank', False):
                        f.write('\n')
                    elif getattr(rule, 'is_comment', False):
                        f.write(rule.comment_text + '\n')
                    else:
                        f.write(rule.to_string() + '\n')
            
            # Save companion .var file if variables are used
            if used_vars:
                self.save_variables_file(filename, variables)
            
            # Save companion .history file if tracking enabled
            if tracking_enabled and pending_history:
                self.save_history_file(filename, pending_history)
            
            return True
            
        except PermissionError:
            raise Exception(f"Permission denied writing to file: {filename}")
        except OSError as e:
            raise Exception(f"File system error writing to {filename}: {str(e)}")
        except Exception as e:
            raise Exception(f"Failed to save file {filename}: {str(e)}")
    
    def load_variables_file(self, suricata_filename: str) -> dict:
        """Load companion .var file if it exists
        
        Supports both legacy format (string values) and new format (dict with definition/description).
        Legacy format: {"$VAR": "value"}
        New format: {"$VAR": {"definition": "value", "description": "text"}}
        
        Returns:
            dict: Variables in new format with definition and description
        """
        var_filename = suricata_filename.replace('.suricata', '.var')
        if not var_filename.endswith('.var'):
            var_filename += '.var'
        
        if os.path.exists(var_filename):
            try:
                with open(var_filename, 'r', encoding='utf-8') as f:
                    raw_data = json.load(f)
                
                # Convert to new format if needed (backward compatibility)
                variables = {}
                for name, value in raw_data.items():
                    if isinstance(value, str):
                        # Legacy format: string value
                        variables[name] = {
                            "definition": value,
                            "description": ""
                        }
                    elif isinstance(value, dict):
                        # New format: dict with definition and optional description
                        variables[name] = {
                            "definition": value.get("definition", ""),
                            "description": value.get("description", "")
                        }
                    else:
                        # Unknown format, treat as empty
                        variables[name] = {
                            "definition": "",
                            "description": ""
                        }
                
                return variables
                
            except FileNotFoundError:
                pass  # Variable file doesn't exist
            except PermissionError:
                pass  # Cannot read variable file
            except json.JSONDecodeError:
                pass  # Variable file is corrupted
            except (TypeError, ValueError):
                pass  # Other errors
        return {}
    
    def save_variables_file(self, suricata_filename: str, variables: dict):
        """Save companion .var file with variable definitions
        
        Always saves in new format with definition and description fields.
        Maintains backward compatibility by supporting reading of old format.
        
        Args:
            variables: Dict with structure {name: {"definition": str, "description": str}}
        """
        if not variables:
            return
        
        var_filename = suricata_filename.replace('.suricata', '.var')
        if not var_filename.endswith('.var'):
            var_filename += '.var'
        
        try:
            # Save in new format with definition and description
            # Variables should already be in the new format from load_variables_file
            with open(var_filename, 'w', encoding='utf-8') as f:
                json.dump(variables, f, indent=2)
        except PermissionError:
            pass  # Cannot write variable file
        except OSError:
            pass  # File system error
        except (TypeError, ValueError):
            pass  # Other errors
    
    def save_history_file(self, suricata_filename: str, pending_history: List):
        """Save companion .history file with change tracking data"""
        if not pending_history:
            return
        
        # Validate and sanitize filename to prevent path traversal
        base_name = os.path.basename(suricata_filename)
        if '..' in base_name or '/' in base_name or '\\' in base_name:
            return
        
        # Use only the sanitized base name and construct path in same directory as suricata file
        suricata_dir = os.path.dirname(os.path.abspath(suricata_filename))
        safe_base_name = base_name.replace('.suricata', '.history')
        if not safe_base_name.endswith('.history'):
            safe_base_name += '.history'
        history_filename = os.path.join(suricata_dir, safe_base_name)
        
        try:
            import datetime
            
            # Load existing history or create new
            history_data = {
                'file': os.path.basename(suricata_filename),
                'tracking_enabled': datetime.datetime.now().isoformat(),
                'changes': []
            }
            
            if os.path.exists(history_filename):
                try:
                    with open(history_filename, 'r', encoding='utf-8') as f:
                        history_data = json.load(f)
                except:
                    pass
            
            # Separate different entry types
            snapshot_entries = [e for e in pending_history if 'rule_snapshot' in e.get('details', {})]
            regular_entries = [e for e in pending_history 
                             if 'rule_snapshot' not in e.get('details', {})]
            
            # Handle v2.0 snapshot entries using RevisionManager
            if snapshot_entries:
                try:
                    from revision_manager import RevisionManager
                    revision_manager = RevisionManager(history_filename)
                    
                    # Write snapshot entries directly (batch write)
                    revision_manager.write_pending_snapshots(snapshot_entries)
                except Exception:
                    # If RevisionManager fails, fall back to regular append
                    history_data['changes'].extend(snapshot_entries)
            
            # Handle regular v1.0 entries (append to changes)
            if regular_entries:
                history_data['changes'].extend(regular_entries)
                
                # Save updated history as valid JSON
                with open(history_filename, 'w', encoding='utf-8') as f:
                    json.dump(history_data, f, indent=2, ensure_ascii=False)
                
        except PermissionError:
            pass  # Cannot write history file
        except OSError:
            pass  # File system error
        except TypeError:
            pass  # Cannot serialize history data
        except (ValueError, KeyError):
            pass  # Other errors
    
    def _prepare_rules_for_export(self, rules: List, test_mode: bool) -> List:
        """Prepare rules for export with test mode conversion and action preservation
        
        Args:
            rules: List of SuricataRule objects
            test_mode: If True, convert all actions to 'alert' with [TEST-ACTION] prefix
            
        Returns:
            List of prepared rules (deepcopy if test_mode, original if not)
        """
        if not test_mode:
            return rules  # Return original rules for normal export
        
        from copy import deepcopy
        export_rules = []
        
        for rule in rules:
            rule_copy = deepcopy(rule)
            
            # Only convert actual rules (skip comments and blank lines)
            if not getattr(rule_copy, 'is_comment', False) and \
               not getattr(rule_copy, 'is_blank', False):
                
                # Store original action for message prefix
                original_action = rule_copy.action.upper()
                
                # Convert action to alert
                rule_copy.action = 'alert'
                
                # Add [TEST-ACTION] prefix with original action
                prefix = f"[TEST-{original_action}]"
                if not rule_copy.message.startswith('[TEST'):
                    rule_copy.message = f"{prefix} {rule_copy.message}"
                
                # Update original_options to reflect action change and message prefix
                if rule_copy.original_options:
                    import re
                    # Change action keyword to 'alert'
                    rule_copy.original_options = re.sub(
                        r'^(pass|drop|reject|alert)', 
                        'alert', 
                        rule_copy.original_options
                    )
                    # Add prefix to message
                    rule_copy.original_options = re.sub(
                        r'msg:"([^"]*)"',
                        lambda m: f'msg:"{prefix} {m.group(1)}"' 
                                 if not m.group(1).startswith('[TEST') 
                                 else m.group(0),
                        rule_copy.original_options
                    )
            
            export_rules.append(rule_copy)
        
        return export_rules
    
    def generate_terraform_template(self, rules: List[SuricataRule], variables: dict,
                                   test_mode: bool = False) -> str:
        """Generate Terraform template for AWS Network Firewall rule group with optional test mode"""
        
        # STEP 1: Prepare rules for export (convert to alert-only if test mode)
        export_rules = self._prepare_rules_for_export(rules, test_mode)
        
        # STEP 2: Calculate capacity using CONVERTED rules
        actual_capacity = len([r for r in export_rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)])
        capacity = actual_capacity + SuricataConstants.CAPACITY_BUFFER
        
        # Generate rules string with normalized line endings (LF only)
        # IMPORTANT: AWS Network Firewall API requires Unix (LF) line endings.
        # Normalize all line endings to LF to ensure cross-platform compatibility.
        # This prevents "Illegal rule syntax" errors when using comments on Windows.
        # See: GitHub issue hashicorp/terraform-provider-aws#40856
        rules_lines = []
        for rule in export_rules:
            if getattr(rule, 'is_blank', False):
                rules_lines.append('')
            elif getattr(rule, 'is_comment', False):
                # Strip any \r characters to ensure Unix line endings
                clean_comment = rule.comment_text.replace('\r\n', '\n').replace('\r', '')
                rules_lines.append(clean_comment)
            else:
                # Strip any \r characters from rule strings
                clean_rule = rule.to_string().replace('\r\n', '\n').replace('\r', '')
                rules_lines.append(clean_rule)
        
        # Join with Unix line endings only
        rules_string = '\n'.join(rules_lines)
        
        # Add comprehensive warning if test mode
        if test_mode:
            warning_comment = (
                "# ⚠️  WARNING: This rule group was exported in TEST MODE\n"
                "# All rule actions have been converted to 'alert' for safe testing\n"
                "# Message prefixes show original action: [TEST-DROP], [TEST-PASS], etc.\n"
                "#\n"
                "# IMPORTANT PREREQUISITE:\n"
                "# For test mode to work, your AWS Network Firewall POLICY must be\n"
                "# configured with NO default drop action.\n"
                "# Do NOT use: 'Drop all', 'Drop established', or 'Application Layer drop established'\n"
                "#\n"
                "# OPTIONAL (Recommended): Add 'Alert all' or 'Alert established' for enhanced visibility\n"
                "#\n"
                "# If your policy has ANY default drop action, traffic will be blocked\n"
                "# regardless of these alert rules. See AWS documentation:\n"
                "# https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html\n"
                "#\n"
                "# Rules will NOT block or drop traffic (assuming prerequisite met)\n"
                "# Export again without test mode checkbox for production deployment\n\n"
            )
            rules_string = warning_comment + rules_string
        
        # Analyze variable usage in rules to determine correct types
        variable_usage = self.analyze_variable_usage(export_rules)
        
        # Generate rule_variables and reference_sets sections
        rule_variables = ""
        reference_sets = ""
        
        if variables:
            has_rule_vars = False
            
            for var_name, var_data in variables.items():
                # Handle both old format (string) and new format (dict with definition/description)
                if isinstance(var_data, dict):
                    var_definition = var_data.get("definition", "")
                else:
                    var_definition = var_data  # Legacy format
                
                if var_definition.strip():
                    clean_name = var_name.lstrip('$@')
                    var_type = self.get_variable_type_from_usage(var_name, variable_usage)
                    
                    if var_type == "IP Set":
                        if not has_rule_vars:
                            rule_variables = "    rule_variables {\n"
                            has_rule_vars = True
                        # Strip brackets if present before splitting
                        clean_def = var_definition.strip()
                        if clean_def.startswith('[') and clean_def.endswith(']'):
                            clean_def = clean_def[1:-1]
                        cidrs = [f'"{cidr.strip()}"' for cidr in clean_def.split(',') if cidr.strip()]
                        cidr_array = '[' + ', '.join(cidrs) + ']'
                        rule_variables += f"      ip_sets {{\n"
                        rule_variables += f"        key = \"{clean_name}\"\n"
                        rule_variables += f"        ip_set {{ definition = {cidr_array} }}\n"
                        rule_variables += f"      }}\n"
                    elif var_type == "Port Set":
                        if not has_rule_vars:
                            rule_variables = "    rule_variables {\n"
                            has_rule_vars = True
                        # Strip brackets if present before splitting
                        clean_def = var_definition.strip()
                        if clean_def.startswith('[') and clean_def.endswith(']'):
                            clean_def = clean_def[1:-1]
                        ports = [f'"{port.strip()}"' for port in clean_def.split(',') if port.strip()]
                        port_array = '[' + ', '.join(ports) + ']'
                        rule_variables += f"      port_sets {{\n"
                        rule_variables += f"        key = \"{clean_name}\"\n"
                        rule_variables += f"        port_set {{ definition = {port_array} }}\n"
                        rule_variables += f"      }}\n"
                    elif var_type == "Reference":
                        reference_sets += f"    reference_sets {{\n"
                        reference_sets += f"      key = \"{clean_name}\"\n"
                        reference_sets += f"      reference_arn = \"{var_definition}\"\n"
                        reference_sets += f"    }}\n"
            
            if has_rule_vars:
                rule_variables += "    }\n"
        
        # Generate template
        template = f'''resource "aws_networkfirewall_rule_group" "suricata_rule_group" {{
  capacity    = {capacity}
  description = "This rule group was created by the Suricata Generator version {self.version}"
  name        = "suricata-generator-rg"
  type        = "STATEFUL"
  
  rule_group {{
{reference_sets}{rule_variables}    rules_source {{
      rules_string = <<EOF
{rules_string}
EOF
    }}
    stateful_rule_options {{
      rule_order = "STRICT_ORDER"
    }}
  }}

  tags = {{
    Name = "suricata-generator-rg"
  }}
}}
'''
        return template
    
    def generate_cloudformation_template(self, rules: List[SuricataRule], variables: dict,
                                        test_mode: bool = False) -> str:
        """Generate CloudFormation JSON template for AWS Network Firewall rule group with optional test mode"""
        
        # STEP 1: Prepare rules for export (convert to alert-only if test mode)
        export_rules = self._prepare_rules_for_export(rules, test_mode)
        
        # STEP 2: Calculate capacity using CONVERTED rules
        actual_capacity = len([r for r in export_rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)])
        capacity = actual_capacity + 100
        
        # Generate rules string with normalized line endings (LF only)
        # IMPORTANT: AWS Network Firewall API requires Unix (LF) line endings.
        # Normalize all line endings to LF to ensure cross-platform compatibility.
        # This prevents "Illegal rule syntax" errors when using comments on Windows.
        # See: GitHub issue hashicorp/terraform-provider-aws#40856
        rules_lines = []
        for rule in export_rules:
            if getattr(rule, 'is_blank', False):
                rules_lines.append('')
            elif getattr(rule, 'is_comment', False):
                # Strip any \r characters to ensure Unix line endings
                clean_comment = rule.comment_text.replace('\r\n', '\n').replace('\r', '')
                rules_lines.append(clean_comment)
            else:
                # Strip any \r characters from rule strings
                clean_rule = rule.to_string().replace('\r\n', '\n').replace('\r', '')
                rules_lines.append(clean_rule)
        
        # Join with Unix line endings only
        rules_string = '\n'.join(rules_lines)
        
        # Add comprehensive warning if test mode
        if test_mode:
            warning_comment = (
                "# ⚠️  WARNING: This rule group was exported in TEST MODE\n"
                "# All rule actions have been converted to 'alert' for safe testing\n"
                "# Message prefixes show original action: [TEST-DROP], [TEST-PASS], etc.\n"
                "#\n"
                "# IMPORTANT PREREQUISITE:\n"
                "# For test mode to work, your AWS Network Firewall POLICY must be\n"
                "# configured with NO default drop action.\n"
                "# Do NOT use: 'Drop all', 'Drop established', or 'Application Layer drop established'\n"
                "#\n"
                "# OPTIONAL (Recommended): Add 'Alert all' or 'Alert established' for enhanced visibility\n"
                "#\n"
                "# If your policy has ANY default drop action, traffic will be blocked\n"
                "# regardless of these alert rules. See AWS documentation:\n"
                "# https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html\n"
                "#\n"
                "# Rules will NOT block or drop traffic (assuming prerequisite met)\n"
                "# Export again without test mode checkbox for production deployment\n\n"
            )
            rules_string = warning_comment + rules_string
        
        # Analyze variable usage in rules to determine correct types
        variable_usage = self.analyze_variable_usage(export_rules)
        
        # Build template structure with conditional description
        description = (
            "TEST MODE: All actions converted to alert. Requires policy with no default drop action. "
            f"Created by Suricata Generator version {self.version}"
        ) if test_mode else f"Network Firewall Rule Group created by Suricata Generator version {self.version}"
        
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": description,
            "Resources": {
                "SuricataRuleGroup": {
                    "Type": "AWS::NetworkFirewall::RuleGroup",
                    "Properties": {
                        "Capacity": capacity,
                        "RuleGroupName": "suricata-generator-rg",
                        "Type": "STATEFUL",
                        "Description": description,
                        "RuleGroup": {
                            "RulesSource": {
                                "RulesString": rules_string
                            },
                            "StatefulRuleOptions": {
                                "RuleOrder": "STRICT_ORDER"
                            }
                        },
                        "Tags": [
                            {
                                "Key": "Name",
                                "Value": "suricata-generator-rg"
                            }
                        ]
                    }
                }
            }
        }
        
        # Add variables if they exist
        if variables:
            rule_variables = {}
            reference_sets = {}
            
            for var_name, var_data in variables.items():
                # Handle both old format (string) and new format (dict with definition/description)
                if isinstance(var_data, dict):
                    var_definition = var_data.get("definition", "")
                else:
                    var_definition = var_data  # Legacy format
                
                if var_definition.strip():
                    clean_name = var_name.lstrip('$@')
                    var_type = self.get_variable_type_from_usage(var_name, variable_usage)
                    
                    if var_type == "IP Set":
                        # Strip brackets if present before splitting
                        clean_def = var_definition.strip()
                        if clean_def.startswith('[') and clean_def.endswith(']'):
                            clean_def = clean_def[1:-1]
                        cidrs = [cidr.strip() for cidr in clean_def.split(',') if cidr.strip()]
                        if "IPSets" not in rule_variables:
                            rule_variables["IPSets"] = {}
                        rule_variables["IPSets"][clean_name] = {"Definition": cidrs}
                    elif var_type == "Port Set":
                        # Strip brackets if present before splitting
                        clean_def = var_definition.strip()
                        if clean_def.startswith('[') and clean_def.endswith(']'):
                            clean_def = clean_def[1:-1]
                        ports = [port.strip() for port in clean_def.split(',') if port.strip()]
                        if "PortSets" not in rule_variables:
                            rule_variables["PortSets"] = {}
                        rule_variables["PortSets"][clean_name] = {"Definition": ports}
                    elif var_type == "Reference":
                        reference_sets[clean_name] = {"ReferenceArn": var_definition}
            
            if rule_variables:
                template["Resources"]["SuricataRuleGroup"]["Properties"]["RuleGroup"]["RuleVariables"] = rule_variables
            
            if reference_sets:
                template["Resources"]["SuricataRuleGroup"]["Properties"]["ReferenceSets"] = reference_sets
        
        return json.dumps(template, indent=2)
    
    def load_aws_template(self) -> tuple[List[SuricataRule], dict]:
        """Load AWS best practices Suricata rules template from website"""
        try:
            url = "https://aws.github.io/aws-security-services-best-practices/guides/network-firewall/"
            # Validate URL scheme for security
            if not url.startswith(('http://', 'https://')):
                raise ValueError("Only HTTP/HTTPS URLs are allowed")
            with urllib.request.urlopen(url, timeout=10) as response:
                html_content = response.read().decode('utf-8')
            
            rules_text = self.extract_rules_from_html(html_content)
            
            if not rules_text:
                raise Exception("Could not find Suricata rules in the AWS best practices page.")
            
            # Parse the rules text into rule objects
            rules = []
            variables = {}
            lines = rules_text.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line:
                    blank_rule = SuricataRule()
                    blank_rule.is_blank = True
                    rules.append(blank_rule)
                elif line.startswith('#'):
                    comment_rule = SuricataRule()
                    comment_rule.is_comment = True
                    comment_rule.comment_text = line
                    rules.append(comment_rule)
                else:
                    rule = SuricataRule.from_string(line)
                    if rule:
                        rules.append(rule)
            
            return rules, variables
            
        except urllib.error.HTTPError as e:
            raise Exception(f"HTTP error fetching AWS template (status {e.code}): {str(e)}")
        except urllib.error.URLError as e:
            raise Exception(f"Network error fetching AWS template: {str(e)}")
        except UnicodeDecodeError:
            raise Exception("Failed to decode AWS template content")
        except Exception as e:
            raise Exception(f"Failed to load AWS template: {str(e)}")
    
    def extract_rules_from_html(self, html_content: str) -> str:
        """Extract Suricata rules from AWS best practices HTML content"""
        try:
            start_marker = "Below we have also included a custom template for an egress security use case"
            start_pos = html_content.find(start_marker)
            
            if start_pos == -1:
                return ""
            
            code_start = html_content.find("<code>", start_pos)
            if code_start == -1:
                code_start = html_content.find("<pre>", start_pos)
                if code_start == -1:
                    return ""
                code_end = html_content.find("</pre>", code_start)
                code_start = html_content.find(">", code_start) + 1
            else:
                code_end = html_content.find("</code>", code_start)
                code_start = html_content.find(">", code_start) + 1
            
            if code_end == -1:
                return ""
            
            rules_html = html_content[code_start:code_end]
            
            # Clean up HTML entities and tags
            rules_text = rules_html.replace("&lt;", "<")
            rules_text = rules_text.replace("&gt;", ">")
            rules_text = rules_text.replace("&amp;", "&")
            rules_text = rules_text.replace("&quot;", '"')
            rules_text = re.sub(r'<[^>]+>', '', rules_text)
            
            return rules_text.strip()
            
        except (AttributeError, ValueError, TypeError):
            return ""  # HTML parsing errors
        except (IndexError, KeyError, UnicodeError):
            return ""  # Other parsing errors
    
    def scan_rules_for_variables(self, rules: List[SuricataRule]) -> set:
        """Scan all rules for variable usage and return set of used variables"""
        used_vars = set()
        
        for rule in rules:
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            
            if rule.src_net.startswith(('$', '@')):
                used_vars.add(rule.src_net)
            if rule.dst_net.startswith(('$', '@')):
                used_vars.add(rule.dst_net)
            if rule.src_port.startswith(('$', '@')):
                used_vars.add(rule.src_port)
            if rule.dst_port.startswith(('$', '@')):
                used_vars.add(rule.dst_port)
        
        return used_vars
    
    def analyze_variable_usage(self, rules: List[SuricataRule]) -> dict:
        """Analyze how variables are used in rules to determine their correct types
        
        Returns:
            dict: Variable usage analysis with structure:
                  {var_name: {'ip_positions': set, 'port_positions': set}}
        """
        usage = {}
        
        for rule in rules:
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            
            # Check each field where variables can appear
            fields = [
                (rule.src_net, 'ip'),
                (rule.dst_net, 'ip'), 
                (rule.src_port, 'port'),
                (rule.dst_port, 'port')
            ]
            
            for field_value, position_type in fields:
                if field_value.startswith(('$', '@')):
                    if field_value not in usage:
                        usage[field_value] = {'ip_positions': set(), 'port_positions': set()}
                    
                    if position_type == 'ip':
                        usage[field_value]['ip_positions'].add(position_type)
                    elif position_type == 'port':
                        usage[field_value]['port_positions'].add(position_type)
        
        return usage
    
    def get_variable_type_from_usage(self, var_name: str, variable_usage: dict) -> str:
        """Determine variable type based on actual usage in rules
        
        Args:
            var_name: The variable name (e.g., '$src', '@HOME_REF')
            variable_usage: Usage analysis from analyze_variable_usage()
            
        Returns:
            str: "IP Set", "Port Set", or "Reference"
        """
        # For @ prefix, ALWAYS treat as Reference Set (AWS Network Firewall requirement)
        # @ variables should only be used in network fields, never in port fields
        if var_name.startswith('@'):
            return "Reference"
        
        # For non-$ variables, treat as Reference
        if not var_name.startswith('$'):
            return "Reference"
        
        # For $ variables, analyze usage to determine type
        if var_name in variable_usage:
            usage_info = variable_usage[var_name]
            has_ip_usage = bool(usage_info['ip_positions'])
            has_port_usage = bool(usage_info['port_positions'])
            
            if has_port_usage and not has_ip_usage:
                # Used only in port positions -> Port Set
                return "Port Set"
            elif has_ip_usage and not has_port_usage:
                # Used only in IP positions -> IP Set
                return "IP Set"
            elif has_port_usage and has_ip_usage:
                # Used in both positions - this is ambiguous, default to IP Set
                # In practice this shouldn't happen with well-formed rules
                return "IP Set"
        
        # Fallback: default behavior based on prefix
        return "IP Set"
    
    def get_variable_type(self, var_name: str) -> str:
        """Determine variable type based on prefix (legacy method for CloudFormation)"""
        if var_name.startswith('$'):
            return "IP Set"
        elif var_name.startswith('@'):
            return "Port Set"
        else:
            return "Reference"
    
    def detect_header(self, rules: List[SuricataRule]) -> tuple[bool, Optional[str]]:
        """Detect if file has our header format and extract creation timestamp"""
        if len(rules) < 4:
            return False, None
        
        # Check first 4 rules for exact header format
        if (not getattr(rules[0], 'is_comment', False) or
            not getattr(rules[1], 'is_comment', False) or
            not getattr(rules[2], 'is_comment', False) or
            not getattr(rules[3], 'is_comment', False)):
            return False, None
        
        # Check line 1: Generated by Suricata Rule Generator v[version]
        line1 = rules[0].comment_text
        if not re.match(r'^# Generated by Suricata Rule Generator v[\d.]+$', line1):
            return False, None
        
        # Check line 2: Created: [timestamp]
        line2 = rules[1].comment_text
        created_match = re.match(r'^# Created:\t\t(\d{4}-\d{2}-\d{2} \d{2}:\d{2})$', line2)
        if not created_match:
            return False, None
        
        # Check line 3: Last Modified: [timestamp]
        line3 = rules[2].comment_text
        if not re.match(r'^# Last Modified:\t\t\d{4}-\d{2}-\d{2} \d{2}:\d{2}$', line3):
            return False, None
        
        # Check line 4: Just #
        line4 = rules[3].comment_text
        if line4 != '#':
            return False, None
        
        return True, created_match.group(1)
    
    def create_header(self, rules: List[SuricataRule]) -> List[SuricataRule]:
        """Create header for new files"""
        import datetime
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        
        header_rules = []
        
        # Line 1: Generated by
        gen_rule = SuricataRule()
        gen_rule.is_comment = True
        gen_rule.comment_text = f"# Generated by Suricata Rule Generator v{self.version}"
        header_rules.append(gen_rule)
        
        # Line 2: Created
        created_rule = SuricataRule()
        created_rule.is_comment = True
        created_rule.comment_text = f"# Created:\t\t{timestamp}"
        header_rules.append(created_rule)
        
        # Line 3: Last Modified
        modified_rule = SuricataRule()
        modified_rule.is_comment = True
        modified_rule.comment_text = f"# Last Modified:\t\t{timestamp}"
        header_rules.append(modified_rule)
        
        # Line 4: Empty comment
        empty_rule = SuricataRule()
        empty_rule.is_comment = True
        empty_rule.comment_text = "#"
        header_rules.append(empty_rule)
        
        return header_rules + rules
    
    def update_header(self, rules: List[SuricataRule]):
        """Update header with current version and timestamp"""
        if len(rules) < 4:
            return
        
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        
        # Update line 1: version
        rules[0].comment_text = f"# Generated by Suricata Rule Generator v{self.version}"
        
        # Update line 3: last modified
        rules[2].comment_text = f"# Last Modified:\t\t{timestamp}"
    
    def _auto_correct_port_brackets(self, rule_line: str) -> str:
        """Auto-correct port specifications to use proper Suricata bracket syntax
        
        Converts port ranges and complex port specs to bracket format:
        - 8080:8090 → [8080:8090]  
        - 80,443,8080:8090 → [80,443,8080:8090]
        - 80:100,!85 → [80:100,!85]
        
        Uses bracket-aware tokenization to handle network specifications with spaces correctly.
        
        Args:
            rule_line: Original Suricata rule line
            
        Returns:
            str: Rule line with corrected port bracket syntax
        """
        # Extract the options part if it exists
        options_match = re.search(r'\(([^)]*)\)$', rule_line)
        options_str = options_match.group(0) if options_match else ""
        
        # Remove options part from rule string for field parsing
        if options_match:
            rule_without_options = rule_line[:options_match.start()].strip()
        else:
            rule_without_options = rule_line
        
        # Split into tokens using bracket-aware parsing (same logic as SuricataRule.from_string)
        tokens = []
        current_token = ""
        bracket_depth = 0
        
        for char in rule_without_options:
            if char == '[':
                bracket_depth += 1
                current_token += char
            elif char == ']':
                bracket_depth -= 1
                current_token += char
            elif char.isspace() and bracket_depth == 0:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char
        
        # Don't forget the last token
        if current_token:
            tokens.append(current_token)
        
        # We should have exactly 7 tokens: action protocol src_net src_port direction dst_net dst_port
        if len(tokens) != 7:
            return rule_line  # Can't parse correctly, return unchanged
        
        action, protocol, src_net, src_port, direction, dst_net, dst_port = tokens
        
        # Validate direction token
        if direction not in ['->', '<>']:
            return rule_line  # Invalid direction, return unchanged
        
        # Auto-correct source port if needed
        corrected_src_port = self._add_brackets_if_needed(src_port)
        
        # Auto-correct destination port if needed  
        corrected_dst_port = self._add_brackets_if_needed(dst_port)
        
        # Reconstruct the rule line with corrected ports
        corrected_line = f"{action} {protocol} {src_net} {corrected_src_port} {direction} {dst_net} {corrected_dst_port}"
        
        # Add options back if they existed
        if options_str:
            corrected_line += f" {options_str}"
        
        return corrected_line
    
    def _add_brackets_if_needed(self, port_spec: str) -> str:
        """Add brackets to port specification if needed for Suricata compliance
        
        Args:
            port_spec: Port specification (e.g., "8080:8090", "80,443", "$WEB_PORTS", "any")
            
        Returns:
            str: Port specification with brackets if needed
        """
        port_spec = port_spec.strip()
        
        # Don't modify these cases:
        if (port_spec.lower() == 'any' or          # 'any' keyword
            port_spec.startswith('$') or           # Variables
            port_spec.startswith('@') or           # Reference sets  
            port_spec.startswith('[') or           # Already has brackets
            not port_spec):                        # Empty
            return port_spec
        
        # Check if it's a simple single port number
        try:
            port_num = int(port_spec)
            if 1 <= port_num <= 65535:
                return port_spec  # Single ports don't need brackets
        except ValueError:
            pass
        
        # If it contains range operators, commas, or negation, it needs brackets
        if ':' in port_spec or ',' in port_spec or '!' in port_spec:
            return f"[{port_spec}]"
        
        return port_spec  # Return unchanged if none of the above conditions met
    
    def _fix_rule_text_escaping(self, history_filename: str):
        """Post-process history file to fix escaped quotes in rule_text fields"""
        try:
            # Read the JSON file and parse it
            with open(history_filename, 'r', encoding='utf-8') as f:
                history_data = json.load(f)
            
            # Fix escaped quotes in rule_text fields within the parsed data
            changes = history_data.get('changes', [])
            for change in changes:
                details = change.get('details', {})
                if 'rule_text' in details:
                    # The JSON parsing already handles the escaping correctly
                    # No need to modify - just ensure we're working with clean data
                    pass
            
            # Re-save the file with clean JSON formatting
            with open(history_filename, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, indent=2, ensure_ascii=False)
                
        except (OSError, IOError, ValueError, json.JSONDecodeError):
            # If post-processing fails, leave the original file unchanged
            pass
    
    def deploy_to_aws(self, rules: List, variables: dict, rule_group_name: str, 
                     test_mode: bool, parent_app, region: str = None) -> bool:
        """Deploy rules directly to AWS Network Firewall
        
        Args:
            rules: List of SuricataRule objects
            variables: Variable definitions dictionary
            rule_group_name: AWS-compliant rule group name
            test_mode: If True, convert all actions to 'alert'
            parent_app: Reference to parent application for progress updates
            region: AWS region to deploy to (optional, uses default if not specified)
            
        Returns:
            bool: True if deployment succeeded
            
        Raises:
            NoCredentialsError: AWS credentials not configured
            ClientError: AWS API error (permissions, limits, etc.)
        """
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            raise ImportError("boto3 is required for AWS deployment")
        
        # Create progress dialog
        progress_dialog = tk.Toplevel(parent_app.root)
        progress_dialog.title("Deploying to AWS")
        progress_dialog.geometry("400x120")
        progress_dialog.transient(parent_app.root)
        progress_dialog.grab_set()
        
        # Center dialog
        progress_dialog.geometry("+%d+%d" % (
            parent_app.root.winfo_rootx() + 200,
            parent_app.root.winfo_rooty() + 200
        ))
        
        progress_frame = ttk.Frame(progress_dialog)
        progress_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        ttk.Label(progress_frame, text="Deploying rule group to AWS...").pack(pady=20)
        progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        progress_bar.pack(pady=10)
        progress_bar.start(10)
        
        # Force dialog to display
        progress_dialog.update()
        
        try:
            # STEP 1: Convert rules if test mode
            export_rules = self._prepare_rules_for_export(rules, test_mode)
            
            # STEP 2: Calculate capacity
            actual_capacity = len([r for r in export_rules 
                                 if not getattr(r, 'is_comment', False) 
                                 and not getattr(r, 'is_blank', False)])
            capacity = actual_capacity + 100
            
            # STEP 3: Generate rules string (reuse existing logic with normalized line endings)
            rules_lines = []
            for rule in export_rules:
                if getattr(rule, 'is_blank', False):
                    rules_lines.append('')
                elif getattr(rule, 'is_comment', False):
                    # Strip any \r characters to ensure Unix line endings
                    clean_comment = rule.comment_text.replace('\r\n', '\n').replace('\r', '')
                    rules_lines.append(clean_comment)
                else:
                    # Strip any \r characters from rule strings
                    clean_rule = rule.to_string().replace('\r\n', '\n').replace('\r', '')
                    rules_lines.append(clean_rule)
            
            rules_string = '\n'.join(rules_lines)
            
            # STEP 4: Build RuleGroup structure
            rule_group = {
                'RulesSource': {
                    'RulesString': rules_string
                },
                'StatefulRuleOptions': {
                    'RuleOrder': 'STRICT_ORDER'
                }
            }
            
            # STEP 5: Add variables if they exist
            rule_variables = self._build_rule_variables(variables, export_rules)
            if rule_variables:
                rule_group['RuleVariables'] = rule_variables
            
            # STEP 6: Build ReferenceSets
            reference_sets = self._build_reference_sets(variables, export_rules)
            
            # STEP 7: Create boto3 client with specified region
            client = boto3.client('network-firewall', region_name=region)
            
            # STEP 8: Check if rule group exists (for overwrite detection)
            rule_group_exists = False
            rule_group_arn = None
            update_token = None
            
            try:
                existing_rg = client.describe_rule_group(
                    RuleGroupName=rule_group_name,
                    Type='STATEFUL'
                )
                
                # Rule group exists - show overwrite confirmation
                should_proceed = self._show_overwrite_confirmation_dialog(
                    rule_group_name, 
                    existing_rg,
                    parent_app
                )
                
                if not should_proceed:
                    progress_dialog.destroy()
                    return False  # User declined to overwrite
                
                # Extract info needed for update
                rule_group_exists = True
                rule_group_arn = existing_rg['RuleGroupResponse']['RuleGroupArn']
                update_token = existing_rg['UpdateToken']
                    
            except client.exceptions.ResourceNotFoundException:
                # Rule group doesn't exist - safe to create
                rule_group_exists = False
            
            # STEP 9: Create or update rule group based on existence
            # Get current date for description
            from datetime import datetime
            current_date = datetime.now().strftime('%Y-%m-%d')
            
            if rule_group_exists:
                # Update existing rule group
                api_params = {
                    'UpdateToken': update_token,
                    'RuleGroupArn': rule_group_arn,
                    'RuleGroup': rule_group,
                    'Description': f'Updated by Suricata Generator v{self.version} on {current_date}',
                    'Type': 'STATEFUL'
                }
                
                # Only add ReferenceSets if there are actual references (AWS requirement)
                if reference_sets:
                    api_params['ReferenceSets'] = reference_sets
                
                response = client.update_rule_group(**api_params)
            else:
                # Create new rule group
                api_params = {
                    'RuleGroupName': rule_group_name,
                    'Type': 'STATEFUL',
                    'RuleGroup': rule_group,
                    'Capacity': capacity,
                    'Description': f'Created by Suricata Generator v{self.version} on {current_date}'
                }
                
                # Only add ReferenceSets if there are actual references (AWS requirement)
                if reference_sets:
                    api_params['ReferenceSets'] = reference_sets
                
                response = client.create_rule_group(**api_params)
            
            # Close progress dialog
            progress_dialog.destroy()
            
            # STEP 10: Show success dialog
            self._show_deployment_success(
                rule_group_name, 
                response,
                actual_capacity,
                parent_app
            )
            
            # STEP 11: Log deployment if tracking enabled
            if parent_app.tracking_enabled:
                export_details = {
                    'format': 'aws',
                    'test_mode': test_mode,
                    'rule_group_name': rule_group_name,
                    'arn': response['RuleGroupResponse']['RuleGroupArn'],
                    'rule_count': actual_capacity,
                    'capacity': capacity
                }
                action = 'test_export' if test_mode else 'production_export'
                parent_app.add_history_entry(action, export_details)
            
            return True
            
        except NoCredentialsError:
            progress_dialog.destroy()
            messagebox.showerror(
                "AWS Credentials Not Found",
                "AWS credentials are not configured.\n\n"
                "To use AWS export, configure credentials using:\n"
                "• AWS CLI: aws configure\n"
                "• Environment variables\n"
                "• IAM role (if on AWS)\n\n"
                "See Help > AWS Setup for detailed instructions."
            )
            return False
        except ClientError as e:
            progress_dialog.destroy()
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            
            if error_code == 'AccessDeniedException':
                messagebox.showerror(
                    "Insufficient AWS Permissions",
                    "Your AWS credentials lack permission to create rule groups.\n\n"
                    "Required IAM actions:\n"
                    "• network-firewall:CreateRuleGroup\n"
                    "• network-firewall:UpdateRuleGroup\n\n"
                    "See Help > AWS Setup for complete IAM policy."
                )
            elif error_code == 'LimitExceededException':
                messagebox.showerror(
                    "AWS Account Limit Exceeded",
                    f"AWS account limit reached.\n\n"
                    f"Error: {error_message}\n\n"
                    "You may have reached the limit for:\n"
                    "• Total rule groups per account\n"
                    "• Total capacity units used\n\n"
                    "Consider deleting unused rule groups or requesting a limit increase."
                )
            elif error_code == 'InvalidRequestException':
                messagebox.showerror(
                    "Invalid Request",
                    f"AWS rejected the request.\n\n"
                    f"Error: {error_message}\n\n"
                    "This may be due to:\n"
                    "• Invalid rule syntax\n"
                    "• Unsupported features\n"
                    "• Validation errors"
                )
            else:
                messagebox.showerror(
                    "AWS Deployment Error",
                    f"Failed to deploy rule group.\n\n"
                    f"Error Code: {error_code}\n"
                    f"Message: {error_message}"
                )
            return False
        except Exception as e:
            progress_dialog.destroy()
            messagebox.showerror(
                "Deployment Error",
                f"An unexpected error occurred:\n\n{str(e)}"
            )
            return False
    
    def _build_rule_variables(self, variables: dict, export_rules: List) -> dict:
        """Build RuleVariables section for AWS API
        
        Args:
            variables: Variable definitions dictionary
            export_rules: List of rules to export (for usage analysis)
            
        Returns:
            dict: RuleVariables structure for AWS API
        """
        if not variables:
            return {}
        
        # Analyze variable usage to determine correct types
        variable_usage = self.analyze_variable_usage(export_rules)
        
        rule_variables = {}
        
        for var_name, var_data in variables.items():
            # Extract definition (handle both formats)
            if isinstance(var_data, dict):
                definition = var_data.get("definition", "")
            else:
                definition = var_data
            
            if not definition.strip():
                continue
            
            clean_name = var_name.lstrip('$@')
            var_type = self.get_variable_type_from_usage(var_name, variable_usage)
            
            if var_type == "IP Set":
                # Strip brackets if present before splitting
                clean_def = definition.strip()
                if clean_def.startswith('[') and clean_def.endswith(']'):
                    clean_def = clean_def[1:-1]
                cidrs = [cidr.strip() for cidr in clean_def.split(',') if cidr.strip()]
                
                if "IPSets" not in rule_variables:
                    rule_variables["IPSets"] = {}
                rule_variables["IPSets"][clean_name] = {"Definition": cidrs}
            
            elif var_type == "Port Set":
                # Strip brackets if present before splitting
                clean_def = definition.strip()
                if clean_def.startswith('[') and clean_def.endswith(']'):
                    clean_def = clean_def[1:-1]
                ports = [port.strip() for port in clean_def.split(',') if port.strip()]
                
                if "PortSets" not in rule_variables:
                    rule_variables["PortSets"] = {}
                rule_variables["PortSets"][clean_name] = {"Definition": ports}
        
        return rule_variables
    
    def _build_reference_sets(self, variables: dict, export_rules: List) -> dict:
        """Build ReferenceSets section for AWS API
        
        Args:
            variables: Variable definitions dictionary
            export_rules: List of rules to export (for usage analysis)
            
        Returns:
            dict: ReferenceSets structure for AWS API
        """
        if not variables:
            return {}
        
        # Analyze variable usage to determine correct types
        variable_usage = self.analyze_variable_usage(export_rules)
        
        reference_sets = {}
        
        for var_name, var_data in variables.items():
            # Extract definition (handle both formats)
            if isinstance(var_data, dict):
                definition = var_data.get("definition", "")
            else:
                definition = var_data
            
            if not definition.strip():
                continue
            
            clean_name = var_name.lstrip('$@')
            var_type = self.get_variable_type_from_usage(var_name, variable_usage)
            
            if var_type == "Reference":
                reference_sets[clean_name] = {"ReferenceArn": definition}
        
        return reference_sets
    
    def _show_overwrite_confirmation_dialog(self, rule_group_name: str, existing_rg: dict,
                                           parent_app) -> bool:
        """Show confirmation dialog when rule group already exists
        
        Args:
            rule_group_name: Name of existing rule group
            existing_rg: Existing rule group details from describe_rule_group
            parent_app: Reference to parent application for dialog creation
            
        Returns:
            bool: True if user confirms overwrite, False otherwise
        """
        from tkinter import messagebox
        
        # Extract existing rule group details
        rg_response = existing_rg.get('RuleGroupResponse', {})
        existing_capacity = rg_response.get('Capacity', 'Unknown')
        existing_associations = rg_response.get('NumberOfAssociations', 0)
        
        # Detect existing format (standard 5-tuple vs Suricata)
        rules_source = existing_rg.get('RuleGroup', {}).get('RulesSource', {})
        is_standard_format = 'StatefulRules' in rules_source
        is_suricata_format = 'RulesString' in rules_source
        
        if is_standard_format:
            existing_format = "Standard 5-tuple"
        elif is_suricata_format:
            existing_format = "Suricata format"
        else:
            existing_format = "Unknown"
        
        # Build warning message
        warning_message = (
            f"⚠️  A rule group named '{rule_group_name}' already exists in AWS.\n\n"
            f"Existing Rule Group Details:\n"
            f"• Capacity: {existing_capacity}\n"
            f"• Format: {existing_format}\n"
            f"• Firewall Associations: {existing_associations}\n\n"
            f"Deploying will OVERWRITE the existing rule group with your current rules.\n\n"
        )
        
        # Add format conversion note if converting from standard to Suricata
        if is_standard_format:
            warning_message += (
                "ℹ️  Note: The existing rule group uses standard 5-tuple format.\n"
                "Deploying will convert it to Suricata format.\n\n"
            )
        
        # Build dialog with bold text support if associations exist
        if existing_associations > 0:
            # Create custom dialog to support bold text for CRITICAL
            dialog = tk.Toplevel(parent_app.root)
            dialog.title("Confirm Overwrite")
            dialog.geometry("550x400")
            dialog.transient(parent_app.root)
            dialog.grab_set()
            
            # Center dialog
            dialog.geometry("+%d+%d" % (
                parent_app.root.winfo_rootx() + 150,
                parent_app.root.winfo_rooty() + 150
            ))
            
            main_frame = ttk.Frame(dialog)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            # Create text widget for formatted message
            text_widget = tk.Text(main_frame, wrap=tk.WORD, font=("TkDefaultFont", 9),
                                 relief=tk.FLAT, cursor="arrow",
                                 height=16, width=60, borderwidth=0, highlightthickness=0)
            text_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
            
            # Configure tags
            text_widget.tag_configure("bold", font=("TkDefaultFont", 9, "bold"))
            text_widget.tag_configure("critical", font=("TkDefaultFont", 9, "bold"), foreground="red")
            
            # Insert message with formatting
            text_widget.insert(tk.END, f"⚠️  A rule group named '{rule_group_name}' already exists in AWS.\n\n")
            text_widget.insert(tk.END, "Existing Rule Group Details:\n")
            text_widget.insert(tk.END, f"• Capacity: {existing_capacity}\n")
            text_widget.insert(tk.END, f"• Format: {existing_format}\n")
            text_widget.insert(tk.END, f"• Firewall Associations: {existing_associations}\n\n")
            text_widget.insert(tk.END, "Deploying will OVERWRITE the existing rule group with your current rules.\n\n")
            
            # Add format conversion note if needed
            if is_standard_format:
                text_widget.insert(tk.END, "ℹ️  Note: The existing rule group uses standard 5-tuple format.\n")
                text_widget.insert(tk.END, "Deploying will convert it to Suricata format.\n\n")
            
            # Add CRITICAL warning with bold formatting
            text_widget.insert(tk.END, "⚠️  ")
            text_widget.insert(tk.END, "CRITICAL:", "critical")
            text_widget.insert(tk.END, f" This rule group is currently attached to {existing_associations} firewall(s).\n")
            text_widget.insert(tk.END, "Overwriting will immediately affect live traffic on these firewalls!\n\n")
            
            text_widget.insert(tk.END, "Are you sure you want to overwrite the existing rule group?")
            
            # Make read-only
            text_widget.config(state=tk.DISABLED)
            
            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X)
            
            result = [False]
            
            def on_yes():
                result[0] = True
                dialog.destroy()
            
            def on_no():
                result[0] = False
                dialog.destroy()
            
            ttk.Button(button_frame, text="Yes", command=on_yes).pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(button_frame, text="No", command=on_no).pack(side=tk.RIGHT)
            
            dialog.wait_window()
            return result[0]
        else:
            # No associations - use standard messagebox
            warning_message += "Are you sure you want to overwrite the existing rule group?"
            
            response = messagebox.askyesno(
                "Confirm Overwrite",
                warning_message,
                icon='warning'
            )
            
            return response
    
    def _show_deployment_success(self, rule_group_name: str, response: dict, 
                                 rule_count: int, parent_app):
        """Show success dialog after deployment with clickable AWS console link
        
        Args:
            rule_group_name: Name of deployed rule group
            response: AWS API response
            rule_count: Number of rules deployed
            parent_app: Reference to parent application for dialog creation
        """
        import webbrowser
        import boto3
        
        arn = response['RuleGroupResponse']['RuleGroupArn']
        
        # Get region from boto3 session
        session = boto3.Session()
        region = session.region_name or 'us-east-1'
        
        # Construct AWS console URL for the rule group
        console_url = f"https://{region}.console.aws.amazon.com/vpcconsole/home?region={region}#NetworkFirewallRuleGroups:"
        
        # Create custom dialog
        dialog = tk.Toplevel(parent_app.root)
        dialog.title("✓ Deployment Successful")
        dialog.geometry("550x350")
        dialog.transient(parent_app.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (
            parent_app.root.winfo_rootx() + 150,
            parent_app.root.winfo_rooty() + 150
        ))
        
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Success title
        title_label = ttk.Label(
            main_frame, 
            text="✓ Deployment Successful",
            font=("TkDefaultFont", 12, "bold"),
            foreground="green"
        )
        title_label.pack(pady=(0, 15))
        
        # Details frame
        details_frame = ttk.LabelFrame(main_frame, text="Deployment Details")
        details_frame.pack(fill=tk.X, pady=(0, 15))
        
        details_text = (
            f"Rule Group: {rule_group_name}\n"
            f"Status: Active\n"
            f"Rules Deployed: {rule_count}\n"
            f"ARN: {arn}"
        )
        
        details_label = ttk.Label(
            details_frame,
            text=details_text,
            justify=tk.LEFT,
            font=("TkDefaultFont", 9)
        )
        details_label.pack(anchor=tk.W, padx=10, pady=10)
        
        # AWS Console link section
        console_frame = ttk.LabelFrame(main_frame, text="View in AWS Console")
        console_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Instruction text
        console_text = ttk.Label(
            console_frame,
            text="Network Firewall → Rule Groups →",
            font=("TkDefaultFont", 9)
        )
        console_text.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        # Clickable rule group name (as a button styled like a link)
        def open_console():
            webbrowser.open(console_url)
        
        link_button = tk.Button(
            console_frame,
            text=rule_group_name,
            fg="blue",
            cursor="hand2",
            relief=tk.FLAT,
            font=("TkDefaultFont", 9, "underline"),
            command=open_console,
            borderwidth=0,
            highlightthickness=0
        )
        link_button.pack(anchor=tk.W, padx=10, pady=(0, 10))
        
        # Add hover effect
        def on_enter(e):
            link_button.config(fg="dark blue")
        
        def on_leave(e):
            link_button.config(fg="blue")
        
        link_button.bind("<Enter>", on_enter)
        link_button.bind("<Leave>", on_leave)
        
        # Close button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        close_button = ttk.Button(
            button_frame,
            text="Close",
            command=dialog.destroy
        )
        close_button.pack(side=tk.RIGHT)
        
        # Focus the close button
        close_button.focus()
        
        # Bind Enter key to close
        dialog.bind('<Return>', lambda e: dialog.destroy())
        dialog.bind('<Escape>', lambda e: dialog.destroy())
