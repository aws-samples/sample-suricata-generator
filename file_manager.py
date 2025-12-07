"""
File Manager Module for Suricata Rule Generator

Handles all file I/O operations including:
- Loading/saving .suricata files
- Variable file management (.var files)
- History file management (.history files)
- Export functionality (Terraform/CloudFormation)
"""

import os
import json
import re
import urllib.request
import urllib.error
from typing import List, Optional
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
        undefined_vars = [var for var in used_vars if var not in variables or not variables[var].strip()]
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
        """Load companion .var file if it exists"""
        var_filename = suricata_filename.replace('.suricata', '.var')
        if not var_filename.endswith('.var'):
            var_filename += '.var'
        
        if os.path.exists(var_filename):
            try:
                with open(var_filename, 'r', encoding='utf-8') as f:
                    return json.load(f)
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
        """Save companion .var file with variable definitions"""
        if not variables:
            return
        
        var_filename = suricata_filename.replace('.suricata', '.var')
        if not var_filename.endswith('.var'):
            var_filename += '.var'
        
        try:
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
            
            # Add pending entries
            history_data['changes'].extend(pending_history)
            
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
    
    def generate_terraform_template(self, rules: List[SuricataRule], variables: dict) -> str:
        """Generate Terraform template for AWS Network Firewall rule group"""
        
        # Calculate capacity and add buffer
        actual_capacity = len([r for r in rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)])
        capacity = actual_capacity + SuricataConstants.CAPACITY_BUFFER
        
        # Generate rules string with normalized line endings (LF only)
        # IMPORTANT: AWS Network Firewall API requires Unix (LF) line endings.
        # Normalize all line endings to LF to ensure cross-platform compatibility.
        # This prevents "Illegal rule syntax" errors when using comments on Windows.
        # See: GitHub issue hashicorp/terraform-provider-aws#40856
        rules_lines = []
        for rule in rules:
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
        
        # Analyze variable usage in rules to determine correct types
        variable_usage = self.analyze_variable_usage(rules)
        
        # Generate rule_variables and reference_sets sections
        rule_variables = ""
        reference_sets = ""
        
        if variables:
            has_rule_vars = False
            
            for var_name, var_definition in variables.items():
                if var_definition.strip():
                    clean_name = var_name.lstrip('$@')
                    var_type = self.get_variable_type_from_usage(var_name, variable_usage)
                    
                    if var_type == "IP Set":
                        if not has_rule_vars:
                            rule_variables = "    rule_variables {\n"
                            has_rule_vars = True
                        cidrs = [f'"{cidr.strip()}"' for cidr in var_definition.split(',') if cidr.strip()]
                        cidr_array = '[' + ', '.join(cidrs) + ']'
                        rule_variables += f"      ip_sets {{\n"
                        rule_variables += f"        key = \"{clean_name}\"\n"
                        rule_variables += f"        ip_set {{ definition = {cidr_array} }}\n"
                        rule_variables += f"      }}\n"
                    elif var_type == "Port Set":
                        if not has_rule_vars:
                            rule_variables = "    rule_variables {\n"
                            has_rule_vars = True
                        ports = [f'"{port.strip()}"' for port in var_definition.split(',') if port.strip()]
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
    
    def generate_cloudformation_template(self, rules: List[SuricataRule], variables: dict) -> str:
        """Generate CloudFormation JSON template for AWS Network Firewall rule group"""
        
        # Calculate capacity and add buffer
        actual_capacity = len([r for r in rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)])
        capacity = actual_capacity + 100
        
        # Generate rules string with normalized line endings (LF only)
        # IMPORTANT: AWS Network Firewall API requires Unix (LF) line endings.
        # Normalize all line endings to LF to ensure cross-platform compatibility.
        # This prevents "Illegal rule syntax" errors when using comments on Windows.
        # See: GitHub issue hashicorp/terraform-provider-aws#40856
        rules_lines = []
        for rule in rules:
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
        
        # Analyze variable usage in rules to determine correct types
        variable_usage = self.analyze_variable_usage(rules)
        
        # Build template structure
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"Network Firewall Rule Group created by Suricata Generator version {self.version}",
            "Resources": {
                "SuricataRuleGroup": {
                    "Type": "AWS::NetworkFirewall::RuleGroup",
                    "Properties": {
                        "Capacity": capacity,
                        "RuleGroupName": "suricata-generator-rg",
                        "Type": "STATEFUL",
                        "Description": f"This rule group was created by the Suricata Generator version {self.version}",
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
            
            for var_name, var_definition in variables.items():
                if var_definition.strip():
                    clean_name = var_name.lstrip('$@')
                    var_type = self.get_variable_type_from_usage(var_name, variable_usage)
                    
                    if var_type == "IP Set":
                        cidrs = [cidr.strip() for cidr in var_definition.split(',') if cidr.strip()]
                        if "IPSets" not in rule_variables:
                            rule_variables["IPSets"] = {}
                        rule_variables["IPSets"][clean_name] = {"Definition": cidrs}
                    elif var_type == "Port Set":
                        ports = [port.strip() for port in var_definition.split(',') if port.strip()]
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
