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
from src.core.suricata_rule import SuricataRule
from src.core.constants import SuricataConstants, SecurityConstants, ValidationMessages, classify_reference_arn
from src.core.security_validator import validate_file_operation, security_validator
from src.core.version import get_main_version


class FileManager:
    """Manages all file operations for the Suricata Rule Generator"""
    
    # AWS Network Firewall limits the RulesString of a stateful rule group to
    # 2 MB (2,000,000 bytes, UTF-8). Exceeding it makes AWS reject the deploy /
    # apply, so the export paths check this before proceeding.
    RULES_STRING_MAX_BYTES = 2_000_000
    
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
            
            # Load companion .var file if it exists (returns both variables and tags)
            variables, tags = self.load_variables_file(filename)
            
            # Check for existing header and extract timestamp
            has_header, created_timestamp = self.detect_header(rules)
            
            # Note: load_rules_from_file returns only variables for backward compatibility
            # Tags will be loaded separately by the main application via load_variables_file
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
                          tags: dict = None, has_header: bool = False, tracking_enabled: bool = False, 
                          pending_history: List = None) -> bool:
        """Save rules to a .suricata file with validation
        
        Args:
            filename: Path to .suricata file
            rules: List of SuricataRule objects
            variables: Variables dictionary
            tags: Tags dictionary (optional, defaults to empty dict)
            has_header: Whether file has header
            tracking_enabled: Whether change tracking is enabled
            pending_history: Pending history entries to write
        """
        
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
            
            # Save companion .var file if variables or tags are used
            if used_vars or tags:
                self.save_variables_file(filename, variables, tags)
            
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
    
    def detect_var_format(self, var_data: dict) -> str:
        """Detect .var file format version
        
        Args:
            var_data: Parsed JSON from .var file
            
        Returns:
            str: '1.0' (legacy), '2.0' (variables + tags), or '2.1'
                 (adds a stored 'type' marker on @ variables)
        """
        # Check for format_version key (explicit versioning).
        # Recognizes '2.1' (container-association type markers) as well as
        # any other explicitly stated version; 2.0 and 2.1 are structurally
        # identical on load, differing only in whether @ vars carry 'type'.
        if 'format_version' in var_data:
            return var_data['format_version']
        
        # Check for 'variables' or 'tags' keys (implicit v2.0)
        if 'variables' in var_data or 'tags' in var_data:
            return '2.0'
        
        # Legacy format - variables at root level
        return '1.0'
    
    def load_variables_file(self, suricata_filename: str) -> tuple[dict, dict]:
        """Load companion .var file if it exists
        
        Supports v1.0 (legacy), v2.0, and v2.1 formats.
        Legacy format: {"$VAR": "value"} or {"$VAR": {"definition": "value", "description": "text"}}
        New format v2.0: {"format_version": "2.0", "variables": {...}, "tags": {...}}
        New format v2.1: same as v2.0, but @ variables may carry a stored
            "type" ("reference" | "container"). v1.0/v2.0 @ variables have no
            "type" and default to Reference via resolve_reference_type.
        
        Returns:
            tuple: (variables_dict, tags_dict)
        """
        var_filename = suricata_filename.replace('.suricata', '.var')
        if not var_filename.endswith('.var'):
            var_filename += '.var'
        
        if os.path.exists(var_filename):
            try:
                with open(var_filename, 'r', encoding='utf-8') as f:
                    raw_data = json.load(f)
                
                # Detect format version
                format_version = self.detect_var_format(raw_data)
                
                # v2.0 and v2.1 share the same structure (format_version,
                # variables, tags); only v1.0 stores variables at the root.
                if format_version in ('2.0', '2.1'):
                    # New format - has format_version, variables, and tags keys
                    variables_data = raw_data.get('variables', {})
                    tags = raw_data.get('tags', {})
                else:
                    # Legacy format (v1.0) - variables at root level
                    variables_data = raw_data
                    tags = {}  # No tags in legacy format
                
                # Convert variables to new dict format if needed
                variables = {}
                for name, value in variables_data.items():
                    if isinstance(value, str):
                        # Legacy string format
                        variables[name] = {
                            "definition": value,
                            "description": ""
                        }
                    elif isinstance(value, dict):
                        # New dict format
                        entry = {
                            "definition": value.get("definition", ""),
                            "description": value.get("description", "")
                        }
                        # Preserve the stored type marker (v2.1) so container
                        # associations round-trip. Only @ variables carry a
                        # type; @ variables without one (v1.0/v2.0) are left
                        # untyped so resolve_reference_type defaults them to
                        # Reference. $ variables never store a type.
                        if name.startswith('@') and 'type' in value:
                            entry['type'] = value['type']
                        variables[name] = entry
                    else:
                        # Unknown format, treat as empty
                        variables[name] = {
                            "definition": "",
                            "description": ""
                        }
                
                return variables, tags
                
            except FileNotFoundError:
                pass  # Variable file doesn't exist
            except PermissionError:
                pass  # Cannot read variable file
            except json.JSONDecodeError:
                pass  # Variable file is corrupted
            except (TypeError, ValueError):
                pass  # Other errors
        return {}, {}
    
    def save_variables_file(self, suricata_filename: str, variables: dict, tags: dict = None):
        """Save companion .var file with variable definitions and tags
        
        Always saves in v2.1 format with format_version, variables, and tags
        sections. Any opened v1.0/v2.0 file is therefore upgraded to v2.1 on
        the next save. Backward compatibility is maintained by supporting
        reading of the older formats.
        
        The stored "type" field on @ variables (Reference vs Container) is
        persisted as-is so container associations round-trip. $ variables are
        written without a "type" field, since their type is inferred from
        usage rather than stored.
        
        Args:
            suricata_filename: Path to .suricata file
            variables: Dict with structure {name: {"definition": str, "description": str, ["type": str]}}
            tags: Tags dict with key-value pairs (optional, defaults to empty dict)
        """
        if not variables and not tags:
            return
        
        # Default to empty dict if tags not provided
        if tags is None:
            tags = {}
        
        var_filename = suricata_filename.replace('.suricata', '.var')
        if not var_filename.endswith('.var'):
            var_filename += '.var'
        
        # Build the variables dict for serialization. @ variables keep their
        # stored "type" so it persists; $ variables are written without a
        # "type" field even if one somehow leaked into the in-memory entry.
        serialized_variables = {}
        for name, value in variables.items():
            if isinstance(value, dict):
                entry = {
                    "definition": value.get("definition", ""),
                    "description": value.get("description", "")
                }
                if name.startswith('@') and 'type' in value:
                    entry['type'] = value['type']
                serialized_variables[name] = entry
            else:
                # Preserve any non-dict values as-is (defensive; not expected)
                serialized_variables[name] = value
        
        try:
            # Always save in v2.1 format with format_version, variables, and tags
            var_data = {
                'format_version': '2.1',
                'variables': serialized_variables,
                'tags': tags
            }
            
            with open(var_filename, 'w', encoding='utf-8') as f:
                json.dump(var_data, f, indent=2, ensure_ascii=False)
                
        except PermissionError:
            pass  # Cannot write variable file
        except OSError:
            pass  # File system error
        except (TypeError, ValueError):
            pass  # Other errors
    
    def validate_tag_key(self, key: str) -> tuple[bool, str]:
        """Validate AWS tag key
        
        Args:
            key: Tag key to validate
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not key:
            return False, "Tag key is required"
        
        if len(key) > 128:
            return False, "Tag key cannot exceed 128 characters"
        
        # AWS reserved prefix (case-insensitive)
        if key.lower().startswith('aws:'):
            return False, "Tag keys cannot start with 'aws:' (reserved prefix)"
        
        # Valid characters pattern
        valid_pattern = r'^[a-zA-Z0-9 +\-=._:/@]+$'
        if not re.match(valid_pattern, key):
            return False, "Invalid characters. Only a-z, A-Z, 0-9, space, +-=._:/@  allowed"
        
        return True, ""
    
    def validate_tag_value(self, value: str) -> tuple[bool, str]:
        """Validate AWS tag value
        
        Args:
            value: Tag value to validate
            
        Returns:
            tuple: (is_valid, error_message)
        """
        # Empty values are allowed
        if len(value) > 256:
            return False, "Tag value cannot exceed 256 characters"
        
        # Valid characters pattern (same as keys)
        valid_pattern = r'^[a-zA-Z0-9 +\-=._:/@]*$'
        if not re.match(valid_pattern, value):
            return False, "Invalid characters. Only a-z, A-Z, 0-9, space, +-=._:/@  allowed"
        
        return True, ""
    
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
                    from src.managers.revision_manager import RevisionManager
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
    
    def build_rules_string(self, rules: List, test_mode: bool = False) -> str:
        """Build the exact ``RulesString`` that goes into the rule group.

        Single source of truth for the rules-string content shared by the
        Terraform, CloudFormation, and Direct Deploy paths: rules are prepared
        for export (test-mode conversion), normalized to Unix (LF) line
        endings, joined, and prefixed with the test-mode warning when
        applicable. Measuring size against this return value guarantees the
        2 MB check sees the same bytes AWS will.

        Args:
            rules: List of SuricataRule objects.
            test_mode: If True, convert actions to alert and prepend the
                test-mode warning comment.

        Returns:
            The rules string (UTF-8 text, LF line endings).
        """
        export_rules = self._prepare_rules_for_export(rules, test_mode)

        rules_lines = []
        for rule in export_rules:
            if getattr(rule, 'is_blank', False):
                rules_lines.append('')
            elif getattr(rule, 'is_comment', False):
                clean_comment = rule.comment_text.replace('\r\n', '\n').replace('\r', '')
                rules_lines.append(clean_comment)
            else:
                clean_rule = rule.to_string().replace('\r\n', '\n').replace('\r', '')
                rules_lines.append(clean_rule)

        rules_string = '\n'.join(rules_lines)

        if test_mode:
            warning_comment = (
                "# \u26a0\ufe0f  WARNING: This rule group was exported in TEST MODE\n"
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

        return rules_string
    
    def check_rules_string_size(self, rules: List, test_mode: bool = False):
        """Check the rules string against the AWS 2 MB limit.

        Pure (no UI) so it can be unit-tested and reused by every export path.

        Returns:
            Tuple ``(within_limit, size_bytes, max_bytes)``. ``within_limit`` is
            True when ``size_bytes <= max_bytes``.
        """
        rules_string = self.build_rules_string(rules, test_mode)
        size_bytes = len(rules_string.encode('utf-8'))
        return (size_bytes <= self.RULES_STRING_MAX_BYTES, size_bytes,
                self.RULES_STRING_MAX_BYTES)
    
    def generate_terraform_template(self, rules: List[SuricataRule], variables: dict,
                                   tags: dict = None, test_mode: bool = False,
                                   rule_group_name: str = "suricata-generator-rg") -> str:
        """Generate Terraform template for AWS Network Firewall rule group with optional test mode
        
        Args:
            rules: List of SuricataRule objects
            variables: Variable definitions dictionary
            tags: Tags dictionary (optional, defaults to empty dict)
            test_mode: If True, convert all actions to 'alert'
            rule_group_name: AWS rule group name to embed in the template
                (resource name/RuleGroupName and the Name tag). Defaults to
                "suricata-generator-rg" for backward compatibility.

        Raises:
            ValueError: If the variables mix container association and
                traditional reference @ variables (Reference_Exclusivity_Rule).
                This is a pure generator, so it surfaces the violation as an
                exception; the caller (export_file) presents it to the user.
        """
        # STEP 0: Enforce reference-type exclusivity (R7.4). This is a pure
        # generator (no UI); raise so the caller can surface the message.
        is_valid, exclusivity_message = self._check_reference_exclusivity(variables)
        if not is_valid:
            raise ValueError(exclusivity_message)

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
                    var_type = self.get_variable_type_from_usage(var_name, variable_usage, variables)
                    
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
                    elif var_type in ("Reference", "Container"):
                        # Terraform AWS provider schema: a single reference_sets
                        # block contains one ip_set_references block per variable,
                        # each with a key and a nested ip_set_reference { reference_arn }.
                        reference_sets += f"      ip_set_references {{\n"
                        reference_sets += f"        key = \"{clean_name}\"\n"
                        reference_sets += f"        ip_set_reference {{\n"
                        reference_sets += f"          reference_arn = \"{var_definition}\"\n"
                        reference_sets += f"        }}\n"
                        reference_sets += f"      }}\n"
            
            if has_rule_vars:
                rule_variables += "    }\n"

            # Wrap the per-variable ip_set_references blocks in one reference_sets block.
            if reference_sets:
                reference_sets = "    reference_sets {\n" + reference_sets + "    }\n"
        
        # Default to empty dict if tags not provided
        if tags is None:
            tags = {}
        
        # Generate tags section (always include at minimum the Name tag)
        tags_section = '  tags = {\n'
        tags_section += f'    Name = "{rule_group_name}"\n'
        
        # Add user-defined tags automatically (no prompts)
        for key, value in sorted(tags.items()):
            # Escape quotes in values
            escaped_value = value.replace('"', '\\"')
            tags_section += f'    {key} = "{escaped_value}"\n'
        
        tags_section += '  }\n'
        
        # Generate template
        template = f'''resource "aws_networkfirewall_rule_group" "suricata_rule_group" {{
  capacity    = {capacity}
  description = "This rule group was created by the Suricata Generator version {self.version}"
  name        = "{rule_group_name}"
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

{tags_section}}}
'''
        return template
    
    def generate_cloudformation_template(self, rules: List[SuricataRule], variables: dict,
                                        tags: dict = None, test_mode: bool = False,
                                        rule_group_name: str = "suricata-generator-rg") -> str:
        """Generate CloudFormation JSON template for AWS Network Firewall rule group with optional test mode
        
        Args:
            rules: List of SuricataRule objects
            variables: Variable definitions dictionary
            tags: Tags dictionary (optional, defaults to empty dict)
            test_mode: If True, convert all actions to 'alert'
            rule_group_name: AWS rule group name to embed in the template
                (resource name/RuleGroupName and the Name tag). Defaults to
                "suricata-generator-rg" for backward compatibility.

        Raises:
            ValueError: If the variables mix container association and
                traditional reference @ variables (Reference_Exclusivity_Rule).
                This is a pure generator, so it surfaces the violation as an
                exception; the caller (export_file) presents it to the user.
        """
        # STEP 0: Enforce reference-type exclusivity (R7.4). This is a pure
        # generator (no UI); raise so the caller can surface the message.
        is_valid, exclusivity_message = self._check_reference_exclusivity(variables)
        if not is_valid:
            raise ValueError(exclusivity_message)

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
                        "RuleGroupName": rule_group_name,
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
                                "Value": rule_group_name
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
                    var_type = self.get_variable_type_from_usage(var_name, variable_usage, variables)
                    
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
                    elif var_type in ("Reference", "Container"):
                        reference_sets[clean_name] = {"ReferenceArn": var_definition}
            
            if rule_variables:
                template["Resources"]["SuricataRuleGroup"]["Properties"]["RuleGroup"]["RuleVariables"] = rule_variables
            
            # ReferenceSets is a member of the RuleGroup object (not Properties) and
            # its map must be wrapped in an IPSetReferences key, per the Network
            # Firewall CloudFormation schema.
            if reference_sets:
                template["Resources"]["SuricataRuleGroup"]["Properties"]["RuleGroup"]["ReferenceSets"] = {"IPSetReferences": reference_sets}
        
        # Default to empty dict if tags not provided
        if tags is None:
            tags = {}
        
        # Build tags array (always include Name tag at minimum)
        tags_array = [
            {
                "Key": "Name",
                "Value": rule_group_name
            }
        ]
        
        # Add user-defined tags automatically (no prompts)
        for key, value in sorted(tags.items()):
            tags_array.append({
                "Key": key,
                "Value": value
            })
        
        template["Resources"]["SuricataRuleGroup"]["Properties"]["Tags"] = tags_array
        
        return json.dumps(template, indent=2)
    
    def load_aws_template(self) -> tuple[List[SuricataRule], dict]:
        """Load AWS best practices Suricata rules template from website"""
        try:
            url = "https://aws.github.io/aws-security-services-best-practices/guides/network-firewall/sample-suricata-rules/docs/"
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
        """Extract Suricata rules from AWS best practices HTML content

        The best practices page publishes a "Complete rules template" section
        containing a ready-to-deploy ruleset inside a code block. We anchor on
        that section's heading (the most stable marker) and extract the first
        code block that follows it. Legacy markers are kept as fallbacks so the
        feature still works against older copies of the page.
        """
        try:
            # Preferred: the MkDocs heading anchor for the complete template
            # section, e.g. <h2 id="complete-rules-template">.
            start_markers = [
                'id="complete-rules-template"',
                "Complete rules template",
                # Legacy markers from previous versions of the page
                "Here is a custom Suricata template that customer find helpful",
                "Below we have also included a custom template for an egress security use case",
            ]
            start_pos = -1
            for marker in start_markers:
                start_pos = html_content.find(marker)
                if start_pos != -1:
                    break
            
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
            
            # Strip inline tags first (e.g. per-line <a id="__codelineno-..."></a>
            # anchors that MkDocs injects), then decode HTML entities. Stripping
            # before decoding avoids turning encoded "&lt;"/"&gt;" inside rule
            # content into stray angle brackets that the tag regex would eat.
            rules_text = re.sub(r'<[^>]+>', '', rules_html)
            rules_text = rules_text.replace("&lt;", "<")
            rules_text = rules_text.replace("&gt;", ">")
            rules_text = rules_text.replace("&quot;", '"')
            rules_text = rules_text.replace("&#39;", "'")
            rules_text = rules_text.replace("&amp;", "&")
            
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
    
    def resolve_reference_type(self, var_name: str, variables: dict) -> str:
        """Resolve the type of an @ variable from its stored type marker.

        For an @ variable, return "Container" when its stored ``type`` is
        ``"container"`` and "Reference" otherwise. The "Reference" default
        covers untyped @ variables (v1.0/v2.0 files and any entry lacking a
        stored type), preserving backward-compatible behavior.

        Args:
            var_name: The @ variable name (e.g., '@ECS_CONTAINERS').
            variables: The in-memory variables dict.

        Returns:
            str: "Container" or "Reference".
        """
        entry = variables.get(var_name) if variables else None
        if isinstance(entry, dict) and entry.get("type") == "container":
            return "Container"
        return "Reference"

    def get_variable_type_from_usage(self, var_name: str, variable_usage: dict, variables: dict = None) -> str:
        """Determine variable type based on actual usage in rules
        
        Args:
            var_name: The variable name (e.g., '$src', '@HOME_REF')
            variable_usage: Usage analysis from analyze_variable_usage()
            variables: Optional in-memory variables dict. When provided, @
                variables resolve to "Container" or "Reference" via their
                stored type (resolve_reference_type). When omitted, @
                variables preserve the legacy "Reference" behavior.
            
        Returns:
            str: "IP Set", "Port Set", "Reference", or "Container"
        """
        # For @ prefix, resolve the stored type when variables are supplied;
        # otherwise preserve the legacy "Reference" default (AWS Network
        # Firewall requirement). @ variables are only used in network fields,
        # never in port fields.
        if var_name.startswith('@'):
            if variables is not None:
                return self.resolve_reference_type(var_name, variables)
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

    def active_reference_mode(self, variables: dict) -> str:
        """Determine the active reference mode for a file's @ variables.

        Returns "container" when any @ variable is a stored container
        association; otherwise "reference" when at least one @ variable is
        present (stored-reference or untyped); otherwise "none" when the file
        has no @ variables at all.

        Because the Reference_Exclusivity_Rule prevents both stored types from
        coexisting in a valid file, this yields exactly one active mode. The
        container check takes precedence so a mixed (invalid) file still
        surfaces as container mode until the export/deploy gate rejects it.

        Args:
            variables: The in-memory variables dict.

        Returns:
            str: "container", "reference", or "none".
        """
        if not variables:
            return "none"

        has_container = False
        has_reference = False
        for var_name, entry in variables.items():
            if not var_name.startswith('@'):
                continue
            if isinstance(entry, dict) and entry.get("type") == "container":
                has_container = True
            else:
                # Untyped @ variables default to reference (backward compat)
                has_reference = True

        if has_container:
            return "container"
        if has_reference:
            return "reference"
        return "none"

    def _check_reference_exclusivity(self, variables: dict) -> tuple[bool, str]:
        """Check that @ variables do not mix container and reference types.

        AWS requires a rule group's IPSet references to be either all
        traditional references or all container associations; mixing them
        causes an InvalidRequestException at deploy time. This is the shared
        gate used before export/deploy.

        Args:
            variables: The in-memory variables dict.

        Returns:
            tuple[bool, str]: (True, "") when the file is valid (no mix);
                (False, message) when both a stored-container @ variable and a
                stored-reference/untyped @ variable are present.
        """
        if not variables:
            return True, ""

        container_vars = []
        reference_vars = []
        for var_name, entry in variables.items():
            if not var_name.startswith('@'):
                continue
            if isinstance(entry, dict) and entry.get("type") == "container":
                container_vars.append(var_name)
            else:
                # Untyped @ variables default to reference (backward compat)
                reference_vars.append(var_name)

        if container_vars and reference_vars:
            message = (
                "Reference-type exclusivity violation: this file mixes container "
                "association and traditional reference variables. AWS Network "
                "Firewall requires a rule group's references to be either all "
                "container associations or all traditional references, not both.\n\n"
                f"Container associations: {', '.join(sorted(container_vars))}\n"
                f"Traditional references: {', '.join(sorted(reference_vars))}\n\n"
                "Remove all variables of one type before proceeding."
            )
            return False, message

        return True, ""
    
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
    
    def deploy_to_aws(self, rules: List, variables: dict, tags: dict = None,
                     rule_group_name: str = None, test_mode: bool = False, 
                     parent_app = None, region: str = None) -> bool:
        """Deploy rules directly to AWS Network Firewall
        
        Args:
            rules: List of SuricataRule objects
            variables: Variable definitions dictionary
            tags: Tags dictionary (optional, defaults to empty dict)
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

        # STEP 0a: Enforce reference-type exclusivity (R7.4) BEFORE any dialog
        # or AWS call. On a mixed file, show the error and abort.
        is_valid, exclusivity_message = self._check_reference_exclusivity(variables)
        if not is_valid:
            messagebox.showerror("Reference-Type Exclusivity Violation", exclusivity_message)
            return False

        # STEP 0b: Warn when container references exceed the AWS limit of 30
        # (R7.5). Non-blocking: allow the user to proceed (AWS is authoritative).
        if variables and self.active_reference_mode(variables) == "container":
            container_count = sum(
                1 for name, entry in variables.items()
                if name.startswith('@') and isinstance(entry, dict)
                and entry.get("type") == "container"
            )
            if container_count > 30:
                proceed = messagebox.askyesno(
                    "Container Association Limit Exceeded",
                    f"This rule group has {container_count} container association "
                    f"references, but AWS Network Firewall allows at most 30 per "
                    f"rule group.\n\nAWS will reject the deployment if it exceeds "
                    f"the limit.\n\nDo you want to continue anyway?"
                )
                if not proceed:
                    return False

        # STEP 0c: Enforce the AWS 2 MB rules-string limit before deploying.
        # AWS rejects a rule group whose RulesString exceeds 2,000,000 bytes,
        # so fail fast with a clear message rather than surfacing an opaque
        # API error.
        within_limit, size_bytes, max_bytes = self.check_rules_string_size(rules, test_mode)
        if not within_limit:
            messagebox.showerror(
                "Rules Too Large",
                f"The rules string is {size_bytes:,} bytes, which exceeds the AWS "
                f"Network Firewall limit of {max_bytes:,} bytes (2 MB).\n\n"
                f"The deployment has been cancelled. To reduce the size:\n"
                f"• Remove or consolidate rules\n"
                f"• Shorten rule messages and content\n"
                f"• Split the rules across multiple rule groups"
            )
            return False

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
            # ReferenceSets is a member of the RuleGroup object (alongside RulesSource,
            # RuleVariables, StatefulRuleOptions) and its map must be wrapped in an
            # IPSetReferences key per the Network Firewall API. It is NOT a top-level
            # create_rule_group/update_rule_group parameter.
            reference_sets = self._build_reference_sets(variables, export_rules)
            if reference_sets:
                rule_group['ReferenceSets'] = {'IPSetReferences': reference_sets}
            
            # STEP 7: Create boto3 client with specified region (via aws_session manager)
            client = parent_app.aws_session.get_client('network-firewall', region_name=region)
            
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
            
            # STEP 9: Build tags for AWS API call
            # Default to empty dict if tags not provided
            if tags is None:
                tags = {}
            
            # Build tags for AWS API (always include Name tag)
            aws_tags = [{'Key': 'Name', 'Value': rule_group_name}]
            
            # Add user-defined tags automatically (no prompts)
            for key, value in tags.items():
                aws_tags.append({'Key': key, 'Value': value})
            
            # STEP 10: Create or update rule group based on existence
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
                
                # ReferenceSets is nested inside RuleGroup (see STEP 6); it is not a
                # top-level update_rule_group parameter.
                response = client.update_rule_group(**api_params)
            else:
                # Create new rule group with tags
                api_params = {
                    'RuleGroupName': rule_group_name,
                    'Type': 'STATEFUL',
                    'RuleGroup': rule_group,
                    'Capacity': capacity,
                    'Description': f'Created by Suricata Generator v{self.version} on {current_date}',
                    'Tags': aws_tags
                }
                
                # ReferenceSets is nested inside RuleGroup (see STEP 6); it is not a
                # top-level create_rule_group parameter.
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
            profile_display = parent_app.aws_session.display_name if hasattr(parent_app, 'aws_session') else '(default)'
            messagebox.showerror(
                "AWS Credentials Not Found",
                f"AWS credentials are not configured for profile '{profile_display}'.\n\n"
                "To use AWS export, configure credentials using:\n"
                f"• AWS CLI: aws configure" + (f" --profile {profile_display}" if profile_display != '(default)' else "") + "\n"
                "• Environment variables\n"
                "• IAM role (if on AWS)\n\n"
                "Or select a different profile from the status bar dropdown.\n\n"
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
            var_type = self.get_variable_type_from_usage(var_name, variable_usage, variables)
            
            if var_type in ("Reference", "Container"):
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
        
        arn = response['RuleGroupResponse']['RuleGroupArn']
        
        # Get region from aws_session manager
        session = parent_app.aws_session.get_session()
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
