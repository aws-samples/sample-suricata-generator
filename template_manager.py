"""
Template Manager for Suricata Rule Generator

Manages loading, validation, and application of rule templates from JSON file.
Supports parameterized templates with dynamic rule generation and policy templates
with static rules.
"""

import json
import os
from typing import List, Dict, Optional, Any
from suricata_rule import SuricataRule


class TemplateManager:
    """Manages rule templates for quick rule generation from common patterns"""
    
    def __init__(self, template_file: str = 'rule_templates.json'):
        """Initialize template manager
        
        Args:
            template_file: Path to JSON file containing template definitions
        """
        self.templates = []
        self.template_file = template_file
        self.load_templates()
    
    def load_templates(self) -> bool:
        """Load and validate templates from JSON file
        
        Returns:
            bool: True if templates loaded successfully, False otherwise
        """
        try:
            # Check if template file exists
            if not os.path.exists(self.template_file):
                print(f"Warning: Template file not found: {self.template_file}")
                return False
            
            # Load JSON
            with open(self.template_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Validate JSON structure
            if 'templates' not in data:
                print(f"Error: Invalid template file format - missing 'templates' key")
                return False
            
            self.templates = data['templates']
            return True
            
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in template file: {e}")
            return False
        except Exception as e:
            print(f"Error loading templates: {e}")
            return False
    
    def get_template_list(self) -> List[tuple]:
        """Return list of (template_id, template_name) tuples for UI
        
        Returns:
            List of (id, name) tuples for all templates
        """
        return [(t['id'], t['name']) for t in self.templates]
    
    def get_templates_by_category(self) -> Dict[str, List[Dict]]:
        """Group templates by category for organized UI display
        
        Returns:
            Dict mapping category names to lists of templates
        """
        categories = {}
        for template in self.templates:
            category = template.get('category', 'Uncategorized')
            if category not in categories:
                categories[category] = []
            categories[category].append(template)
        return categories
    
    def get_template(self, template_id: str) -> Optional[Dict]:
        """Get template by ID
        
        Args:
            template_id: Template identifier
            
        Returns:
            Template dict or None if not found
        """
        for template in self.templates:
            if template['id'] == template_id:
                return template
        return None
    
    def apply_template(self, template_id: str, parameters: Dict[str, Any], 
                      start_sid: int, test_mode: bool = False):
        """Generate rules from template
        
        Args:
            template_id: Template identifier
            parameters: Dict with user selections (e.g., {'MODE': 'block', 'COUNTRIES': ['CN', 'RU']})
            start_sid: Starting SID number
            test_mode: If True, convert all rule actions to 'alert'
            
        Returns:
            List of SuricataRule objects, or Dict with 'top_rules' and 'bottom_rules' for dual insertion
        """
        template = self.get_template(template_id)
        if not template:
            return []
        
        # Check for dual insertion point
        if template.get('insertion_point') == 'dual':
            # Generate both top and bottom rules
            top_rules = []
            bottom_rules = []
            
            # Generate top rules if present
            if template.get('top_rules'):
                top_rules = self.generate_static_rules_from_list(template['top_rules'], start_sid)
            
            # Generate bottom rules (main rules)
            if template.get('template_type') == 'policy':
                bottom_rules = self.generate_static_rules(template, start_sid)
            else:
                bottom_rules = self.generate_dynamic_rules(template, parameters, start_sid)
            
            # Apply test mode if enabled
            if test_mode:
                top_rules = self.apply_test_mode(top_rules)
                bottom_rules = self.apply_test_mode(bottom_rules)
            
            return {
                'top_rules': top_rules,
                'bottom_rules': bottom_rules
            }
        else:
            # Standard single insertion point
            if template.get('template_type') == 'policy':
                rules = self.generate_static_rules(template, start_sid)
            else:
                rules = self.generate_dynamic_rules(template, parameters, start_sid)
            
            # Apply test mode if enabled
            if test_mode:
                rules = self.apply_test_mode(rules)
            
            return rules
    
    def apply_test_mode(self, rules: List[SuricataRule]) -> List[SuricataRule]:
        """Convert all rule actions to 'alert' for testing
        
        Args:
            rules: List of SuricataRule objects
            
        Returns:
            Modified list with all actions set to 'alert'
        """
        for rule in rules:
            # Skip blank lines and comments (they don't have action/message)
            if getattr(rule, 'is_blank', False) or getattr(rule, 'is_comment', False):
                continue
            
            rule.action = 'alert'
            if not rule.message.startswith('[TEST]'):
                rule.message = f'[TEST] {rule.message}'
        return rules
    
    def generate_static_rules(self, template: Dict, start_sid: int) -> List[SuricataRule]:
        """Generate rules from policy template (no parameters)
        
        Args:
            template: Template dictionary
            start_sid: Starting SID number
            
        Returns:
            List of SuricataRule objects
        """
        return self.generate_static_rules_from_list(template['rules'], start_sid)
    
    def generate_static_rules_from_list(self, rule_list: List[Dict], start_sid: int) -> List[SuricataRule]:
        """Generate rules from a list of rule definitions
        
        Args:
            rule_list: List of rule definition dictionaries
            start_sid: Starting SID number (ignored if rule has explicit SID)
            
        Returns:
            List of SuricataRule objects
        """
        rules = []
        current_sid = start_sid
        
        for rule_def in rule_list:
            # Handle blank line rules
            if rule_def.get('is_blank', False):
                blank_rule = SuricataRule()
                blank_rule.is_blank = True
                rules.append(blank_rule)
                # Don't increment SID for blank lines
                continue
            
            # Handle comment rules
            if rule_def.get('is_comment', False):
                comment_rule = SuricataRule()
                comment_rule.is_comment = True
                comment_rule.comment_text = rule_def.get('comment_text', '# Comment')
                rules.append(comment_rule)
                # Don't increment SID for comments
                continue
            
            # Use explicit SID if provided, otherwise use current_sid
            sid = rule_def.get('sid', current_sid)
            
            rule = SuricataRule(
                action=rule_def['action'],
                protocol=rule_def['protocol'],
                src_net=rule_def['src_net'],
                src_port=rule_def['src_port'],
                direction=rule_def.get('direction', '->'),
                dst_net=rule_def['dst_net'],
                dst_port=rule_def['dst_port'],
                message=rule_def['message'],
                content=rule_def['content'],
                sid=sid
            )
            rules.append(rule)
            
            # Only increment if rule didn't have explicit SID
            if 'sid' not in rule_def:
                current_sid += 1
        
        return rules
    
    def generate_dynamic_rules(self, template: Dict, parameters: Dict[str, Any], 
                               start_sid: int) -> List[SuricataRule]:
        """Generate multiple rules from parameterized template
        
        Handles:
        - Multi-select parameters (countries, protocols, ports)
        - Radio button selections
        - Checkbox conditionals
        - Placeholder substitution
        
        Args:
            template: Template dictionary
            parameters: User parameter selections
            start_sid: Starting SID number
            
        Returns:
            List of SuricataRule objects
        """
        rules = []
        current_sid = start_sid
        
        # Resolve all parameter values first - this extracts metadata from radio button options,
        # combines multi-select choices, and prepares all placeholder values for substitution
        param_values = self.resolve_parameter_values(template, parameters)
        
        # Determine if this template uses multi-select parameters (countries, protocols, ports)
        # Multi-select templates generate multiple rules (one per selection in most cases)
        multi_select_param = self.get_multi_select_parameter(template)
        
        if multi_select_param:
            # Multi-select templates handle rule generation differently than single-value templates
            # We process all selections here to avoid duplication issues with the outer loop
            
            # Geographic country control in allow-list mode is a special case:
            # Instead of one rule per country (block mode), we generate a SINGLE rule
            # with all countries negated (e.g., geoip:dst,!US,!CA,!GB means "block all except these")
            is_geo_allow_mode = (
                template.get('id') == 'geographic_country_control' and
                parameters.get('MODE') == 'allow' and
                multi_select_param['name'] == 'COUNTRIES'
            )
            
            if is_geo_allow_mode:
                    # ALLOW-LIST MODE: Generate ONE rule with all countries combined
                    # Example: If user selects US, CA, GB, we generate:
                    # geoip:dst,!US,!CA,!GB (meaning "block all countries EXCEPT these")
                    selections = parameters.get(multi_select_param['name'], [])
                    
                    if selections:
                        # Build the negated country list for geoip keyword
                        # Format: !US,!CA,!GB (comma-separated, each with ! prefix)
                        geoip_list = ','.join([f'!{sel}' for sel in selections])
                        
                        # Extract human-readable country names from option metadata
                        # This allows us to generate a descriptive message like:
                        # "Block all countries except United States, Canada (US, CA)"
                        country_names = []
                        for sel in selections:
                            option = next((o for o in multi_select_param['options'] 
                                         if o['value'] == sel), None)
                            if option:
                                country_names.append(option['label'])
                        
                        # Prepare different formats for different parts of the rule
                        countries_text = ', '.join(country_names)  # "United States, Canada, United Kingdom"
                        codes_for_message = ', '.join(selections)  # "US, CA, GB" (for message parentheses)
                        codes_for_metadata = ', geo '.join(selections)  # "US, geo CA, geo GB" (each code needs "geo" prefix)
                        
                        # Create a modified parameter set specifically for allow-list mode
                        # We override GEOIP_COUNTRIES with our negated list (!US,!CA,!GB)
                        allow_param_values = param_values.copy()
                        allow_param_values['GEOIP_COUNTRIES'] = geoip_list  # Override with negated countries
                        
                        # Build a synthetic "option" object that contains all selected countries
                        # This lets us use the standard placeholder substitution mechanism
                        # but with combined values instead of processing each country separately
                        combined_option = {
                            'value': selections[0],
                            'label': countries_text,
                            'COUNTRY_NAME': countries_text,
                            'COUNTRY_CODE': codes_for_message,  # For message: "AF, AM, AZ"
                        }
                        
                        # Use first rule template (geographic template has only 1 rule)
                        rule_template = template['rules'][0]
                        
                        rule = self.create_rule_from_template(
                            rule_template,
                            allow_param_values,  # Use overridden param_values
                            combined_option,
                            current_sid
                        )
                        
                        # Post-process the metadata field to add "geo" prefix to each country code
                        # Suricata requires: metadata:geo US, geo CA, geo GB
                        # Not: metadata:geo US, CA, GB
                        # This is a quirk of Suricata's metadata syntax for multiple values
                        if 'metadata:geo' in rule.content:
                            old_metadata = f'metadata:geo {codes_for_message}'  # "geo US, CA, GB"
                            new_metadata = f'metadata:geo {codes_for_metadata}'  # "geo US, geo CA, geo GB"
                            rule.content = rule.content.replace(old_metadata, new_metadata)
                        
                        rules.append(rule)
                        current_sid += 1
            else:
                # STANDARD MULTI-SELECT MODE: Generate separate rules for each selection
                # Example: If user selects CN, RU, KP, we generate 3 separate rules
                selections = parameters.get(multi_select_param['name'], [])
                
                # PORT MULTI-SELECT is a special case: generates ONE rule with bracketed port list
                # Example: user selects ports 53, 135, 445 → generates "[53,135,445]" in single rule
                # This is different from protocol/country multi-select which generate multiple rules
                if multi_select_param['type'] == 'multi_select_port':
                    # The port list has already been combined in resolve_parameter_values()
                    # as PORT_LIST parameter, so we just need to create one rule with it
                    if selections:  # Only generate rule if ports were actually selected
                        rule_template = template['rules'][0]
                        rule = self.create_rule_from_template(
                            rule_template,
                            param_values,
                            None,  # No per-option metadata needed
                            current_sid
                        )
                        rules.append(rule)
                        current_sid += 1
                
                # CATEGORY MULTI-SELECT: generates ONE rule with comma-separated categories
                # Example: user selects Malware, Phishing → generates "aws_domain_category:Malware,Phishing"
                # This is more efficient than separate rules per category
                elif multi_select_param['type'] == 'multi_select_category':
                    if selections:
                        # Combine all selected categories into comma-separated string
                        category_list = ','.join(selections)
                        
                        # Create modified param_values with combined categories
                        category_param_values = param_values.copy()
                        category_param_values['CATEGORY'] = category_list
                        
                        # Generate CATEGORY_DISPLAY for message (match ui_manager.py format)
                        if len(selections) == 1:
                            # Single category: "Malware"
                            category_param_values['CATEGORY_DISPLAY'] = selections[0]
                        elif len(selections) == 2:
                            # Two categories: "Malware and Phishing"
                            category_param_values['CATEGORY_DISPLAY'] = f"{selections[0]} and {selections[1]}"
                        else:
                            # Three or more: "Malware, Phishing, and 1 more"
                            category_param_values['CATEGORY_DISPLAY'] = f"{selections[0]}, {selections[1]}, and {len(selections) - 2} more"
                        
                        rule_template = template['rules'][0]
                        rule = self.create_rule_from_template(
                            rule_template,
                            category_param_values,
                            None,
                            current_sid
                        )
                        rules.append(rule)
                        current_sid += 1
                
                # MULTI-RULE TEMPLATES: Generate multiple rule variants per selection
                # Example: Protocol enforcement template has 2 rules (one for port check, one for protocol check)
                # If user selects 3 protocols, we generate 6 rules total (2 per protocol)
                elif len(template['rules']) > 1:
                    # Group rules by selection - all rule variants for protocol A, then all for protocol B, etc.
                    for selection in selections:
                            option = next((o for o in multi_select_param['options'] 
                                         if o['value'] == selection), None)
                            
                            if option:
                                # Create all rule variants for this specific selection
                                # Example: For HTTPS protocol, create both the port rule AND the protocol rule
                                for rule_tmpl in template['rules']:
                                    # Handle conditional rules (rules that only apply if a checkbox is checked)
                                    # Example: "bidirectional" checkbox might add reverse direction rules
                                    if 'conditional' in rule_tmpl:
                                        condition_param = rule_tmpl['conditional']
                                        if not parameters.get(condition_param, False):
                                            continue  # Skip this rule variant if condition not met
                                    
                                    rule = self.create_rule_from_template(
                                        rule_tmpl,
                                        param_values,
                                        option,
                                        current_sid
                                    )
                                    rules.append(rule)
                                    current_sid += 1
                else:
                    # SINGLE-RULE TEMPLATES: Generate one rule per selection (most common case)
                    # Example: Block File Sharing template with 3 protocols → generates 3 rules
                    for selection in selections:
                        option = next((o for o in multi_select_param['options'] 
                                     if o['value'] == selection), None)
                        
                        if option:
                            # Use first rule template for single-rule templates
                            rule_template = template['rules'][0]
                            rule = self.create_rule_from_template(
                                rule_template, 
                                param_values, 
                                option, 
                                current_sid
                            )
                            rules.append(rule)
                            current_sid += 1
        else:
            # NON-MULTI-SELECT TEMPLATES: Simple parameter substitution
            # Example: JA3 fingerprint template takes a hash string and generates 1 rule
            # OR: Enforce TLS version template with radio button selection generates 1 rule
            for rule_template in template['rules']:
                # Handle conditional rules (only generated if a condition is met)
                if 'conditional' in rule_template:
                    condition_param = rule_template['conditional']
                    if not parameters.get(condition_param, False):
                        continue  # Skip this rule variant
                
                # Single rule with substituted values
                rule = self.create_rule_from_template(
                    rule_template,
                    param_values,
                    None,
                    current_sid
                )
                rules.append(rule)
                current_sid += 1
        
        return rules
    
    def resolve_parameter_values(self, template: Dict, 
                                 parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve parameter values from user selections and option metadata
        
        This method transforms user selections into actual values for placeholder substitution.
        For example:
        - Radio button "Enforce TLS 1.2+" → version_list="sslv2,sslv3,tls1.0,tls1.1"
        - Multi-select ports [53, 135, 445] → PORT_LIST="53,135,445"
        - Text input "abc123hash" → HASH="abc123hash"
        
        Args:
            template: Template dictionary
            parameters: User parameter selections
            
        Returns:
            Dict of resolved parameter values for placeholder substitution
        """
        param_values = {}
        
        for param_def in template.get('parameters', []):
            param_name = param_def['name']
            param_type = param_def['type']
            
            if param_type == 'radio':
                # Radio button: user selects ONE option, and that option's metadata becomes parameters
                # Example: User selects "Enforce TLS 1.2+" which has metadata:
                #   {version_list: "sslv2,sslv3,tls1.0,tls1.1", version_display: "SSLv2, SSLv3..."}
                # This becomes: {VERSION_LIST: "sslv2,sslv3,tls1.0,tls1.1", VERSION_DISPLAY: "SSLv2, SSLv3..."}
                selected_value = parameters.get(param_name)
                selected_option = next(
                    (o for o in param_def['options'] if o['value'] == selected_value),
                    None
                )
                if selected_option:
                    # Extract all metadata fields from the selected option (excluding value/label)
                    # and convert to uppercase for placeholder substitution (e.g., {VERSION_LIST})
                    for key, value in selected_option.items():
                        if key not in ['value', 'label']:
                            param_values[key.upper()] = value
            
            elif param_type == 'checkbox':
                # Checkbox: simple boolean value (used for conditional rules)
                param_values[param_name] = parameters.get(param_name, 
                                                         param_def.get('default', False))
            
            elif param_type == 'text_input':
                # Text input: user types a value (like JA3 hash)
                # The parameter name itself becomes the placeholder
                # Example: param_name="HASH", user types "abc123..." → {HASH} placeholder
                input_value = parameters.get(param_name, '')
                param_values[param_name] = input_value
            
            elif param_type == 'multi_select_port':
                # Port multi-select: combine all selected ports into bracketed format
                # Example: User selects [53, 135, 445] → PORT_LIST="53,135,445"
                # This gets inserted into rule as dst_port:"[{PORT_LIST}]" → "[53,135,445]"
                selected_ports = parameters.get(param_name, [])
                if selected_ports:
                    port_list = ','.join(selected_ports)
                    param_values['PORT_LIST'] = port_list
            
            elif param_type == 'multi_select_protocol':
                # Protocol multi-select: each selection generates a separate rule
                # Metadata extraction happens per-option in create_rule_from_template()
                # so we don't need to store anything in global param_values here
                pass
            
            elif param_type == 'multi_select_extension':
                # Extension multi-select: each selection generates a separate rule
                # Similar to protocol multi-select - metadata extracted per-option
                pass
            
            elif param_type == 'multi_select_method':
                # HTTP method multi-select: each selection generates a separate rule
                # Similar to protocol multi-select - metadata extracted per-option
                pass
        
        return param_values
    
    def create_rule_from_template(self, rule_template: Dict, param_values: Dict[str, Any],
                                  option: Optional[Dict], sid: int) -> SuricataRule:
        """Create SuricataRule from template with placeholder substitution
        
        This method performs a two-phase substitution:
        1. First, substitute values from param_values (global parameters)
        2. Then, substitute values from option (per-selection metadata for multi-select)
        
        Placeholders are in the format {PLACEHOLDER_NAME} and are case-sensitive.
        
        Args:
            rule_template: Rule template dictionary
            param_values: Resolved parameter values (from resolve_parameter_values)
            option: Option metadata for multi-select items (or None for non-multi-select)
            sid: SID to assign to this rule
            
        Returns:
            SuricataRule object with all placeholders substituted
        """
        # Extract initial values from template (before any substitution)
        content = rule_template['content']
        message = rule_template['message']
        dst_port = rule_template.get('dst_port', 'any')
        src_port = rule_template.get('src_port', 'any')
        dst_net = rule_template.get('dst_net', 'any')
        src_net = rule_template.get('src_net', 'any')
        protocol = rule_template.get('protocol', 'tcp')
        action = rule_template.get('action', 'pass')
        
        # PHASE 1: Substitute placeholders from global parameters
        # Example: {VERSION_LIST} → "sslv2,sslv3,tls1.0,tls1.1"
        # This handles radio button metadata, text inputs, and combined port lists
        for key, value in param_values.items():
            placeholder = f'{{{key}}}'
            content = content.replace(placeholder, str(value))
            message = message.replace(placeholder, str(value))
            dst_port = dst_port.replace(placeholder, str(value))
            src_port = src_port.replace(placeholder, str(value))
            dst_net = dst_net.replace(placeholder, str(value))
            src_net = src_net.replace(placeholder, str(value))
            protocol = protocol.replace(placeholder, str(value))
            action = action.replace(placeholder, str(value))
        
        # PHASE 2: Substitute placeholders from per-selection metadata (multi-select only)
        # Example for geographic template: {COUNTRY_CODE} → "CN", {COUNTRY_NAME} → "China"
        # This allows each generated rule to have selection-specific values
        if option:
            # Build a mapping of all placeholders from the option metadata
            # We need special handling because:
            # - Standard fields use uppercase keys: {PROTOCOL_UPPER} from protocol_upper
            # - Country template has special aliases: label→COUNTRY_NAME, value→COUNTRY_CODE
            placeholder_map = {}
            for key, value in option.items():
                # Standard mapping: convert key to uppercase for placeholder
                placeholder_map[f'{{{key.upper()}}}'] = str(value)
                
                # Special mappings for geographic country template
                # These provide more semantic placeholder names
                if key == 'label':
                    placeholder_map['{COUNTRY_NAME}'] = str(value)  # "China" instead of {LABEL}
                if key == 'value':
                    placeholder_map['{COUNTRY_CODE}'] = str(value)  # "CN" instead of {VALUE}
            
            # Apply all per-selection substitutions to all rule fields
            for placeholder, value in placeholder_map.items():
                content = content.replace(placeholder, value)
                message = message.replace(placeholder, value)
                dst_port = dst_port.replace(placeholder, value)
                src_port = src_port.replace(placeholder, value)
                protocol = protocol.replace(placeholder, value)
                action = action.replace(placeholder, value)
        
        # Create SuricataRule object
        rule = SuricataRule(
            action=action,
            protocol=protocol,
            src_net=src_net,  # Use substituted value, not template value
            src_port=src_port,
            direction=rule_template.get('direction', '->'),
            dst_net=dst_net,  # Use substituted value, not template value
            dst_port=dst_port,
            message=message,
            content=content,
            sid=sid
        )
        
        return rule
    
    def get_multi_select_parameter(self, template: Dict) -> Optional[Dict]:
        """Find the multi-select parameter in template (if any)
        
        Args:
            template: Template dictionary
            
        Returns:
            Multi-select parameter dict or None
        """
        for param in template.get('parameters', []):
            param_type = param.get('type', '')
            # Check for multi-select types (including new category type)
            if param_type in ['multi_select_port', 'multi_select_protocol', 'multi_select_country', 
                             'multi_select_extension', 'multi_select_method', 'multi_select_category']:
                return param
            # Legacy support for multi_select flag
            if param.get('multi_select', False):
                return param
        return None
    
    def preview_rules(self, template_id: str, parameters: Dict[str, Any], 
                     start_sid: int, test_mode: bool = False) -> str:
        """Generate preview text before applying
        
        Args:
            template_id: Template identifier
            parameters: User parameter selections
            start_sid: Starting SID number
            test_mode: Whether test mode is enabled
            
        Returns:
            String with formatted rule preview
        """
        result = self.apply_template(template_id, parameters, start_sid, test_mode)
        
        # Check if this is a dual insertion template
        if isinstance(result, dict) and 'top_rules' in result:
            preview_lines = []
            top_rules = result['top_rules']
            bottom_rules = result['bottom_rules']
            
            if top_rules:
                preview_lines.append("Rules to be inserted at TOP of file:")
                preview_lines.append("-" * 50)
                for rule in top_rules:
                    # Skip blank lines in preview
                    if not getattr(rule, 'is_blank', False):
                        preview_lines.append(f"• {rule.to_string()}")
                preview_lines.append("")
            
            if bottom_rules:
                preview_lines.append("Rules to be inserted at BOTTOM of file:")
                preview_lines.append("-" * 50)
                shown_count = 0
                for rule in bottom_rules:
                    # Handle blank lines in preview
                    if getattr(rule, 'is_blank', False):
                        preview_lines.append("• (blank line)")
                    # Handle comments in preview
                    elif getattr(rule, 'is_comment', False):
                        preview_lines.append(f"• {rule.comment_text}")
                    else:
                        preview_lines.append(f"• {rule.to_string()}")
                        shown_count += 1
                    
                    # Only show first 10 actual rules
                    if shown_count >= 10:
                        break
                
                # Count total non-blank rules for summary
                non_blank_count = sum(1 for r in bottom_rules if not getattr(r, 'is_blank', False))
                if non_blank_count > 10:
                    preview_lines.append(f"\n... and {non_blank_count - 10} more rules")
            
            return '\n'.join(preview_lines)
        else:
            # Standard single insertion
            rules = result
            if not rules:
                return "No rules generated"
            
            preview_lines = []
            
            # Show first 10 rules in detail, handling blank lines
            shown_count = 0
            for rule in rules:
                if getattr(rule, 'is_blank', False):
                    preview_lines.append("• (blank line)")
                elif getattr(rule, 'is_comment', False):
                    preview_lines.append(f"• {rule.comment_text}")
                else:
                    preview_lines.append(f"• {rule.to_string()}")
                    shown_count += 1
                
                if shown_count >= 10:
                    break
            
            # Count total non-blank rules for summary
            non_blank_count = sum(1 for r in rules if not getattr(r, 'is_blank', False))
            if non_blank_count > 10:
                preview_lines.append(f"\n... and {non_blank_count - 10} more rules")
            
            return '\n'.join(preview_lines)
    
    def get_suggested_starting_sid(self, template: Dict, 
                                   existing_sids: set) -> int:
        """Get suggested starting SID for template
        
        Default Block template uses predefined SIDs (unless conflicts exist).
        All other templates get next available SID (max + 1).
        
        Args:
            template: Template dictionary
            existing_sids: Set of SIDs already in use
            
        Returns:
            Suggested starting SID
        """
        template_id = template.get('id', '')
        
        # Default Block template has predefined SIDs in the JSON
        # Check if any of those SIDs conflict with existing rules
        if template_id == 'default_block':
            # Get SIDs defined in the template
            template_sids = []
            
            # Check top_rules for explicit SIDs
            if template.get('top_rules'):
                for rule_def in template['top_rules']:
                    if 'sid' in rule_def and not rule_def.get('is_blank') and not rule_def.get('is_comment'):
                        template_sids.append(rule_def['sid'])
            
            # Check main rules for explicit SIDs
            if template.get('rules'):
                for rule_def in template['rules']:
                    if 'sid' in rule_def and not rule_def.get('is_blank') and not rule_def.get('is_comment'):
                        template_sids.append(rule_def['sid'])
            
            # Check if any template SIDs conflict with existing SIDs
            has_conflict = any(sid in existing_sids for sid in template_sids)
            
            if has_conflict:
                # Conflict detected - use next available SID like any other template
                if not existing_sids:
                    return 100
                return max(existing_sids) + 1
            else:
                # No conflict - return the first predefined SID (will be used as start_sid)
                # The actual predefined SIDs from JSON will be used in generate_static_rules_from_list
                if template_sids:
                    return min(template_sids)
                # Fallback if no SIDs defined
                if not existing_sids:
                    return 100
                return max(existing_sids) + 1
        
        # All other templates: find next available SID (max + 1)
        if not existing_sids:
            return 100
        
        # Return max + 1 for next available (like main program window)
        return max(existing_sids) + 1
