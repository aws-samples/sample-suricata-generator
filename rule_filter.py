"""
Rule Filter Module

This module provides filtering capabilities for Suricata rules based on various criteria
including action, protocol, SID range, and network variables.
"""

from typing import List, Set
from suricata_rule import SuricataRule


class RuleFilter:
    """Manages rule filtering criteria and matching logic"""
    
    def __init__(self):
        """Initialize filter with default settings (show all)"""
        # Action filters (which actions to show)
        self.actions = ['pass', 'drop', 'reject', 'alert']
        self.show_comments = True
        
        # Protocol filter (empty = show all)
        self.protocols = []
        
        # SID range filter
        self.sid_min = None
        self.sid_max = None
        self.sid_exclude_range = False  # If True, EXCLUDE rules in range
        
        # Variable filter (empty = show all)
        self.variables = []
    
    def matches(self, rule: SuricataRule) -> bool:
        """Check if rule matches current filter criteria
        
        Args:
            rule: The SuricataRule to check
            
        Returns:
            bool: True if rule matches filter criteria and should be displayed
        """
        # Comment filtering
        if getattr(rule, 'is_comment', False):
            return self.show_comments
        
        # Blank line filtering - hide blank lines when filters are active
        if getattr(rule, 'is_blank', False):
            return not self.is_active()
        
        # Action filtering
        if rule.action.lower() not in self.actions:
            return False
        
        # Protocol filtering (if protocols list is not empty, only show matching protocols)
        if self.protocols and rule.protocol.lower() not in self.protocols:
            return False
        
        # SID range filtering with negation support
        if self.sid_min is not None or self.sid_max is not None:
            # Check if SID is within the specified range
            in_range = True
            if self.sid_min is not None and rule.sid < self.sid_min:
                in_range = False
            if self.sid_max is not None and rule.sid > self.sid_max:
                in_range = False
            
            # Apply negation if exclude checkbox is checked
            if self.sid_exclude_range:
                # EXCLUDE rules in range (show rules OUTSIDE range)
                if in_range:
                    return False  # Rule is in range, so exclude it
            else:
                # Normal behavior: INCLUDE rules in range (show rules INSIDE range)
                if not in_range:
                    return False  # Rule is outside range, so exclude it
        
        # Variable filtering (show rules that use ANY of the selected variables)
        if self.variables:
            rule_vars = self._extract_variables(rule)
            if not any(var in rule_vars for var in self.variables):
                return False
        
        return True
    
    def _extract_variables(self, rule: SuricataRule) -> List[str]:
        """Extract all variables used in a rule
        
        Args:
            rule: The SuricataRule to extract variables from
            
        Returns:
            List of variable names used in the rule
        """
        variables = []
        for field in [rule.src_net, rule.dst_net, rule.src_port, rule.dst_port]:
            if field.startswith(('$', '@')):
                variables.append(field)
        return variables
    
    def get_used_variables(self, rules: List[SuricataRule]) -> List[str]:
        """Get list of all variables used in rules (for populating Variable dropdown)
        
        Args:
            rules: List of all rules to scan for variables
            
        Returns:
            List of unique variable names sorted alphabetically
        """
        used_vars = set()
        for rule in rules:
            if not getattr(rule, 'is_comment', False) and not getattr(rule, 'is_blank', False):
                used_vars.update(self._extract_variables(rule))
        return sorted(list(used_vars))
    
    def is_active(self) -> bool:
        """Check if any filters are currently active
        
        Returns:
            bool: True if any filters are active (not showing all rules)
        """
        # Check if all actions are enabled
        all_actions = set(['pass', 'drop', 'reject', 'alert'])
        if set(self.actions) != all_actions:
            return True
        
        # Check if comments are hidden
        if not self.show_comments:
            return True
        
        # Check if protocol filter is active
        if self.protocols:
            return True
        
        # Check if SID range filter is active
        if self.sid_min is not None or self.sid_max is not None:
            return True
        
        # Check if variable filter is active
        if self.variables:
            return True
        
        return False
    
    def get_filter_description(self) -> str:
        """Get a human-readable description of active filters
        
        Returns:
            str: Description of active filters
        """
        if not self.is_active():
            return ""
        
        descriptions = []
        
        # Action filter description
        all_actions = set(['pass', 'drop', 'reject', 'alert'])
        if set(self.actions) != all_actions:
            action_text = ", ".join([a.capitalize() for a in self.actions])
            descriptions.append(f"Action={action_text}")
        
        # Comments filter
        if not self.show_comments:
            descriptions.append("Comments=Hidden")
        
        # Protocol filter description
        if self.protocols:
            if len(self.protocols) == 1:
                descriptions.append(f"Protocol={self.protocols[0].upper()}")
            else:
                descriptions.append(f"Protocols={','.join([p.upper() for p in self.protocols])}")
        
        # SID range filter description
        if self.sid_min is not None or self.sid_max is not None:
            if self.sid_exclude_range:
                if self.sid_min is not None and self.sid_max is not None:
                    descriptions.append(f"SID exclude {self.sid_min}-{self.sid_max}")
                elif self.sid_min is not None:
                    descriptions.append(f"SID exclude >={self.sid_min}")
                else:
                    descriptions.append(f"SID exclude <={self.sid_max}")
            else:
                if self.sid_min is not None and self.sid_max is not None:
                    descriptions.append(f"SID={self.sid_min}-{self.sid_max}")
                elif self.sid_min is not None:
                    descriptions.append(f"SID>={self.sid_min}")
                else:
                    descriptions.append(f"SID<={self.sid_max}")
        
        # Variable filter description
        if self.variables:
            if len(self.variables) == 1:
                descriptions.append(f"Var={self.variables[0]}")
            else:
                descriptions.append(f"Vars={','.join(self.variables)}")
        
        return " | ".join(descriptions)
