"""
Suricata Rule Analyzer

This module provides comprehensive analysis capabilities for Suricata rules,
including conflict detection, shadowing analysis, and rule validation.
Extracted from the main application for better modularity and testability.

Version: See version.py for current version information
"""

import re
import ipaddress
from typing import List, Dict, Optional, Tuple
from suricata_rule import SuricataRule
from version import get_analyzer_version


class RuleAnalyzer:
    """Analyzes Suricata rules for conflicts, shadowing, and optimization opportunities"""
    
    def __init__(self):
        """Initialize the rule analyzer"""
        pass
    
    def analyze_rule_conflicts(self, rules: List[SuricataRule], variables: Dict[str, str]) -> Dict[str, List[Dict]]:
        """Analyze rules for conflicts and shadowing issues with bidirectional analysis
        
        Args:
            rules: List of SuricataRule objects to analyze
            variables: Dictionary of network variable definitions for analysis
            
        Returns:
            Dictionary with conflict categories: {'critical': [], 'warning': [], 'info': [], 'protocol_layering': [], 'sticky_buffer_order': [], 'udp_flow_established': [], 'protocol_keyword_mismatch': []}
        """
        conflicts = {'critical': [], 'warning': [], 'info': [], 'protocol_layering': [], 'sticky_buffer_order': [], 'udp_flow_established': [], 'protocol_keyword_mismatch': []}
        
        # Filter out comments and blank lines for analysis
        actual_rules = [r for r in rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        # Check each pair of rules for conflicts in both directions
        for i in range(len(actual_rules)):
            for j in range(i + 1, len(actual_rules)):
                rule_a = actual_rules[i]
                rule_b = actual_rules[j]
                line_a = rules.index(rule_a) + 1
                line_b = rules.index(rule_b) + 1
                
                # Forward check: Does rule A shadow rule B?
                conflict = self.check_rule_conflict(rule_a, rule_b, line_a, line_b, variables)
                if conflict:
                    conflicts[conflict['severity']].append(conflict)
                
                # Reverse check: Does rule B make rule A unreachable?
                reverse_conflict = self.check_reverse_shadowing(rule_a, rule_b, line_a, line_b, variables)
                if reverse_conflict:
                    conflicts[reverse_conflict['severity']].append(reverse_conflict)
                
                # Protocol layering check: Only check forward direction for intra-type conflicts
                # For inter-type conflicts, check both directions since protocol layering affects processing regardless of rule order
                protocol_conflict = self.check_protocol_layering_conflict(rule_a, rule_b, line_a, line_b, variables)
                if protocol_conflict:
                    conflicts['protocol_layering'].append(protocol_conflict)
                
                # Only check reverse direction for inter-type protocol layering conflicts
                upper_type = self.get_suricata_rule_type(rule_a)
                lower_type = self.get_suricata_rule_type(rule_b)
                
                if upper_type != lower_type:
                    reverse_protocol_conflict = self.check_protocol_layering_conflict(rule_b, rule_a, line_b, line_a, variables)
                    if reverse_protocol_conflict:
                        conflicts['protocol_layering'].append(reverse_protocol_conflict)
        
        # Remove critical/warning conflicts that are covered by protocol layering conflicts
        self._deduplicate_protocol_layering_conflicts(conflicts)
        
        # Check for sticky buffer ordering issues (separate from conflict detection)
        sticky_buffer_issues = self.check_sticky_buffer_ordering(rules)
        conflicts['sticky_buffer_order'] = sticky_buffer_issues
        
        # Check for UDP flow:established issues
        udp_flow_issues = self.check_udp_flow_established_issues(rules)
        conflicts['udp_flow_established'] = udp_flow_issues
        
        # Check for protocol/keyword mismatches
        protocol_keyword_issues = self.check_protocol_keyword_mismatch(rules)
        conflicts['protocol_keyword_mismatch'] = protocol_keyword_issues
        
        # Check for port/protocol mismatches
        port_protocol_issues = self.check_port_protocol_mismatch(rules)
        conflicts['port_protocol_mismatch'] = port_protocol_issues
        
        # Check for contradictory flow keywords
        contradictory_flow_issues = self.check_contradictory_flow_keywords(rules)
        conflicts['contradictory_flow'] = contradictory_flow_issues
        
        # Check for packet-scope drop/reject conflicting with flow-scope pass
        # This was a bug in Suricata <8.0 that has been fixed
        packet_flow_conflicts = self.check_packet_drop_flow_pass_conflict(rules)
        conflicts['packet_drop_flow_pass'] = packet_flow_conflicts
        
        return conflicts
    
    def check_rule_conflict(self, upper_rule: SuricataRule, lower_rule: SuricataRule, 
                           upper_line: int, lower_line: int, variables: Dict[str, str]) -> Optional[Dict]:
        """Check if upper rule conflicts with lower rule
        
        Args:
            upper_rule: Rule that appears first in the list
            lower_rule: Rule that appears later in the list
            upper_line: Line number of upper rule
            lower_line: Line number of lower rule
            variables: Dictionary of network variable definitions
            
        Returns:
            Conflict dictionary if conflict exists, None otherwise
        """
        # Skip if rules don't overlap in basic parameters
        if not self.rules_overlap(upper_rule, lower_rule, variables):
            return None
        
        # Apply filters to eliminate false positives
        if self.has_flowbits_dependency(upper_rule) or self.has_flowbits_dependency(lower_rule):
            return None
        
        if self.is_intentional_layered_pattern(upper_rule, lower_rule):
            return None
        
        # Determine conflict severity based on actions
        if upper_rule.action in ['pass', 'drop', 'reject'] and lower_rule.action in ['drop', 'reject']:
            severity = 'critical'
            issue = f"{upper_rule.action.upper()} rule prevents {lower_rule.action.upper()} rule from executing (security bypass)"
            suggestion = f"Move line {lower_line} above line {upper_line} to ensure blocking occurs"
        elif upper_rule.action in ['drop', 'reject'] and lower_rule.action == 'pass':
            severity = 'critical'
            issue = f"{upper_rule.action.upper()} rule prevents PASS rule from executing (security policy violation)"
            suggestion = f"Move line {lower_line} above line {upper_line} to ensure traffic is allowed as intended"
        elif upper_rule.action in ['pass', 'drop', 'reject'] and lower_rule.action == 'alert':
            severity = 'warning'
            issue = f"{upper_rule.action.upper()} rule prevents ALERT rule from logging (missing alerts)"
            suggestion = f"Move line {lower_line} above line {upper_line} to ensure logging occurs"
        elif upper_rule.action == lower_rule.action:
            severity = 'info'
            issue = f"Redundant {upper_rule.action.upper()} rule (same action, overlapping conditions)"
            suggestion = f"Consider removing line {lower_line} or making it more specific"
        else:
            return None
        
        return {
            'upper_rule': upper_rule,
            'lower_rule': lower_rule,
            'upper_line': upper_line,
            'lower_line': lower_line,
            'severity': severity,
            'issue': issue,
            'suggestion': suggestion
        }
    
    def rules_overlap(self, rule1: SuricataRule, rule2: SuricataRule, variables: Dict[str, str]) -> bool:
        """Check if two rules overlap in their matching conditions"""
        # Protocol must be compatible
        if not self.is_equal_or_broader_protocol(rule1, rule2):
            return False
        
        # Direction must overlap
        if not self.directions_overlap(rule1.direction, rule2.direction):
            return False
        
        # Networks must overlap
        if not (self.is_network_equal_or_broader(rule1.src_net, rule2.src_net, variables) and
                self.is_network_equal_or_broader(rule1.dst_net, rule2.dst_net, variables)):
            return False
        
        # Ports must overlap
        if not (self.is_port_equal_or_broader(rule1.src_port, rule2.src_port, variables) and
                self.is_port_equal_or_broader(rule1.dst_port, rule2.dst_port, variables)):
            return False
        
        # Content must be compatible
        if not self.is_content_equal_or_broader(rule1, rule2):
            return False
        
        return True
    
    def is_equal_or_broader_protocol(self, rule1: SuricataRule, rule2: SuricataRule) -> bool:
        """Check if rule1 protocol is equal to or broader than rule2 protocol"""
        proto1 = rule1.protocol.lower()
        proto2 = rule2.protocol.lower()
        
        if proto1 == proto2:
            return True
        
        # 'ip' is broader than all other protocols
        if proto1 == 'ip':
            return True
        
        # TCP is broader than HTTP/TLS (application layer protocols over TCP)
        if proto1 == 'tcp' and proto2 in ['http', 'tls']:
            return True
        
        return False
    
    def directions_overlap(self, dir1: str, dir2: str) -> bool:
        """Check if two direction specifications overlap"""
        if dir1 == dir2:
            return True
        if dir1 == '<>' or dir2 == '<>':
            return True  # Bidirectional overlaps with everything
        return False
    
    def is_network_equal_or_broader(self, net1: str, net2: str, variables: Dict[str, str]) -> bool:
        """Check if net1 is equal to or broader than net2 for complete shadowing
        
        Now supports full Suricata CIDR range formats including:
        - Bracket notation: [10.0.0.0/24, !10.0.0.5]
        - Variable groups: [$HOME_NET, !192.168.1.0/24]  
        - Negated groups: ![1.1.1.1, 1.1.1.2]
        """
        if net1 == net2:
            return True
        if net1 == 'any':
            return True  # 'any' is broader than everything
        if net2 == 'any':
            return False  # Specific network cannot be broader than 'any'
        
        # Parse both network specifications into comparable formats
        parsed_net1 = self._parse_network_specification(net1, variables)
        parsed_net2 = self._parse_network_specification(net2, variables)
        
        # If parsing failed for either, be conservative
        if parsed_net1 is None or parsed_net2 is None:
            return False
        
        # Compare parsed specifications for containment
        return self._network_specification_contains(parsed_net1, parsed_net2)
    
    def _parse_network_specification(self, net_spec: str, variables: Dict[str, str]) -> Optional[Dict]:
        """Parse a network specification into a comparable format
        
        Args:
            net_spec: Network specification (e.g., "192.168.1.0/24", "[10.0.0.0/24, !10.0.0.5]", "$HOME_NET")
            variables: Dictionary of variable definitions
            
        Returns:
            Dict with 'type', 'networks', 'excluded' keys, or None if too complex/invalid
        """
        net_spec = net_spec.strip()
        
        # Handle simple 'any'
        if net_spec.lower() == 'any':
            return {'type': 'any', 'networks': set(), 'excluded': set()}
        
        # Handle simple variables - resolve them
        if net_spec.startswith(('$', '@')) and '[' not in net_spec and '!' not in net_spec:
            resolved = variables.get(net_spec, net_spec)
            if resolved == net_spec:
                # Variable not found, be conservative
                return None
            # Recursively parse the resolved value
            return self._parse_network_specification(resolved, variables)
        
        # Handle negated expressions
        if net_spec.startswith('!'):
            negated_part = net_spec[1:].strip()
            if negated_part.startswith('[') and negated_part.endswith(']'):
                # Negated group: ![1.1.1.1, 1.1.1.2] - too complex for reliable analysis
                return None
            else:
                # Simple negation: !192.168.1.0/24 or !$HOME_NET - too complex for reliable analysis
                return None
        
        # Handle bracket notation groups
        if net_spec.startswith('[') and net_spec.endswith(']'):
            return self._parse_network_group(net_spec[1:-1], variables)
        
        # Handle simple CIDR or IP
        try:
            ip_network = ipaddress.ip_network(net_spec, strict=False)
            return {
                'type': 'simple',
                'networks': {ip_network},
                'excluded': set()
            }
        except ValueError:
            return None
    
    def _parse_network_group(self, group_content: str, variables: Dict[str, str]) -> Optional[Dict]:
        """Parse the contents of a network group [item1, item2, ...]"""
        if not group_content.strip():
            return None
        
        networks = set()
        excluded = set()
        
        # Split by commas and process each item
        items = [item.strip() for item in group_content.split(',')]
        
        for item in items:
            if not item:
                continue
            
            # Handle negated items within group
            if item.startswith('!'):
                excluded_item = item[1:].strip()
                if not excluded_item:
                    continue
                
                # Resolve variables in excluded items
                if excluded_item.startswith(('$', '@')):
                    resolved = variables.get(excluded_item, excluded_item)
                    if resolved == excluded_item:
                        # Variable not found, be conservative
                        return None
                    excluded_item = resolved
                
                # Parse as network
                try:
                    if excluded_item.lower() != 'any':
                        excluded_network = ipaddress.ip_network(excluded_item, strict=False)
                        excluded.add(excluded_network)
                except ValueError:
                    # Complex excluded item, too complex for analysis
                    return None
            else:
                # Regular item
                # Resolve variables
                if item.startswith(('$', '@')):
                    resolved = variables.get(item, item)
                    if resolved == item:
                        # Variable not found, be conservative
                        return None
                    item = resolved
                
                # Parse as network
                try:
                    if item.lower() != 'any':
                        network = ipaddress.ip_network(item, strict=False)
                        networks.add(network)
                    else:
                        # 'any' in a group means the group effectively matches everything
                        return {'type': 'any', 'networks': set(), 'excluded': excluded}
                except ValueError:
                    # Complex item, too complex for analysis
                    return None
        
        return {
            'type': 'group',
            'networks': networks,
            'excluded': excluded
        }
    
    def _network_specification_contains(self, broader_spec: Dict, specific_spec: Dict) -> bool:
        """Check if broader network specification contains the specific one"""
        # 'any' contains everything
        if broader_spec['type'] == 'any':
            return True
        
        # Nothing contains 'any' except 'any' itself
        if specific_spec['type'] == 'any':
            return False
        
        # Handle exclusions in the specific spec - if specific has exclusions, be conservative
        if specific_spec['excluded']:
            return False
        
        # Simple case: both are simple networks
        if (broader_spec['type'] == 'simple' and specific_spec['type'] == 'simple' and
            len(broader_spec['networks']) == 1 and len(specific_spec['networks']) == 1):
            
            broader_net = list(broader_spec['networks'])[0]
            specific_net = list(specific_spec['networks'])[0]
            
            # Check basic containment
            is_contained = specific_net.subnet_of(broader_net) or broader_net == specific_net
            
            # If broader spec has exclusions, check if specific network is excluded
            if is_contained and broader_spec['excluded']:
                for excluded_net in broader_spec['excluded']:
                    try:
                        # If the specific network is contained within any excluded network, it's not shadowed
                        if (specific_net.subnet_of(excluded_net) or specific_net == excluded_net or
                            excluded_net.subnet_of(specific_net)):
                            return False
                    except:
                        # On IP network comparison errors, be conservative
                        continue
            
            return is_contained
        
        # Handle group containment scenarios
        if broader_spec['type'] == 'group' and specific_spec['type'] == 'simple':
            # Check if the specific network is contained within any network in the group
            specific_network = list(specific_spec['networks'])[0]
            is_contained = False
            
            for broader_network in broader_spec['networks']:
                try:
                    if specific_network.subnet_of(broader_network) or broader_network == specific_network:
                        is_contained = True
                        break
                except:
                    # On IP network comparison errors, be conservative
                    continue
            
            # If not contained in any broader network, return False
            if not is_contained:
                return False
            
            # If broader spec has exclusions, check if specific network is excluded
            if broader_spec['excluded']:
                for excluded_net in broader_spec['excluded']:
                    try:
                        # If the specific network is contained within any excluded network, it's not shadowed
                        if (specific_network.subnet_of(excluded_net) or specific_network == excluded_net or
                            excluded_net.subnet_of(specific_network)):
                            return False
                    except:
                        # On IP network comparison errors, be conservative
                        continue
            
            return True
        
        # For other complex scenarios, be conservative
        # Complete analysis would require set operations on IP ranges which is complex
        return False
    
    def is_port_equal_or_broader(self, port1: str, port2: str, variables: Dict[str, str] = None) -> bool:
        """Check if port1 is equal to or broader than port2 for complete shadowing"""
        if port1 == port2:
            return True
        if port1 == 'any':
            return True  # 'any' is broader than everything
        if port2 == 'any':
            return False  # Specific port cannot be broader than 'any'
        
        # For complete shadowing, we need port1 to completely contain port2
        try:
            # Simple case: both are single ports
            if port1.isdigit() and port2.isdigit():
                return int(port1) == int(port2)
            
            # Parse port specifications for range/list analysis (with variable resolution)
            ports1 = self.parse_port_specification(port1, variables)
            ports2 = self.parse_port_specification(port2, variables)
            
            # If parsing failed for either, be conservative
            if ports1 is None or ports2 is None:
                return False
            
            # Check if all ports in port2 are contained within port1's specification
            return self.port_set_contains(ports1, ports2)
            
        except:
            return False
    
    def parse_port_specification(self, port_spec: str, variables: Dict[str, str] = None) -> Optional[set]:
        """Parse a port specification into a set of port numbers
        
        Args:
            port_spec: Port specification (e.g., "80", "[80:90]", "[80,443]", "!80", "$HTTP_PORTS")
            variables: Dictionary of variable definitions for resolution
            
        Returns:
            Set of port numbers, or None if specification is too complex/invalid
        """
        try:
            port_spec = port_spec.strip()
            
            # Resolve port variables
            if port_spec.startswith(('$', '@')) and variables:
                resolved_port = variables.get(port_spec, port_spec)
                if resolved_port != port_spec:
                    port_spec = resolved_port
                elif port_spec.startswith(('$', '@')):
                    # Variable not found, be conservative
                    return None
            
            # Handle bracketed port specifications - remove brackets and parse content
            if port_spec.startswith('[') and port_spec.endswith(']'):
                port_spec = port_spec[1:-1].strip()  # Remove brackets
                if not port_spec:
                    return None  # Empty brackets
            
            # Handle simple negated ports - these are complex, return None to be conservative
            if port_spec.startswith('!') and ',' not in port_spec:
                return None
            
            ports = set()
            excluded_ports = set()
            
            # Split by comma for port lists
            for part in port_spec.split(','):
                part = part.strip()
                
                # Handle negated parts within bracketed specs
                if part.startswith('!'):
                    negated_part = part[1:].strip()
                    
                    if negated_part.isdigit():
                        # Single negated port (e.g., !83)
                        port = int(negated_part)
                        if 1 <= port <= 65535:
                            excluded_ports.add(port)
                    elif ':' in negated_part:
                        # Negated range (e.g., !8080:8090) - this is complex, be conservative
                        return None
                    else:
                        # Other negated specs are too complex
                        return None
                    continue
                
                if ':' in part:
                    # Port range (e.g., "80:90")
                    range_parts = part.split(':')
                    if len(range_parts) != 2:
                        return None  # Invalid range format
                    
                    start_str, end_str = range_parts
                    if not start_str.isdigit() or not end_str.isdigit():
                        return None  # Invalid range values
                    
                    start_port = int(start_str)
                    end_port = int(end_str)
                    
                    # Validate port range
                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        return None  # Invalid port range
                    
                    # Add all ports in range
                    for port in range(start_port, end_port + 1):
                        ports.add(port)
                        
                elif part.isdigit():
                    # Single port
                    port = int(part)
                    if port < 1 or port > 65535:
                        return None  # Invalid port number
                    ports.add(port)
                    
                else:
                    # Complex specification we don't handle (variables, etc.)
                    return None
            
            # Apply exclusions: remove excluded ports from the final set
            final_ports = ports - excluded_ports
            return final_ports if final_ports else None
            
        except (ValueError, OverflowError):
            return None
    
    def port_set_contains(self, broader_ports: set, specific_ports: set) -> bool:
        """Check if broader_ports set completely contains specific_ports set
        
        Args:
            broader_ports: Set of ports from the broader rule
            specific_ports: Set of ports from the more specific rule
            
        Returns:
            True if broader_ports completely contains specific_ports
        """
        # For complete shadowing, all ports in specific_ports must be in broader_ports
        return specific_ports.issubset(broader_ports)
    
    def is_content_equal_or_broader(self, rule1: SuricataRule, rule2: SuricataRule) -> bool:
        """Check if rule1 content is equal to or broader than rule2 content for complete shadowing"""
        content1 = (rule1.content or '').lower()
        content2 = (rule2.content or '').lower()
        
        # If rule1 has no content restrictions, it's broader
        if not content1 and content2:
            return True
        
        # If rule2 has no content restrictions but rule1 does, rule1 is not broader
        if content1 and not content2:
            return False
        
        # If both have no content, they're equal
        if not content1 and not content2:
            return True
        
        # Apply filters for non-conflicts
        if 'noalert' in content1 or 'noalert' in content2:
            return False
        if self.has_negated_content(content1) or self.has_negated_content(content2):
            return False
        if self.uses_different_detection_mechanisms(content1, content2):
            return False
        if self.has_geographic_specificity(content1, content2):
            return False
        if self.domains_dont_match_patterns(content1, content2):
            return False
        if not self.flow_states_overlap(content1, content2):
            return False
        
        # NEW: Handle endswith patterns for domain matching (critical for TLS SNI and HTTP host shadowing)
        if self.has_endswith_pattern(content1) and self.has_endswith_pattern(content2):
            domain1 = self.extract_endswith_domain(content1)
            domain2 = self.extract_endswith_domain(content2)
            
            if domain1 and domain2:
                # If domain2 ends with domain1, then domain1 pattern is broader
                # e.g., "amazon.com" is broader than "aws.amazon.com" because
                # any SNI ending with "aws.amazon.com" also ends with "amazon.com"
                if domain2.endswith(domain1) and domain1 != domain2:
                    return True
                # If domain1 ends with domain2, then domain2 pattern is broader
                elif domain1.endswith(domain2) and domain1 != domain2:
                    return False
                # If domains are equal, patterns are equal
                elif domain1 == domain2:
                    return True
                # If neither ends with the other, patterns don't shadow
                else:
                    return False
        
        # For complete shadowing with content, we need very specific analysis
        return content1 == content2
    
    def flow_states_overlap(self, content1: str, content2: str) -> bool:
        """Check if flow states in two rules can overlap"""
        flow1 = self.extract_flow_keywords(content1)
        flow2 = self.extract_flow_keywords(content2)
        
        # If either rule has no flow keywords, assume they could overlap
        if not flow1 or not flow2:
            return True
        
        # Check for mutually exclusive flow states
        if ('not_established' in flow1 and any(state in flow2 for state in ['established', 'to_server', 'to_client'])) or \
           ('not_established' in flow2 and any(state in flow1 for state in ['established', 'to_server', 'to_client'])):
            return False
        
        # to_server vs to_client (different directions)
        if ('to_server' in flow1 and 'to_client' in flow2) or \
           ('to_client' in flow1 and 'to_server' in flow2):
            return False
        
        return True
    
    def flow_states_are_mutually_exclusive(self, rule1: SuricataRule, rule2: SuricataRule) -> bool:
        """Check if two rules have mutually exclusive flow states that prevent conflicts
        
        This is specifically for cases where one rule targets connection establishment
        and another targets application layer content (which requires established connections).
        """
        content1 = (rule1.content or '').lower()
        content2 = (rule2.content or '').lower()
        
        flow1 = self.extract_flow_keywords(content1)
        flow2 = self.extract_flow_keywords(content2)
        
        # Rule targeting not_established (handshake) vs rule requiring application layer parsing
        if ('not_established' in flow1 and self.requires_established_connection(rule2)) or \
           ('not_established' in flow2 and self.requires_established_connection(rule1)):
            return True
        
        return False
    
    def requires_established_connection(self, rule: SuricataRule) -> bool:
        """Check if rule requires an established connection for application layer parsing"""
        content = (rule.content or '').lower()
        protocol = rule.protocol.lower()
        
        # Application layer protocols inherently require established connections
        if protocol in ['dcerpc', 'dhcp', 'dns', 'ftp', 'http', 'http2', 'https', 'ikev2', 'imap', 'krb5', 'msn', 'ntp', 'pop3', 'quic', 'smb', 'smtp', 'ssh', 'tftp', 'tls']:
            return True
        
        # Application layer keywords that require established connections
        app_layer_keywords = [
            'http.host', 'http.uri', 'http.method', 'http.user_agent',
            'tls.sni', 'tls.subject', 'tls.issuer',
            'ja3.hash', 'ja3s.hash', 'ja4.hash',
            'ssl_state:client_hello', 'ssl_state:server_hello',
            'app-layer-protocol:'
        ]
        
        return any(keyword in content for keyword in app_layer_keywords)
    
    def extract_flow_keywords(self, content: str) -> set:
        """Extract flow-related keywords from rule content"""
        flow_keywords = set()
        
        # Look for flow: keyword and extract its values
        flow_matches = re.findall(r'flow:\s*([^;]+)', content)
        for match in flow_matches:
            # Split by comma and clean up
            keywords = [kw.strip() for kw in match.split(',')]
            flow_keywords.update(keywords)
        
        return flow_keywords
    
    def has_flowbits_dependency(self, rule: SuricataRule) -> bool:
        """Check if rule has flowbits dependencies that prevent conflicts"""
        if not rule.content and not rule.original_options:
            return False
        
        # Check both content and original_options for flowbits
        content = (rule.content or '') + ' ' + (rule.original_options or '')
        
        # Rules with flowbits:set typically are conditional and may not conflict
        if 'flowbits:set,' in content or 'flowbits:isnotset,' in content:
            return True
        
        return False
    
    def has_negated_content(self, content: str) -> bool:
        """Check if content has negated matches like content:!"something" """
        return 'content:!' in content
    
    def uses_different_detection_mechanisms(self, content1: str, content2: str) -> bool:
        """Check if rules use fundamentally different detection mechanisms"""
        # Application layer keywords for content inspection
        app_layer_keywords = ['http.host', 'tls.sni', 'http.', 'tls.', 'ssl_state', 'ja3', 'ja4']
        
        # Network layer keywords for packet-level detection
        network_layer_keywords = ['geoip:', 'ip_proto:']
        
        has_app_layer1 = any(keyword in content1 for keyword in app_layer_keywords)
        has_app_layer2 = any(keyword in content2 for keyword in app_layer_keywords)
        has_network_layer1 = any(keyword in content1 for keyword in network_layer_keywords)
        has_network_layer2 = any(keyword in content2 for keyword in network_layer_keywords)
        
        # If one rule uses app layer detection and the other uses network layer, they don't conflict
        if (has_app_layer1 and has_network_layer2) or (has_network_layer1 and has_app_layer2):
            return True
        
        return False
    
    def has_geographic_specificity(self, content1: str, content2: str) -> bool:
        """Check if one rule has geographic specificity and the other is generic"""
        geo_keywords = ['geoip:']
        
        has_geo1 = any(keyword in content1 for keyword in geo_keywords)
        has_geo2 = any(keyword in content2 for keyword in geo_keywords)
        
        # If one rule has geographic specificity and the other doesn't, they don't conflict
        if (has_geo1 and not has_geo2) or (has_geo2 and not has_geo1):
            return True
        
        return False
    
    def is_intentional_layered_pattern(self, upper_rule: SuricataRule, lower_rule: SuricataRule) -> bool:
        """Check for intentional layered security patterns"""
        # Pattern: specific reject/drop rules before generic alert rules
        if upper_rule.action in ['reject', 'drop'] and lower_rule.action == 'alert':
            upper_content = (upper_rule.content or '').lower()
            lower_content = (lower_rule.content or '').lower()
            
            # Check if upper rule has specific content and lower rule has generic pcre pattern
            if ('content:' in upper_content and 'pcre:' in lower_content and 
                'suspicious' in lower_rule.message.lower()):
                return True
        
        return False
    
    def domains_dont_match_patterns(self, content1: str, content2: str) -> bool:
        """Check if specific domains wouldn't match generic patterns"""
        domain1 = self.extract_domain_from_content(content1)
        domain2 = self.extract_domain_from_content(content2)
        
        # Check if one has a specific domain and the other has a pattern that wouldn't match it
        if domain1 and 'pcre:' in content2:
            if 'suspicious' in content2 and '.amazonaws.com' in domain1:
                return True
        
        if domain2 and 'pcre:' in content1:
            if 'suspicious' in content1 and '.amazonaws.com' in domain2:
                return True
        
        return False
    
    def extract_domain_from_content(self, content: str) -> Optional[str]:
        """Extract domain from tls.sni or http.host content"""
        # Look for domain patterns in content
        domain_match = re.search(r'content:\s*"([^"]*)"', content)
        if not domain_match:
            domain_match = re.search(r"content:\s*'([^']*)'", content)
        if domain_match:
            domain = domain_match.group(1)
            if domain.startswith('.'):
                return domain[1:]  # Remove leading dot
            return domain
        return None
    
    def has_endswith_pattern(self, content: str) -> bool:
        """Check if content contains an endswith pattern for domain matching"""
        return ('content:' in content and 'endswith' in content and 
                ('tls.sni' in content or 'http.host' in content))
    
    def extract_endswith_domain(self, content: str) -> Optional[str]:
        """Extract domain from content that uses endswith pattern"""
        if not self.has_endswith_pattern(content):
            return None
        
        # Look for content:"domain" patterns 
        domain_match = re.search(r'content:\s*"([^"]*)"', content)
        if not domain_match:
            domain_match = re.search(r"content:\s*'([^']*)'", content)
        
        if domain_match:
            domain = domain_match.group(1)
            # Remove leading dot if present (for wildcard domains)
            if domain.startswith('.'):
                domain = domain[1:]
            return domain
        
        return None
    
    def check_reverse_shadowing(self, upper_rule: SuricataRule, lower_rule: SuricataRule,
                               upper_line: int, lower_line: int, variables: Dict[str, str]) -> Optional[Dict]:
        """Check if lower rule makes upper rule unreachable (reverse shadowing)
        
        Args:
            upper_rule: Rule that appears first in the list
            lower_rule: Rule that appears later in the list  
            upper_line: Line number of upper rule
            lower_line: Line number of lower rule
            variables: Dictionary of network variable definitions
            
        Returns:
            Conflict dictionary if reverse shadowing exists, None otherwise
        """
        # Only check if lower rule could make upper rule unreachable
        # This happens when lower rule is broader and would match traffic before upper rule gets a chance
        if not self.rules_overlap_reverse(lower_rule, upper_rule, variables):
            return None
        
        # Apply filters to eliminate false positives
        if self.has_flowbits_dependency(upper_rule) or self.has_flowbits_dependency(lower_rule):
            return None
        
        if self.is_intentional_layered_pattern(lower_rule, upper_rule):
            return None
        
        # Only flag if lower rule is significantly broader (especially protocol "ip")
        if not self.is_significantly_broader(lower_rule, upper_rule):
            return None
        
        # Determine severity - broad rules making specific rules unreachable
        if lower_rule.action in ['pass'] and upper_rule.action in ['drop', 'reject']:
            severity = 'critical'
            issue = f"Broad {lower_rule.action.upper()} rule at line {lower_line} makes specific {upper_rule.action.upper()} rule unreachable (security bypass)"
            suggestion = f"Move line {lower_line} after line {upper_line} or make it more specific"
        elif lower_rule.action in ['pass', 'drop', 'reject'] and upper_rule.action == 'alert':
            severity = 'warning' 
            issue = f"Broad {lower_rule.action.upper()} rule at line {lower_line} makes specific ALERT rule unreachable (missing alerts)"
            suggestion = f"Move line {lower_line} after line {upper_line} or make it more specific"
        else:
            return None
        
        return {
            'upper_rule': upper_rule,
            'lower_rule': lower_rule, 
            'upper_line': upper_line,
            'lower_line': lower_line,
            'severity': severity,
            'issue': issue,
            'suggestion': suggestion
        }
    
    def rules_overlap_reverse(self, broader_rule: SuricataRule, specific_rule: SuricataRule, variables: Dict[str, str]) -> bool:
        """Check if broader rule would match traffic intended for specific rule"""
        # Protocol must be broader or equal
        if not self.is_equal_or_broader_protocol(broader_rule, specific_rule):
            return False
        
        # Direction must overlap
        if not self.directions_overlap(broader_rule.direction, specific_rule.direction):
            return False
        
        # Networks must overlap (broader rule contains specific rule's networks)
        if not (self.is_network_equal_or_broader(broader_rule.src_net, specific_rule.src_net, variables) and
                self.is_network_equal_or_broader(broader_rule.dst_net, specific_rule.dst_net, variables)):
            return False
        
        # Ports must overlap (broader rule contains specific rule's ports)
        if not (self.is_port_equal_or_broader(broader_rule.src_port, specific_rule.src_port, variables) and
                self.is_port_equal_or_broader(broader_rule.dst_port, specific_rule.dst_port, variables)):
            return False
        
        # Content must be broader or equal
        if not self.is_content_equal_or_broader(broader_rule, specific_rule):
            return False
        
        return True
    
    def is_significantly_broader(self, rule1: SuricataRule, rule2: SuricataRule) -> bool:
        """Check if rule1 is significantly broader than rule2 (not just marginally)"""
        # Protocol "ip" is significantly broader than specific protocols
        if rule1.protocol.lower() == 'ip' and rule2.protocol.lower() != 'ip':
            return True
        
        # "any" networks are significantly broader than specific networks
        if ((rule1.src_net == 'any' and rule2.src_net != 'any') or 
            (rule1.dst_net == 'any' and rule2.dst_net != 'any')):
            return True
        
        # "any" ports are significantly broader than specific ports
        if ((rule1.src_port == 'any' and rule2.src_port != 'any') or
            (rule1.dst_port == 'any' and rule2.dst_port != 'any')):
            return True
        
        # No content restrictions vs specific content
        if not rule1.content and rule2.content:
            return True
        
        return False
    
    def check_protocol_layering_conflict(self, upper_rule: SuricataRule, lower_rule: SuricataRule,
                                        upper_line: int, lower_line: int, variables: Dict[str, str]) -> Optional[Dict]:
        """Check for protocol layering conflicts based on Suricata's rule type processing order
        
        Suricata processes rules in this order regardless of file position:
        1. SIG_TYPE_APPLAYER (rules with app-layer-protocol keywords)
        2. SIG_TYPE_PKT (rules with flow keywords but no app-layer-protocol)  
        3. SIG_TYPE_IPONLY (rules with neither app-layer-protocol nor flow keywords)
        
        This can cause conflicts when broader rules of a higher-priority type shadow 
        more specific rules of a lower-priority type.
        
        Args:
            upper_rule: Rule that appears first in the list
            lower_rule: Rule that appears later in the list
            upper_line: Line number of upper rule  
            lower_line: Line number of lower rule
            variables: Dictionary of network variable definitions
            
        Returns:
            Conflict dictionary if protocol layering conflict exists, None otherwise
        """
        
        # Determine Suricata rule types
        upper_type = self.get_suricata_rule_type(upper_rule)
        lower_type = self.get_suricata_rule_type(lower_rule)
        
        # Check for type-based processing conflicts (regardless of file order)
        type_conflict = self.check_rule_type_conflict(upper_rule, lower_rule, upper_line, lower_line, 
                                                     upper_type, lower_type, variables)
        if type_conflict:
            return type_conflict
        
        # Original protocol layering logic for low-level vs high-level protocols
        return self.check_traditional_protocol_layering(upper_rule, lower_rule, upper_line, lower_line, variables)
    
    def get_suricata_rule_type(self, rule: SuricataRule) -> str:
        """Determine Suricata rule type based on keywords for AWS Network Firewall"""
        content = (rule.content or '').lower()
        protocol = rule.protocol.lower()
        
        # FIRST: Check for application layer sticky buffers - these take precedence
        # Even with flow:established, if a rule uses app-layer sticky buffers, it's APP_TX
        app_layer_buffers = [
            'http.accept', 'http.accept_enc', 'http.accept_lang', 'http.connection',
            'http.content_len', 'http.content_type', 'http.cookie', 'http.header',
            'http.header_names', 'http.host', 'http.method', 'http.protocol',
            'http.referer', 'http.request_body', 'http.request_header', 'http.request_line',
            'http.response_body', 'http.response_header', 'http.response_line',
            'http.server', 'http.start', 'http.stat_code', 'http.stat_msg',
            'http.uri', 'http.uri.raw', 'http.user_agent',
            'tls.cert_fingerprint', 'tls.cert_issuer', 'tls.cert_serial',
            'tls.cert_subject', 'tls.certs', 'tls.sni', 'tls.version',
            'dns.query', 'dns.answer',
            'ssh.proto', 'ssh.software',
            'ja3.hash', 'ja3.string', 'ja3s.hash', 'ja3s.string',
            'ja4.hash', 'ja4.string',
            'file.data', 'file.name',
            'smb.named_pipe', 'smb.share',
            'krb5.cname', 'krb5.sname',
            'dcerpc.iface', 'dcerpc.stub_data',
            'ftp.command', 'ftp.command_line'
        ]
        
        if any(buffer in content for buffer in app_layer_buffers):
            return 'SIG_TYPE_APPLAYER'
        
        # Application layer protocols (http, tls, etc.) are SIG_TYPE_APPLAYER
        if protocol in ['dcerpc', 'dhcp', 'dns', 'ftp', 'http', 'http2', 'https', 'ikev2', 'imap', 'krb5', 'msn', 'ntp', 'quic', 'smb', 'smtp', 'ssh', 'tftp', 'tls']:
            return 'SIG_TYPE_APPLAYER'
        
        # Rules with app-layer-protocol keywords are always SIG_TYPE_APPLAYER
        if 'app-layer-protocol:' in content:
            return 'SIG_TYPE_APPLAYER'
        
        # SECOND: Check for variable-like keywords that force packet-level classification
        # Per https://docs.suricata.io/en/latest/rules/rule-types.html#variable-like-keywords-sig-type
        # Rules with flow:established or flow:not_established become packet rules (if not app-layer)
        if 'flow:established' in content or 'flow:not_established' in content or 'not_established' in content:
            return 'SIG_TYPE_PKT'
        
        # Rules with flowbits isset/isnotset (but NOT set/unset/toggle), flowint isset/notset, or iprep become packet rules
        # Note: flowbits:set does NOT change rule type per documentation
        if any(keyword in content for keyword in ['flowbits:isset', 'flowbits:isnotset', 'iprep:']):
            return 'SIG_TYPE_PKT'
        
        # flowint with isset/notset operations (but not just defining/setting variables)
        if 'flowint:' in content:
            # Check if it's an isset/notset operation (these force packet type)
            if any(op in content for op in ['isset', 'notset']):
                return 'SIG_TYPE_PKT'
        
        # Low-level protocol rules (tcp, ip) with flow keywords get elevated to application layer processing
        if protocol in ['tcp', 'ip'] and 'flow:' in content:
            return 'SIG_TYPE_APPLAYER'
        
        # Other rules with flow keywords are SIG_TYPE_PKT
        if 'flow:' in content:
            return 'SIG_TYPE_PKT'
        
        # Rules with no special keywords are SIG_TYPE_IPONLY
        return 'SIG_TYPE_IPONLY'
    
    def check_rule_type_conflict(self, upper_rule: SuricataRule, lower_rule: SuricataRule,
                                upper_line: int, lower_line: int, upper_type: str, lower_type: str,
                                variables: Dict[str, str]) -> Optional[Dict]:
        """Check for conflicts based on Suricata rule type processing order"""
        
        # Rule type processing priority (1 = processes first, 3 = processes last)
        type_priority = {
            'SIG_TYPE_IPONLY': 1,     # Process FIRST - basic IP/TCP/UDP rules without keywords
            'SIG_TYPE_PKT': 2,        # Process SECOND - rules with flow keywords  
            'SIG_TYPE_APPLAYER': 3    # Process LAST - rules with app-layer-protocol or application protocols
        }
        
        # Look for cases where a higher-priority type rule could shadow a lower-priority type rule
        # regardless of file order
        higher_priority_rule = None
        lower_priority_rule = None
        higher_line = None
        lower_line_num = None
        
        if type_priority[upper_type] < type_priority[lower_type]:
            # Upper rule has higher processing priority
            higher_priority_rule = upper_rule
            lower_priority_rule = lower_rule
            higher_line = upper_line
            lower_line_num = lower_line
        elif type_priority[lower_type] < type_priority[upper_type]:
            # Lower rule has higher processing priority  
            higher_priority_rule = lower_rule
            lower_priority_rule = upper_rule
            higher_line = lower_line
            lower_line_num = upper_line
        else:
            # Same type priority - this is NOT a protocol layering conflict
            # It's an intra-type ordering issue handled separately
            return None
        
        # CRITICAL: Only flag as protocol layering conflict if the higher-priority rule
        # is a low-level protocol rule WITHOUT flow/app-layer keywords
        # If it HAS these keywords, it's elevated to application layer processing
        
        # Check if the higher priority rule is truly a low-level protocol rule
        higher_protocol = higher_priority_rule.protocol.lower()
        higher_content = (higher_priority_rule.content or '').lower()
        
        # If it's a low-level protocol with flow/app-layer keywords, it's elevated - not a protocol layering issue
        if (higher_protocol in ['tcp', 'ip'] and 
            ('flow:' in higher_content or 'app-layer-protocol:' in higher_content)):
            return None
        
        # Only flag true protocol layering conflicts: low-level protocol rules WITHOUT elevation keywords
        if not (higher_protocol in ['ip', 'icmp', 'udp', 'tcp'] and 
                'flow:' not in higher_content and 
                'app-layer-protocol:' not in higher_content):
            return None
        
        # Check if higher priority rule could shadow lower priority rule
        if not self.rules_could_match_same_traffic(higher_priority_rule, lower_priority_rule, variables):
            return None
        
        # Check if higher priority rule is broader than lower priority rule
        if not self.rule_is_broader_for_type_conflict(higher_priority_rule, lower_priority_rule):
            return None
        
        # Generate conflict description
        higher_type_name = higher_priority_rule.protocol.upper()
        lower_type_name = lower_priority_rule.protocol.upper()
        
        if (higher_priority_rule.action in ['drop', 'reject'] and 
            lower_priority_rule.action == 'pass'):
            
            issue = (f"{higher_type_name} rule at line {higher_line} (SIG_TYPE_IPONLY) "
                    f"will be processed before {lower_type_name} rule at line {lower_line_num} due to protocol layering, "
                    f"potentially blocking traffic that should be allowed")
            
            suggestion = f"Add flow keywords to line {higher_line} or reorder rules"
            
            return {
                'upper_rule': upper_rule,
                'lower_rule': lower_rule,
                'upper_line': upper_line,
                'lower_line': lower_line,
                'severity': 'protocol_layering',
                'issue': issue,
                'suggestion': suggestion
            }
        
        elif (higher_priority_rule.action == 'pass' and 
              lower_priority_rule.action in ['drop', 'reject']):
            
            issue = (f"{higher_type_name} rule at line {higher_line} (SIG_TYPE_IPONLY) "
                    f"will be processed before {lower_type_name} rule at line {lower_line_num} due to protocol layering, "
                    f"potentially allowing traffic that should be blocked")
            
            suggestion = f"Add flow keywords to line {higher_line} or reorder rules"
            
            return {
                'upper_rule': upper_rule,
                'lower_rule': lower_rule,
                'upper_line': upper_line,
                'lower_line': lower_line,
                'severity': 'protocol_layering',
                'issue': issue,
                'suggestion': suggestion
            }
        
        return None
    
    def rules_could_match_same_traffic(self, rule1: SuricataRule, rule2: SuricataRule, variables: Dict[str, str]) -> bool:
        """Check if two rules could potentially match the same traffic"""
        # Networks must overlap
        if not (self.networks_overlap_loose(rule1.src_net, rule2.src_net, variables) and
                self.networks_overlap_loose(rule1.dst_net, rule2.dst_net, variables)):
            return False
        
        # Ports must overlap  
        if not (self.ports_overlap_loose(rule1.src_port, rule2.src_port) and
                self.ports_overlap_loose(rule1.dst_port, rule2.dst_port)):
            return False
        
        # Direction must overlap
        if not self.directions_overlap(rule1.direction, rule2.direction):
            return False
        
        # Protocol compatibility check
        if not self.protocols_could_match_same_traffic(rule1, rule2):
            return False
        
        # Check if rules have mutually exclusive flow states (e.g., handshake vs application layer)
        if self.flow_states_are_mutually_exclusive(rule1, rule2):
            return False
        
        return True
    
    def protocols_could_match_same_traffic(self, rule1: SuricataRule, rule2: SuricataRule) -> bool:
        """Check if two rules' protocol specifications could match the same traffic"""
        proto1 = rule1.protocol.lower()
        proto2 = rule2.protocol.lower()
        
        # Same protocol always matches
        if proto1 == proto2:
            return True
        
        # Different base protocols (TCP vs ICMP vs UDP) cannot match the same traffic
        base_protocols = {'tcp', 'icmp', 'udp'}
        if proto1 in base_protocols and proto2 in base_protocols and proto1 != proto2:
            return False
        
        # Check if rule1 has app-layer-protocol restrictions that could match rule2's protocol
        rule1_content = (rule1.content or '').lower()
        if 'app-layer-protocol:!' in rule1_content:
            # Extract what protocols are excluded
            excluded_pattern = re.search(r'app-layer-protocol:!(\w+)', rule1_content)
            if excluded_pattern:
                excluded_protocol = excluded_pattern.group(1)
                # If rule2's protocol IS the excluded protocol, rule1 CANNOT match rule2's traffic
                if proto2 == excluded_protocol:
                    return False
                # If rule2's protocol is not the excluded protocol, rule1 could match rule2's traffic
                return True
        
        # Check if rule2 has app-layer-protocol restrictions that could match rule1's protocol
        rule2_content = (rule2.content or '').lower()
        if 'app-layer-protocol:!' in rule2_content:
            # Extract what protocols are excluded
            excluded_pattern = re.search(r'app-layer-protocol:!(\w+)', rule2_content)
            if excluded_pattern:
                excluded_protocol = excluded_pattern.group(1)
                # If rule1's protocol IS the excluded protocol, rule2 CANNOT match rule1's traffic
                if proto1 == excluded_protocol:
                    return False
                # If rule1's protocol is not the excluded protocol, rule2 could match rule1's traffic
                return True
        
        # TCP can match HTTP/TLS traffic (application protocols over TCP)
        if proto1 == 'tcp' and proto2 in ['http', 'tls']:
            return True
        if proto2 == 'tcp' and proto1 in ['http', 'tls']:
            return True
        
        # IP can match any protocol (IP is the base layer for all)
        if proto1 == 'ip' or proto2 == 'ip':
            return True
        
        return False
    
    def rule_is_broader_for_type_conflict(self, broader_rule: SuricataRule, specific_rule: SuricataRule) -> bool:
        """Check if one rule is broader than another for type-based conflicts"""
        broader_content = (broader_rule.content or '').lower()
        specific_content = (specific_rule.content or '').lower()
        
        # If broader rule has app-layer-protocol negation, it's broader than specific protocol rules
        if 'app-layer-protocol:!' in broader_content:
            return True
        
        # If broader rule has no content restrictions but specific rule does
        if not broader_content and specific_content:
            return True
        
        # TCP protocol is broader than specific application protocols
        if (broader_rule.protocol.lower() == 'tcp' and 
            specific_rule.protocol.lower() in ['http', 'tls', 'https']):
            return True
        
        return False
    
    def check_intra_type_conflict(self, upper_rule: SuricataRule, lower_rule: SuricataRule,
                                 upper_line: int, lower_line: int, variables: Dict[str, str]) -> Optional[Dict]:
        """Check for conflicts within the same Suricata rule type based on file order
        
        Within the same rule type (e.g., both SIG_TYPE_APPLAYER), AWS Network Firewall
        processes rules in file order (top to bottom). So an earlier rule can shadow
        a later rule if it's broader and matches the same traffic.
        
        Args:
            upper_rule: Rule that appears first in the list
            lower_rule: Rule that appears later in the list
            upper_line: Line number of upper rule
            lower_line: Line number of lower rule
            variables: Dictionary of network variable definitions
            
        Returns:
            Conflict dictionary if intra-type conflict exists, None otherwise
        """
        
        # Check if rules could match the same traffic (includes flow state exclusion logic)
        if not self.rules_could_match_same_traffic(upper_rule, lower_rule, variables):
            return None
        
        # Check if upper rule is broader than lower rule  
        if not self.rule_is_broader_for_type_conflict(upper_rule, lower_rule):
            return None
        
        # Additional check: Skip conflicts between TCP handshake rules and application layer content rules
        # This prevents false positives where handshake allowance rules are flagged against content inspection rules
        if self.flow_states_are_mutually_exclusive(upper_rule, lower_rule):
            return None
        
        # Generate conflict based on actions (file order matters)
        if (upper_rule.action in ['drop', 'reject'] and 
            lower_rule.action == 'pass'):
            
            issue = (f"{upper_rule.protocol.upper()} rule at line {upper_line} will be processed before "
                    f"{lower_rule.protocol.upper()} rule at line {lower_line} (same rule type), "
                    f"potentially blocking traffic that should be allowed")
            
            suggestion = f"Move line {lower_line} above line {upper_line} to ensure traffic is allowed as intended"
            
            return {
                'upper_rule': upper_rule,
                'lower_rule': lower_rule,
                'upper_line': upper_line,
                'lower_line': lower_line,
                'severity': 'protocol_layering',
                'issue': issue,
                'suggestion': suggestion
            }
        
        elif (upper_rule.action == 'pass' and 
              lower_rule.action in ['drop', 'reject']):
            
            issue = (f"{upper_rule.protocol.upper()} rule at line {upper_line} will be processed before "
                    f"{lower_rule.protocol.upper()} rule at line {lower_line} (same rule type), "
                    f"potentially allowing traffic that should be blocked")
            
            suggestion = f"Move line {lower_line} above line {upper_line} to ensure traffic is blocked as intended"
            
            return {
                'upper_rule': upper_rule,
                'lower_rule': lower_rule,
                'upper_line': upper_line,
                'lower_line': lower_line,
                'severity': 'protocol_layering',
                'issue': issue,
                'suggestion': suggestion
            }
        
        return None
    
    def check_traditional_protocol_layering(self, upper_rule: SuricataRule, lower_rule: SuricataRule,
                                          upper_line: int, lower_line: int, variables: Dict[str, str]) -> Optional[Dict]:
        """Original protocol layering logic for low-level vs high-level protocols"""
        # PRIMARY CASE: Low-level protocol rule followed by higher-layer protocol rule
        # This is the most problematic because low-level rules process first
        if (self.is_low_level_protocol(upper_rule.protocol) and 
            self.is_higher_layer_protocol(lower_rule.protocol)):
            
            # Must be targeting the same networks and ports
            if not self.networks_and_ports_overlap(upper_rule, lower_rule, variables):
                return None
            
            # The low-level protocol rule must be broader (less restrictive) than the higher-layer rule
            if not self.low_level_rule_is_broader_than_app_rule(upper_rule, lower_rule):
                return None
            
            # CRITICAL: Check if the low-level protocol rule lacks flow keywords
            # This is the most dangerous scenario - broad low-level rules without flow constraints
            if self.has_flow_keywords(upper_rule):
                return None  # Flow keywords help mitigate the issue
            
            # Generate appropriate conflict based on actions
            low_level_protocol = upper_rule.protocol.upper()
            higher_protocol_name = lower_rule.protocol.upper()
            
            if (upper_rule.action in ['drop', 'reject'] and 
                lower_rule.action == 'pass'):
                
                issue = (f"{low_level_protocol} rule at line {upper_line} will be processed before {higher_protocol_name} rule at line {lower_line} "
                        f"due to protocol layering, potentially blocking traffic that should be allowed")
                
                suggestion = f"Add flow keywords (e.g., 'flow:established;') to line {upper_line} or move {higher_protocol_name} rule above {low_level_protocol} rule"
                
                return {
                    'upper_rule': upper_rule,
                    'lower_rule': lower_rule,
                    'upper_line': upper_line,
                    'lower_line': lower_line,
                    'severity': 'protocol_layering',
                    'issue': issue,
                    'suggestion': suggestion
                }
            
            elif (upper_rule.action == 'pass' and 
                  lower_rule.action in ['drop', 'reject']):
                
                issue = (f"{low_level_protocol} rule at line {upper_line} will be processed before {higher_protocol_name} rule at line {lower_line} "
                        f"due to protocol layering, potentially allowing traffic that should be blocked")
                
                suggestion = f"Add flow keywords (e.g., 'flow:established;') to line {upper_line}"
                
                return {
                    'upper_rule': upper_rule,
                    'lower_rule': lower_rule,
                    'upper_line': upper_line,  
                    'lower_line': lower_line,
                    'severity': 'protocol_layering',
                    'issue': issue,
                    'suggestion': suggestion
                }
            
            elif (upper_rule.action in ['pass', 'drop', 'reject'] and 
                  lower_rule.action == 'alert'):
                
                issue = (f"{low_level_protocol} rule at line {upper_line} will be processed before {higher_protocol_name} rule at line {lower_line} "
                        f"due to protocol layering, potentially preventing alerts from being generated")
                
                suggestion = f"Add flow keywords (e.g., 'flow:established;') to line {upper_line}"
                
                return {
                    'upper_rule': upper_rule,
                    'lower_rule': lower_rule,
                    'upper_line': upper_line,
                    'lower_line': lower_line,
                    'severity': 'protocol_layering',
                    'issue': issue,
                    'suggestion': suggestion
                }
            
            elif (upper_rule.action in ['drop', 'reject'] and 
                  lower_rule.action in ['drop', 'reject']):
                
                issue = (f"{low_level_protocol} rule at line {upper_line} will be processed before {higher_protocol_name} rule at line {lower_line} "
                        f"due to protocol layering, potentially interfering with application-layer processing")
                
                suggestion = f"Add flow keywords (e.g., 'flow:established;') to line {upper_line}"
                
                return {
                    'upper_rule': upper_rule,
                    'lower_rule': lower_rule,
                    'upper_line': upper_line,
                    'lower_line': lower_line,
                    'severity': 'protocol_layering',
                    'issue': issue,
                    'suggestion': suggestion
                }
        
        # SECONDARY CASE: Higher-layer rule followed by low-level protocol rule 
        # Less common but still problematic in some scenarios
        elif (self.is_higher_layer_protocol(upper_rule.protocol) and 
              self.is_low_level_protocol(lower_rule.protocol)):
            
            # Must be targeting the same networks and ports
            if not self.networks_and_ports_overlap(upper_rule, lower_rule, variables):
                return None
            
            # The low-level protocol rule must be broader (less restrictive) than the higher-layer rule
            if not self.low_level_rule_is_broader_than_app_rule(lower_rule, upper_rule):
                return None
            
            # Check if the low-level protocol rule lacks flow keywords
            if self.has_flow_keywords(lower_rule):
                return None
            
            # Only flag this as a secondary concern (less critical than the primary case)
            protocol_name = lower_rule.protocol.upper()
            higher_protocol_name = upper_rule.protocol.upper()
            
            if (upper_rule.action in ['drop', 'reject'] and 
                lower_rule.action == 'pass'):
                
                issue = (f"Broad {protocol_name} rule at line {lower_line} without flow keywords may interfere with "
                        f"{higher_protocol_name} rule at line {upper_line} in some scenarios")
                
                suggestion = f"Add flow keywords (e.g., 'flow:established;') to line {lower_line}"
                
                return {
                    'upper_rule': upper_rule,
                    'lower_rule': lower_rule,
                    'upper_line': upper_line,
                    'lower_line': lower_line,
                    'severity': 'protocol_layering',
                    'issue': issue,
                    'suggestion': suggestion
                }
        
        return None
    
    def networks_and_ports_overlap(self, rule1: SuricataRule, rule2: SuricataRule, variables: Dict[str, str]) -> bool:
        """Check if two rules have overlapping networks and ports"""
        # Networks must overlap
        if not (self.networks_overlap_loose(rule1.src_net, rule2.src_net, variables) and
                self.networks_overlap_loose(rule1.dst_net, rule2.dst_net, variables)):
            return False
        
        # Ports must overlap  
        if not (self.ports_overlap_loose(rule1.src_port, rule2.src_port) and
                self.ports_overlap_loose(rule1.dst_port, rule2.dst_port)):
            return False
        
        # Direction must overlap
        if not self.directions_overlap(rule1.direction, rule2.direction):
            return False
        
        return True
    
    def networks_overlap_loose(self, net1: str, net2: str, variables: Dict[str, str]) -> bool:
        """Check if two networks overlap (looser check than exact shadowing)
        
        Now supports full Suricata CIDR range formats for overlap detection
        """
        if net1 == net2:
            return True
        if net1 == 'any' or net2 == 'any':
            return True
        
        # Parse both network specifications
        parsed_net1 = self._parse_network_specification(net1, variables)
        parsed_net2 = self._parse_network_specification(net2, variables)
        
        # If parsing failed for either, be conservative (assume overlap)
        if parsed_net1 is None or parsed_net2 is None:
            return True
        
        # 'any' type overlaps with everything
        if parsed_net1['type'] == 'any' or parsed_net2['type'] == 'any':
            return True
        
        # For complex analysis involving exclusions, be conservative
        if parsed_net1['excluded'] or parsed_net2['excluded']:
            return True  # Conservative - exclusions make analysis complex
        
        # Check if any networks in net1 overlap with any networks in net2
        for network1 in parsed_net1['networks']:
            for network2 in parsed_net2['networks']:
                try:
                    if network1.overlaps(network2):
                        return True
                except:
                    return True  # Conservative on IP network errors
        
        # If no overlaps found and no exclusions to consider
        return len(parsed_net1['networks']) == 0 and len(parsed_net2['networks']) == 0
    
    def ports_overlap_loose(self, port1: str, port2: str) -> bool:
        """Check if two port specifications overlap (looser check)"""
        if port1 == port2:
            return True
        if port1 == 'any' or port2 == 'any':
            return True
        
        # For simple port numbers, check for exact match
        try:
            if port1.isdigit() and port2.isdigit():
                return int(port1) == int(port2)
        except:
            pass
        
        # For complex port specs, assume they might overlap
        return True
    
    
    def is_higher_layer_protocol(self, protocol: str) -> bool:
        """Check if protocol is a higher-layer/application protocol"""
        return protocol.lower() in ['dcerpc', 'dhcp', 'dns', 'ftp', 'http', 'http2', 'https', 'ikev2', 'imap', 'krb5', 'msn', 'nfs', 'ntp', 'pop3', 'quic', 'rdp', 'smb', 'smtp', 'ssh', 'tftp', 'tls']
    
    def is_low_level_protocol(self, protocol: str) -> bool:
        """Check if protocol is a low-level/network protocol"""
        return protocol.lower() in ['ip', 'icmp', 'udp', 'tcp']
    
    def low_level_rule_is_broader_than_app_rule(self, low_level_rule: SuricataRule, app_rule: SuricataRule) -> bool:
        """Check if low-level protocol rule is broader (less restrictive) than application layer rule"""
        # Low-level rule should have fewer content restrictions than higher-layer rule
        low_level_content = (low_level_rule.content or '').lower()
        app_content = (app_rule.content or '').lower()
        
        # If low-level rule has no content restrictions but app rule does, low-level is broader
        if not low_level_content and app_content:
            return True
        
        # If both have content, check for broad low-level protocol patterns
        if low_level_content and app_content:
            # Check if low-level rule uses broad negated application-layer protocol patterns
            # that would actually match the traffic type of the app-layer rule
            
            # Extract the app-layer protocol from the higher-layer rule
            app_protocol = app_rule.protocol.lower()
            
            # Check for patterns that would conflict with the specific app-layer protocol
            conflicting_patterns = []
            
            if app_protocol == 'tls':
                # For TLS rules, only patterns that match TLS traffic are conflicting
                conflicting_patterns = [
                    'app-layer-protocol:!http',    # TLS ≠ HTTP, so TLS traffic matches !http
                    'app-layer-protocol:!dns',     # TLS ≠ DNS, so TLS traffic matches !dns  
                    'app-layer-protocol:!smtp',    # TLS ≠ SMTP, so TLS traffic matches !smtp
                    'app-layer-protocol:!ftp',     # TLS ≠ FTP, so TLS traffic matches !ftp
                    'app-layer-protocol:!ssh',     # TLS ≠ SSH, so TLS traffic matches !ssh
                    # Note: 'app-layer-protocol:!tls' is NOT included because TLS traffic is excluded by !tls
                ]
            elif app_protocol == 'http':
                # For HTTP rules, patterns that match HTTP traffic are conflicting
                conflicting_patterns = [
                    'app-layer-protocol:!tls',     # HTTP ≠ TLS, so HTTP traffic matches !tls
                    'app-layer-protocol:!dns',     # HTTP ≠ DNS, so HTTP traffic matches !dns  
                    'app-layer-protocol:!smtp',    # HTTP ≠ SMTP, so HTTP traffic matches !smtp
                    'app-layer-protocol:!ftp',     # HTTP ≠ FTP, so HTTP traffic matches !ftp
                    'app-layer-protocol:!ssh',     # HTTP ≠ SSH, so HTTP traffic matches !ssh
                    # Note: 'app-layer-protocol:!http' is NOT included because HTTP traffic is excluded by !http
                ]
            else:
                # For other protocols, use a more conservative approach
                conflicting_patterns = [
                    'app-layer-protocol:!http',
                    'app-layer-protocol:!tls',
                    'app-layer-protocol:!dns',
                    'app-layer-protocol:!smtp',
                    'app-layer-protocol:!ftp',
                    'app-layer-protocol:!ssh',
                ]
                # Remove the pattern that would exclude the current app protocol
                exclusion_pattern = f'app-layer-protocol:!{app_protocol}'
                if exclusion_pattern in conflicting_patterns:
                    conflicting_patterns.remove(exclusion_pattern)
            
            # If low-level rule uses any conflicting patterns, it's broader than the app-layer rule
            if any(pattern in low_level_content for pattern in conflicting_patterns):
                return True
            
            # Otherwise, if both have content, low-level rule is not necessarily broader
            return False
        
        # If neither has content, check other factors like network/port specificity
        return True
    
    def has_flow_keywords(self, rule: SuricataRule) -> bool:
        """Check if rule has any flow keywords that would mitigate protocol layering issues"""
        content = (rule.content or '').lower()
        original_options = (rule.original_options or '').lower()
        full_content = content + ' ' + original_options
        
        # Check for any flow keywords
        flow_keywords = [
            'flow:established',
            'flow:to_server', 
            'flow:to_client',
            'flow:not_established',
            'flow:stateless',
            'flowbits:'
        ]
        
        return any(keyword in full_content for keyword in flow_keywords)
    
    def _deduplicate_protocol_layering_conflicts(self, conflicts: Dict[str, List[Dict]]) -> None:
        """Remove critical/warning conflicts that are covered by protocol layering conflicts
        
        When both a protocol layering conflict and a critical/warning conflict exist for the same
        rule pair, the protocol layering conflict is the root cause and should be shown instead.
        
        Args:
            conflicts: Dictionary of conflicts to deduplicate in-place
        """
        if not conflicts['protocol_layering']:
            return  # No protocol layering conflicts to check against
        
        # Create a set of rule pairs involved in protocol layering conflicts
        protocol_layering_pairs = set()
        for conflict in conflicts['protocol_layering']:
            upper_line = conflict['upper_line']
            lower_line = conflict['lower_line']
            # Store both orderings since conflicts can be detected in either direction
            protocol_layering_pairs.add((upper_line, lower_line))
            protocol_layering_pairs.add((lower_line, upper_line))
        
        # Remove critical and warning conflicts that match protocol layering pairs
        for severity in ['critical', 'warning']:
            conflicts[severity] = [
                conflict for conflict in conflicts[severity]
                if (conflict['upper_line'], conflict['lower_line']) not in protocol_layering_pairs
            ]
    
    def check_sticky_buffer_ordering(self, rules: List[SuricataRule]) -> List[Dict]:
        """Check for improper sticky buffer keyword ordering in rules
        
        Validates that sticky buffer keywords (e.g., tls.sni, http.host) appear BEFORE
        their associated content keywords. Content keywords without a preceding sticky
        buffer will have no context and may not work as intended.
        
        Args:
            rules: List of SuricataRule objects to analyze
            
        Returns:
            List of dictionaries describing sticky buffer ordering issues
        """
        issues = []
        
        # Define all known sticky buffer keywords
        sticky_buffers = self._get_sticky_buffer_keywords()
        
        # Filter out comments and blank lines
        actual_rules = [r for r in rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        for rule in actual_rules:
            # Get line number in original rules list
            line_num = rules.index(rule) + 1
            
            # Get the full rule content for analysis
            # Use original_options if available (more complete), otherwise use content
            # Don't concatenate both to avoid processing duplicate tokens
            full_content = rule.original_options or rule.content or ''
            
            if not full_content.strip():
                continue  # Skip rules with no content
            
            # Parse the rule options to check keyword ordering
            ordering_issues = self._check_rule_sticky_buffer_order(rule, full_content, sticky_buffers, line_num)
            
            if ordering_issues:
                issues.extend(ordering_issues)
        
        return issues
    
    def _get_sticky_buffer_keywords(self) -> set:
        """Get the set of all known Suricata sticky buffer keywords
        
        Returns:
            Set of sticky buffer keyword strings
        """
        return {
            # HTTP sticky buffers
            'http.accept', 'http.accept_enc', 'http.accept_lang', 'http.connection',
            'http.content_len', 'http.content_type', 'http.cookie', 'http.header',
            'http.header_names', 'http.host', 'http.method', 'http.protocol',
            'http.referer', 'http.request_body', 'http.request_header', 'http.request_line',
            'http.response_body', 'http.response_header', 'http.response_line',
            'http.server', 'http.start', 'http.stat_code', 'http.stat_msg',
            'http.uri', 'http.uri.raw', 'http.user_agent',
            
            # TLS sticky buffers
            'tls.cert_fingerprint', 'tls.cert_issuer', 'tls.cert_serial',
            'tls.cert_subject', 'tls.certs', 'tls.sni', 'tls.version',
            
            # DNS sticky buffers
            'dns.query', 'dns.answer',
            
            # SSH sticky buffers
            'ssh.proto', 'ssh.software', 'ssh.protoversion', 'ssh.softwareversion',
            
            # JA3/JA4 sticky buffers
            'ja3.hash', 'ja3.string', 'ja3s.hash', 'ja3s.string',
            'ja4.hash', 'ja4.string',
            
            # File sticky buffers
            'file.data', 'file.name',
            
            # SMB sticky buffers
            'smb.named_pipe', 'smb.share',
            
            # Kerberos sticky buffers
            'krb5.cname', 'krb5.sname',
            
            # Other protocol sticky buffers
            'dcerpc.iface', 'dcerpc.stub_data',
            'ftp.command', 'ftp.command_line',
            'modbus.data', 'modbus.function',
            'nfs3.procedure',
            'sip.method', 'sip.uri', 'sip.request_line', 'sip.stat_code',
            'snmp.community', 'snmp.pdu_type',
        }
    
    def _check_rule_sticky_buffer_order(self, rule: SuricataRule, full_content: str, 
                                        sticky_buffers: set, line_num: int) -> List[Dict]:
        """Check a single rule for sticky buffer ordering issues and dotprefix validation
        
        Args:
            rule: The SuricataRule object to check
            full_content: Full content string with all options
            sticky_buffers: Set of known sticky buffer keywords
            line_num: Line number of this rule
            
        Returns:
            List of issue dictionaries for this rule
        """
        issues = []
        
        # Split rule content into keyword tokens (separated by semicolons)
        # We need to track the position of keywords relative to each other
        tokens = self._tokenize_rule_options(full_content)
        
        if not tokens:
            return issues
        
        # Track the current sticky buffer context (None means no sticky buffer in effect)
        current_sticky_buffer = None
        
        # Track content keywords that appear before any sticky buffer
        orphaned_content_keywords = []
        
        # Track content keywords that appear after a sticky buffer ends but before a new one starts
        misplaced_content_keywords = []
        
        # Check for dotprefix issues first
        dotprefix_issues = self._check_dotprefix_ordering(tokens, line_num, rule)
        if dotprefix_issues:
            issues.extend(dotprefix_issues)
        
        # Always get dotprefix content indices to avoid double-reporting
        # (whether or not there were dotprefix issues, we don't want to also flag
        # these content keywords as orphaned)
        dotprefix_content_indices = self._get_dotprefix_content_indices(tokens)
        
        for i, token in enumerate(tokens):
            token_lower = token.strip().lower()
            
            # Check if this token is a sticky buffer keyword
            if any(token_lower.startswith(sb) for sb in sticky_buffers):
                # Extract the sticky buffer name
                for sb in sticky_buffers:
                    if token_lower.startswith(sb):
                        current_sticky_buffer = sb
                        break
            
            # Check if this token is dotprefix (it establishes context for the next content keyword)
            elif token_lower == 'dotprefix':
                # dotprefix acts like a pseudo-sticky buffer for the next content keyword
                current_sticky_buffer = 'dotprefix'
            
            # Check if this is a content keyword
            elif token_lower.startswith('content:'):
                # Skip this content keyword if it's part of a dotprefix issue already reported
                if i in dotprefix_content_indices:
                    continue
                
                # If no sticky buffer is active, this content has no context
                if current_sticky_buffer is None:
                    # Check if there ARE sticky buffers later in the rule
                    has_sticky_buffers_later = any(
                        any(future_token.strip().lower().startswith(sb) for sb in sticky_buffers)
                        for future_token in tokens[i+1:]
                    )
                    
                    if has_sticky_buffers_later:
                        orphaned_content_keywords.append((i, token))
        
        # Generate issues for orphaned content keywords (Option A: content before any sticky buffer)
        if orphaned_content_keywords:
            # Find the first sticky buffer keyword that appears after the orphaned content
            first_sticky_buffer_index = None
            first_sticky_buffer_name = None
            
            for i, token in enumerate(tokens):
                token_lower = token.strip().lower()
                if any(token_lower.startswith(sb) for sb in sticky_buffers):
                    for sb in sticky_buffers:
                        if token_lower.startswith(sb):
                            first_sticky_buffer_index = i
                            first_sticky_buffer_name = sb
                            break
                    if first_sticky_buffer_index is not None:
                        break
            
            # Check if the orphaned content appears before the first sticky buffer
            for content_index, content_token in orphaned_content_keywords:
                if first_sticky_buffer_index and content_index < first_sticky_buffer_index:
                    issue = {
                        'line': line_num,
                        'rule': rule,
                        'issue': f"Content keyword appears before sticky buffer keyword '{first_sticky_buffer_name}'",
                        'suggestion': f"Move '{first_sticky_buffer_name}' keyword before the content keyword, or add an appropriate sticky buffer before the content keyword",
                        'severity': 'warning'
                    }
                    issues.append(issue)
                    break  # Only report once per rule to avoid clutter
        
        # Check for content keywords with NO sticky buffer at all in the rule (Option B)
        has_any_sticky_buffer = any(
            any(token.strip().lower().startswith(sb) for sb in sticky_buffers)
            for token in tokens
        )
        
        has_content_keyword = any(
            token.strip().lower().startswith('content:')
            for token in tokens
        )
        
        # Only flag if rule has content keywords but uses sticky buffer keywords AFTER the content
        # (This prevents false positives for rules that intentionally don't use sticky buffers)
        if not issues and has_content_keyword and has_any_sticky_buffer:
            # Double-check: This case should have been caught above
            # But if we get here, it means content appears but there's still a sticky buffer issue
            pass
        
        return issues
    
    def _get_dotprefix_content_indices(self, tokens: List[str]) -> set:
        """Get the indices of content keywords that follow dotprefix keywords
        
        This is used to avoid double-reporting when both dotprefix and sticky buffer checks
        would flag the same content keyword.
        
        Args:
            tokens: List of tokenized rule options
            
        Returns:
            Set of token indices for content keywords that have dotprefix before them
        """
        indices = set()
        
        for i, token in enumerate(tokens):
            token_lower = token.strip().lower()
            
            if token_lower == 'dotprefix':
                # Check if the next token is a content keyword
                if i + 1 < len(tokens):
                    next_token = tokens[i + 1].strip().lower()
                    if next_token.startswith('content:'):
                        indices.add(i + 1)  # Add the index of the content keyword
        
        return indices
    
    def _check_dotprefix_ordering(self, tokens: List[str], line_num: int, rule: SuricataRule) -> List[Dict]:
        """Check for proper dotprefix keyword usage and ordering
        
        Validates that:
        1. dotprefix appears directly before content keyword
        2. When dotprefix is used, the content value includes a leading dot
        
        Note: Only one issue is reported per dotprefix keyword to avoid duplicate warnings.
        
        Args:
            tokens: List of tokenized rule options
            line_num: Line number of the rule
            rule: The SuricataRule object
            
        Returns:
            List of issue dictionaries for dotprefix problems
        """
        issues = []
        seen_issues = set()  # Track unique issues to prevent duplicates
        
        # Find all dotprefix keywords
        for i, token in enumerate(tokens):
            token_lower = token.strip().lower()
            
            if token_lower == 'dotprefix':
                # Check if the next token exists
                if i + 1 >= len(tokens):
                    # dotprefix is the last token - invalid
                    issue_key = (line_num, "not_followed_by_content")
                    if issue_key not in seen_issues:
                        issue = {
                            'line': line_num,
                            'rule': rule,
                            'issue': f"dotprefix keyword is not followed by content keyword",
                            'suggestion': "When using dotprefix, place it directly before content and always include the leading dot in the content value (e.g., dotprefix; content:\".example.com\")",
                            'severity': 'warning'
                        }
                        issues.append(issue)
                        seen_issues.add(issue_key)
                    continue  # Move to next token, don't check further for this dotprefix
                
                next_token = tokens[i + 1].strip().lower()
                
                # Case 1: dotprefix is NOT directly before content
                if not next_token.startswith('content:'):
                    issue_key = (line_num, "not_directly_before_content")
                    if issue_key not in seen_issues:
                        issue = {
                            'line': line_num,
                            'rule': rule,
                            'issue': f"dotprefix keyword does not directly precede content keyword",
                            'suggestion': "When using dotprefix, place it directly before content and always include the leading dot in the content value (e.g., dotprefix; content:\".example.com\")",
                            'severity': 'warning'
                        }
                        issues.append(issue)
                        seen_issues.add(issue_key)
                    continue  # Move to next token, don't check leading dot since positioning is wrong
                
                # Case 2: dotprefix IS directly before content - now check if content has leading dot
                # Extract the content value
                content_match = re.search(r'content:\s*"([^"]*)"', next_token)
                if not content_match:
                    content_match = re.search(r"content:\s*'([^']*)'", next_token)
                
                if content_match:
                    content_value = content_match.group(1)
                    # Check if content value starts with a dot
                    if not content_value.startswith('.'):
                        issue_key = (line_num, f"missing_leading_dot_{content_value}")
                        if issue_key not in seen_issues:
                            issue = {
                                'line': line_num,
                                'rule': rule,
                                'issue': f"dotprefix used but content value does not include leading dot (content:\"{content_value}\")",
                                'suggestion': "When using dotprefix, place it directly before content and always include the leading dot in the content value (e.g., dotprefix; content:\".example.com\")",
                                'severity': 'warning'
                            }
                            issues.append(issue)
                            seen_issues.add(issue_key)
        
        return issues
    
    def _tokenize_rule_options(self, content: str) -> List[str]:
        """Tokenize rule options by splitting on semicolons while respecting quotes
        
        Args:
            content: Rule content string with semicolon-separated options
            
        Returns:
            List of token strings
        """
        tokens = []
        current_token = ""
        in_quotes = False
        quote_char = None
        
        for char in content:
            if char in ('"', "'") and (not in_quotes or char == quote_char):
                in_quotes = not in_quotes
                quote_char = char if in_quotes else None
                current_token += char
            elif char == ';' and not in_quotes:
                if current_token.strip():
                    tokens.append(current_token.strip())
                current_token = ""
            else:
                current_token += char
        
        # Add the last token if there is one
        if current_token.strip():
            tokens.append(current_token.strip())
        
        return tokens
    
    def check_udp_flow_established_issues(self, rules: List[SuricataRule]) -> List[Dict]:
        """Check for UDP/ICMP rules that use flow:established with drop/reject actions
        
        UDP and ICMP flows are only considered "established" after bidirectional traffic is seen.
        This means a UDP/ICMP rule with flow:established and drop/reject action will NOT block
        the initial packet (e.g., DNS query, ICMP echo request), creating a security gap.
        
        Args:
            rules: List of SuricataRule objects to analyze
            
        Returns:
            List of dictionaries describing UDP/ICMP flow:established issues
        """
        issues = []
        
        # Define connectionless protocols (UDP-based and ICMP)
        connectionless_protocols = {
            'icmp',     # ICMP (ping, etc.)
            'udp',      # Generic UDP
            'dns',      # DNS over UDP (port 53)
            'dhcp',     # DHCP
            'ntp',      # Network Time Protocol
            'tftp',     # Trivial FTP
            'snmp',     # Simple Network Management Protocol
            'syslog',   # Syslog
            'radius',   # RADIUS
            'quic',     # QUIC (HTTP/3)
        }
        
        # Filter out comments and blank lines
        actual_rules = [r for r in rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        for rule in actual_rules:
            # Get line number in original rules list
            line_num = rules.index(rule) + 1
            
            # Check if rule uses a connectionless protocol (UDP-based or ICMP)
            protocol = rule.protocol.lower()
            if protocol not in connectionless_protocols:
                continue
            
            # Check if rule has drop or reject action
            if rule.action.lower() not in ['drop', 'reject']:
                continue
            
            # Check if rule contains flow:established
            full_content = (rule.content or '') + ' ' + (rule.original_options or '')
            if 'flow:established' not in full_content.lower() and 'flow: established' not in full_content.lower():
                continue
            
            # This is a problematic pattern - UDP/ICMP drop/reject with flow:established
            # Determine appropriate message based on protocol type
            if protocol == 'icmp':
                packet_example = "ICMP echo requests"
                suggestion_text = f"Remove 'flow:established' to match initial ICMP packets, or add a separate rule without 'flow:established' to catch the first packet in the flow."
            else:
                packet_example = "DNS queries" if protocol == 'dns' else f"{protocol.upper()} packets"
                suggestion_text = f"Remove 'flow:established' to match initial {protocol.upper()} packets, or add a separate rule without 'flow:established' to catch the first packet in the flow."
            
            issue = {
                'line': line_num,
                'rule': rule,
                'protocol': protocol.upper(),
                'action': rule.action.upper(),
                'issue': (f"{rule.action.upper()} rule for {protocol.upper()} protocol uses 'flow:established', "
                         f"but {protocol.upper()} flows are only considered established after bidirectional traffic. "
                         f"Initial packets (like {packet_example}) will NOT match this rule and will be allowed through."),
                'suggestion': suggestion_text,
                'severity': 'warning'
            }
            issues.append(issue)
        
        return issues
    
    def check_protocol_keyword_mismatch(self, rules: List[SuricataRule]) -> List[Dict]:
        """Check for protocols using incompatible application-layer keywords
        
        Uses transport layer hierarchy to detect:
        1. INVALID combinations (WARNING): Protocol's transport incompatible with keyword's requirements
        2. Suboptimal combinations (INFO): Low-level protocol when specific app protocol is better
        
        Args:
            rules: List of SuricataRule objects to analyze
            
        Returns:
            List of dictionaries describing protocol/keyword mismatches
        """
        issues = []
        
        # Protocol hierarchy: Map each protocol to its transport layer
        protocol_transport_layer = {
            # TCP-based protocols
            'tcp': 'tcp',
            'tls': 'tcp',
            'http': 'tcp',
            'http2': 'tcp',
            'https': 'tcp',
            'ssh': 'tcp',
            'smtp': 'tcp',
            'ftp': 'tcp',
            'smb': 'tcp',
            'dcerpc': 'tcp',
            'krb5': 'tcp',
            'imap': 'tcp',
            'pop3': 'tcp',
            'msn': 'tcp',
            'ikev2': 'tcp',
            'rdp': 'tcp',
            
            # UDP-based protocols
            'udp': 'udp',
            'dns': 'udp',
            'dhcp': 'udp',
            'ntp': 'udp',
            'tftp': 'udp',
            'snmp': 'udp',
            'quic': 'udp',
            'syslog': 'udp',
            'radius': 'udp',
            'nfs': 'udp',
            
            # Other
            'icmp': 'icmp',
            'ip': 'ip'  # IP can carry anything
        }
        
        # Define protocol-to-keyword mappings
        protocol_keyword_map = {
            'tls': ['tls.sni', 'tls.cert_subject', 'tls.cert_issuer', 'tls.cert_serial',
                    'tls.cert_fingerprint', 'tls.certs', 'tls.version', 'ja3.hash', 
                    'ja3.string', 'ja3s.hash', 'ja3s.string', 'ja4.hash', 'ja4.string'],
            'http': ['http.host', 'http.uri', 'http.method', 'http.user_agent', 'http.header',
                     'http.cookie', 'http.accept', 'http.content_type', 'http.request_header',
                     'http.response_header', 'http.request_body', 'http.response_body'],
            'dns': ['dns.query', 'dns.answer'],
            'ssh': ['ssh.proto', 'ssh.software', 'ssh.protoversion', 'ssh.softwareversion'],
            'smtp': ['smtp.command', 'smtp.data'],
            'ftp': ['ftp.command', 'ftp.command_line'],
            'smb': ['smb.named_pipe', 'smb.share'],
            'dcerpc': ['dcerpc.iface', 'dcerpc.stub_data'],
            'krb5': ['krb5.cname', 'krb5.sname']
        }
        
        # Map each app protocol to its required transport layer
        keyword_transport_requirements = {
            'tls': 'tcp',
            'http': 'tcp',
            'ssh': 'tcp',
            'smtp': 'tcp',
            'ftp': 'tcp',
            'smb': 'tcp',
            'dcerpc': 'tcp',
            'krb5': 'tcp',
            'dns': 'udp'
        }
        
        # Filter out comments and blank lines
        actual_rules = [r for r in rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        for rule in actual_rules:
            # Get line number in original rules list
            line_num = rules.index(rule) + 1
            
            protocol = rule.protocol.lower()
            
            # Get protocol's transport layer
            protocol_transport = protocol_transport_layer.get(protocol, None)
            if not protocol_transport:
                continue  # Unknown protocol, skip
            
            # Get rule content
            full_content = (rule.content or '') + ' ' + (rule.original_options or '')
            full_content_lower = full_content.lower()
            
            # Check if rule uses any application-layer keywords
            for app_protocol, keywords in protocol_keyword_map.items():
                # Check if any of the app-layer keywords are present
                mismatched_keywords = [kw for kw in keywords if kw in full_content_lower]
                
                if mismatched_keywords:
                    keyword_list = ', '.join(f"'{kw}'" for kw in mismatched_keywords[:3])
                    if len(mismatched_keywords) > 3:
                        keyword_list += f" and {len(mismatched_keywords) - 3} more"
                    
                    # Get transport layer required by these keywords
                    required_transport = keyword_transport_requirements.get(app_protocol)
                    
                    # Check for cross-protocol keyword mismatch (app-layer protocol using different app-layer keywords)
                    if protocol in protocol_keyword_map and protocol != app_protocol:
                        # App-layer protocol using keywords from DIFFERENT app-layer protocol
                        # e.g., HTTP using tls.sni or TLS using http.host
                        # This is INVALID - the keywords won't match the protocol's traffic
                        issue = {
                            'line': line_num,
                            'rule': rule,
                            'current_protocol': protocol.upper(),
                            'suggested_protocol': app_protocol.upper(),
                            'keywords': mismatched_keywords,
                            'issue': (f"Rule uses {protocol.upper()} protocol with {app_protocol.upper()}-specific keyword(s): {keyword_list}. "
                                     f"{protocol.upper()} traffic does not contain {app_protocol.upper()} data - this rule will never match"),
                            'suggestion': f"Change protocol from '{protocol}' to '{app_protocol}' (or use appropriate {protocol.upper()} keywords instead)",
                            'severity': 'warning'
                        }
                        issues.append(issue)
                        break
                    
                    # Check transport compatibility
                    if protocol == 'ip':
                        # IP is universal - can't determine transport, skip check
                        continue
                    elif protocol_transport != required_transport:
                        # INVALID: Transport layer mismatch
                        # e.g., DHCP (udp) with tls.sni (requires tcp)
                        issue = {
                            'line': line_num,
                            'rule': rule,
                            'current_protocol': protocol.upper(),
                            'suggested_protocol': app_protocol.upper(),
                            'keywords': mismatched_keywords,
                            'issue': (f"Rule uses {protocol.upper()} protocol with {app_protocol.upper()}-specific keyword(s): {keyword_list}. "
                                     f"{app_protocol.upper()} requires {required_transport.upper()} transport but {protocol.upper()} uses {protocol_transport.upper()} - this rule will never match"),
                            'suggestion': f"Change protocol from '{protocol}' to '{app_protocol}' to fix transport layer mismatch",
                            'severity': 'warning'
                        }
                        issues.append(issue)
                        break
                    elif protocol in ['tcp', 'udp'] and protocol != app_protocol:
                        # SUBOPTIMAL: Low-level protocol with app-layer keywords
                        # Transport matches, but using specific protocol is better
                        issue = {
                            'line': line_num,
                            'rule': rule,
                            'current_protocol': protocol.upper(),
                            'suggested_protocol': app_protocol.upper(),
                            'keywords': mismatched_keywords,
                            'issue': (f"Rule uses {protocol.upper()} protocol with {app_protocol.upper()}-specific keyword(s): {keyword_list}"),
                            'suggestion': f"Consider using '{app_protocol}' protocol instead of '{protocol}' for better clarity and performance",
                            'severity': 'info'
                        }
                        issues.append(issue)
                        break
        
        return issues
    
    def check_port_protocol_mismatch(self, rules: List[SuricataRule]) -> List[Dict]:
        """Check for protocols on unusual/unexpected ports
        
        Detects when protocols are used on non-standard ports that might indicate
        configuration errors.
        
        Args:
            rules: List of SuricataRule objects to analyze
            
        Returns:
            List of dictionaries describing port/protocol mismatches
        """
        issues = []
        
        # Define typical ports for each protocol
        protocol_typical_ports = {
            'http': {80, 8080, 8000, 8888, 3000, 5000},
            'https': {443, 8443},
            'tls': {443, 8443, 465, 587, 993, 995, 636},  # HTTPS, SMTPS, IMAPS, POP3S, LDAPS
            'ssh': {22},
            'ftp': {20, 21},
            'smtp': {25, 465, 587},  # SMTP, SMTPS, Submission
            'dns': {53},
            'dhcp': {67, 68},
            'ntp': {123},
            'snmp': {161, 162},
            'tftp': {69},
            'pop3': {110, 995},  # POP3, POP3S
            'imap': {143, 993},  # IMAP, IMAPS
            'smb': {139, 445},
            'rdp': {3389}
        }
        
        # Filter out comments and blank lines
        actual_rules = [r for r in rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        for rule in actual_rules:
            line_num = rules.index(rule) + 1
            protocol = rule.protocol.lower()
            
            # Only check protocols that have typical ports defined
            if protocol not in protocol_typical_ports:
                continue
            
            # Check destination port (most relevant for protocol detection)
            dst_port = rule.dst_port.strip()
            
            # Skip 'any' and variables - can't validate those
            if dst_port.lower() == 'any' or dst_port.startswith(('$', '@', '[')):
                continue
            
            # Parse single port
            try:
                port_num = int(dst_port)
            except ValueError:
                continue  # Not a simple port, skip
            
            # Check if port is in the typical set for this protocol
            typical_ports = protocol_typical_ports[protocol]
            if port_num not in typical_ports:
                # Found mismatch
                typical_ports_str = ', '.join(str(p) for p in sorted(typical_ports))
                
                issue = {
                    'line': line_num,
                    'rule': rule,
                    'protocol': protocol.upper(),
                    'port': port_num,
                    'typical_ports': typical_ports_str,
                    'issue': f"Rule uses {protocol.upper()} protocol on port {port_num}, but {protocol.upper()} typically uses ports: {typical_ports_str}",
                    'suggestion': f"Verify that {protocol.upper()} is actually running on port {port_num}, or check if protocol should be changed",
                    'severity': 'info'
                }
                issues.append(issue)
        
        return issues
    
    def check_contradictory_flow_keywords(self, rules: List[SuricataRule]) -> List[Dict]:
        """Check for contradictory flow keywords in same rule
        
        Detects mutually exclusive flow states like:
        - flow:to_server,to_client (can't be both directions)
        - flow:established,not_established (can't be both states)
        
        Args:
            rules: List of SuricataRule objects to analyze
            
        Returns:
            List of dictionaries describing contradictory flow keywords
        """
        issues = []
        
        # Filter out comments and blank lines
        actual_rules = [r for r in rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        for rule in actual_rules:
            line_num = rules.index(rule) + 1
            
            # Extract flow keywords
            flow_keywords = self.extract_flow_keywords((rule.content or '') + ' ' + (rule.original_options or ''))
            
            if not flow_keywords:
                continue
            
            # Check for contradictions
            contradictions = []
            
            # Check for both to_server and to_client
            if 'to_server' in flow_keywords and 'to_client' in flow_keywords:
                contradictions.append("'to_server' and 'to_client' (flow cannot be in both directions)")
            
        # Check for both established and not_established
        if 'established' in flow_keywords and 'not_established' in flow_keywords:
            contradictions.append("'established' and 'not_established' (mutually exclusive states)")
            
            if contradictions:
                contradiction_str = '; '.join(contradictions)
                issue = {
                    'line': line_num,
                    'rule': rule,
                    'contradictions': contradictions,
                    'issue': f"Rule contains contradictory flow keywords: {contradiction_str}",
                    'suggestion': "Remove one of the contradictory flow keywords - the rule will never match in its current state",
                    'severity': 'warning'
                }
                issues.append(issue)
        
        return issues
    
    def check_packet_drop_flow_pass_conflict(self, rules: List[SuricataRule]) -> List[Dict]:
        """Check for packet-scope DROP/REJECT conflicting with flow-scope PASS
        
        In Suricata versions before 8.0, packet-scope drop/reject and flow-scope pass
        had ambiguous behavior. This was fixed in Suricata 8.0 with deconfliction logic.
        
        See: https://redmine.openinfosecfoundation.org/issues/7653
        
        Args:
            rules: List of SuricataRule objects to analyze
            
        Returns:
            List of dictionaries describing packet/flow action conflicts
        """
        issues = []
        
        # Filter out comments and blank lines
        actual_rules = [r for r in rules if not getattr(r, 'is_comment', False) and not getattr(r, 'is_blank', False)]
        
        # Group rules by type for analysis
        for i in range(len(actual_rules)):
            for j in range(i + 1, len(actual_rules)):
                rule1 = actual_rules[i]
                rule2 = actual_rules[j]
                line1 = rules.index(rule1) + 1
                line2 = rules.index(rule2) + 1
                
                # Get rule types
                type1 = self.get_suricata_rule_type(rule1)
                type2 = self.get_suricata_rule_type(rule2)
                
                # Check if one is packet-scope DROP/REJECT and other is flow-scope PASS
                is_packet_drop = (type1 == 'SIG_TYPE_PKT' and rule1.action.lower() in ['drop', 'reject'])
                is_flow_pass = (type2 == 'SIG_TYPE_APPLAYER' and rule2.action.lower() == 'pass')
                
                if is_packet_drop and is_flow_pass:
                    # Check if they could match same traffic
                    if self.rules_could_match_same_traffic(rule1, rule2, {}):
                        issue = {
                            'line1': line1,
                            'line2': line2,
                            'rule1': rule1,
                            'rule2': rule2,
                            'issue': (f"Packet-scope {rule1.action.upper()} rule at line {line1} conflicts with flow-scope PASS rule at line {line2}. "
                                     f"Behavior was ambiguous in Suricata <8.0 (fixed in 8.0+). "
                                     f"Current AWS Network Firewall may block this traffic."),
                            'suggestion': f"Move PASS rule (line {line2}) before {rule1.action.upper()} rule (line {line1}), or ensure rules don't overlap. See: https://redmine.openinfosecfoundation.org/issues/7653",
                            'severity': 'warning'
                        }
                        issues.append(issue)
        
        return issues
    
    def generate_analysis_report(self, conflicts: Dict[str, List[Dict]],
                               total_rules: int, current_file: str = None, 
                               version: str = None) -> str:
        """Generate formatted analysis report with timestamp and version info"""
        import datetime
        
        total_conflicts = sum(len(conflicts[severity]) for severity in conflicts)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Always use the analyzer's own version
        analyzer_version = get_analyzer_version()
        
        report = f"SURICATA RULE ANALYSIS REPORT\n"
        report += f"=" * 50 + "\n\n"
        report += f"Generated: {timestamp}\n"
        report += f"Rule Analyzer Version: {analyzer_version}\n"
        report += f"File: {current_file or 'Unsaved'}\n\n"
        
        # Disclaimer
        report += "DISCLAIMER:\n"
        report += "This analysis is provided for illustrative purposes only and should be used\n"
        report += "as a starting point for rule review. All findings must be validated by a\n"
        report += "qualified security professional familiar with your specific environment\n"
        report += "and requirements. The tool may produce false positives or miss complex\n"
        report += "rule interactions. Always test rule changes in a non-production environment.\n\n"
        
        report += f"Total Rules Analyzed: {total_rules}\n"
        report += f"Total Conflicts Found: {total_conflicts}\n\n"
        
        if total_conflicts == 0:
            report += "✓ No rule conflicts detected. Your rule ordering looks good!\n"
            return report
        
        # Protocol layering issues (displayed first)
        if conflicts['protocol_layering']:
            report += f"🔄 PROTOCOL LAYERING CONFLICTS ({len(conflicts['protocol_layering'])})\n"
            report += f"-" * 30 + "\n"
            for i, conflict in enumerate(conflicts['protocol_layering'], 1):
                report += f"{i}. Line {conflict['upper_line']} vs Line {conflict['lower_line']}\n"
                report += f"   Issue: {conflict['issue']}\n"
                report += f"   Upper: {conflict['upper_rule'].to_string()[:80]}...\n"
                report += f"   Lower: {conflict['lower_rule'].to_string()[:80]}...\n"
                report += f"   Action: {conflict['suggestion']}\n\n"
        
        # Critical issues (displayed second)
        if conflicts['critical']:
            report += f"🚨 CRITICAL ISSUES ({len(conflicts['critical'])})\n"
            report += f"-" * 30 + "\n"
            for i, conflict in enumerate(conflicts['critical'], 1):
                report += f"{i}. Line {conflict['upper_line']} shadows Line {conflict['lower_line']}\n"
                report += f"   Issue: {conflict['issue']}\n"
                report += f"   Upper: {conflict['upper_rule'].to_string()[:80]}...\n"
                report += f"   Lower: {conflict['lower_rule'].to_string()[:80]}...\n"
                report += f"   Action: {conflict['suggestion']}\n\n"
        
        # Warning issues
        if conflicts['warning']:
            report += f"⚠️ WARNING ISSUES ({len(conflicts['warning'])})\n"
            report += f"-" * 30 + "\n"
            for i, conflict in enumerate(conflicts['warning'], 1):
                report += f"{i}. Line {conflict['upper_line']} shadows Line {conflict['lower_line']}\n"
                report += f"   Issue: {conflict['issue']}\n"
                report += f"   Action: {conflict['suggestion']}\n\n"
        
        # Info issues
        if conflicts['info']:
            report += f"ℹ️ INFORMATIONAL ({len(conflicts['info'])})\n"
            report += f"-" * 30 + "\n"
            for i, conflict in enumerate(conflicts['info'], 1):
                report += f"{i}. Line {conflict['upper_line']} shadows Line {conflict['lower_line']}\n"
                report += f"   Issue: {conflict['issue']}\n"
                report += f"   Action: {conflict['suggestion']}\n\n"
        
        # Sticky buffer ordering issues
        if conflicts.get('sticky_buffer_order'):
            report += f"⚠️ STICKY BUFFER ORDERING ISSUES ({len(conflicts['sticky_buffer_order'])})\n"
            report += f"-" * 30 + "\n"
            for i, issue in enumerate(conflicts['sticky_buffer_order'], 1):
                report += f"{i}. Line {issue['line']}\n"
                report += f"   Issue: {issue['issue']}\n"
                report += f"   Rule: {issue['rule'].to_string()[:80]}...\n"
                report += f"   Action: {issue['suggestion']}\n\n"
        
        # UDP flow:established issues
        if conflicts.get('udp_flow_established'):
            report += f"⚠️ UDP FLOW:ESTABLISHED WARNINGS ({len(conflicts['udp_flow_established'])})\n"
            report += f"-" * 30 + "\n"
            for i, issue in enumerate(conflicts['udp_flow_established'], 1):
                report += f"{i}. Line {issue['line']} - {issue['protocol']} {issue['action']} rule\n"
                report += f"   Issue: {issue['issue']}\n"
                report += f"   Rule: {issue['rule'].to_string()[:80]}...\n"
                report += f"   Action: {issue['suggestion']}\n\n"
        
        # Protocol/keyword mismatch issues (can contain both WARNING and INFO severity)
        if conflicts.get('protocol_keyword_mismatch'):
            # Count severities
            warning_count = sum(1 for issue in conflicts['protocol_keyword_mismatch'] if issue['severity'] == 'warning')
            info_count = sum(1 for issue in conflicts['protocol_keyword_mismatch'] if issue['severity'] == 'info')
            
            report += f"⚠️ PROTOCOL/KEYWORD MISMATCH ({len(conflicts['protocol_keyword_mismatch'])})\n"
            if warning_count > 0 and info_count > 0:
                report += f"   ({warning_count} warnings, {info_count} info)\n"
            report += f"-" * 30 + "\n"
            for i, issue in enumerate(conflicts['protocol_keyword_mismatch'], 1):
                severity_icon = "⚠️" if issue['severity'] == 'warning' else "ℹ️"
                report += f"{i}. {severity_icon} Line {issue['line']}\n"
                report += f"   Issue: {issue['issue']}\n"
                report += f"   Rule: {issue['rule'].to_string()[:80]}...\n"
                report += f"   Suggestion: {issue['suggestion']}\n\n"
        
        # Port/protocol mismatch issues
        if conflicts.get('port_protocol_mismatch'):
            report += f"ℹ️ PORT/PROTOCOL MISMATCH (INFO) ({len(conflicts['port_protocol_mismatch'])})\n"
            report += f"-" * 30 + "\n"
            for i, issue in enumerate(conflicts['port_protocol_mismatch'], 1):
                report += f"{i}. Line {issue['line']}\n"
                report += f"   Issue: {issue['issue']}\n"
                report += f"   Rule: {issue['rule'].to_string()[:80]}...\n"
                report += f"   Suggestion: {issue['suggestion']}\n\n"
        
        # Contradictory flow keywords
        if conflicts.get('contradictory_flow'):
            report += f"⚠️ CONTRADICTORY FLOW KEYWORDS ({len(conflicts['contradictory_flow'])})\n"
            report += f"-" * 30 + "\n"
            for i, issue in enumerate(conflicts['contradictory_flow'], 1):
                report += f"{i}. Line {issue['line']}\n"
                report += f"   Issue: {issue['issue']}\n"
                report += f"   Rule: {issue['rule'].to_string()[:80]}...\n"
                report += f"   Suggestion: {issue['suggestion']}\n\n"
        
        # Packet-scope DROP/REJECT vs flow-scope PASS conflicts
        if conflicts.get('packet_drop_flow_pass'):
            report += f"⚠️ PACKET/FLOW ACTION CONFLICTS (Suricata <8.0 behavior) ({len(conflicts['packet_drop_flow_pass'])})\n"
            report += f"-" * 30 + "\n"
            for i, issue in enumerate(conflicts['packet_drop_flow_pass'], 1):
                report += f"{i}. Line {issue['line1']} vs Line {issue['line2']}\n"
                report += f"   Issue: {issue['issue']}\n"
                report += f"   Suggestion: {issue['suggestion']}\n\n"
        
        report += "\nRECOMMENDATIONS:\n"
        report += "- Address protocol layering conflicts first (add flow constraints)\n"
        report += "- Address critical issues next (security bypasses)\n"
        report += "- Fix UDP flow:established warnings to block initial UDP packets\n"
        report += "- Fix sticky buffer ordering to ensure content keywords have proper context\n"
        report += "- Use Move Up/Down buttons to reorder rules\n"
        report += "- Make broader rules more specific when possible\n"
        report += "- Test rule changes in a non-production environment\n"
        
        return report
    
    def generate_html_report(self, conflicts: Dict[str, List[Dict]], 
                           total_rules: int, current_file: str = None, 
                           version: str = None) -> str:
        """Generate HTML formatted analysis report"""
        import datetime
        
        total_conflicts = sum(len(conflicts[severity]) for severity in conflicts)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Always use the analyzer's own version
        analyzer_version = get_analyzer_version()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Suricata Rule Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .title {{ color: #2c3e50; font-size: 24px; font-weight: bold; margin-bottom: 10px; }}
        .meta {{ color: #6c757d; font-size: 14px; }}
        .disclaimer {{ background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }}
        .summary {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .warning {{ color: #fd7e14; font-weight: bold; }}
        .info {{ color: #17a2b8; font-weight: bold; }}
        .success {{ color: #28a745; font-weight: bold; }}
        .conflict {{ margin: 15px 0; padding: 10px; border-left: 3px solid #dee2e6; }}
        .conflict-critical {{ border-left-color: #dc3545; }}
        .conflict-warning {{ border-left-color: #fd7e14; }}
        .conflict-info {{ border-left-color: #17a2b8; }}
        .rule-text {{ font-family: monospace; background-color: #f8f9fa; padding: 5px; border-radius: 3px; font-size: 12px; }}
        .recommendations {{ background-color: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">SURICATA RULE ANALYSIS REPORT</div>
        <div class="meta">
            <strong>Generated:</strong> {timestamp}<br>
            <strong>Rule Analyzer Version:</strong> {analyzer_version}<br>
            <strong>File:</strong> {current_file or 'Unsaved'}
        </div>
    </div>
    
    <div class="disclaimer">
        <strong>DISCLAIMER:</strong><br>
        This analysis is provided for illustrative purposes only and should be used
        as a starting point for rule review. All findings must be validated by a
        qualified security professional familiar with your specific environment
        and requirements. The tool may produce false positives or miss complex
        rule interactions. Always test rule changes in a non-production environment.
    </div>
    
    <div class="summary">
        <strong>Analysis Summary:</strong><br>
        Total Rules Analyzed: {total_rules}<br>
        Total Conflicts Found: {total_conflicts}
    </div>
"""
        
        if total_conflicts == 0:
            html += '<div class="success">✓ No rule conflicts detected. Your rule ordering looks good!</div>'
        else:
            # Protocol layering issues (displayed first)
            if conflicts['protocol_layering']:
                html += f'<h2 style="color: #6f42c1; font-weight: bold;">🔄 PROTOCOL LAYERING CONFLICTS ({len(conflicts["protocol_layering"])})</h2>'
                for i, conflict in enumerate(conflicts['protocol_layering'], 1):
                    html += f'<div class="conflict" style="border-left-color: #6f42c1;">'
                    html += f'<strong>{i}. Line {conflict["upper_line"]} vs Line {conflict["lower_line"]}</strong><br>'
                    html += f'<strong>Issue:</strong> {conflict["issue"]}<br>'
                    html += f'<strong>Action:</strong> {conflict["suggestion"]}<br>'
                    html += f'<div class="rule-text">Upper: {conflict["upper_rule"].to_string()[:100]}...</div>'
                    html += f'<div class="rule-text">Lower: {conflict["lower_rule"].to_string()[:100]}...</div>'
                    html += '</div>'
            
            # Critical issues (displayed second)
            if conflicts['critical']:
                html += f'<h2 class="critical">🚨 CRITICAL ISSUES ({len(conflicts["critical"])})</h2>'
                for i, conflict in enumerate(conflicts['critical'], 1):
                    html += f'<div class="conflict conflict-critical">'
                    html += f'<strong>{i}. Line {conflict["upper_line"]} shadows Line {conflict["lower_line"]}</strong><br>'
                    html += f'<strong>Issue:</strong> {conflict["issue"]}<br>'
                    html += f'<strong>Action:</strong> {conflict["suggestion"]}<br>'
                    html += f'<div class="rule-text">Upper: {conflict["upper_rule"].to_string()[:100]}...</div>'
                    html += f'<div class="rule-text">Lower: {conflict["lower_rule"].to_string()[:100]}...</div>'
                    html += '</div>'
            
            # Warning issues
            if conflicts['warning']:
                html += f'<h2 class="warning">⚠️ WARNING ISSUES ({len(conflicts["warning"])})</h2>'
                for i, conflict in enumerate(conflicts['warning'], 1):
                    html += f'<div class="conflict conflict-warning">'
                    html += f'<strong>{i}. Line {conflict["upper_line"]} shadows Line {conflict["lower_line"]}</strong><br>'
                    html += f'<strong>Issue:</strong> {conflict["issue"]}<br>'
                    html += f'<strong>Action:</strong> {conflict["suggestion"]}'
                    html += '</div>'
            
            # Info issues
            if conflicts['info']:
                html += f'<h2 class="info">ℹ️ INFORMATIONAL ({len(conflicts["info"])})</h2>'
                for i, conflict in enumerate(conflicts['info'], 1):
                    html += f'<div class="conflict conflict-info">'
                    html += f'<strong>{i}. Line {conflict["upper_line"]} shadows Line {conflict["lower_line"]}</strong><br>'
                    html += f'<strong>Issue:</strong> {conflict["issue"]}<br>'
                    html += f'<strong>Action:</strong> {conflict["suggestion"]}'
                    html += '</div>'
            
            # Sticky buffer ordering issues
            if conflicts.get('sticky_buffer_order'):
                html += f'<h2 class="warning">⚠️ STICKY BUFFER ORDERING ISSUES ({len(conflicts["sticky_buffer_order"])})</h2>'
                for i, issue in enumerate(conflicts['sticky_buffer_order'], 1):
                    html += f'<div class="conflict conflict-warning">'
                    html += f'<strong>{i}. Line {issue["line"]}</strong><br>'
                    html += f'<strong>Issue:</strong> {issue["issue"]}<br>'
                    html += f'<strong>Action:</strong> {issue["suggestion"]}<br>'
                    html += f'<div class="rule-text">Rule: {issue["rule"].to_string()[:100]}...</div>'
                    html += '</div>'
            
            # UDP flow:established issues
            if conflicts.get('udp_flow_established'):
                html += f'<h2 class="warning">⚠️ UDP FLOW:ESTABLISHED WARNINGS ({len(conflicts["udp_flow_established"])})</h2>'
                for i, issue in enumerate(conflicts['udp_flow_established'], 1):
                    html += f'<div class="conflict conflict-warning">'
                    html += f'<strong>{i}. Line {issue["line"]} - {issue["protocol"]} {issue["action"]} rule</strong><br>'
                    html += f'<strong>Issue:</strong> {issue["issue"]}<br>'
                    html += f'<strong>Action:</strong> {issue["suggestion"]}<br>'
                    html += f'<div class="rule-text">Rule: {issue["rule"].to_string()[:100]}...</div>'
                    html += '</div>'
            
            # Protocol/keyword mismatch issues (can contain both WARNING and INFO severity)
            if conflicts.get('protocol_keyword_mismatch'):
                warning_count = sum(1 for issue in conflicts['protocol_keyword_mismatch'] if issue['severity'] == 'warning')
                info_count = sum(1 for issue in conflicts['protocol_keyword_mismatch'] if issue['severity'] == 'info')
                
                title = f'⚠️ PROTOCOL/KEYWORD MISMATCH ({len(conflicts["protocol_keyword_mismatch"])})'
                if warning_count > 0 and info_count > 0:
                    title += f' - {warning_count} warnings, {info_count} info'
                
                html += f'<h2 class="warning">{title}</h2>'
                for i, issue in enumerate(conflicts['protocol_keyword_mismatch'], 1):
                    # Use warning or info styling based on individual issue severity
                    conflict_class = 'conflict-warning' if issue['severity'] == 'warning' else 'conflict-info'
                    severity_icon = '⚠️' if issue['severity'] == 'warning' else 'ℹ️'
                    
                    html += f'<div class="conflict {conflict_class}">'
                    html += f'<strong>{i}. {severity_icon} Line {issue["line"]}</strong><br>'
                    html += f'<strong>Issue:</strong> {issue["issue"]}<br>'
                    html += f'<strong>Suggestion:</strong> {issue["suggestion"]}<br>'
                    html += f'<div class="rule-text">Rule: {issue["rule"].to_string()[:100]}...</div>'
                    html += '</div>'
            
            # Port/protocol mismatch issues
            if conflicts.get('port_protocol_mismatch'):
                html += f'<h2 class="info">ℹ️ PORT/PROTOCOL MISMATCH (INFO) ({len(conflicts["port_protocol_mismatch"])})</h2>'
                for i, issue in enumerate(conflicts['port_protocol_mismatch'], 1):
                    html += f'<div class="conflict conflict-info">'
                    html += f'<strong>{i}. Line {issue["line"]}</strong><br>'
                    html += f'<strong>Issue:</strong> {issue["issue"]}<br>'
                    html += f'<strong>Suggestion:</strong> {issue["suggestion"]}<br>'
                    html += f'<div class="rule-text">Rule: {issue["rule"].to_string()[:100]}...</div>'
                    html += '</div>'
            
            # Contradictory flow keywords
            if conflicts.get('contradictory_flow'):
                html += f'<h2 class="warning">⚠️ CONTRADICTORY FLOW KEYWORDS ({len(conflicts["contradictory_flow"])})</h2>'
                for i, issue in enumerate(conflicts['contradictory_flow'], 1):
                    html += f'<div class="conflict conflict-warning">'
                    html += f'<strong>{i}. Line {issue["line"]}</strong><br>'
                    html += f'<strong>Issue:</strong> {issue["issue"]}<br>'
                    html += f'<strong>Suggestion:</strong> {issue["suggestion"]}<br>'
                    html += f'<div class="rule-text">Rule: {issue["rule"].to_string()[:100]}...</div>'
                    html += '</div>'
            
            # Packet-scope DROP/REJECT vs flow-scope PASS conflicts
            if conflicts.get('packet_drop_flow_pass'):
                html += f'<h2 class="warning">⚠️ PACKET/FLOW ACTION CONFLICTS (Suricata &lt;8.0) ({len(conflicts["packet_drop_flow_pass"])})</h2>'
                for i, issue in enumerate(conflicts['packet_drop_flow_pass'], 1):
                    html += f'<div class="conflict conflict-warning">'
                    html += f'<strong>{i}. Line {issue["line1"]} vs Line {issue["line2"]}</strong><br>'
                    html += f'<strong>Issue:</strong> {issue["issue"]}<br>'
                    html += f'<strong>Suggestion:</strong> {issue["suggestion"]}<br>'
                    html += '</div>'
        
        html += '''
    <div class="recommendations">
        <h3>RECOMMENDATIONS:</h3>
        <ul>
            <li>Address protocol layering conflicts first (add flow constraints)</li>
            <li>Address critical issues next (security bypasses)</li>
            <li>Fix UDP flow:established warnings to block initial UDP packets</li>
            <li>Fix sticky buffer ordering to ensure content keywords have proper context</li>
            <li>Use Move Up/Down buttons to reorder rules</li>
            <li>Make broader rules more specific when possible</li>
            <li>Test rule changes in a non-production environment</li>
        </ul>
    </div>
</body>
</html>'''
        
        return html
