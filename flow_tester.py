"""
Flow Tester for Suricata Rule Generator

This module provides flow testing capabilities to evaluate how rules would
process a given network flow. Supports low-level protocols (IP, ICMP, UDP, TCP)
and application layer protocols (HTTP, TLS).

Version: See version.py for current version information
"""

import ipaddress
import re
from typing import List, Dict, Optional, Tuple
from suricata_rule import SuricataRule
from version import get_flow_tester_version


class FlowTester:
    """Tests network flows against Suricata rules to determine matching and final action"""
    
    def __init__(self, rules: List[SuricataRule], variables: Dict[str, str], rule_analyzer):
        """Initialize FlowTester with rules, variables, and rule analyzer
        
        Args:
            rules: List of SuricataRule objects to test against
            variables: Dictionary of network variable definitions
            rule_analyzer: RuleAnalyzer instance for protocol layering logic
        """
        self.rules = rules
        self.variables = variables
        self.rule_analyzer = rule_analyzer
        
    def test_flow(self, src_ip: str, src_port: str, dst_ip: str, dst_port: str,
                  protocol: str, direction: str = "->", url: str = None) -> Dict:
        """Test a network flow against all rules and return results
        
        Args:
            src_ip: Source IP address (e.g., "192.168.1.100")
            src_port: Source port (e.g., "12345" or "any")
            dst_ip: Destination IP address
            dst_port: Destination port (e.g., "80" or "any")
            protocol: Protocol (ip, icmp, udp, tcp, http, tls)
            direction: Flow direction (->, <-, <>)
            url: URL/domain for HTTP/TLS protocols (e.g., "www.example.com/path")
            
        Returns:
            Dictionary with test results including matched rules, final action, and flow diagram
        """
        results = {
            'matched_rules': [],
            'alert_rules': [],
            'final_action': None,
            'final_rule': None,
            'flow_steps': [],
            'protocol': protocol.lower(),
            'step_rule_mapping': {},  # Maps step numbers/phases to matched rules
            'url': url,  # Store URL for HTTP/TLS protocols
            'parsed_url': self._parse_url(url) if url else None  # Parsed URL components
        }
        
        # Filter out comments and blank lines
        actual_rules = [r for r in self.rules if not getattr(r, 'is_comment', False) 
                       and not getattr(r, 'is_blank', False)]
        
        if not actual_rules:
            results['final_action'] = 'NO_RULES'
            return results
        
        # Classify rules by Suricata processing type
        classified_rules = self._classify_rules_by_type(actual_rules)
        
        # Generate flow steps based on protocol
        results['flow_steps'] = self._generate_flow_steps(protocol, src_ip, src_port, 
                                                          dst_ip, dst_port, direction, url)
        
        # For TCP and application layer protocols over TCP, test both handshake and established phases
        # For other protocols, test as a single phase
        if protocol.lower() in ['tcp', 'http', 'tls', 'https']:
            # Phase 1: Test handshake (flow:not_established rules)
            handshake_passed = self._test_flow_phase(classified_rules, src_ip, src_port, dst_ip, dst_port,
                                                     protocol, direction, 'handshake', results, url)
            
            # Phase 2: If handshake passed, test established connection
            if handshake_passed:
                self._test_flow_phase(classified_rules, src_ip, src_port, dst_ip, dst_port,
                                     protocol, direction, 'established', results, url)
        else:
            # Non-TCP protocols: test in single phase
            self._test_flow_phase(classified_rules, src_ip, src_port, dst_ip, dst_port,
                                 protocol, direction, 'all', results, url)
        
        # If no action rule matched, flow is implicitly allowed
        if results['final_action'] is None:
            results['final_action'] = 'ALLOWED (no matching rules)'
        
        return results
    
    def _classify_rules_by_type(self, rules: List[SuricataRule]) -> Dict[str, List[Dict]]:
        """Classify rules by Suricata processing type using RuleAnalyzer logic
        
        Returns:
            Dictionary mapping rule types to lists of {rule, line} dictionaries
        """
        classified = {
            'SIG_TYPE_IPONLY': [],
            'SIG_TYPE_PKT': [],
            'SIG_TYPE_APPLAYER': []
        }
        
        for i, rule in enumerate(rules):
            rule_type = self.rule_analyzer.get_suricata_rule_type(rule)
            line_num = self.rules.index(rule) + 1  # Get actual line number from full rules list
            
            # Use full Suricata nomenclature as per official documentation
            if rule_type == 'SIG_TYPE_IPONLY':
                classified['SIG_TYPE_IPONLY'].append({'rule': rule, 'line': line_num})
            elif rule_type == 'SIG_TYPE_PKT':
                classified['SIG_TYPE_PKT'].append({'rule': rule, 'line': line_num})
            elif rule_type == 'SIG_TYPE_APPLAYER':
                classified['SIG_TYPE_APPLAYER'].append({'rule': rule, 'line': line_num})
        
        return classified
    
    def _parse_url(self, url: str) -> Optional[Dict]:
        """Parse URL into components for application layer matching
        
        Args:
            url: URL string (e.g., "www.example.com/path" or "https://example.com/api")
            
        Returns:
            Dictionary with domain, path, and scheme components
        """
        if not url:
            return None
        
        url = url.strip()
        if not url:
            return None
        
        # Parse URL components
        parsed = {
            'domain': '',
            'path': '/',
            'scheme': 'https'  # Default to https
        }
        
        # Check for scheme
        if '://' in url:
            scheme, rest = url.split('://', 1)
            parsed['scheme'] = scheme.lower()
            url = rest
        
        # Split domain and path
        if '/' in url:
            domain, path = url.split('/', 1)
            parsed['domain'] = domain.lower()
            parsed['path'] = '/' + path
        else:
            parsed['domain'] = url.lower()
            parsed['path'] = '/'
        
        return parsed
    
    def _generate_flow_steps(self, protocol: str, src_ip: str, src_port: str,
                            dst_ip: str, dst_port: str, direction: str, url: str = None) -> List[Dict]:
        """Generate flow communication steps based on protocol
        
        Returns:
            List of flow step dictionaries with description and direction
        """
        steps = []
        protocol = protocol.lower()
        parsed_url = self._parse_url(url) if url else None
        
        if protocol in ['http', 'tls', 'https']:
            # Application layer protocols over TCP
            # Show TCP handshake first
            steps.append({
                'step': 1,
                'description': 'TCP SYN',
                'from': f"{src_ip}:{src_port}",
                'to': f"{dst_ip}:{dst_port}",
                'direction': '->',
                'flags': '[SYN]'
            })
            steps.append({
                'step': 2,
                'description': 'TCP SYN-ACK',
                'from': f"{dst_ip}:{dst_port}",
                'to': f"{src_ip}:{src_port}",
                'direction': '<-',
                'flags': '[SYN,ACK]'
            })
            steps.append({
                'step': 3,
                'description': 'TCP ACK',
                'from': f"{src_ip}:{src_port}",
                'to': f"{dst_ip}:{dst_port}",
                'direction': '->',
                'flags': '[ACK]'
            })
            
            # Add application layer steps
            if protocol in ['tls', 'https']:
                domain = parsed_url['domain'] if parsed_url else 'unknown.com'
                steps.append({
                    'step': 4,
                    'description': f'TLS ClientHello (SNI: {domain})',
                    'from': f"{src_ip}:{src_port}",
                    'to': f"{dst_ip}:{dst_port}",
                    'direction': '->',
                    'flags': '',
                    'app_layer': True
                })
                steps.append({
                    'step': 5,
                    'description': 'TLS ServerHello',
                    'from': f"{dst_ip}:{dst_port}",
                    'to': f"{src_ip}:{src_port}",
                    'direction': '<-',
                    'flags': '',
                    'app_layer': True
                })
                steps.append({
                    'step': 6,
                    'description': 'Encrypted Application Data',
                    'from': f"{src_ip}:{src_port}",
                    'to': f"{dst_ip}:{dst_port}",
                    'direction': direction,
                    'flags': '',
                    'app_layer': True
                })
            elif protocol == 'http':
                path = parsed_url['path'] if parsed_url else '/'
                domain = parsed_url['domain'] if parsed_url else 'unknown.com'
                steps.append({
                    'step': 4,
                    'description': f'HTTP GET {path}',
                    'from': f"{src_ip}:{src_port}",
                    'to': f"{dst_ip}:{dst_port}",
                    'direction': '->',
                    'flags': '',
                    'app_layer': True,
                    'http_host': domain
                })
                steps.append({
                    'step': 5,
                    'description': 'HTTP Response',
                    'from': f"{dst_ip}:{dst_port}",
                    'to': f"{src_ip}:{src_port}",
                    'direction': '<-',
                    'flags': '',
                    'app_layer': True
                })
        elif protocol == 'tcp':
            # TCP three-way handshake
            steps.append({
                'step': 1,
                'description': 'TCP SYN',
                'from': f"{src_ip}:{src_port}",
                'to': f"{dst_ip}:{dst_port}",
                'direction': '->',
                'flags': '[SYN]'
            })
            steps.append({
                'step': 2,
                'description': 'TCP SYN-ACK',
                'from': f"{dst_ip}:{dst_port}",
                'to': f"{src_ip}:{src_port}",
                'direction': '<-',
                'flags': '[SYN,ACK]'
            })
            steps.append({
                'step': 3,
                'description': 'TCP ACK',
                'from': f"{src_ip}:{src_port}",
                'to': f"{dst_ip}:{dst_port}",
                'direction': '->',
                'flags': '[ACK]'
            })
            steps.append({
                'step': 4,
                'description': 'Connection Established',
                'from': f"{src_ip}:{src_port}",
                'to': f"{dst_ip}:{dst_port}",
                'direction': direction,
                'flags': ''
            })
        elif protocol == 'udp':
            # UDP connectionless
            steps.append({
                'step': 1,
                'description': 'UDP Packet',
                'from': f"{src_ip}:{src_port}",
                'to': f"{dst_ip}:{dst_port}",
                'direction': direction,
                'flags': ''
            })
        elif protocol == 'icmp':
            # ICMP packet
            steps.append({
                'step': 1,
                'description': 'ICMP Packet',
                'from': src_ip,
                'to': dst_ip,
                'direction': direction,
                'flags': ''
            })
        elif protocol == 'ip':
            # Generic IP packet
            steps.append({
                'step': 1,
                'description': 'IP Packet',
                'from': src_ip,
                'to': dst_ip,
                'direction': direction,
                'flags': ''
            })
        else:
            # Other protocols
            steps.append({
                'step': 1,
                'description': f'{protocol.upper()} Packet',
                'from': f"{src_ip}:{src_port}" if src_port != 'any' else src_ip,
                'to': f"{dst_ip}:{dst_port}" if dst_port != 'any' else dst_ip,
                'direction': direction,
                'flags': ''
            })
        
        return steps
    
    def _rule_matches_flow(self, rule: SuricataRule, src_ip: str, src_port: str,
                          dst_ip: str, dst_port: str, protocol: str, direction: str,
                          flow_state: str = 'all', url: str = None) -> bool:
        """Check if a rule matches the given flow
        
        Args:
            rule: SuricataRule to test
            src_ip: Source IP address
            src_port: Source port
            dst_ip: Destination IP address
            dst_port: Destination port
            protocol: Protocol
            direction: Flow direction
            flow_state: Which flow state to test ('handshake', 'established', or 'all')
            
        Returns:
            True if rule matches the flow
        """
        content = (rule.content or '').lower()
        
        # Skip rules with geoip keywords (Phase 1 doesn't support geolocation)
        if 'geoip:' in content:
            return False
        
        # Skip rules with flowbits:isnotset dependencies (cannot simulate flowbits state)
        # This is consistent with rule analyzer behavior which skips flowbits-dependent rules
        if 'flowbits:isnotset' in content:
            return False
        
        # Check flow state compatibility
        if not self._flow_state_matches(rule, flow_state):
            return False
        
        # Check protocol compatibility
        if not self._protocol_matches(rule.protocol, protocol):
            return False
        
        # Check ip_proto keyword constraints (e.g., ip_proto:!TCP)
        if not self._check_ip_proto_keyword(rule, protocol):
            return False
        
        # Check direction compatibility
        if not self._direction_matches(rule.direction, direction):
            return False
        
        # Check source network
        if not self._ip_matches_network(src_ip, rule.src_net):
            return False
        
        # Check destination network
        if not self._ip_matches_network(dst_ip, rule.dst_net):
            return False
        
        # Check source port
        if not self._port_matches(src_port, rule.src_port):
            return False
        
        # Check destination port
        if not self._port_matches(dst_port, rule.dst_port):
            return False
        
        # Check app-layer-protocol enforcement (must be done before URL matching)
        if not self._check_app_layer_protocol(rule, protocol):
            return False
        
        # For application layer protocols, check application layer keywords
        if protocol.lower() in ['http', 'tls', 'https'] and url:
            if not self._check_application_layer_match(rule, protocol, url):
                return False
        
        return True
    
    def _test_flow_phase(self, classified_rules: Dict, src_ip: str, src_port: str,
                        dst_ip: str, dst_port: str, protocol: str, direction: str,
                        flow_state: str, results: Dict, url: str = None) -> bool:
        """Test a single phase of the flow against rules using Suricata's action scope model
        
        Suricata rules have different action scopes based on their type:
        - SIG_TYPE_IPONLY: Action Scope = FLOW
        - SIG_TYPE_PKT: Action Scope = PACKET
        - SIG_TYPE_APPLAYER: Action Scope = FLOW
        
        When both packet-scope and flow-scope rules match:
        - Flow-scope actions take precedence over packet-scope actions
        - This is why a flow-level PASS can override a packet-level DROP
        
        Args:
            classified_rules: Classified rules by type
            src_ip, src_port, dst_ip, dst_port: Flow parameters
            protocol, direction: Protocol and direction
            flow_state: 'handshake', 'established', or 'all'
            results: Results dictionary to update
            url: Optional URL for application layer matching
            
        Returns:
            True if flow passed (was allowed), False if blocked
        """
        # Define action scopes for each rule type per Suricata documentation
        action_scopes = {
            'SIG_TYPE_IPONLY': 'FLOW',      # SIG_PROP_FLOW_ACTION_FLOW
            'SIG_TYPE_PKT': 'PACKET',       # SIG_PROP_FLOW_ACTION_PACKET
            'SIG_TYPE_APPLAYER': 'FLOW'     # SIG_PROP_FLOW_ACTION_FLOW
        }
        
        # Track actions at different scopes
        packet_scope_action = None
        packet_scope_rule = None
        flow_scope_action = None
        flow_scope_rule = None
        
        # Collect all rules in LINE ORDER (not type order)
        all_rules = []
        for rule_type in ['SIG_TYPE_IPONLY', 'SIG_TYPE_PKT', 'SIG_TYPE_APPLAYER']:
            for rule_info in classified_rules.get(rule_type, []):
                all_rules.append({
                    'rule': rule_info['rule'],
                    'line': rule_info['line'],
                    'type': rule_type,
                    'scope': action_scopes[rule_type]
                })
        
        # Sort by line number to process in file order
        all_rules.sort(key=lambda x: x['line'])
        
        # Process rules in line order, tracking actions at each scope
        for rule_info in all_rules:
            rule = rule_info['rule']
            rule_type = rule_info['type']
            scope = rule_info['scope']
            
            # Test if this rule matches the flow in this state
            if self._rule_matches_flow(rule, src_ip, src_port, dst_ip, dst_port,
                                      protocol, direction, flow_state, url):
                match_info = {
                    'rule': rule,
                    'line': rule_info['line'],
                    'type': rule_type,
                    'action': rule.action,
                    'phase': flow_state,
                    'scope': scope  # Track action scope
                }
                
                # Separate alert rules from action rules
                if rule.action.lower() == 'alert':
                    # Always include alert rules
                    results['alert_rules'].append(match_info)
                    
                    # Track for step mapping
                    if flow_state not in results['step_rule_mapping']:
                        results['step_rule_mapping'][flow_state] = []
                    results['step_rule_mapping'][flow_state].append(match_info)
                else:
                    # Action rules (pass/drop/reject)
                    if rule.action.lower() in ['pass', 'drop', 'reject']:
                        if scope == 'PACKET':
                            # Packet-scope action: only set if not already set
                            # (first match wins within packet scope)
                            if packet_scope_action is None:
                                packet_scope_action = rule.action.lower()
                                packet_scope_rule = match_info
                        else:  # scope == 'FLOW'
                            # Flow-scope action: only set if not already set
                            # (first match wins within flow scope)
                            if flow_scope_action is None:
                                flow_scope_action = rule.action.lower()
                                flow_scope_rule = match_info
        
        # Determine final action using Suricata 8.0+ deconfliction logic
        # Per bug fix: https://redmine.openinfosecfoundation.org/issues/7653
        # If packet-scope DROP/REJECT matches, flow-scope PASS is skipped
        if packet_scope_action in ['drop', 'reject'] and flow_scope_action == 'pass':
            # Packet-scope DROP/REJECT blocks flow-scope PASS (Suricata 8.0+ behavior)
            final_action = packet_scope_action
            final_rule = packet_scope_rule
        elif flow_scope_action is not None:
            # Flow-level action wins (normal case)
            final_action = flow_scope_action
            final_rule = flow_scope_rule
        elif packet_scope_action is not None:
            # Packet-level action (no flow-level action matched)
            final_action = packet_scope_action
            final_rule = packet_scope_rule
        else:
            # No action rules matched this phase, continue to next phase
            return True
        
        # Store the final matching rule
        results['matched_rules'].append(final_rule)
        
        # Track step-to-rule mapping
        if flow_state not in results['step_rule_mapping']:
            results['step_rule_mapping'][flow_state] = []
        results['step_rule_mapping'][flow_state].append(final_rule)
        
        # Update final action
        results['final_action'] = final_action.upper()
        results['final_rule'] = final_rule
        
        # Return whether this phase passed (allows next phase)
        return final_action == 'pass'
    
    def _flow_state_matches(self, rule: SuricataRule, flow_state: str) -> bool:
        """Check if rule's flow state requirements match the tested flow state
        
        Args:
            rule: Rule to check
            flow_state: 'handshake', 'established', or 'all'
            
        Returns:
            True if rule applies to this flow state
        """
        content = (rule.content or '').lower()
        
        # If no flow keywords, rule matches established connections only (not handshake)
        # In real Suricata, rules without flow keywords match regular packets (established connections)
        if 'flow:' not in content:
            return flow_state == 'established' or flow_state == 'all'
        
        # Rules with flow:not_established only match handshake (TCP only)
        if 'not_established' in content:
            return flow_state == 'handshake'
        
        # Rules with flow:established or flow:to_server/to_client only match established TCP connections
        # These should NOT match connectionless protocols (ICMP, UDP, IP) even when flow_state='all'
        if 'established' in content or 'to_server' in content or 'to_client' in content:
            # Only match if we're specifically in the 'established' phase (not 'all')
            return flow_state == 'established'
        
        # Other flow keywords match all states
        return True
    
    def _protocol_matches(self, rule_protocol: str, flow_protocol: str) -> bool:
        """Check if rule protocol matches flow protocol"""
        rule_proto = rule_protocol.lower()
        flow_proto = flow_protocol.lower()
        
        if rule_proto == flow_proto:
            return True
        
        # 'ip' matches all protocols
        if rule_proto == 'ip':
            return True
        
        # TCP matches application protocols over TCP
        if rule_proto == 'tcp' and flow_proto in ['http', 'tls', 'https', 'smtp', 'ftp', 'ssh']:
            return True
        
        return False
    
    def _direction_matches(self, rule_direction: str, flow_direction: str) -> bool:
        """Check if rule direction matches flow direction"""
        if rule_direction == '<>':  # Bidirectional
            return True
        
        if rule_direction == flow_direction:
            return True
        
        return False
    
    def _ip_matches_network(self, ip: str, network_spec: str) -> bool:
        """Check if IP address matches network specification
        
        Supports:
        - 'any'
        - Single IP: 192.168.1.100
        - CIDR: 192.168.1.0/24
        - Variables: $HOME_NET, @REFERENCE
        - Negation: !192.168.1.5
        - Groups: [10.0.0.0/24, !10.0.0.5]
        - Comma-separated lists: 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
        """
        network_spec = network_spec.strip()
        
        # Handle 'any'
        if network_spec.lower() == 'any':
            return True
        
        # Handle variables - resolve them
        if network_spec.startswith(('$', '@')):
            resolved = self.variables.get(network_spec, '')
            if not resolved:
                # Variable not defined - check if it's $EXTERNAL_NET (inverse of $HOME_NET)
                if network_spec == '$EXTERNAL_NET':
                    # Try to use inverse of $HOME_NET if it exists
                    home_net = self.variables.get('$HOME_NET', '')
                    if home_net:
                        # Check if IP is NOT in HOME_NET (then it's in EXTERNAL_NET)
                        return not self._ip_matches_network(ip, home_net)
                    else:
                        # No HOME_NET defined, EXTERNAL_NET matches all
                        return True
                # For other undefined variables, be conservative and match all
                return True
            # Recursively resolve the variable value
            return self._ip_matches_network(ip, resolved)
        
        # Handle negation
        if network_spec.startswith('!'):
            negated_spec = network_spec[1:].strip()
            # Check if IP is in the negated network (recursive call)
            if self._ip_matches_network(ip, negated_spec):
                return False  # IP is explicitly excluded
            return True  # IP is not in excluded network, so it matches
        
        # Handle groups [item1, item2, ...]
        if network_spec.startswith('[') and network_spec.endswith(']'):
            return self._ip_matches_group(ip, network_spec[1:-1])
        
        # Handle comma-separated CIDR lists (common in variable definitions)
        if ',' in network_spec and not network_spec.startswith('['):
            # Split and check if IP matches any of the networks
            networks = [net.strip() for net in network_spec.split(',')]
            for network in networks:
                if network and self._ip_matches_network(ip, network):
                    return True
            return False
        
        # Simple CIDR or IP check
        return self._ip_in_network(ip, network_spec)
    
    def _ip_matches_group(self, ip: str, group_content: str) -> bool:
        """Check if IP matches any item in a network group"""
        items = [item.strip() for item in group_content.split(',')]
        
        included = False
        
        for item in items:
            if not item:
                continue
            
            if item.startswith('!'):
                # Exclusion - if IP matches this, it's excluded
                excluded_item = item[1:].strip()
                # Use _ip_matches_network to handle variables recursively
                if self._ip_matches_network(ip, excluded_item):
                    return False  # Explicitly excluded
            else:
                # Inclusion - if IP matches this, it's included
                # Use _ip_matches_network to handle variables recursively
                if self._ip_matches_network(ip, item):
                    included = True
        
        return included
    
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP address is in network (CIDR or single IP)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Try as network first
            try:
                network_obj = ipaddress.ip_network(network, strict=False)
                return ip_obj in network_obj
            except ValueError:
                # Try as single IP
                network_ip = ipaddress.ip_address(network)
                return ip_obj == network_ip
        except ValueError:
            # Invalid IP format, be conservative
            return False
    
    def _port_matches(self, flow_port: str, rule_port: str) -> bool:
        """Check if flow port matches rule port specification
        
        Supports:
        - 'any'
        - Single port: 80
        - Variables: $WEB_PORTS
        - Ranges: [8080:8090]
        - Lists: [80,443,8080]
        - Negation: [!22]
        """
        rule_port = rule_port.strip()
        
        # Handle 'any'
        if rule_port.lower() == 'any':
            return True
        
        # Handle variables - resolve them
        if rule_port.startswith(('$', '@')):
            resolved = self.variables.get(rule_port, '')
            if not resolved:
                # Variable not defined, be conservative and match
                return True
            rule_port = resolved
        
        # Remove brackets if present
        if rule_port.startswith('[') and rule_port.endswith(']'):
            rule_port = rule_port[1:-1]
        
        # Parse flow port
        try:
            flow_port_num = int(flow_port) if flow_port.lower() != 'any' else None
        except ValueError:
            return False
        
        # If flow port is 'any', it matches any rule port
        if flow_port_num is None:
            return True
        
        # Split by comma for port lists
        port_specs = [spec.strip() for spec in rule_port.split(',')]
        
        included = False
        
        for spec in port_specs:
            if not spec:
                continue
            
            if spec.startswith('!'):
                # Exclusion
                excluded_spec = spec[1:].strip()
                if self._port_in_spec(flow_port_num, excluded_spec):
                    return False  # Explicitly excluded
            else:
                # Inclusion
                if self._port_in_spec(flow_port_num, spec):
                    included = True
        
        # If no inclusions specified, assume all ports included except exclusions
        if not any(not spec.startswith('!') for spec in port_specs if spec):
            return True
        
        return included
    
    def _port_in_spec(self, port_num: int, spec: str) -> bool:
        """Check if port number matches a port specification"""
        spec = spec.strip()
        
        # Handle 'any'
        if spec.lower() == 'any':
            return True
        
        # Handle range (e.g., "8080:8090")
        if ':' in spec:
            try:
                start, end = spec.split(':', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                return start_port <= port_num <= end_port
            except ValueError:
                return False
        
        # Handle single port
        try:
            spec_port = int(spec)
            return port_num == spec_port
        except ValueError:
            return False
    
    def _check_application_layer_match(self, rule: SuricataRule, protocol: str, url: str) -> bool:
        """Check if rule's application layer keywords match the URL
        
        Args:
            rule: Rule to check
            protocol: Protocol (http, tls, https)
            url: URL string to test against
            
        Returns:
            True if rule matches or has no app layer keywords, False otherwise
        """
        content = (rule.content or '').lower()
        parsed_url = self._parse_url(url)
        
        if not parsed_url:
            # No URL to match against, only match if rule has no app layer keywords requiring domain
            return not self._has_application_layer_keywords(content, protocol)
        
        protocol = protocol.lower()
        
        # Check TLS keywords
        if protocol in ['tls', 'https']:
            # Special case: Rules designed to detect "No SNI" (direct-to-IP) connections
            # These typically use ja4.hash with patterns like content:"_"; startswith;
            # If we have a domain/SNI, these rules should NOT match
            if 'ja4.hash' in content or 'ja3.hash' in content:
                # Check if this appears to be a "no SNI" detection rule
                if self._is_no_sni_detection_rule(content):
                    # We have SNI (domain provided), so this rule doesn't match
                    return False
            
            # Check tls.sni keyword for domain matching
            if 'tls.sni' in content:
                sni_match = self._extract_keyword_value(content, 'tls.sni')
                if sni_match and not self._matches_pattern(parsed_url['domain'], sni_match):
                    return False
        
        # Check HTTP keywords
        if protocol == 'http':
            # Check http.host keyword
            if 'http.host' in content:
                host_match = self._extract_keyword_value(content, 'http.host')
                if host_match and not self._matches_pattern(parsed_url['domain'], host_match):
                    return False
            
            # Check http.uri keyword
            if 'http.uri' in content:
                uri_match = self._extract_keyword_value(content, 'http.uri')
                if uri_match and not self._matches_pattern(parsed_url['path'], uri_match):
                    return False
            
            # Check http.method keyword (default to GET if not specified)
            if 'http.method' in content:
                method_match = self._extract_keyword_value(content, 'http.method')
                if method_match and method_match.lower() != 'get':
                    # We're simulating a GET request, so only match GET methods
                    return False
        
        return True
    
    def _check_ip_proto_keyword(self, rule: SuricataRule, protocol: str) -> bool:
        """Check if rule's ip_proto keyword matches the tested protocol
        
        The ip_proto keyword filters by IP protocol number (e.g., TCP=6, UDP=17, ICMP=1).
        This is commonly used with negation to exclude certain protocols.
        
        Args:
            rule: Rule to check
            protocol: Protocol being tested (tcp, udp, icmp, tls, http, etc.)
            
        Returns:
            True if rule matches or has no ip_proto keyword
        """
        content = (rule.content or '').lower()
        
        # If no ip_proto keyword, rule matches
        if 'ip_proto:' not in content:
            return True
        
        # Map protocol names to their underlying IP protocol
        protocol = protocol.lower()
        ip_proto_map = {
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp',
            'http': 'tcp',   # HTTP runs over TCP
            'tls': 'tcp',    # TLS runs over TCP
            'https': 'tcp',  # HTTPS runs over TCP
            'ssh': 'tcp',    # SSH runs over TCP
            'ftp': 'tcp',    # FTP runs over TCP
            'smtp': 'tcp',   # SMTP runs over TCP
            'dns': 'udp',    # DNS typically runs over UDP (can also be TCP)
            'quic': 'udp',   # QUIC runs over UDP
        }
        
        flow_ip_proto = ip_proto_map.get(protocol, protocol)
        
        # Extract all ip_proto keywords (there can be multiple)
        # Pattern: ip_proto:!TCP or ip_proto:TCP or ip_proto:6
        ip_proto_matches = re.findall(r'ip_proto:\s*(!?)(\w+)', content)
        
        if not ip_proto_matches:
            return True  # Can't parse, be conservative
        
        # Check each ip_proto constraint
        for match in ip_proto_matches:
            is_negated = match[0] == '!'
            expected_proto = match[1].lower()
            
            # Normalize protocol numbers to names
            proto_number_map = {
                '1': 'icmp',
                '6': 'tcp',
                '17': 'udp',
            }
            expected_proto = proto_number_map.get(expected_proto, expected_proto)
            
            # Check if flow's IP protocol matches the expected protocol
            protocol_match = (flow_ip_proto == expected_proto)
            
            # Handle negation
            if is_negated:
                # ip_proto:!TCP means "NOT TCP"
                # If we're testing TCP (or TLS/HTTP which runs over TCP), protocol_match=True
                # So return not True = False (rule doesn't match TCP traffic)
                if protocol_match:
                    return False  # Flow IS the negated protocol, so rule doesn't match
            else:
                # ip_proto:TCP means "MUST be TCP"
                # If we're not testing TCP, return False
                if not protocol_match:
                    return False  # Flow is NOT the required protocol, so rule doesn't match
        
        return True  # All ip_proto constraints passed
    
    def _check_app_layer_protocol(self, rule: SuricataRule, protocol: str) -> bool:
        """Check if rule's app-layer-protocol keyword matches the tested protocol
        
        Args:
            rule: Rule to check
            protocol: Protocol being tested
            
        Returns:
            True if rule matches or has no app-layer-protocol keyword
        """
        content = (rule.content or '').lower()
        
        # If no app-layer-protocol keyword, rule matches
        if 'app-layer-protocol:' not in content:
            return True
        
        protocol = protocol.lower()
        
        # Extract app-layer-protocol value
        # Pattern: app-layer-protocol:tls or app-layer-protocol:!tls
        match = re.search(r'app-layer-protocol:\s*(!?)(\w+)', content)
        if not match:
            return True  # Can't parse, be conservative
        
        is_negated = match.group(1) == '!'
        expected_proto = match.group(2).lower()
        
        # Check if our protocol matches the expected protocol
        protocol_match = (protocol == expected_proto)
        
        # Handle negation
        if is_negated:
            # app-layer-protocol:!tls means "reject if NOT TLS"
            # If we're testing TLS, protocol_match=True, so return not True = False (rule doesn't match)
            # If we're testing HTTP, protocol_match=False, so return not False = True (rule matches)
            return not protocol_match
        else:
            # app-layer-protocol:tls means "MUST be TLS" 
            # If we're testing TLS, protocol_match=True, return True (rule matches)
            # If we're testing HTTP, protocol_match=False, return False (rule doesn't match)
            return protocol_match
    
    def _is_no_sni_detection_rule(self, content: str) -> bool:
        """Check if rule is designed to detect TLS connections without SNI
        
        Args:
            content: Rule content string (lowercased)
            
        Returns:
            True if this appears to be a "no SNI" detection rule
        """
        # Common patterns for detecting no-SNI/direct-to-IP TLS:
        # - ja4.hash with content:"_"; startswith; (JA4 hash starts with _ when no SNI)
        # - Message contains "No SNI" or "Direct to IP"
        
        # IMPORTANT: We must check for startswith modifier, not just content:"_"
        # Default block rules may use content:"_" for logging but without startswith,
        # they match ALL TLS traffic (underscore appears somewhere in most JA4 hashes)
        
        if 'ja4.hash' in content and 'content:"_"' in content:
            # Only consider it a no-SNI rule if it has startswith modifier
            # This specifically detects when JA4 hash STARTS with underscore (no SNI indicator)
            if 'startswith' in content:
                return True
        
        # Check message for explicit clues about no-SNI detection
        if 'msg:' in content:
            msg_match = re.search(r'msg:\s*"([^"]+)"', content)
            if msg_match:
                msg = msg_match.group(1).lower()
                # Look for explicit "no sni" or "direct to ip" in message
                # But NOT "default" as that indicates a default block rule
                if 'no sni' in msg or (('direct' in msg or 'direct-to') in msg and 'ip' in msg):
                    return True
        
        return False
    
    def _has_application_layer_keywords(self, content: str, protocol: str) -> bool:
        """Check if content has application layer keywords that require URL matching
        
        Args:
            content: Rule content string (lowercased)
            protocol: Protocol name
            
        Returns:
            True if content has app layer keywords that need URL validation
        """
        protocol = protocol.lower()
        
        if protocol in ['tls', 'https']:
            # Only keywords that require domain matching
            tls_keywords = ['tls.sni', 'tls.subject', 'tls.issuer']
            return any(kw in content for kw in tls_keywords)
        
        if protocol == 'http':
            http_keywords = ['http.host', 'http.uri', 'http.method', 'http.user_agent',
                            'http.header', 'http.cookie']
            return any(kw in content for kw in http_keywords)
        
        return False
    
    def _extract_keyword_value(self, content: str, keyword: str) -> Optional[Dict]:
        """Extract the value and modifiers for a specific keyword from rule content
        
        Args:
            content: Rule content string (lowercased)
            keyword: Keyword to extract (e.g., 'tls.sni', 'http.host')
            
        Returns:
            Dictionary with 'value' and 'modifiers' (startswith, endswith, etc.) or None
        """
        # Look for pattern like: tls.sni; content:"example.com"; startswith; endswith;
        
        # Find the keyword
        idx = content.find(keyword)
        if idx == -1:
            return None
        
        # Look for content:" after the keyword
        rest = content[idx:]
        content_match = re.search(r'content:\s*"([^"]+)"', rest)
        if not content_match:
            # Try pcre pattern
            pcre_match = re.search(r'pcre:\s*"([^"]+)"', rest)
            if pcre_match:
                pattern = pcre_match.group(1)
                pattern = pattern.replace('.*', '').replace('.+', '').replace('^', '').replace('$', '')
                return {'value': pattern, 'modifiers': []} if pattern else None
            return None
        
        value = content_match.group(1)
        
        # Extract modifiers that appear after the content match
        # Look for the section after content:"value" up to the next semicolon or end
        after_content = rest[content_match.end():]
        
        # Find modifiers (startswith, endswith, dotprefix, etc.)
        modifiers = []
        if 'startswith' in after_content:
            modifiers.append('startswith')
        if 'endswith' in after_content:
            modifiers.append('endswith')
        if 'dotprefix' in after_content:
            modifiers.append('dotprefix')
        
        return {'value': value, 'modifiers': modifiers}
    
    def _matches_pattern(self, value: str, pattern_info) -> bool:
        """Check if a value matches a pattern with modifiers
        
        Args:
            value: The value to test (e.g., domain, path)
            pattern_info: Dictionary with 'value' and 'modifiers', or string pattern
            
        Returns:
            True if value matches the pattern
        """
        # Handle legacy string pattern
        if isinstance(pattern_info, str):
            pattern = pattern_info
            modifiers = []
        elif isinstance(pattern_info, dict):
            pattern = pattern_info.get('value', '')
            modifiers = pattern_info.get('modifiers', [])
        else:
            return True
        
        if not pattern:
            return True
        
        value = value.lower()
        pattern = pattern.lower()
        
        # Handle modifiers
        if 'startswith' in modifiers and 'endswith' in modifiers:
            # Both startswith and endswith = exact match
            return value == pattern
        elif 'startswith' in modifiers:
            # Must start with pattern
            return value.startswith(pattern)
        elif 'endswith' in modifiers:
            # Must end with pattern
            return value.endswith(pattern)
        elif 'dotprefix' in modifiers:
            # dotprefix means pattern must match as subdomain (e.g., amazon.com matches *.amazon.com)
            # Check if value ends with pattern and has a dot before it
            if value.endswith(pattern):
                # Check if it's an exact match or has a dot prefix
                if value == pattern:
                    return True
                # Check if there's a dot before the pattern
                prefix_len = len(value) - len(pattern)
                if prefix_len > 0 and value[prefix_len - 1] == '.':
                    return True
            return False
        else:
            # No modifiers - check for exact match, then contains, then wildcard
            # Exact match
            if value == pattern:
                return True
            
            # Contains match (if no wildcards)
            if '*' not in pattern and '?' not in pattern:
                return pattern in value
            
            # Wildcard matching
            regex_pattern = pattern.replace('.', r'\.').replace('*', '.*').replace('?', '.')
            try:
                return bool(re.search(regex_pattern, value))
            except re.error:
                return pattern.replace('*', '').replace('?', '') in value
