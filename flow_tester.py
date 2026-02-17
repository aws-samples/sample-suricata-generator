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
            'unknown_rules': [],  # Rules that couldn't be evaluated (category-based, geoip, etc.)
            'final_action': None,
            'final_rule': None,
            'flow_steps': [],
            'protocol': protocol.lower(),
            'step_rule_mapping': {},  # Maps step numbers/phases to matched rules
            'url': url,  # Store URL for HTTP/TLS protocols
            'parsed_url': self._parse_url(url) if url else None,  # Parsed URL components
            'scope_details': {},  # Per-phase scope verdicts for multi-scope display
            'scope_conflict': False,  # True when FLOW=PASS but PACKET=REJECT/DROP
            'partial_allow': False,  # True when handshake passes but established fails
            'flowbits_inferences': [],  # Inferred flowbits state explanations
        }
        
        # Filter out comments and blank lines
        actual_rules = [r for r in self.rules if not getattr(r, 'is_comment', False) 
                       and not getattr(r, 'is_blank', False)]
        
        if not actual_rules:
            results['final_action'] = 'NO_RULES'
            return results
        
        # Build flowbits mapping for inference
        self._flowbits_map = self._build_flowbits_map(actual_rules)
        
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
                established_passed = self._test_flow_phase(classified_rules, src_ip, src_port, dst_ip, dst_port,
                                     protocol, direction, 'established', results, url)
                
                # Check for partial allow: handshake succeeded but established failed
                if not established_passed and results['final_action'] in ['DROP', 'REJECT']:
                    results['partial_allow'] = True
        else:
            # Non-TCP protocols: test in single phase
            self._test_flow_phase(classified_rules, src_ip, src_port, dst_ip, dst_port,
                                 protocol, direction, 'all', results, url)
        
        # If no action rule matched, flow is implicitly allowed
        if results['final_action'] is None:
            results['final_action'] = 'ALLOWED (no matching rules)'
        
        return results
    
    def _build_flowbits_map(self, rules: List[SuricataRule]) -> Dict[str, List]:
        """Build a mapping of flowbit names to rules that set them
        
        This is used for flowbits inference - when we encounter flowbits:isnotset,<bitname>,
        we can check if any rule that does flowbits:set,<bitname> would match this flow.
        
        Args:
            rules: List of active (non-comment, non-blank) SuricataRule objects
            
        Returns:
            Dictionary mapping flowbit names to lists of rules that set them
        """
        flowbits_set_map = {}
        
        for rule in rules:
            content = (rule.content or '').lower()
            
            # Find all flowbits:set,<bitname> patterns
            set_matches = re.findall(r'flowbits:\s*set\s*,\s*(\w+)', content)
            
            for bitname in set_matches:
                if bitname not in flowbits_set_map:
                    flowbits_set_map[bitname] = []
                flowbits_set_map[bitname].append(rule)
        
        return flowbits_set_map
    
    def _infer_flowbits_isnotset(self, rule: SuricataRule, src_ip: str, src_port: str,
                                  dst_ip: str, dst_port: str, protocol: str,
                                  direction: str, flow_state: str, url: str = None) -> Tuple[bool, List[str]]:
        """Infer whether flowbits:isnotset conditions would be true for this flow
        
        Scans the ruleset for rules that do flowbits:set,<bitname> and checks if any
        of them would match this flow. If none match, the bit is NOT set, so isnotset = TRUE.
        
        Args:
            rule: The rule containing flowbits:isnotset to evaluate
            src_ip, src_port, dst_ip, dst_port: Flow parameters
            protocol: Flow protocol
            direction: Flow direction
            flow_state: Current flow state
            url: Optional URL for app layer matching
            
        Returns:
            Tuple of (all_isnotset_true: bool, explanations: List[str])
            - all_isnotset_true: True if ALL isnotset conditions are inferred TRUE
            - explanations: Human-readable explanations of each inference
        """
        content = (rule.content or '').lower()
        
        # Extract all flowbits:isnotset,<bitname> from this rule
        isnotset_matches = re.findall(r'flowbits:\s*isnotset\s*,\s*(\w+)', content)
        
        if not isnotset_matches:
            return (True, [])
        
        explanations = []
        all_true = True
        
        for bitname in isnotset_matches:
            # Find rules that set this bit
            setter_rules = self._flowbits_map.get(bitname, [])
            
            if not setter_rules:
                # No rule sets this bit at all - it's always NOT set
                explanations.append(
                    f"flowbits:isnotset,{bitname} = TRUE (no rule in ruleset sets '{bitname}')"
                )
                continue
            
            # Check if any setter rule would match this flow
            bit_would_be_set = False
            setter_rule_that_matches = None
            
            for setter_rule in setter_rules:
                # Test if the setter rule would match this flow
                # We need to check protocol, IP, port, and direction compatibility
                # But we skip the flowbits check on the setter rule itself (to avoid recursion)
                if self._setter_rule_matches_flow(setter_rule, src_ip, src_port, dst_ip, dst_port,
                                                   protocol, direction, flow_state, url):
                    bit_would_be_set = True
                    setter_rule_that_matches = setter_rule
                    break
            
            if bit_would_be_set:
                # A setter rule matches - the bit WOULD be set - so isnotset = FALSE
                setter_sid = getattr(setter_rule_that_matches, 'sid', '?')
                setter_proto = getattr(setter_rule_that_matches, 'protocol', '?')
                explanations.append(
                    f"flowbits:isnotset,{bitname} = FALSE (SID {setter_sid} [{setter_proto}] would set '{bitname}')"
                )
                all_true = False
            else:
                # No setter rule matches - the bit is NOT set - so isnotset = TRUE
                setter_protocols = set()
                for sr in setter_rules:
                    setter_protocols.add(getattr(sr, 'protocol', '?').lower())
                proto_str = '/'.join(sorted(setter_protocols))
                explanations.append(
                    f"flowbits:isnotset,{bitname} = TRUE (no {proto_str} rule that sets '{bitname}' matches this {protocol} flow)"
                )
        
        return (all_true, explanations)
    
    def _setter_rule_matches_flow(self, setter_rule: SuricataRule, src_ip: str, src_port: str,
                                   dst_ip: str, dst_port: str, protocol: str,
                                   direction: str, flow_state: str, url: str = None) -> bool:
        """Check if a flowbits:set rule would match the current flow
        
        This is a simplified matching check focused on protocol, IP, port, and direction.
        We don't check flowbits on the setter rule to avoid circular dependencies.
        
        Args:
            setter_rule: Rule that does flowbits:set,<bitname>
            src_ip, src_port, dst_ip, dst_port: Flow parameters
            protocol: Flow protocol
            direction: Flow direction
            flow_state: Current flow state
            url: Optional URL
            
        Returns:
            True if the setter rule would match this flow
        """
        # Check protocol compatibility
        if not self._protocol_matches(setter_rule.protocol, protocol):
            return False
        
        # Check flow state compatibility
        if not self._flow_state_matches(setter_rule, flow_state):
            return False
        
        # Check ip_proto keyword constraints
        if not self._check_ip_proto_keyword(setter_rule, protocol):
            return False
        
        # Check direction compatibility
        if not self._direction_matches(setter_rule.direction, direction):
            return False
        
        # Check source/destination networks
        # For to_client rules, check with reversed src/dst
        content_lower = (setter_rule.content or '').lower()
        if 'to_client' in content_lower and 'to_server' not in content_lower:
            if not self._ip_matches_network(dst_ip, setter_rule.src_net):
                return False
            if not self._ip_matches_network(src_ip, setter_rule.dst_net):
                return False
            if not self._port_matches(dst_port, setter_rule.src_port):
                return False
            if not self._port_matches(src_port, setter_rule.dst_port):
                return False
        else:
            if not self._ip_matches_network(src_ip, setter_rule.src_net):
                return False
            if not self._ip_matches_network(dst_ip, setter_rule.dst_net):
                return False
            if not self._port_matches(src_port, setter_rule.src_port):
                return False
            if not self._port_matches(dst_port, setter_rule.dst_port):
                return False
        
        # Check app-layer-protocol keyword
        if not self._check_app_layer_protocol(setter_rule, protocol):
            return False
        
        # For application layer protocols, check app layer keywords
        if protocol.lower() in ['http', 'tls', 'https'] and url:
            if not self._check_application_layer_match(setter_rule, protocol, url):
                return False
        
        return True
    
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
            
            if rule_type == 'SIG_TYPE_IPONLY':
                classified['SIG_TYPE_IPONLY'].append({'rule': rule, 'line': line_num})
            elif rule_type == 'SIG_TYPE_PKT':
                classified['SIG_TYPE_PKT'].append({'rule': rule, 'line': line_num})
            elif rule_type == 'SIG_TYPE_APPLAYER':
                classified['SIG_TYPE_APPLAYER'].append({'rule': rule, 'line': line_num})
        
        return classified
    
    def _parse_url(self, url: str) -> Optional[Dict]:
        """Parse URL into components for application layer matching"""
        if not url:
            return None
        
        url = url.strip()
        if not url:
            return None
        
        parsed = {
            'domain': '',
            'path': '/',
            'scheme': 'https'
        }
        
        if '://' in url:
            scheme, rest = url.split('://', 1)
            parsed['scheme'] = scheme.lower()
            url = rest
        
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
        """Generate flow communication steps based on protocol"""
        steps = []
        protocol = protocol.lower()
        parsed_url = self._parse_url(url) if url else None
        
        if protocol in ['http', 'tls', 'https']:
            steps.append({'step': 1, 'description': 'TCP SYN', 'from': f"{src_ip}:{src_port}",
                         'to': f"{dst_ip}:{dst_port}", 'direction': '->', 'flags': '[SYN]'})
            steps.append({'step': 2, 'description': 'TCP SYN-ACK', 'from': f"{dst_ip}:{dst_port}",
                         'to': f"{src_ip}:{src_port}", 'direction': '<-', 'flags': '[SYN,ACK]'})
            steps.append({'step': 3, 'description': 'TCP ACK', 'from': f"{src_ip}:{src_port}",
                         'to': f"{dst_ip}:{dst_port}", 'direction': '->', 'flags': '[ACK]'})
            
            if protocol in ['tls', 'https']:
                domain = parsed_url['domain'] if parsed_url else 'unknown.com'
                steps.append({'step': 4, 'description': f'TLS ClientHello (SNI: {domain})',
                             'from': f"{src_ip}:{src_port}", 'to': f"{dst_ip}:{dst_port}",
                             'direction': '->', 'flags': '', 'app_layer': True})
                steps.append({'step': 5, 'description': 'TLS ServerHello',
                             'from': f"{dst_ip}:{dst_port}", 'to': f"{src_ip}:{src_port}",
                             'direction': '<-', 'flags': '', 'app_layer': True})
                steps.append({'step': 6, 'description': 'Encrypted Application Data',
                             'from': f"{src_ip}:{src_port}", 'to': f"{dst_ip}:{dst_port}",
                             'direction': direction, 'flags': '', 'app_layer': True})
            elif protocol == 'http':
                path = parsed_url['path'] if parsed_url else '/'
                domain = parsed_url['domain'] if parsed_url else 'unknown.com'
                steps.append({'step': 4, 'description': f'HTTP GET {path}',
                             'from': f"{src_ip}:{src_port}", 'to': f"{dst_ip}:{dst_port}",
                             'direction': '->', 'flags': '', 'app_layer': True, 'http_host': domain})
                steps.append({'step': 5, 'description': 'HTTP Response',
                             'from': f"{dst_ip}:{dst_port}", 'to': f"{src_ip}:{src_port}",
                             'direction': '<-', 'flags': '', 'app_layer': True})
        elif protocol == 'tcp':
            steps.append({'step': 1, 'description': 'TCP SYN', 'from': f"{src_ip}:{src_port}",
                         'to': f"{dst_ip}:{dst_port}", 'direction': '->', 'flags': '[SYN]'})
            steps.append({'step': 2, 'description': 'TCP SYN-ACK', 'from': f"{dst_ip}:{dst_port}",
                         'to': f"{src_ip}:{src_port}", 'direction': '<-', 'flags': '[SYN,ACK]'})
            steps.append({'step': 3, 'description': 'TCP ACK', 'from': f"{src_ip}:{src_port}",
                         'to': f"{dst_ip}:{dst_port}", 'direction': '->', 'flags': '[ACK]'})
            steps.append({'step': 4, 'description': 'Connection Established',
                         'from': f"{src_ip}:{src_port}", 'to': f"{dst_ip}:{dst_port}",
                         'direction': direction, 'flags': ''})
        elif protocol == 'udp':
            steps.append({'step': 1, 'description': 'UDP Packet', 'from': f"{src_ip}:{src_port}",
                         'to': f"{dst_ip}:{dst_port}", 'direction': direction, 'flags': ''})
        elif protocol == 'icmp':
            steps.append({'step': 1, 'description': 'ICMP Packet', 'from': src_ip,
                         'to': dst_ip, 'direction': direction, 'flags': ''})
        elif protocol == 'ip':
            steps.append({'step': 1, 'description': 'IP Packet', 'from': src_ip,
                         'to': dst_ip, 'direction': direction, 'flags': ''})
        else:
            steps.append({'step': 1, 'description': f'{protocol.upper()} Packet',
                         'from': f"{src_ip}:{src_port}" if src_port != 'any' else src_ip,
                         'to': f"{dst_ip}:{dst_port}" if dst_port != 'any' else dst_ip,
                         'direction': direction, 'flags': ''})
        
        return steps
    
    def _rule_matches_flow(self, rule: SuricataRule, src_ip: str, src_port: str,
                          dst_ip: str, dst_port: str, protocol: str, direction: str,
                          flow_state: str = 'all', url: str = None) -> Tuple[bool, str, List[str]]:
        """Check if a rule matches the given flow
        
        Returns:
            Tuple of (matches: bool, status: str, flowbits_explanations: List[str])
            where status is 'match', 'no_match', or 'unknown'
        """
        content = (rule.content or '').lower()
        
        if not self._protocol_matches(rule.protocol, protocol):
            return (False, 'no_match', [])
        
        if not self._flow_state_matches(rule, flow_state):
            return (False, 'no_match', [])
        
        if 'geoip:' in content:
            return (False, 'no_match', [])
        
        # Handle flowbits:isnotset through inference instead of skipping
        flowbits_explanations = []
        if 'flowbits:isnotset' in content:
            all_isnotset_true, explanations = self._infer_flowbits_isnotset(
                rule, src_ip, src_port, dst_ip, dst_port, protocol, direction, flow_state, url
            )
            flowbits_explanations = explanations
            
            if not all_isnotset_true:
                return (False, 'no_match', flowbits_explanations)
        
        if 'aws_url_category:' in content or 'aws_domain_category:' in content:
            return (False, 'unknown', flowbits_explanations)
        
        if not self._check_ip_proto_keyword(rule, protocol):
            return (False, 'no_match', [])
        
        if not self._direction_matches(rule.direction, direction):
            return (False, 'no_match', [])
        
        if not self._ip_matches_network(src_ip, rule.src_net):
            return (False, 'no_match', [])
        
        if not self._ip_matches_network(dst_ip, rule.dst_net):
            return (False, 'no_match', [])
        
        if not self._port_matches(src_port, rule.src_port):
            return (False, 'no_match', [])
        
        if not self._port_matches(dst_port, rule.dst_port):
            return (False, 'no_match', [])
        
        if not self._check_app_layer_protocol(rule, protocol):
            return (False, 'no_match', [])
        
        if protocol.lower() in ['http', 'tls', 'https'] and url:
            if not self._check_application_layer_match(rule, protocol, url):
                return (False, 'no_match', [])
        
        return (True, 'match', flowbits_explanations)
    
    def _test_flow_phase(self, classified_rules: Dict, src_ip: str, src_port: str,
                        dst_ip: str, dst_port: str, protocol: str, direction: str,
                        flow_state: str, results: Dict, url: str = None) -> bool:
        """Test a single phase of the flow against rules using Suricata's action scope model
        
        Suricata rules have different action scopes based on their type:
        - SIG_TYPE_IPONLY: Action Scope = FLOW
        - SIG_TYPE_PKT: Action Scope = PACKET
        - SIG_TYPE_APPLAYER: Action Scope = FLOW
        
        CRITICAL: A FLOW-scope action does NOT stop PACKET-scope rules from evaluating.
        PACKET-scope DROP/REJECT overrides FLOW-scope PASS because:
        - FLOW-scope PASS allows the flow to exist at the flow level
        - But PACKET-scope rules inspect individual packets and can reject them
        - This is why an IPONLY "pass ip" doesn't prevent a PKT "reject tcp"
        
        Returns:
            True if flow passed (was allowed), False if blocked
        """
        action_scopes = {
            'SIG_TYPE_IPONLY': 'FLOW',
            'SIG_TYPE_PKT': 'PACKET',
            'SIG_TYPE_APPLAYER': 'FLOW'
        }
        
        packet_scope_action = None
        packet_scope_rule = None
        packet_scope_line = None
        flow_scope_action = None
        flow_scope_rule = None
        flow_scope_line = None
        
        phase_flowbits_explanations = []
        
        # Process each type tier in order
        # IMPORTANT: A FLOW-scope action from IPONLY does NOT prevent PKT tier from evaluating.
        # Only within the same scope does first-match-wins apply.
        for rule_type in ['SIG_TYPE_IPONLY', 'SIG_TYPE_PKT', 'SIG_TYPE_APPLAYER']:
            scope = action_scopes[rule_type]
            
            # Skip if we already have an action at this specific scope from a previous tier
            # FLOW scope: IPONLY and APPLAYER share FLOW scope - first FLOW-scope tier wins
            # PACKET scope: Only PKT tier uses this scope
            if scope == 'FLOW' and flow_scope_action is not None:
                continue
            if scope == 'PACKET' and packet_scope_action is not None:
                continue
            
            # Track if action was taken in THIS tier
            tier_action_taken = False
            tier_action_direction = None
            
            type_rules = classified_rules.get(rule_type, [])
            type_rules_sorted = sorted(type_rules, key=lambda x: x['line'])
            
            for rule_info in type_rules_sorted:
                # If action was taken in THIS tier, check if we should stop
                if tier_action_taken:
                    if flow_state == 'handshake' and tier_action_direction:
                        rule_content = (rule_info['rule'].content or '').lower()
                        rule_direction_kw = None
                        if 'to_server' in rule_content:
                            rule_direction_kw = 'to_server'
                        elif 'to_client' in rule_content:
                            rule_direction_kw = 'to_client'
                        
                        if rule_direction_kw and rule_direction_kw != tier_action_direction:
                            pass  # Continue processing opposite direction
                        else:
                            break
                    else:
                        break
                
                rule = rule_info['rule']
                
                # Test if this rule matches the flow
                rule_content_lower = (rule.content or '').lower()
                if 'to_client' in rule_content_lower and 'to_server' not in rule_content_lower:
                    matches, status, fb_explanations = self._rule_matches_flow(
                        rule, dst_ip, dst_port, src_ip, src_port,
                        protocol, direction, flow_state, url)
                else:
                    matches, status, fb_explanations = self._rule_matches_flow(
                        rule, src_ip, src_port, dst_ip, dst_port,
                        protocol, direction, flow_state, url)
                
                # Collect flowbits explanations
                if fb_explanations:
                    phase_flowbits_explanations.extend(fb_explanations)
                
                # Handle unknown rules (category-based, etc.)
                if status == 'unknown':
                    unknown_info = {
                        'rule': rule,
                        'line': rule_info['line'],
                        'type': rule_type,
                        'action': rule.action,
                        'phase': flow_state,
                        'scope': scope,
                        'status': 'unknown'
                    }
                    results['unknown_rules'].append(unknown_info)
                    
                    if flow_state not in results['step_rule_mapping']:
                        results['step_rule_mapping'][flow_state] = []
                    results['step_rule_mapping'][flow_state].append(unknown_info)
                    continue
                
                if matches:
                    match_info = {
                        'rule': rule,
                        'line': rule_info['line'],
                        'type': rule_type,
                        'action': rule.action,
                        'phase': flow_state,
                        'scope': scope,
                        'flowbits_inferences': fb_explanations if fb_explanations else []
                    }
                    
                    if rule.action.lower() == 'alert':
                        results['alert_rules'].append(match_info)
                        if flow_state not in results['step_rule_mapping']:
                            results['step_rule_mapping'][flow_state] = []
                        results['step_rule_mapping'][flow_state].append(match_info)
                    else:
                        # Action rules (pass/drop/reject)
                        if rule.action.lower() in ['pass', 'drop', 'reject']:
                            if scope == 'PACKET':
                                if packet_scope_action is None:
                                    packet_scope_action = rule.action.lower()
                                    packet_scope_rule = match_info
                                    packet_scope_line = rule_info['line']
                                    tier_action_taken = True
                                    
                                    if flow_state == 'handshake':
                                        rule_content = (rule.content or '').lower()
                                        if 'to_server' in rule_content:
                                            tier_action_direction = 'to_server'
                                        elif 'to_client' in rule_content:
                                            tier_action_direction = 'to_client'
                                    
                                    # Add to matched_rules
                                    results['matched_rules'].append(match_info)
                                    self._add_step_mapping(results, flow_state, match_info, rule)
                                elif flow_state == 'handshake':
                                    # Second matching PACKET-scope rule in handshake (opposite direction)
                                    results['matched_rules'].append(match_info)
                                    self._add_step_mapping(results, flow_state, match_info, rule)
                            else:  # scope == 'FLOW'
                                if flow_scope_action is None:
                                    flow_scope_action = rule.action.lower()
                                    flow_scope_rule = match_info
                                    flow_scope_line = rule_info['line']
                                    tier_action_taken = True
                                    
                                    results['matched_rules'].append(match_info)
                                    self._add_step_mapping(results, flow_state, match_info, rule)
        
        # Store flowbits inferences for this phase
        if phase_flowbits_explanations:
            results["flowbits_inferences"].extend(phase_flowbits_explanations)
        
        # Store per-phase scope details for multi-scope display
        phase_scope_detail = {
            "flow_scope_action": flow_scope_action,
            "flow_scope_rule": flow_scope_rule,
            "packet_scope_action": packet_scope_action,
            "packet_scope_rule": packet_scope_rule,
        }
        results["scope_details"][flow_state] = phase_scope_detail
        
        # Determine final action using cross-scope deconfliction
        # CRITICAL FIX: PACKET-scope DROP/REJECT overrides FLOW-scope PASS
        final_action = None
        final_rule = None
        
        if packet_scope_action in ["drop", "reject"] and flow_scope_action == "pass":
            # PACKET-scope DROP/REJECT overrides FLOW-scope PASS
            final_action = packet_scope_action
            final_rule = packet_scope_rule
            results["scope_conflict"] = True
        elif packet_scope_action == "pass" and flow_scope_action in ["drop", "reject"]:
            final_action = flow_scope_action
            final_rule = flow_scope_rule
        elif packet_scope_action in ["drop", "reject"] and flow_scope_action in ["drop", "reject"]:
            final_action = packet_scope_action
            final_rule = packet_scope_rule
        elif packet_scope_action == "pass" and flow_scope_action == "pass":
            final_action = flow_scope_action
            final_rule = flow_scope_rule
        elif flow_scope_action is not None and packet_scope_action is None:
            final_action = flow_scope_action
            final_rule = flow_scope_rule
        elif packet_scope_action is not None and flow_scope_action is None:
            final_action = packet_scope_action
            final_rule = packet_scope_rule
        else:
            return True
        
        if final_rule and final_rule not in results["matched_rules"]:
            results["matched_rules"].append(final_rule)
            if flow_state not in results["step_rule_mapping"]:
                results["step_rule_mapping"][flow_state] = []
            results["step_rule_mapping"][flow_state].append(final_rule)
        
        results["final_action"] = final_action.upper()
        results["final_rule"] = final_rule
        
        return final_action == "pass"
    
    def _add_step_mapping(self, results, flow_state, match_info, rule):
        """Helper to add step mapping for handshake and other phases"""
        if flow_state == "handshake":
            rc = (rule.content or "").lower()
            if "to_server" in rc:
                step_key = "handshake_to_server"
            elif "to_client" in rc:
                step_key = "handshake_to_client"
            else:
                step_key = "handshake"
            if step_key not in results["step_rule_mapping"]:
                results["step_rule_mapping"][step_key] = []
            results["step_rule_mapping"][step_key].append(match_info)
            if "handshake" not in results["step_rule_mapping"]:
                results["step_rule_mapping"]["handshake"] = []
            if match_info not in results["step_rule_mapping"]["handshake"]:
                results["step_rule_mapping"]["handshake"].append(match_info)
        else:
            if flow_state not in results["step_rule_mapping"]:
                results["step_rule_mapping"][flow_state] = []
            results["step_rule_mapping"][flow_state].append(match_info)
    
    def _flow_state_matches(self, rule, flow_state):
        """Check if rule's flow state requirements match the tested flow state"""
        content = (rule.content or '').lower()
        rule_type = self.rule_analyzer.get_suricata_rule_type(rule)
        
        if rule_type == 'SIG_TYPE_IPONLY' and 'flow:' not in content:
            return True
        
        if 'not_established' in content:
            return flow_state == 'handshake'
        
        if 'established' in content:
            return flow_state == 'established'
        
        if rule_type == 'SIG_TYPE_PKT':
            if 'to_server' in content or 'to_client' in content:
                return True
        
        if 'flow:' not in content:
            return flow_state == 'established' or flow_state == 'all'
        
        if 'to_server' in content or 'to_client' in content:
            return flow_state in ['established', 'all']
        
        return True
    
    def _protocol_matches(self, rule_protocol, flow_protocol):
        """Check if rule protocol matches flow protocol"""
        rule_proto = rule_protocol.lower()
        flow_proto = flow_protocol.lower()
        
        if rule_proto == flow_proto:
            return True
        if rule_proto == 'ip':
            return True
        if rule_proto == 'tcp' and flow_proto in ['http', 'tls', 'https', 'smtp', 'ftp', 'ssh']:
            return True
        return False
    
    def _direction_matches(self, rule_direction, flow_direction):
        """Check if rule direction matches flow direction"""
        if rule_direction == '<>':
            return True
        if rule_direction == flow_direction:
            return True
        return False
    
    def _ip_matches_network(self, ip, network_spec):
        """Check if IP address matches network specification"""
        network_spec = network_spec.strip()
        
        if network_spec.lower() == 'any':
            return True
        
        if network_spec.startswith(('$', '@')):
            resolved = self.variables.get(network_spec, '')
            if not resolved:
                if network_spec == '$EXTERNAL_NET':
                    home_net = self.variables.get('$HOME_NET', '')
                    if home_net:
                        return not self._ip_matches_network(ip, home_net)
                    else:
                        return True
                return False
            if isinstance(resolved, dict):
                resolved = resolved.get('definition', '')
                if not resolved or not isinstance(resolved, str):
                    return False
            return self._ip_matches_network(ip, str(resolved))
        
        if network_spec.startswith('!'):
            negated_spec = network_spec[1:].strip()
            if self._ip_matches_network(ip, negated_spec):
                return False
            return True
        
        if network_spec.startswith('[') and network_spec.endswith(']'):
            return self._ip_matches_group(ip, network_spec[1:-1])
        
        if ',' in network_spec and not network_spec.startswith('['):
            networks = [net.strip() for net in network_spec.split(',')]
            for network in networks:
                if network and self._ip_matches_network(ip, network):
                    return True
            return False
        
        return self._ip_in_network(ip, network_spec)
    
    def _ip_matches_group(self, ip, group_content):
        """Check if IP matches any item in a network group"""
        items = [item.strip() for item in group_content.split(',')]
        included = False
        for item in items:
            if not item:
                continue
            if item.startswith('!'):
                excluded_item = item[1:].strip()
                if self._ip_matches_network(ip, excluded_item):
                    return False
            else:
                if self._ip_matches_network(ip, item):
                    included = True
        return included
    
    def _ip_in_network(self, ip, network):
        """Check if IP address is in network (CIDR or single IP)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            try:
                network_obj = ipaddress.ip_network(network, strict=False)
                return ip_obj in network_obj
            except ValueError:
                network_ip = ipaddress.ip_address(network)
                return ip_obj == network_ip
        except ValueError:
            return False
    
    def _port_matches(self, flow_port, rule_port):
        """Check if flow port matches rule port specification"""
        rule_port = rule_port.strip()
        
        if rule_port.lower() == 'any':
            return True
        
        if rule_port.startswith(('$', '@')):
            resolved = self.variables.get(rule_port, '')
            if not resolved:
                return False
            if isinstance(resolved, dict):
                resolved = resolved.get('definition', '')
                if not resolved or not isinstance(resolved, str):
                    return False
            rule_port = str(resolved)
        
        if rule_port.startswith('[') and rule_port.endswith(']'):
            rule_port = rule_port[1:-1]
        
        try:
            flow_port_num = int(flow_port) if flow_port.lower() != 'any' else None
        except ValueError:
            return False
        
        if flow_port_num is None:
            return rule_port.lower() == 'any'
        
        port_specs = [spec.strip() for spec in rule_port.split(',')]
        included = False
        
        for spec in port_specs:
            if not spec:
                continue
            if spec.startswith('!'):
                excluded_spec = spec[1:].strip()
                if self._port_in_spec(flow_port_num, excluded_spec):
                    return False
            else:
                if self._port_in_spec(flow_port_num, spec):
                    included = True
        
        if not any(not spec.startswith('!') for spec in port_specs if spec):
            return True
        
        return included
    
    def _port_in_spec(self, port_num, spec):
        """Check if port number matches a port specification"""
        spec = spec.strip()
        if spec.lower() == 'any':
            return True
        if ':' in spec:
            try:
                start, end = spec.split(':', 1)
                return int(start.strip()) <= port_num <= int(end.strip())
            except ValueError:
                return False
        try:
            return port_num == int(spec)
        except ValueError:
            return False
    
    def _check_application_layer_match(self, rule, protocol, url):
        """Check if rule's application layer keywords match the URL"""
        content = (rule.content or '').lower()
        parsed_url = self._parse_url(url)
        
        if not parsed_url:
            return not self._has_application_layer_keywords(content, protocol)
        
        protocol = protocol.lower()
        domain_is_ip = self._is_ip_address(parsed_url['domain'])
        
        if protocol in ['tls', 'https']:
            if 'ja4.hash' in content or 'ja3.hash' in content:
                if self._is_no_sni_detection_rule(content):
                    return False
            if 'tls.sni' in content:
                sni_match = self._extract_keyword_value(content, 'tls.sni')
                if sni_match:
                    if domain_is_ip and self._is_tld_checking_rule(sni_match):
                        return False
                    if not self._matches_pattern(parsed_url['domain'], sni_match):
                        return False
        
        if protocol == 'http':
            if 'http.host' in content:
                host_match = self._extract_keyword_value(content, 'http.host')
                if host_match:
                    if domain_is_ip and self._is_tld_checking_rule(host_match):
                        return False
                    if not self._matches_pattern(parsed_url['domain'], host_match):
                        return False
            if 'http.uri' in content:
                uri_match = self._extract_keyword_value(content, 'http.uri')
                if uri_match and not self._matches_pattern(parsed_url['path'], uri_match):
                    return False
            if 'http.method' in content:
                method_match = self._extract_keyword_value(content, 'http.method')
                if method_match and method_match.lower() != 'get':
                    return False
        
        return True
    
    def _check_ip_proto_keyword(self, rule, protocol):
        """Check if rule's ip_proto keyword matches the tested protocol"""
        content = (rule.content or '').lower()
        if 'ip_proto:' not in content:
            return True
        
        protocol = protocol.lower()
        ip_proto_map = {
            'tcp': 'tcp', 'udp': 'udp', 'icmp': 'icmp',
            'http': 'tcp', 'tls': 'tcp', 'https': 'tcp',
            'ssh': 'tcp', 'ftp': 'tcp', 'smtp': 'tcp',
            'dns': 'udp', 'quic': 'udp',
        }
        flow_ip_proto = ip_proto_map.get(protocol, protocol)
        
        ip_proto_matches = re.findall(r'ip_proto:\s*(!?)(\w+)', content)
        if not ip_proto_matches:
            return True
        
        for match in ip_proto_matches:
            is_negated = match[0] == '!'
            expected_proto = match[1].lower()
            proto_number_map = {'1': 'icmp', '6': 'tcp', '17': 'udp'}
            expected_proto = proto_number_map.get(expected_proto, expected_proto)
            protocol_match = (flow_ip_proto == expected_proto)
            if is_negated:
                if protocol_match:
                    return False
            else:
                if not protocol_match:
                    return False
        return True
    
    def _check_app_layer_protocol(self, rule, protocol):
        """Check if rule's app-layer-protocol keyword matches the tested protocol"""
        content = (rule.content or '').lower()
        if 'app-layer-protocol:' not in content:
            return True
        
        protocol = protocol.lower()
        match = re.search(r'app-layer-protocol:\s*(!?)(\w+)', content)
        if not match:
            return True
        
        is_negated = match.group(1) == '!'
        expected_proto = match.group(2).lower()
        protocol_match = (protocol == expected_proto)
        
        if is_negated:
            return not protocol_match
        else:
            return protocol_match
    
    def _is_no_sni_detection_rule(self, content):
        """Check if rule is designed to detect TLS connections without SNI"""
        if 'ja4.hash' in content and 'content:"_"' in content:
            if 'startswith' in content:
                return True
        if 'msg:' in content:
            msg_match = re.search(r'msg:\s*"([^"]+)"', content)
            if msg_match:
                msg = msg_match.group(1).lower()
                if 'no sni' in msg:
                    return True
        return False
    
    def _has_application_layer_keywords(self, content, protocol):
        """Check if content has application layer keywords that require URL matching"""
        protocol = protocol.lower()
        if protocol in ['tls', 'https']:
            return any(kw in content for kw in ['tls.sni', 'tls.subject', 'tls.issuer'])
        if protocol == 'http':
            return any(kw in content for kw in ['http.host', 'http.uri', 'http.method',
                       'http.user_agent', 'http.header', 'http.cookie'])
        return False
    
    def _is_ip_address(self, value):
        """Check if a string is an IP address"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def _is_tld_checking_rule(self, pattern_info):
        """Check if a pattern is for TLD checking"""
        if not pattern_info:
            return False
        modifiers = pattern_info.get('modifiers', [])
        pcre_pattern = pattern_info.get('pcre_pattern', '')
        if pcre_pattern and ('lookahead' in pcre_pattern or '?!' in pcre_pattern):
            return True
        if 'endswith' in modifiers:
            value = pattern_info.get('value', '')
            if value.startswith('.') and len(value) <= 5 and value[1:].isalpha():
                return True
        return False
    
    def _extract_keyword_value(self, content, keyword):
        """Extract the value and modifiers for a specific keyword from rule content"""
        idx = content.find(keyword)
        if idx == -1:
            return None
        
        rest = content[idx:]
        content_match = re.search(r'content:\s*"([^"]+)"', rest)
        
        if not content_match:
            pcre_match = re.search(r'pcre:\s*"([^"]+)"', rest)
            if pcre_match:
                pattern = pcre_match.group(1)
                pattern = pattern.replace('.*', '').replace('.+', '').replace('^', '').replace('$', '')
                return {'value': pattern, 'modifiers': ['pcre'], 'pcre_pattern': pcre_match.group(1)} if pattern else None
            return None
        
        value = content_match.group(1)
        after_content = rest[content_match.end():]
        
        modifiers = []
        if 'startswith' in after_content:
            modifiers.append('startswith')
        if 'endswith' in after_content:
            modifiers.append('endswith')
        if 'dotprefix' in after_content:
            modifiers.append('dotprefix')
        
        pcre_match = re.search(r'pcre:\s*"([^"]+)"', after_content)
        if pcre_match:
            modifiers.append('pcre')
            return {'value': value, 'modifiers': modifiers, 'pcre_pattern': pcre_match.group(1)}
        
        return {'value': value, 'modifiers': modifiers}
    
    def _matches_pattern(self, value, pattern_info):
        """Check if a value matches a pattern with modifiers"""
        if isinstance(pattern_info, str):
            pattern = pattern_info
            modifiers = []
            pcre_pattern = None
        elif isinstance(pattern_info, dict):
            pattern = pattern_info.get('value', '')
            modifiers = pattern_info.get('modifiers', [])
            pcre_pattern = pattern_info.get('pcre_pattern', None)
        else:
            return True
        
        if not pattern and not pcre_pattern:
            return True
        
        value = value.lower()
        pattern = pattern.lower()
        
        if 'pcre' in modifiers and pcre_pattern:
            cleaned_pattern = pcre_pattern.strip()
            if cleaned_pattern.startswith('/'):
                parts = cleaned_pattern.split('/')
                if len(parts) >= 2:
                    cleaned_pattern = parts[1]
            try:
                return bool(re.search(cleaned_pattern, value, re.IGNORECASE))
            except re.error:
                pass
        
        if 'startswith' in modifiers and 'endswith' in modifiers:
            return value == pattern
        elif 'startswith' in modifiers:
            return value.startswith(pattern)
        elif 'endswith' in modifiers:
            return value.endswith(pattern)
        elif 'dotprefix' in modifiers:
            if value.endswith(pattern):
                if value == pattern:
                    return True
                prefix_len = len(value) - len(pattern)
                if prefix_len > 0 and value[prefix_len - 1] == '.':
                    return True
            return False
        else:
            if value == pattern:
                return True
            if '*' not in pattern and '?' not in pattern:
                return pattern in value
            regex_pattern = pattern.replace('.', r'\.').replace('*', '.*').replace('?', '.')
            try:
                return bool(re.search(regex_pattern, value))
            except re.error:
                return pattern.replace('*', '').replace('?', '') in value
