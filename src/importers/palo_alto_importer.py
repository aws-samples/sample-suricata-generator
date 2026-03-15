"""
Palo Alto Networks Configuration Importer for Suricata Generator

This module provides the ability to import Palo Alto Networks firewall
security policy rules from XML configuration exports and convert them
to Suricata format for use with AWS Network Firewall.

Classes:
    PaloAltoParser - XML configuration parsing logic
    PaloAltoAppMapper - Application-to-protocol/domain mapping tables
    PaloAltoConverter - Conversion logic from PA objects to Suricata rules
    PaloAltoImporter - Main orchestrator for UI dialogs and import workflow

Phase 1 Implementation: PaloAltoParser + PaloAltoAppMapper (data loading only)
Phase 2 Implementation: PaloAltoConverter + PaloAltoAppMapper resolution methods
Phase 3 Implementation: App-ID, FQDN, URL Category conversion
Phase 4 Implementation: PaloAltoImporter UI workflow + integration
Phase 5 Implementation: Reporting, documentation, progress bar, error handling
"""

import json
import os
import re
import datetime
import logging
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple, Any
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

logger = logging.getLogger(__name__)


class PaloAltoAppMapper:
    """Loads and provides access to the palo_alto_app_map.json mapping data."""

    def __init__(self, json_path: str = None):
        if json_path is None:
            json_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'data', 'palo_alto_app_map.json')
        self.json_path = json_path
        self.data = {}
        self.protocol_mappings = {}
        self.domain_mappings = {}
        self.url_category_mappings = {}
        self.application_default_ports = {}
        self.builtin_services = {}
        self.country_codes = set()
        self._load_mappings()

    def _load_mappings(self):
        """Load all mapping data from the JSON file."""
        try:
            with open(self.json_path, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            self.protocol_mappings = {k: v for k, v in self.data.get('protocol_mappings', {}).items() if k != '_description'}
            self.domain_mappings = {k: v for k, v in self.data.get('domain_mappings', {}).items() if k != '_description'}
            self.url_category_mappings = {k: v for k, v in self.data.get('url_category_mappings', {}).items() if k != '_description'}
            self.application_default_ports = {k: v for k, v in self.data.get('application_default_ports', {}).items() if k != '_description'}
            self.builtin_services = {k: v for k, v in self.data.get('builtin_services', {}).items() if k != '_description'}
            cc_data = self.data.get('country_codes', {})
            self.country_codes = {k for k in cc_data.keys() if k != '_description'}
            logger.info(f"Loaded PA app mappings: {len(self.protocol_mappings)} protocols, "
                        f"{len(self.domain_mappings)} domains, {len(self.url_category_mappings)} URL categories, "
                        f"{len(self.country_codes)} country codes, {len(self.builtin_services)} built-in services")
        except Exception as e:
            logger.error(f"Failed to load palo_alto_app_map.json: {e}")
            raise

    def is_country_code(self, value: str) -> bool:
        """Check if a value is a valid ISO 3166-1 alpha-2 country code."""
        return value in self.country_codes

    def is_builtin_url_category(self, category_name: str) -> bool:
        """Check if a category name is a built-in PA URL category."""
        return category_name in self.url_category_mappings

    def get_builtin_service(self, service_name: str) -> Optional[Dict]:
        """Look up a built-in PAN-OS service by name. Returns dict with 'protocol' and 'port' or None."""
        return self.builtin_services.get(service_name)

    def get_mapping_version(self) -> str:
        """Get the version of the mapping file."""
        return self.data.get('version', 'unknown')

    def resolve_application(self, app_name: str) -> Dict[str, Any]:
        """Resolve a PA application name to its Suricata conversion info.
        
        Returns a dict describing how to convert this application:
        {
            'tier': 1|2|3,
            'tier_label': 'protocol'|'domain'|'unmappable',
            'suricata_protocol': str or None,
            'default_port': str or None,
            'app_layer': bool,
            'domain': str or None,          # For Tier 2 only
            'deny_action': str or None,     # 'reject' or 'drop' for PA deny mapping
            'description': str,
        }
        """
        # Tier 1: Direct protocol mapping
        if app_name in self.protocol_mappings:
            mapping = self.protocol_mappings[app_name]
            return {
                'tier': 1,
                'tier_label': 'protocol',
                'suricata_protocol': mapping['suricata_protocol'],
                'default_port': mapping.get('default_port'),
                'app_layer': mapping.get('app_layer', False),
                'domain': None,
                'deny_action': mapping.get('deny_action', 'drop'),
                'description': mapping.get('description', ''),
            }
        
        # Tier 2: Domain-based mapping (all TLS/TCP, default deny_action is reject)
        if app_name in self.domain_mappings:
            mapping = self.domain_mappings[app_name]
            return {
                'tier': 2,
                'tier_label': 'domain',
                'suricata_protocol': 'tls',
                'default_port': '443',
                'app_layer': True,
                'domain': mapping['domain'],
                'deny_action': mapping.get('deny_action', 'reject'),
                'description': mapping.get('description', ''),
            }
        
        # Tier 3: Unmappable
        return {
            'tier': 3,
            'tier_label': 'unmappable',
            'suricata_protocol': None,
            'default_port': None,
            'app_layer': False,
            'domain': None,
            'deny_action': 'drop',
            'description': f'No Suricata equivalent for PA App-ID "{app_name}"',
        }

    def resolve_service(self, service_name: str, service_objects: Dict = None,
                        service_groups: Dict = None) -> List[Dict[str, str]]:
        """Resolve a PA service reference to protocol/port pairs.
        
        Follows the service member resolution precedence:
        1. 'any' -> port 'any'
        2. 'application-default' -> deferred (returns special marker)
        3. Custom service object name (from parsed service_objects)
        4. Built-in service name (from builtin_services in JSON)
        5. Service group name (from parsed service_groups)
        6. Unresolved reference
        
        Returns list of dicts: [{'protocol': 'tcp', 'port': '80'}, ...]
        """
        if service_objects is None:
            service_objects = {}
        if service_groups is None:
            service_groups = {}
        
        # 1. 'any' — all ports
        if service_name == 'any':
            return [{'protocol': None, 'port': 'any', 'source': 'any'}]
        
        # 2. 'application-default' — deferred to converter
        if service_name == 'application-default':
            return [{'protocol': None, 'port': None, 'source': 'application-default'}]
        
        # 3. Custom service object
        if service_name in service_objects:
            svc = service_objects[service_name]
            return [{'protocol': svc.get('protocol'), 'port': svc.get('port', 'any'),
                      'source': 'custom-service'}]
        
        # 4. Built-in service
        builtin = self.get_builtin_service(service_name)
        if builtin:
            return [{'protocol': builtin['protocol'], 'port': builtin['port'],
                      'source': 'builtin-service'}]
        
        # 5. Service group
        if service_name in service_groups:
            group = service_groups[service_name]
            results = []
            for expanded_svc in group.get('expanded_services', []):
                if expanded_svc.get('protocol'):
                    results.append({
                        'protocol': expanded_svc['protocol'],
                        'port': expanded_svc.get('port', 'any'),
                        'source': 'service-group',
                    })
            if results:
                return results
        
        # 6. Unresolved
        return [{'protocol': None, 'port': None, 'source': 'unresolved',
                  'name': service_name}]

    def resolve_category(self, category_name: str) -> Optional[Dict[str, str]]:
        """Resolve a PA URL category to an AWS domain category.
        
        Returns dict with AWS category info or None if not mappable:
        {'aws_category': 'Malware', 'confidence': 'high'}
        """
        if category_name in self.url_category_mappings:
            mapping = self.url_category_mappings[category_name]
            return {
                'aws_category': mapping['aws_category'],
                'confidence': mapping.get('confidence', 'medium'),
            }
        return None

    def get_application_default_port(self, app_name: str) -> Optional[Tuple[str, str]]:
        """Get the default protocol/port for an application when service is 'application-default'.
        
        Returns tuple (protocol, port) or None if not found.
        Example: 'ssl' -> ('tcp', '443'), 'dns' -> ('udp', '53')
        """
        port_spec = self.application_default_ports.get(app_name)
        if port_spec:
            parts = port_spec.split('/')
            if len(parts) == 2:
                return (parts[0], parts[1])
        return None


class PaloAltoParser:
    """Parses Palo Alto Networks XML configuration exports.

    Extracts security rules, address objects, service objects, zones,
    and other policy-related elements. Skips sensitive management data.
    """

    def __init__(self, app_mapper: PaloAltoAppMapper = None):
        self.app_mapper = app_mapper or PaloAltoAppMapper()
        self.warnings = []

    def parse_config(self, xml_path: str, vsys_name: str = 'vsys1') -> Dict[str, Any]:
        """Parse a Palo Alto XML configuration file.
        
        Args:
            xml_path: Path to the XML configuration file
            vsys_name: Virtual system to parse (default: 'vsys1')
            
        Returns:
            Dictionary containing all parsed configuration data:
            {
                'metadata': { version, detail_version, source_file },
                'vsys_list': [ { name } ],
                'vsys_name': str,
                'zones': { zone_name: { interfaces: [...] } },
                'address_objects': { name: { type, value, description } },
                'address_groups': { name: { members: [...], expanded_members: [...] } },
                'service_objects': { name: { protocol, port, ... } },
                'service_groups': { name: { members: [...], expanded_services: [...] } },
                'custom_url_categories': { name: { domains: [...], type } },
                'security_rules': [ { name, action, from, to, source, destination, ... } ],
                'tags': [ str ],
                'warnings': [ str ],
                'summary': { rule_count, disabled_count, address_count, ... }
            }
        """
        self.warnings = []
        result = {}
        
        # File size check (warn for very large files > 50MB)
        try:
            file_size = os.path.getsize(xml_path)
            if file_size > 50 * 1024 * 1024:
                self.warnings.append(
                    f"Large configuration file ({file_size / (1024*1024):.1f} MB). "
                    f"Parsing may take a moment.")
            if file_size == 0:
                raise ValueError("Configuration file is empty (0 bytes).")
        except OSError as e:
            raise FileNotFoundError(f"Cannot access configuration file: {e}")
        
        # Parse XML with enhanced error handling
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except ET.ParseError as e:
            # Provide helpful error messages for common XML issues
            err_str = str(e)
            if 'encoding' in err_str.lower() or 'codec' in err_str.lower():
                raise ValueError(
                    f"XML encoding error: {e}\n\n"
                    f"The file may use a non-UTF-8 encoding. Try opening the file "
                    f"in a text editor and re-saving as UTF-8.")
            elif 'not well-formed' in err_str.lower() or 'syntax error' in err_str.lower():
                raise ValueError(
                    f"Malformed XML: {e}\n\n"
                    f"The XML file contains syntax errors. Verify this is a valid "
                    f"Palo Alto configuration export (not a partial snippet or corrupted file).")
            else:
                raise ValueError(f"Invalid XML file: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {xml_path}")
        except PermissionError:
            raise ValueError(f"Permission denied reading file: {xml_path}")
        except UnicodeDecodeError as e:
            raise ValueError(
                f"File encoding error: {e}\n\n"
                f"The file contains characters that cannot be decoded. "
                f"Try re-saving the file as UTF-8 encoding.")
        
        # Verify this is a PAN-OS config
        if root.tag != 'config':
            raise ValueError(f"Not a valid Palo Alto configuration file. Root element is '{root.tag}', expected 'config'.")
        
        # Extract metadata (version, etc.)
        result['metadata'] = self._parse_config_metadata(root)
        result['metadata']['source_file'] = os.path.basename(xml_path)
        
        # Get available virtual systems
        result['vsys_list'] = self._get_vsys_list(root)
        if not result['vsys_list']:
            raise ValueError("No virtual systems found in configuration file.")
        
        # Find the target vsys
        vsys_elem = None
        devices = root.find('.//devices')
        if devices is not None:
            for device_entry in devices.findall('entry'):
                vsys_container = device_entry.find('vsys')
                if vsys_container is not None:
                    for vsys_entry in vsys_container.findall('entry'):
                        if vsys_entry.get('name') == vsys_name:
                            vsys_elem = vsys_entry
                            break
                if vsys_elem is not None:
                    break
        
        if vsys_elem is None:
            raise ValueError(f"Virtual system '{vsys_name}' not found in configuration.")
        
        result['vsys_name'] = vsys_name
        
        # Get the shared section (sibling to devices, may be absent)
        shared_elem = root.find('shared')
        
        # Parse all object types
        result['zones'] = self._parse_zones(vsys_elem)
        result['address_objects'] = self._parse_address_objects(vsys_elem, shared_elem)
        result['address_groups'] = self._parse_address_groups(vsys_elem, shared_elem, result['address_objects'])
        result['service_objects'] = self._parse_service_objects(vsys_elem, shared_elem)
        result['service_groups'] = self._parse_service_groups(vsys_elem, shared_elem, result['service_objects'])
        result['custom_url_categories'] = self._parse_custom_url_categories(vsys_elem)
        result['security_rules'] = self._parse_security_rules(vsys_elem)
        result['tags'] = self._parse_tags(vsys_elem)
        result['warnings'] = self.warnings
        
        # Build summary statistics
        disabled_count = sum(1 for r in result['security_rules'] if r.get('disabled', False))
        fqdn_count = sum(1 for a in result['address_objects'].values() if a.get('type') == 'fqdn')
        
        # Collect unique applications and categories referenced in rules
        apps_referenced = set()
        categories_referenced = set()
        zones_referenced = set()
        for rule in result['security_rules']:
            for app in rule.get('applications', []):
                if app != 'any':
                    apps_referenced.add(app)
            for cat in rule.get('categories', []):
                if cat != 'any':
                    categories_referenced.add(cat)
            for z in rule.get('from_zones', []):
                if z != 'any':
                    zones_referenced.add(z)
            for z in rule.get('to_zones', []):
                if z != 'any':
                    zones_referenced.add(z)
        
        result['summary'] = {
            'rule_count': len(result['security_rules']),
            'disabled_count': disabled_count,
            'enabled_count': len(result['security_rules']) - disabled_count,
            'address_object_count': len(result['address_objects']),
            'address_group_count': len(result['address_groups']),
            'service_object_count': len(result['service_objects']),
            'service_group_count': len(result['service_groups']),
            'fqdn_object_count': fqdn_count,
            'custom_url_category_count': len(result['custom_url_categories']),
            'zone_count': len(result['zones']),
            'applications_referenced': sorted(apps_referenced),
            'categories_referenced': sorted(categories_referenced),
            'zones_referenced': sorted(zones_referenced),
            'tag_count': len(result['tags']),
        }
        
        logger.info(f"Parsed PA config: {result['summary']['rule_count']} rules, "
                     f"{result['summary']['address_object_count']} address objects, "
                     f"{result['summary']['service_object_count']} service objects, "
                     f"{result['summary']['zone_count']} zones")
        
        return result

    def _parse_config_metadata(self, root: ET.Element) -> Dict[str, str]:
        """Extract PAN-OS version and other metadata from <config> root element."""
        metadata = {
            'panos_version': root.get('version', 'unknown'),
            'detail_version': root.get('detail-version', 'unknown'),
            'urldb': root.get('urldb', 'unknown'),
        }
        return metadata

    def _get_vsys_list(self, root: ET.Element) -> List[Dict[str, str]]:
        """Get list of virtual systems found in the configuration."""
        vsys_list = []
        devices = root.find('.//devices')
        if devices is None:
            return vsys_list
        for device_entry in devices.findall('entry'):
            vsys_container = device_entry.find('vsys')
            if vsys_container is not None:
                for vsys_entry in vsys_container.findall('entry'):
                    name = vsys_entry.get('name', 'unknown')
                    vsys_list.append({'name': name})
        return vsys_list

    def _parse_zones(self, vsys_elem: ET.Element) -> Dict[str, Dict]:
        """Parse zone definitions from a vsys element.
        
        Returns dict mapping zone name to zone info:
        { 'Trust': { 'interfaces': ['ethernet1/1'] } }
        """
        zones = {}
        zone_container = vsys_elem.find('zone')
        if zone_container is None:
            return zones
        for entry in zone_container.findall('entry'):
            zone_name = entry.get('name')
            if not zone_name:
                continue
            interfaces = []
            # Zones map to interfaces via network > layer3 > member
            network = entry.find('network')
            if network is not None:
                layer3 = network.find('layer3')
                if layer3 is not None:
                    for member in layer3.findall('member'):
                        if member.text:
                            interfaces.append(member.text.strip())
            zones[zone_name] = {
                'interfaces': interfaces,
            }
        return zones

    def _parse_address_objects(self, vsys_elem: ET.Element, shared_elem: Optional[ET.Element] = None) -> Dict[str, Dict]:
        """Parse address objects from vsys and shared sections.
        
        Handles three address types:
        - ip-netmask: CIDR notation (e.g., 10.1.1.10/32)
        - ip-range: IP range (e.g., 10.1.1.1-10.1.1.255)
        - fqdn: Domain name (e.g., malware.example.com)
        
        Vsys objects take precedence over shared objects with the same name.
        """
        objects = {}
        
        # Parse shared objects first (lower precedence)
        if shared_elem is not None:
            self._parse_address_entries(shared_elem, objects, source='shared')
        
        # Parse vsys objects (higher precedence - overwrites shared)
        self._parse_address_entries(vsys_elem, objects, source='vsys')
        
        return objects

    def _parse_address_entries(self, parent_elem: ET.Element, objects: Dict, source: str = 'vsys'):
        """Parse address entries from a parent element into the objects dict."""
        address_container = parent_elem.find('address')
        if address_container is None:
            return
        for entry in address_container.findall('entry'):
            name = entry.get('name')
            if not name:
                continue
            addr_obj = {'source': source}
            
            # Check for ip-netmask
            ip_netmask = entry.find('ip-netmask')
            if ip_netmask is not None and ip_netmask.text:
                addr_obj['type'] = 'ip-netmask'
                addr_obj['value'] = ip_netmask.text.strip()
            
            # Check for ip-range
            ip_range = entry.find('ip-range')
            if ip_range is not None and ip_range.text:
                addr_obj['type'] = 'ip-range'
                addr_obj['value'] = ip_range.text.strip()
            
            # Check for fqdn
            fqdn = entry.find('fqdn')
            if fqdn is not None and fqdn.text:
                addr_obj['type'] = 'fqdn'
                addr_obj['value'] = fqdn.text.strip()
            
            # Only add if we found a recognized type
            if 'type' not in addr_obj:
                self.warnings.append(f"Address object '{name}' has no recognized type (ip-netmask, ip-range, fqdn). Skipped.")
                continue
            
            # Optional fields
            description = self._get_text(entry, 'description')
            if description:
                addr_obj['description'] = description
            
            tags = self._get_members(entry, 'tag')
            if tags:
                addr_obj['tags'] = tags
            
            objects[name] = addr_obj

    def _parse_address_groups(self, vsys_elem: ET.Element, shared_elem: Optional[ET.Element] = None, address_objects: Dict = None) -> Dict[str, Dict]:
        """Parse address groups with recursive nested group expansion.
        
        Returns dict mapping group name to group info with both raw members
        and fully expanded address object names.
        """
        if address_objects is None:
            address_objects = {}
        groups_raw = {}
        
        # Parse shared groups first
        if shared_elem is not None:
            self._parse_address_group_entries(shared_elem, groups_raw, source='shared')
        
        # Parse vsys groups (higher precedence)
        self._parse_address_group_entries(vsys_elem, groups_raw, source='vsys')
        
        # Now expand all groups recursively
        groups = {}
        for group_name, group_data in groups_raw.items():
            expanded = self._expand_address_group(group_name, groups_raw, address_objects)
            groups[group_name] = {
                'members': group_data['members'],
                'expanded_members': expanded,
                'source': group_data.get('source', 'vsys'),
            }
            if 'description' in group_data:
                groups[group_name]['description'] = group_data['description']
        
        return groups

    def _parse_address_group_entries(self, parent_elem: ET.Element, groups: Dict, source: str = 'vsys'):
        """Parse address group entries from a parent element."""
        ag_container = parent_elem.find('address-group')
        if ag_container is None:
            return
        for entry in ag_container.findall('entry'):
            name = entry.get('name')
            if not name:
                continue
            members = []
            static = entry.find('static')
            if static is not None:
                for member in static.findall('member'):
                    if member.text:
                        members.append(member.text.strip())
            group_data = {
                'members': members,
                'source': source,
            }
            description = self._get_text(entry, 'description')
            if description:
                group_data['description'] = description
            groups[name] = group_data

    def _expand_address_group(self, group_name: str, groups_raw: Dict, address_objects: Dict, visited: set = None) -> List[str]:
        """Recursively expand an address group to its leaf address object names.
        
        Handles nested groups by recursively expanding group members.
        Detects circular references to prevent infinite loops.
        """
        if visited is None:
            visited = set()
        
        if group_name in visited:
            self.warnings.append(f"Circular reference detected in address group '{group_name}'. Expansion stopped.")
            return []
        visited.add(group_name)
        
        if group_name not in groups_raw:
            # Not a group - might be an address object or unknown
            return [group_name]
        
        expanded = []
        for member in groups_raw[group_name].get('members', []):
            if member in groups_raw:
                # Member is another group - recurse
                expanded.extend(self._expand_address_group(member, groups_raw, address_objects, visited.copy()))
            else:
                # Member is a leaf address object (or unresolved reference)
                expanded.append(member)
        
        return expanded

    def _parse_service_objects(self, vsys_elem: ET.Element, shared_elem: Optional[ET.Element] = None) -> Dict[str, Dict]:
        """Parse service objects from vsys and shared sections.
        
        Handles TCP and UDP protocols with port numbers, port ranges, and
        comma-separated port lists. Ignores <override> elements.
        Vsys objects take precedence over shared objects.
        """
        objects = {}
        
        # Parse shared first (lower precedence)
        if shared_elem is not None:
            self._parse_service_entries(shared_elem, objects, source='shared')
        
        # Parse vsys (higher precedence)
        self._parse_service_entries(vsys_elem, objects, source='vsys')
        
        return objects

    def _parse_service_entries(self, parent_elem: ET.Element, objects: Dict, source: str = 'vsys'):
        """Parse service entries from a parent element into the objects dict."""
        svc_container = parent_elem.find('service')
        if svc_container is None:
            return
        for entry in svc_container.findall('entry'):
            name = entry.get('name')
            if not name:
                continue
            svc_obj = {'source': source}
            
            protocol_elem = entry.find('protocol')
            if protocol_elem is None:
                self.warnings.append(f"Service object '{name}' has no <protocol> element. Skipped.")
                continue
            
            # Check for TCP
            tcp_elem = protocol_elem.find('tcp')
            if tcp_elem is not None:
                svc_obj['protocol'] = 'tcp'
                port_elem = tcp_elem.find('port')
                if port_elem is not None and port_elem.text:
                    svc_obj['port'] = port_elem.text.strip()
                else:
                    svc_obj['port'] = 'any'
                # source-port is optional
                src_port_elem = tcp_elem.find('source-port')
                if src_port_elem is not None and src_port_elem.text:
                    svc_obj['source_port'] = src_port_elem.text.strip()
            
            # Check for UDP
            udp_elem = protocol_elem.find('udp')
            if udp_elem is not None:
                svc_obj['protocol'] = 'udp'
                port_elem = udp_elem.find('port')
                if port_elem is not None and port_elem.text:
                    svc_obj['port'] = port_elem.text.strip()
                else:
                    svc_obj['port'] = 'any'
                src_port_elem = udp_elem.find('source-port')
                if src_port_elem is not None and src_port_elem.text:
                    svc_obj['source_port'] = src_port_elem.text.strip()
            
            if 'protocol' not in svc_obj:
                self.warnings.append(f"Service object '{name}' has no TCP or UDP protocol. Skipped.")
                continue
            
            # Optional tags
            tags = self._get_members(entry, 'tag')
            if tags:
                svc_obj['tags'] = tags
            
            objects[name] = svc_obj

    def _parse_service_groups(self, vsys_elem: ET.Element, shared_elem: Optional[ET.Element] = None, service_objects: Dict = None) -> Dict[str, Dict]:
        """Parse service groups and expand members.
        
        Service group members can be:
        - Custom service object names
        - Built-in service names (e.g., service-http)
        - Other service group names (recursive)
        """
        if service_objects is None:
            service_objects = {}
        groups = {}
        
        # Parse shared first
        if shared_elem is not None:
            self._parse_service_group_entries(shared_elem, groups, source='shared')
        
        # Parse vsys (higher precedence)
        self._parse_service_group_entries(vsys_elem, groups, source='vsys')
        
        # Expand members - resolve each member to its service definition
        for group_name, group_data in groups.items():
            expanded = []
            for member_name in group_data.get('members', []):
                if member_name in service_objects:
                    expanded.append({
                        'name': member_name,
                        'protocol': service_objects[member_name].get('protocol'),
                        'port': service_objects[member_name].get('port'),
                    })
                else:
                    # Try built-in service
                    builtin = self.app_mapper.get_builtin_service(member_name)
                    if builtin:
                        expanded.append({
                            'name': member_name,
                            'protocol': builtin['protocol'],
                            'port': builtin['port'],
                        })
                    else:
                        self.warnings.append(
                            f"Service group '{group_name}' member '{member_name}' "
                            f"not found in service objects or built-in services.")
                        expanded.append({'name': member_name, 'protocol': None, 'port': None})
            group_data['expanded_services'] = expanded
        
        return groups

    def _parse_service_group_entries(self, parent_elem: ET.Element, groups: Dict, source: str = 'vsys'):
        """Parse service group entries from a parent element."""
        sg_container = parent_elem.find('service-group')
        if sg_container is None:
            return
        for entry in sg_container.findall('entry'):
            name = entry.get('name')
            if not name:
                continue
            # Service groups use <members> (note plural) not <member> directly
            members = []
            members_elem = entry.find('members')
            if members_elem is not None:
                for member in members_elem.findall('member'):
                    if member.text:
                        members.append(member.text.strip())
            groups[name] = {
                'members': members,
                'source': source,
            }

    def _parse_custom_url_categories(self, vsys_elem: ET.Element) -> Dict[str, Dict]:
        """Parse custom URL category lists from profiles > custom-url-category.
        
        These are user-defined URL lists containing specific domains.
        Distinguished from built-in PA URL categories (adult, malware, etc.).
        """
        categories = {}
        profiles = vsys_elem.find('profiles')
        if profiles is None:
            return categories
        
        custom_url_container = profiles.find('custom-url-category')
        if custom_url_container is None:
            return categories
        
        for entry in custom_url_container.findall('entry'):
            name = entry.get('name')
            if not name:
                continue
            
            # Extract domain list
            domains = []
            list_elem = entry.find('list')
            if list_elem is not None:
                for member in list_elem.findall('member'):
                    if member.text:
                        domains.append(member.text.strip())
            
            cat_type = self._get_text(entry, 'type', 'URL List')
            
            categories[name] = {
                'domains': domains,
                'type': cat_type,
            }
        
        return categories

    def _parse_security_rules(self, vsys_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse all security rules from the rulebase, preserving order."""
        rules = []
        rulebase = vsys_elem.find('rulebase')
        if rulebase is None:
            return rules
        
        security = rulebase.find('security')
        if security is None:
            return rules
        
        rules_container = security.find('rules')
        if rules_container is None:
            return rules
        
        for rule_elem in rules_container.findall('entry'):
            rule_data = self._parse_single_rule(rule_elem)
            if rule_data:
                rules.append(rule_data)
        
        return rules

    def _parse_single_rule(self, rule_elem: ET.Element) -> Dict[str, Any]:
        """Parse a single security rule entry element into a dictionary.
        
        Extracts all rule fields including optional elements.
        """
        rule = {}
        
        # Name and UUID
        rule['name'] = rule_elem.get('name', 'unnamed')
        uuid_val = rule_elem.get('uuid')
        if uuid_val:
            rule['uuid'] = uuid_val
        
        # Zone fields
        rule['from_zones'] = self._get_members(rule_elem, 'from')
        rule['to_zones'] = self._get_members(rule_elem, 'to')
        
        # Source and destination
        rule['sources'] = self._get_members(rule_elem, 'source')
        rule['destinations'] = self._get_members(rule_elem, 'destination')
        
        # Applications and services
        rule['applications'] = self._get_members(rule_elem, 'application')
        rule['services'] = self._get_members(rule_elem, 'service')
        
        # Categories (URL filtering)
        rule['categories'] = self._get_members(rule_elem, 'category')
        
        # Action (required)
        rule['action'] = self._get_text(rule_elem, 'action', 'deny')
        
        # Disabled state (absent = enabled)
        disabled_text = self._get_text(rule_elem, 'disabled', 'no')
        rule['disabled'] = (disabled_text == 'yes')
        
        # Description (optional)
        description = self._get_text(rule_elem, 'description')
        if description:
            rule['description'] = description
        
        # Tags (optional)
        rule['tags'] = self._get_members(rule_elem, 'tag')
        
        # Logging
        rule['log_start'] = self._get_text(rule_elem, 'log-start', 'no')
        rule['log_end'] = self._get_text(rule_elem, 'log-end', 'yes')
        
        # Rule type (optional: universal, intrazone, interzone)
        rule_type = self._get_text(rule_elem, 'rule-type')
        if rule_type:
            rule['rule_type'] = rule_type
        
        # Negation flags (optional, absent = no negation)
        negate_src = self._get_text(rule_elem, 'negate-source', 'no')
        rule['negate_source'] = (negate_src == 'yes')
        
        negate_dst = self._get_text(rule_elem, 'negate-destination', 'no')
        rule['negate_destination'] = (negate_dst == 'yes')
        
        # Source user (noted but not convertible)
        rule['source_users'] = self._get_members(rule_elem, 'source-user')
        
        # HIP profiles (noted but not convertible)
        rule['source_hip'] = self._get_members(rule_elem, 'source-hip')
        rule['destination_hip'] = self._get_members(rule_elem, 'destination-hip')
        
        # Profile settings (noted but not convertible)
        profile_setting = rule_elem.find('profile-setting')
        if profile_setting is not None:
            rule['has_security_profiles'] = True
        
        return rule

    def _get_members(self, parent_elem: ET.Element, tag_name: str) -> List[str]:
        """Extract member values from a parent element's child tag. Returns empty list if absent.
        
        Handles:
        - Absent elements (tag not present at all) -> []
        - Self-closing elements (e.g., <service/>) -> []
        - Elements with <member> children -> list of text values
        """
        if parent_elem is None:
            return []
        container = parent_elem.find(tag_name)
        if container is None:
            return []
        members = []
        for member_elem in container.findall('member'):
            if member_elem.text:
                members.append(member_elem.text.strip())
        return members

    def _get_text(self, parent_elem: ET.Element, tag_name: str, default: str = None) -> Optional[str]:
        """Get text content of a child element. Returns default if absent."""
        if parent_elem is None:
            return default
        elem = parent_elem.find(tag_name)
        if elem is None or elem.text is None:
            return default
        return elem.text.strip()

    def _parse_tags(self, vsys_elem: ET.Element) -> List[str]:
        """Parse tag definitions from vsys."""
        tags = []
        tag_container = vsys_elem.find('tag')
        if tag_container is None:
            return tags
        for entry in tag_container.findall('entry'):
            name = entry.get('name')
            if name:
                tags.append(name)
        return tags


# IP address/CIDR regex pattern for detecting inline IPs in source/destination
IP_PATTERN = re.compile(
    r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})?$'
)


class PaloAltoConverter:
    """Converts parsed Palo Alto configuration objects into Suricata rules.

    Handles action mapping, network/port resolution, zone variables,
    GeoIP conversion, negation, disabled rules, logging, and metadata
    comment generation. App-ID, FQDN, and URL category conversion are
    deferred to Phase 3.
    """

    # PA action -> Suricata action mapping
    ACTION_MAP = {
        'allow': 'pass',
        'deny': 'drop',
        'drop': 'drop',
        'reset-client': 'reject',
        'reset-server': 'reject',
        'reset-both': 'reject',
    }

    # App-layer protocols in Suricata that support port-independent detection
    APP_LAYER_PROTOCOLS = {
        'dcerpc', 'dhcp', 'dns', 'ftp', 'http', 'http2', 'ikev2',
        'imap', 'krb5', 'msn', 'ntp', 'quic', 'smb', 'smtp',
        'ssh', 'tftp', 'tls',
    }

    # Protocols that support domain-based matching (tls.sni / http.host)
    DOMAIN_MATCHABLE_PROTOCOLS = {'tls', 'http'}

    def __init__(self, parsed_config, app_mapper, options=None):
        """Initialize the converter with parsed configuration data.

        Args:
            parsed_config: Dict from PaloAltoParser.parse_config()
            app_mapper: PaloAltoAppMapper instance
            options: Dict of conversion options:
                - include_disabled: bool (import disabled rules as comments)
                - include_descriptions: bool (add PA descriptions as comments)
                - include_zone_info: bool (add zone from/to as comments)
                - include_conversion_notes: bool (add warnings inline)
                - starting_sid: int (first SID to assign)
                - test_mode: bool (convert all actions to alert)
                - zone_cidrs: dict (zone_name -> CIDR string, user-provided)
        """
        self.config = parsed_config
        self.app_mapper = app_mapper
        self.options = options or {}

        # Parsed objects for quick lookup
        self.address_objects = parsed_config.get('address_objects', {})
        self.address_groups = parsed_config.get('address_groups', {})
        self.service_objects = parsed_config.get('service_objects', {})
        self.service_groups = parsed_config.get('service_groups', {})
        self.custom_url_categories = parsed_config.get('custom_url_categories', {})
        self.zones = parsed_config.get('zones', {})
        self.metadata = parsed_config.get('metadata', {})

        # SID counter
        self.current_sid = self.options.get('starting_sid', 100)

        # Zone CIDR mappings (user-provided or empty)
        self.zone_cidrs = self.options.get('zone_cidrs', {})

        # Variables to be created (populated during conversion)
        # Key: variable name (without $), Value: variable value string
        self.variables = {}

        # Conversion statistics
        self.stats = {
            'pa_rules_processed': 0,
            'suricata_rules_generated': 0,
            'fully_converted': 0,
            'partially_converted': 0,
            'not_convertible': 0,
            'disabled_skipped': 0,
            'disabled_imported': 0,
        }

        # Conversion notes (warnings, errors, info per rule)
        self.notes = []

        # Application mapping stats
        self.app_stats = {
            'tier1_protocol': 0,
            'tier2_domain': 0,
            'tier3_unmappable': 0,
            'tier5_wildcard': 0,
        }

    def convert(self):
        """Convert all security rules to Suricata format.
        
        Returns:
            dict with:
                'lines': list of all output lines (header + rules)
                'variables': dict of variable_name -> value
                'stats': dict of conversion statistics
                'notes': list of all conversion notes
                'app_stats': dict of application mapping statistics
                'rules_by_pa_name': dict mapping PA rule name to generated lines
        """
        options = self.options
        rules = self.config.get('security_rules', [])
        all_lines = []
        rules_by_pa_name = {}
        
        self.stats['pa_rules_processed'] = len(rules)
        
        # Convert each rule
        for rule in rules:
            result = self._convert_single_rule(rule, options)
            
            rule_name = rule.get('name', 'unnamed')
            rules_by_pa_name[rule_name] = result
            
            all_lines.extend(result['lines'])
            self.stats['suricata_rules_generated'] += result['rule_count']
            self.notes.extend(result['notes'])
            
            status = result.get('status', 'full')
            if status == 'full':
                self.stats['fully_converted'] += 1
            elif status == 'partial':
                self.stats['partially_converted'] += 1
            elif status == 'none':
                self.stats['not_convertible'] += 1
            # 'skipped' doesn't count toward conversion stats
        
        # Generate header (after conversion so stats are complete)
        header = self._generate_metadata_header()
        
        # Combine header + rules
        output_lines = header + all_lines
        
        return {
            'lines': output_lines,
            'variables': dict(self.variables),
            'stats': dict(self.stats),
            'notes': list(self.notes),
            'app_stats': dict(self.app_stats),
            'rules_by_pa_name': rules_by_pa_name,
        }

    def _generate_metadata_header(self):
        """Generate the metadata header comment block for the converted file.
        
        Returns list of comment strings.
        """
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        source_file = self.metadata.get('source_file', 'unknown')
        panos_version = self.metadata.get('panos_version', 'unknown')
        vsys_name = self.config.get('vsys_name', 'vsys1')
        
        header = [
            '# ================================================',
            '# Imported from Palo Alto Networks Configuration',
            f'# Source File: {source_file}',
            f'# PAN-OS Version: {panos_version} (detected from XML)',
            f'# Virtual System: {vsys_name}',
            f'# Converted: {now}',
            f'# PA Rules Processed: {self.stats["pa_rules_processed"]}',
            f'# Suricata Rules Generated: {self.stats["suricata_rules_generated"]}',
            f'# Fully Converted: {self.stats["fully_converted"]} | '
            f'Partially Converted: {self.stats["partially_converted"]} | '
            f'Not Convertible: {self.stats["not_convertible"]}',
            '# ================================================',
        ]
        
        if self.stats.get('disabled_imported', 0) > 0:
            header.append(f'# Disabled rules imported as comments: {self.stats["disabled_imported"]}')
        if self.stats.get('disabled_skipped', 0) > 0:
            header.append(f'# Disabled rules skipped: {self.stats["disabled_skipped"]}')
        
        header.append('')
        return header

    def _convert_single_rule(self, rule, options):
        """Convert a single PA security rule to one or more Suricata rule lines.
        
        Handles all conversion scenarios including:
        - Standard IP/port-based rules
        - App-ID Tier 1-5 mappings
        - FQDN address objects → TLS/HTTP domain-matching rule pairs
        - FQDN + non-HTTP/TLS limitation (# [NEEDS MANUAL IP])
        - Built-in URL categories → aws_domain_category rules
        - Custom URL category lists → domain-matching rules
        - GeoIP rules, disabled rules, negation, logging
        
        Args:
            rule: Parsed rule dict from PaloAltoParser
            options: Conversion options dict
            
        Returns:
            dict with:
                'lines': list of output lines (comments + rules)
                'rule_count': number of Suricata rules generated
                'notes': list of conversion notes for this rule
                'status': 'full'|'partial'|'none'
        """
        output_lines = []
        rule_notes = []
        rules_generated = 0
        rule_name = rule.get('name', 'unnamed')
        is_disabled = rule.get('disabled', False)
        
        # Handle disabled rules
        if is_disabled and not options.get('include_disabled', True):
            self.stats['disabled_skipped'] += 1
            return {'lines': [], 'rule_count': 0, 'notes': [], 'status': 'skipped'}
        
        # Build comment block
        comments = self._build_rule_comments(rule, options)
        output_lines.extend(comments)
        
        # Map action
        suricata_action = self._map_action(rule.get('action', 'deny'))
        
        # Resolve source and destination networks
        src_result = self._resolve_source_network(rule)
        dst_result = self._resolve_destination_network(rule)
        
        src_net = src_result['network']
        dst_net = dst_result['network']
        src_geoip = src_result.get('geoip_codes', [])
        dst_geoip = dst_result.get('geoip_codes', [])
        src_fqdns = src_result.get('fqdn_objects', [])
        dst_fqdns = dst_result.get('fqdn_objects', [])
        
        rule_notes.extend(src_result.get('notes', []))
        rule_notes.extend(dst_result.get('notes', []))
        
        # Resolve service/port
        service_info = self._resolve_service_port(rule)
        
        # Determine protocol and port for each application
        proto_port_list = self._determine_protocol_and_port(rule, service_info)
        
        # Check for URL categories (non-'any')
        categories = rule.get('categories', [])
        has_url_categories = categories and not (len(categories) == 1 and categories[0] == 'any')
        
        # Check for FQDN destinations
        has_fqdn_dst = len(dst_fqdns) > 0
        
        # ===================================================================
        # URL Category Handling (takes priority — generates its own rules)
        # ===================================================================
        if has_url_categories:
            cat_result = self._generate_url_category_rules(
                rule, categories, suricata_action, src_net, dst_net,
                src_geoip, dst_geoip, is_disabled, options
            )
            output_lines.extend(cat_result['lines'])
            rules_generated += cat_result['rule_count']
            rule_notes.extend(cat_result['notes'])
            
            # If this rule ONLY has URL categories (no other meaningful content),
            # we're done. But if it also has specific apps or FQDNs, continue
            # generating those rules below.
            is_app_any = (rule.get('applications', ['any']) == ['any'] or 
                          len(rule.get('applications', [])) == 0)
            if is_app_any and not has_fqdn_dst:
                status = self._get_conversion_status(rule_notes)
                output_lines.append('')
                return {
                    'lines': output_lines,
                    'rule_count': rules_generated,
                    'notes': rule_notes,
                    'status': status,
                }
        
        # ===================================================================
        # FQDN Destination Handling
        # ===================================================================
        if has_fqdn_dst:
            fqdn_result = self._generate_fqdn_rules(
                rule, dst_fqdns, proto_port_list, suricata_action,
                src_net, src_geoip, dst_geoip, is_disabled, options
            )
            output_lines.extend(fqdn_result['lines'])
            rules_generated += fqdn_result['rule_count']
            rule_notes.extend(fqdn_result['notes'])
            
            # FQDN rules replace the standard rule generation for this rule
            status = self._get_conversion_status(rule_notes)
            output_lines.append('')
            return {
                'lines': output_lines,
                'rule_count': rules_generated,
                'notes': rule_notes,
                'status': status,
            }
        
        # ===================================================================
        # Standard Rule Generation (IP/port-based, App-ID, GeoIP)
        # ===================================================================
        pa_action = rule.get('action', 'deny')
        
        for pp in proto_port_list:
            protocol = pp['protocol']
            port = pp['port']
            app_name = pp.get('app_name')
            app_tier = pp.get('app_tier')
            domain = pp.get('domain')
            
            rule_notes.extend(pp.get('notes', []))
            
            # Apply app-specific deny action override
            # PA "deny" behavior varies by application (TCP apps send RST, UDP apps drop)
            # The deny_action field in palo_alto_app_map.json specifies the correct mapping
            effective_action = suricata_action
            if pa_action == 'deny' and app_name and app_tier in (1, 2):
                app_info = self.app_mapper.resolve_application(app_name)
                app_deny_action = app_info.get('deny_action', 'drop')
                if app_deny_action == 'reject':
                    # Safety: AWS NF disallows reject on ip and quic protocols
                    if protocol not in ('ip', 'quic'):
                        effective_action = 'reject'
            
            # Determine disabled prefix
            disabled_prefix = ''
            if is_disabled:
                disabled_prefix = '# [DISABLED] '
                self.stats['disabled_imported'] += 1
            elif app_tier == 3:
                disabled_prefix = '# [UNCONVERTIBLE APP-ID] '
            
            # Build msg keyword
            msg_text = self._build_msg_text(rule_name, app_name, app_tier)
            
            # Build keywords list
            keywords = [f'msg:"{msg_text}"']
            
            # Add domain matching for Tier 2 apps — TLS SNI rule
            if app_tier == 2 and domain:
                keywords.append(f'tls.sni; dotprefix; content:"{domain}"; endswith')
            
            # Add geoip keyword if country codes found
            if dst_geoip:
                keywords.append(f'geoip:dst,{",".join(dst_geoip)}')
            if src_geoip:
                keywords.append(f'geoip:src,{",".join(src_geoip)}')
            
            # Add flow keyword (except for icmp which has no client/server flow concept)
            # Note: ip protocol rules GET flow:to_server to avoid SIG_TYPE_IPONLY classification
            # which would cause protocol layering conflicts with app-layer rules
            if protocol not in ('icmp',):
                keywords.append('flow:to_server')
            
            # Handle logging — log-end=no means noalert (for pass rules)
            log_end = rule.get('log_end', 'yes')
            if log_end == 'no' and effective_action == 'pass':
                keywords.append('noalert')
            
            # Add SID and rev
            sid = self._next_sid()
            keywords.append(f'sid:{sid}')
            keywords.append('rev:1')
            
            # Source port is always 'any' for converted rules
            src_port = 'any'
            
            # For ICMP, ports must be 'any'
            if protocol == 'icmp':
                port = 'any'
                src_port = 'any'
            
            # Build the rule string
            rule_str = self._build_suricata_rule_string(
                action=effective_action,
                protocol=protocol,
                src_net=src_net,
                src_port=src_port,
                dst_net=dst_net,
                dst_port=port,
                keywords_list=keywords,
                disabled_prefix=disabled_prefix,
            )
            
            # Add conversion note comments inline if enabled
            if pp.get('notes') and options.get('include_conversion_notes', True):
                for note in pp['notes']:
                    if app_tier == 3:
                        output_lines.append(f'# CONVERSION FAILED: {note}')
                    else:
                        output_lines.append(f'# Note: {note}')
            
            output_lines.append(rule_str)
            rules_generated += 1
            
            # For Tier 2 domain apps, also generate an HTTP rule pair
            if app_tier == 2 and domain:
                http_port = pp.get('http_port', 'any')
                http_result = self._generate_tier2_http_rule(
                    rule_name, app_name, domain, effective_action,
                    src_net, dst_net, port, is_disabled, rule,
                    http_port=http_port
                )
                output_lines.extend(http_result['lines'])
                rules_generated += http_result['rule_count']
        
        # Determine overall conversion status
        status = self._get_conversion_status(rule_notes)
        
        # Add blank line after rule block
        output_lines.append('')
        
        return {
            'lines': output_lines,
            'rule_count': rules_generated,
            'notes': rule_notes,
            'status': status,
        }

    def _map_action(self, pa_action):
        """Map PA action to Suricata action string.
        
        If test_mode is enabled, all actions become 'alert'.
        Adds a conversion note for PA 'deny' -> Suricata 'drop' distinction.
        """
        if self.options.get('test_mode', False):
            return 'alert'
        
        suricata_action = self.ACTION_MAP.get(pa_action, 'drop')
        return suricata_action

    def _classify_member(self, member):
        """Classify a source/destination member value using 6-step precedence.
        
        Returns a dict:
            {'type': 'any'|'address_object'|'address_group'|'inline_ip'|'country_code'|'fqdn'|'unresolved',
             'value': <resolved value or original>,
             'details': <additional info>}
        """
        # 1. Check if value is 'any'
        if member == 'any':
            return {'type': 'any', 'value': 'any', 'details': None}
        
        # 2. Check if value matches a defined address object name
        if member in self.address_objects:
            obj = self.address_objects[member]
            return {'type': 'address_object', 'value': member,
                    'details': obj}
        
        # 3. Check if value matches a defined address group name
        if member in self.address_groups:
            grp = self.address_groups[member]
            return {'type': 'address_group', 'value': member,
                    'details': grp}
        
        # 4. Check if value is a raw IP address or CIDR
        if IP_PATTERN.match(member):
            return {'type': 'inline_ip', 'value': member, 'details': None}
        
        # 5. Check if value is a valid ISO 3166-1 alpha-2 country code
        if self.app_mapper.is_country_code(member):
            return {'type': 'country_code', 'value': member, 'details': None}
        
        # 6. Unresolved reference
        return {'type': 'unresolved', 'value': member, 'details': None}

    def _make_variable_name(self, name):
        """Convert a PA object name to a valid Suricata variable name.
        
        Rules: spaces -> underscores, hyphens -> underscores, all uppercase, $ prefix.
        Returns the name WITHOUT the $ prefix (for storage in variables dict).
        """
        var_name = name.replace(' ', '_').replace('-', '_').upper()
        # Remove any characters that aren't alphanumeric or underscore
        var_name = re.sub(r'[^A-Z0-9_]', '_', var_name)
        # Remove leading/trailing underscores and collapse multiple underscores
        var_name = re.sub(r'_+', '_', var_name).strip('_')
        if not var_name:
            var_name = 'UNNAMED'
        return var_name

    def _convert_port_format(self, pa_port):
        """Convert PA port format to Suricata port format.
        
        PA '80-90'      -> Suricata '[80:90]'
        PA '80,443'     -> Suricata '[80,443]'
        PA '80'         -> Suricata '80'
        PA 'any'        -> Suricata 'any'
        PA '80-90,443'  -> Suricata '[80:90,443]'
        """
        if not pa_port or pa_port == 'any':
            return 'any'
        
        # Single port - no conversion needed
        if pa_port.isdigit():
            return pa_port
        
        # Has ranges or comma-separated values - need Suricata group syntax
        # Replace PA range separator '-' with Suricata ':'
        converted = pa_port.replace('-', ':')
        
        # If it has commas or colons (ranges), wrap in brackets
        if ',' in converted or ':' in converted:
            return f'[{converted}]'
        
        return converted

    def _resolve_network_field(self, members, zones, negate, field_type):
        """Resolve source or destination members to Suricata network field.
        
        Implements the zone interaction logic:
        1. Source/dest is explicit address object -> use object variable (zone in comment only)
        2. Source/dest is 'any' AND zone specified -> use zone variable
        3. Source/dest is 'any' AND zone is 'any' -> use 'any'
        
        Args:
            members: list of source or destination member strings
            zones: list of from_zones or to_zones
            negate: bool, whether negate-source/destination is set
            field_type: 'src' or 'dst' for geoip direction
            
        Returns:
            dict with:
                'network': str (Suricata network field)
                'geoip_codes': list of country codes found (for geoip keyword)
                'fqdn_objects': list of FQDN address objects found
                'notes': list of conversion notes
                'variables_created': dict of new variables
        """
        result = {
            'network': 'any',
            'geoip_codes': [],
            'fqdn_objects': [],
            'notes': [],
            'variables_created': {},
        }
        
        # Check if all members are 'any'
        all_any = (len(members) == 0 or (len(members) == 1 and members[0] == 'any'))
        
        if all_any:
            # Use zone variable if zone is specified and not 'any'
            non_any_zones = [z for z in zones if z != 'any']
            if non_any_zones:
                if len(non_any_zones) == 1:
                    zone_name = non_any_zones[0]
                    var_name = self._make_variable_name(zone_name)
                    # Create zone variable if not already created
                    if var_name not in self.variables:
                        cidr_val = self.zone_cidrs.get(zone_name, '')
                        desc = f'PA Zone: {zone_name}'
                        if not cidr_val:
                            desc += ' - define the CIDR(s) for this zone'
                        self.variables[var_name] = cidr_val
                        result['variables_created'][var_name] = cidr_val
                    network = f'${var_name}'
                else:
                    # Multiple zones - create a group
                    zone_vars = []
                    for z in non_any_zones:
                        vn = self._make_variable_name(z)
                        if vn not in self.variables:
                            cidr_val = self.zone_cidrs.get(z, '')
                            self.variables[vn] = cidr_val
                            result['variables_created'][vn] = cidr_val
                        zone_vars.append(f'${vn}')
                    network = f'[{",".join(zone_vars)}]'
                
                if negate:
                    network = f'!{network}'
                result['network'] = network
                return result
            
            # Zone is also 'any'
            result['network'] = '!any' if negate else 'any'
            return result
        
        # Explicit members specified - classify each one
        ip_parts = []
        country_codes = []
        fqdn_objects = []
        unresolved = []
        
        for member in members:
            classified = self._classify_member(member)
            mtype = classified['type']
            
            if mtype == 'any':
                continue
            elif mtype == 'address_object':
                obj = classified['details']
                obj_type = obj.get('type')
                if obj_type == 'fqdn':
                    fqdn_objects.append({
                        'name': member,
                        'fqdn': obj['value'],
                        'description': obj.get('description', ''),
                    })
                elif obj_type == 'ip-netmask':
                    var_name = self._make_variable_name(member)
                    if var_name not in self.variables:
                        self.variables[var_name] = obj['value']
                        result['variables_created'][var_name] = obj['value']
                    ip_parts.append(f'${var_name}')
                elif obj_type == 'ip-range':
                    var_name = self._make_variable_name(member)
                    if var_name not in self.variables:
                        self.variables[var_name] = obj['value']
                        result['variables_created'][var_name] = obj['value']
                    ip_parts.append(f'${var_name}')
                    result['notes'].append(
                        f'Address object "{member}" uses ip-range ({obj["value"]}). '
                        f'Suricata does not support IP ranges natively. '
                        f'Please convert to CIDR notation in the Variables tab.')
            elif mtype == 'address_group':
                grp = classified['details']
                var_name = self._make_variable_name(member)
                if var_name not in self.variables:
                    # Expand group to IP values
                    expanded_ips = self._expand_group_to_ips(member)
                    self.variables[var_name] = expanded_ips
                    result['variables_created'][var_name] = expanded_ips
                ip_parts.append(f'${var_name}')
            elif mtype == 'inline_ip':
                ip_parts.append(classified['value'])
            elif mtype == 'country_code':
                country_codes.append(classified['value'])
            elif mtype == 'unresolved':
                unresolved.append(classified['value'])
                result['notes'].append(
                    f'Unresolved {field_type} reference "{classified["value"]}" - '
                    f'not found in address objects, groups, or country codes.')
        
        result['geoip_codes'] = country_codes
        result['fqdn_objects'] = fqdn_objects
        
        # Build network field from IP parts
        if ip_parts and not country_codes:
            if len(ip_parts) == 1:
                network = ip_parts[0]
            else:
                network = f'[{",".join(ip_parts)}]'
            if negate:
                network = f'!{network}'
            result['network'] = network
        elif country_codes and not ip_parts:
            # GeoIP only - network stays 'any', geoip keyword added to rule
            result['network'] = '!any' if negate else 'any'
        elif ip_parts and country_codes:
            # Mixed - use IP parts for network, note that rule needs splitting
            if len(ip_parts) == 1:
                network = ip_parts[0]
            else:
                network = f'[{",".join(ip_parts)}]'
            if negate:
                network = f'!{network}'
            result['network'] = network
            result['notes'].append(
                f'Mixed address types: IP addresses and country codes in same '
                f'{field_type} field. Country codes ({",".join(country_codes)}) '
                f'will generate a separate geoip rule.')
        elif not ip_parts and not country_codes and fqdn_objects:
            # FQDN only - handled by Phase 3, use 'any' for now
            result['network'] = '!any' if negate else 'any'
        elif unresolved:
            result['network'] = '!any' if negate else 'any'
        
        return result

    def _expand_group_to_ips(self, group_name):
        """Expand an address group to a Suricata-format IP list string.
        
        Returns string like '[10.1.0.0/32,10.1.2.1/32,10.5.4.1/32]'
        """
        if group_name not in self.address_groups:
            return ''
        
        group = self.address_groups[group_name]
        expanded_members = group.get('expanded_members', [])
        
        ips = []
        for member_name in expanded_members:
            if member_name in self.address_objects:
                obj = self.address_objects[member_name]
                if obj.get('type') in ('ip-netmask', 'ip-range'):
                    ips.append(obj['value'])
                elif obj.get('type') == 'fqdn':
                    # Can't include FQDN in IP group - skip with note
                    pass
            elif IP_PATTERN.match(member_name):
                ips.append(member_name)
        
        if not ips:
            return ''
        if len(ips) == 1:
            return ips[0]
        return f'[{",".join(ips)}]'

    def _resolve_source_network(self, rule):
        """Resolve source network field for a rule."""
        return self._resolve_network_field(
            members=rule.get('sources', ['any']),
            zones=rule.get('from_zones', ['any']),
            negate=rule.get('negate_source', False),
            field_type='src'
        )

    def _resolve_destination_network(self, rule):
        """Resolve destination network field for a rule."""
        return self._resolve_network_field(
            members=rule.get('destinations', ['any']),
            zones=rule.get('to_zones', ['any']),
            negate=rule.get('negate_destination', False),
            field_type='dst'
        )

    def _resolve_service_port(self, rule):
        """Resolve service members to protocol/port info.
        
        Returns list of resolved service dicts:
        [{'protocol': 'tcp'|'udp'|None, 'port': '80'|'any'|None, 'source': '...'}]
        """
        services = rule.get('services', ['any'])
        all_resolved = []
        
        for svc_name in services:
            resolved = self.app_mapper.resolve_service(
                svc_name,
                service_objects=self.service_objects,
                service_groups=self.service_groups
            )
            all_resolved.extend(resolved)
        
        return all_resolved

    def _determine_protocol_and_port(self, rule, service_info):
        """Determine Suricata protocol and port based on application + service.
        
        Logic per spec:
        - If application is specific (not 'any') and service is 'application-default':
          Use application to determine protocol; use app's default port 
          (or 'any' for app-layer protocols)
        - If application is specific AND service is explicit (not application-default):
          Use application for protocol, explicit service for port
        - If application is 'any': use service to determine protocol/port
        - Fallback: ip/any
        
        Returns list of dicts, one per generated rule:
        [{'protocol': str, 'port': str, 'app_name': str|None, 'app_tier': int|None,
          'notes': list, 'domain': str|None}]
        """
        applications = rule.get('applications', ['any'])
        is_app_any = (len(applications) == 1 and applications[0] == 'any') or len(applications) == 0
        
        # Determine if service is application-default, any, or explicit
        svc_source = service_info[0].get('source', '') if service_info else ''
        svc_protocol = service_info[0].get('protocol') if service_info else None
        svc_port = service_info[0].get('port') if service_info else None
        is_svc_app_default = (svc_source == 'application-default')
        is_svc_any = (svc_source == 'any')
        
        results = []
        
        # --- Tier 5: application is 'any' ---
        if is_app_any:
            self.app_stats['tier5_wildcard'] += 1
            
            if is_svc_any:
                # any/any -> ip any any
                results.append({
                    'protocol': 'ip', 'port': 'any',
                    'app_name': None, 'app_tier': 5,
                    'notes': [], 'domain': None,
                })
            elif is_svc_app_default:
                # any/application-default -> ip any any (no app to resolve default from)
                results.append({
                    'protocol': 'ip', 'port': 'any',
                    'app_name': None, 'app_tier': 5,
                    'notes': [],  'domain': None,
                })
            else:
                # any/explicit-service -> use service protocol/port
                for svc in service_info:
                    proto = svc.get('protocol', 'tcp') or 'tcp'
                    port = self._convert_port_format(svc.get('port', 'any'))
                    
                    # Try to upgrade tcp/udp to app-layer protocol based on well-known port
                    upgraded_proto = self._try_upgrade_protocol(proto, port)
                    
                    results.append({
                        'protocol': upgraded_proto, 'port': port,
                        'app_name': None, 'app_tier': 5,
                        'notes': [], 'domain': None,
                    })
            return results
        
        # --- Application is specific (Tier 1/2/3/4) ---
        for app_name in applications:
            app_info = self.app_mapper.resolve_application(app_name)
            tier = app_info['tier']
            
            if tier == 1:
                self.app_stats['tier1_protocol'] += 1
                protocol = app_info['suricata_protocol']
                
                if is_svc_any or is_svc_app_default:
                    # For app-layer protocols (dns, ssh, tls, http, ftp, etc.):
                    #   Suricata detects by content inspection, port can be 'any'
                    #   This is correct for both service:any and application-default
                    # For transport-layer protocols (ms-rdp, mysql, ldap, snmp, etc.):
                    #   Suricata has NO app-layer detection — protocol + port is the
                    #   only way to identify the app. Must use default port even when
                    #   service is 'any', because port 'any' would match ALL tcp/udp
                    #   traffic (not just the target app). This is a known fidelity
                    #   limitation vs PA's App-ID which can detect apps on any port.
                    if app_info.get('app_layer', False):
                        port = 'any'
                    else:
                        port = app_info.get('default_port', 'any') or 'any'
                else:
                    # Explicit service overrides port
                    port = self._convert_port_format(svc_port) if svc_port else 'any'
                
                results.append({
                    'protocol': protocol, 'port': port,
                    'app_name': app_name, 'app_tier': 1,
                    'notes': [], 'domain': None,
                })
                
            elif tier == 2:
                self.app_stats['tier2_domain'] += 1
                # Domain-based: TLS with SNI matching (Phase 3 generates content keywords)
                # Port logic depends on service context:
                #   application-default: TLS=443, HTTP=80 (app's default ports)
                #   any: TLS=any, HTTP=any (no port restriction)
                #   explicit service: both use the explicit port
                if is_svc_any:
                    port = 'any'
                    http_port = 'any'
                elif not is_svc_app_default and svc_port:
                    port = self._convert_port_format(svc_port)
                    http_port = port  # Explicit service overrides both TLS and HTTP port
                else:
                    # application-default: use the app's default ports
                    port = '443'
                    http_port = '80'
                
                results.append({
                    'protocol': 'tls', 'port': port,
                    'app_name': app_name, 'app_tier': 2,
                    'http_port': http_port,
                    'notes': [f'Application "{app_name}" mapped to domain-based rule '
                              f'(tls.sni). Verify domain coverage matches your needs.'],
                    'domain': app_info.get('domain'),
                })
                
            elif tier == 3:
                self.app_stats['tier3_unmappable'] += 1
                # Unmappable - commented out stub
                results.append({
                    'protocol': 'tcp', 'port': 'any',
                    'app_name': app_name, 'app_tier': 3,
                    'notes': [f'Application "{app_name}" has no Suricata equivalent. '
                              f'Palo Alto App-ID uses proprietary behavioral signatures. '
                              f'Rule commented out.'],
                    'domain': None,
                })
        
        return results

    def _try_upgrade_protocol(self, transport_proto, port):
        """Try to upgrade tcp/udp to an app-layer protocol based on well-known port.
        
        Examples: tcp + port 443 -> tls, tcp + port 80 -> http, udp + port 53 -> dns
        """
        if transport_proto not in ('tcp', 'udp'):
            return transport_proto
        
        port_str = str(port).strip('[]')
        
        port_to_app = {
            'tcp': {
                '80': 'http',
                '443': 'tls',
            },
            'udp': {
                '53': 'dns',
                '123': 'ntp',
            }
        }
        
        mapping = port_to_app.get(transport_proto, {})
        return mapping.get(port_str, transport_proto)

    def _build_rule_comments(self, rule, options):
        """Build comment lines to precede a rule.
        
        Returns list of comment strings (each starting with '#').
        """
        comments = []
        rule_name = rule.get('name', 'unnamed')
        disabled_label = ' (DISABLED in PA)' if rule.get('disabled') else ''
        
        comments.append(f'# --- {rule_name}{disabled_label} ---')
        
        # Zone info
        if options.get('include_zone_info', True):
            from_zones = rule.get('from_zones', [])
            to_zones = rule.get('to_zones', [])
            from_str = ', '.join(from_zones) if from_zones else 'any'
            to_str = ', '.join(to_zones) if to_zones else 'any'
            comments.append(f'# Zone: {from_str} -> {to_str}')
        
        # Applications
        apps = rule.get('applications', [])
        if apps and apps != ['any']:
            comments.append(f'# PA Applications: {", ".join(apps)}')
        
        # Description
        if options.get('include_descriptions', True):
            desc = rule.get('description', '')
            if desc:
                comments.append(f'# Description: {desc}')
        
        # Tags
        tags = rule.get('tags', [])
        if tags:
            comments.append(f'# Tags: {", ".join(tags)}')
        
        # Log start note
        if rule.get('log_start') == 'yes':
            comments.append('# Note: PA log-start=yes (no Suricata equivalent for connection start logging)')
        
        # PA action note for deny mapping
        pa_action = rule.get('action', '')
        if pa_action == 'deny':
            if options.get('include_conversion_notes', True):
                comments.append('# Note: PA action "deny" mapped per application definition '
                                '(TCP apps -> reject/RST, UDP/other -> drop). '
                                'PA deny behavior varies by application.')
        
        # Rule type note
        rule_type = rule.get('rule_type', '')
        if rule_type and rule_type != 'universal':
            comments.append(f'# PA Rule Type: {rule_type} (Suricata does not distinguish zone-based rule types)')
        
        # Source user note
        source_users = rule.get('source_users', [])
        if source_users and source_users != ['any']:
            comments.append(f'# PA Source User: {", ".join(source_users)} (not convertible - no Suricata equivalent)')
        
        # Security profiles note
        if rule.get('has_security_profiles'):
            comments.append('# PA Security Profiles attached (not convertible to Suricata)')
        
        return comments

    def _build_suricata_rule_string(self, action, protocol, src_net, src_port,
                                     dst_net, dst_port, keywords_list,
                                     disabled_prefix=''):
        """Build a complete Suricata rule string.
        
        Args:
            action: 'pass', 'drop', 'reject', 'alert'
            protocol: 'tls', 'http', 'tcp', 'ip', etc.
            src_net: source network field
            src_port: source port field
            dst_net: destination network field
            dst_port: destination port field
            keywords_list: list of keyword strings for rule body (e.g. ['msg:"..."', 'sid:100'])
            disabled_prefix: '# [DISABLED] ' or '# [UNCONVERTIBLE APP-ID] ' etc.
            
        Returns: Complete rule string
        """
        keywords_str = '; '.join(keywords_list)
        rule = f'{action} {protocol} {src_net} {src_port} -> {dst_net} {dst_port} ({keywords_str};)'
        if disabled_prefix:
            rule = f'{disabled_prefix}{rule}'
        return rule

    def _next_sid(self):
        """Get the next SID and increment the counter."""
        sid = self.current_sid
        self.current_sid += 1
        return sid

    def _get_conversion_status(self, rule_notes):
        """Determine conversion status from a rule's notes.
        
        Returns: 'full', 'partial', or 'none'
        """
        has_error = False
        has_warning = False
        
        for note in rule_notes:
            note_lower = note.lower() if isinstance(note, str) else ''
            if 'no suricata equivalent' in note_lower or 'commented out' in note_lower:
                has_error = True
            elif ('warning' in note_lower or 'verify' in note_lower or
                  'review' in note_lower or 'needs manual' in note_lower):
                has_warning = True
        
        if has_error:
            return 'none'
        elif has_warning:
            return 'partial'
        return 'full'

    # =================================================================
    # Phase 3: App-ID, FQDN, and URL Category Conversion Methods
    # =================================================================

    def _build_msg_text(self, rule_name, app_name=None, app_tier=None, suffix=None):
        """Build a Suricata msg keyword value.
        
        Args:
            rule_name: PA rule name
            app_name: Optional application name
            app_tier: Optional tier (1,2,3,5)
            suffix: Optional suffix string (e.g., 'TLS', 'HTTP')
            
        Returns:
            Escaped message string (without surrounding quotes)
        """
        msg_parts = [rule_name]
        if app_name and app_tier in (1, 2):
            msg_parts.append(f'[{app_name}]')
        elif app_name and app_tier == 3:
            msg_parts.append(f'[PA App-ID: {app_name}]')
        if suffix:
            msg_parts.append(suffix)
        msg_text = ' '.join(msg_parts)
        # Escape any double quotes in the message
        msg_text = msg_text.replace('"', '\\"')
        return msg_text

    def _generate_tier2_http_rule(self, rule_name, app_name, domain, suricata_action,
                                   src_net, dst_net, tls_port, is_disabled, rule,
                                   http_port=None):
        """Generate an HTTP companion rule for a Tier 2 domain-based application.
        
        When a Tier 2 app generates a TLS SNI rule, we also generate an HTTP
        host-matching rule to cover non-HTTPS traffic to the same domain.
        
        Args:
            rule_name: PA rule name
            app_name: Application name (e.g., 'facebook')
            domain: Domain to match (e.g., '.facebook.com')
            suricata_action: Mapped Suricata action
            src_net: Source network field
            dst_net: Destination network field
            tls_port: Port used in the TLS rule (for reference)
            is_disabled: Whether the PA rule is disabled
            rule: Original rule dict (for logging settings)
            http_port: Destination port for the HTTP rule. When service is
                'application-default', this should be '80' (default HTTP port).
                When service is 'any', this should be 'any'. When an explicit
                service is specified, this matches the explicit port.
            
        Returns:
            dict with 'lines' and 'rule_count'
        """
        lines = []
        
        disabled_prefix = ''
        if is_disabled:
            disabled_prefix = '# [DISABLED] '
            self.stats['disabled_imported'] += 1
        
        msg_text = self._build_msg_text(rule_name, app_name, 2, 'HTTP')
        
        keywords = [f'msg:"{msg_text}"']
        keywords.append(f'http.host; dotprefix; content:"{domain}"; endswith')
        keywords.append('flow:to_server')
        
        # Handle logging
        log_end = rule.get('log_end', 'yes')
        if log_end == 'no' and suricata_action == 'pass':
            keywords.append('noalert')
        
        sid = self._next_sid()
        keywords.append(f'sid:{sid}')
        keywords.append('rev:1')
        
        # Use the http_port parameter if provided, otherwise default to 'any'
        resolved_http_port = http_port if http_port is not None else 'any'

        rule_str = self._build_suricata_rule_string(
            action=suricata_action,
            protocol='http',
            src_net=src_net,
            src_port='any',
            dst_net=dst_net,
            dst_port=resolved_http_port,
            keywords_list=keywords,
            disabled_prefix=disabled_prefix,
        )
        lines.append(rule_str)
        
        return {'lines': lines, 'rule_count': 1}

    def _generate_fqdn_rules(self, rule, dst_fqdns, proto_port_list, suricata_action,
                              src_net, src_geoip, dst_geoip, is_disabled, options):
        """Generate Suricata rules for FQDN address object destinations.
        
        For each FQDN destination, determines whether the application protocol
        supports domain-based matching:
        
        - HTTP/TLS protocols: Generate proper tls.sni + http.host rule pairs
        - Non-HTTP/TLS protocols (SSH, FTP, etc.): Generate commented-out
          stub rules with # [NEEDS MANUAL IP] prefix and warning
        - application: any: Generate TLS + HTTP domain rules (best effort)
          plus a warning about non-HTTP/TLS traffic
        
        Args:
            rule: Parsed rule dict
            dst_fqdns: List of FQDN objects [{'name': str, 'fqdn': str, 'description': str}]
            proto_port_list: Protocol/port list from _determine_protocol_and_port
            suricata_action: Mapped action string
            src_net: Source network field
            src_geoip: Source country codes
            dst_geoip: Destination country codes
            is_disabled: Whether rule is disabled
            options: Conversion options
            
        Returns:
            dict with 'lines', 'rule_count', 'notes'
        """
        lines = []
        notes = []
        rule_count = 0
        rule_name = rule.get('name', 'unnamed')
        
        for fqdn_obj in dst_fqdns:
            fqdn = fqdn_obj['fqdn']
            fqdn_obj_name = fqdn_obj['name']
            
            # Determine what protocols are requested
            for pp in proto_port_list:
                protocol = pp['protocol']
                port = pp['port']
                app_name = pp.get('app_name')
                app_tier = pp.get('app_tier')
                
                # Check if this protocol supports domain matching
                can_match_domain = protocol in self.DOMAIN_MATCHABLE_PROTOCOLS
                
                # Tier 5 (application: any) — generate TLS + HTTP domain rules
                if app_tier == 5 or app_name is None:
                    fqdn_tls_http_result = self._generate_fqdn_tls_http_pair(
                        rule_name, fqdn, suricata_action, src_net,
                        src_geoip, dst_geoip, is_disabled, rule, options
                    )
                    lines.extend(fqdn_tls_http_result['lines'])
                    rule_count += fqdn_tls_http_result['rule_count']
                    notes.extend(fqdn_tls_http_result['notes'])
                    
                    # Add warning that non-HTTP/TLS traffic won't be matched
                    warn_note = (f'FQDN "{fqdn}" generates TLS/HTTP domain rules only. '
                                 f'Non-HTTP/TLS traffic to this domain will not be matched by domain name.')
                    notes.append(warn_note)
                    if options.get('include_conversion_notes', True):
                        lines.append(f'# Note: {warn_note}')
                    break  # Only generate one TLS+HTTP pair per FQDN
                
                elif can_match_domain:
                    # Protocol supports domain matching (tls or http)
                    if protocol == 'tls':
                        fqdn_tls_http_result = self._generate_fqdn_tls_http_pair(
                            rule_name, fqdn, suricata_action, src_net,
                            src_geoip, dst_geoip, is_disabled, rule, options,
                            app_name=app_name
                        )
                        lines.extend(fqdn_tls_http_result['lines'])
                        rule_count += fqdn_tls_http_result['rule_count']
                        notes.extend(fqdn_tls_http_result['notes'])
                    elif protocol == 'http':
                        # HTTP only — generate http.host rule
                        result = self._generate_single_fqdn_rule(
                            rule_name, fqdn, 'http', 'http.host', 'any',
                            suricata_action, src_net, src_geoip, dst_geoip,
                            is_disabled, rule, app_name=app_name
                        )
                        lines.extend(result['lines'])
                        rule_count += result['rule_count']
                
                else:
                    # Non-HTTP/TLS protocol — FQDN limitation
                    manual_ip_result = self._generate_fqdn_manual_ip_rule(
                        rule_name, fqdn, fqdn_obj_name, protocol, port,
                        suricata_action, src_net, src_geoip, dst_geoip,
                        is_disabled, rule, options, app_name=app_name
                    )
                    lines.extend(manual_ip_result['lines'])
                    rule_count += manual_ip_result['rule_count']
                    notes.extend(manual_ip_result['notes'])
        
        return {'lines': lines, 'rule_count': rule_count, 'notes': notes}

    def _generate_fqdn_tls_http_pair(self, rule_name, fqdn, suricata_action,
                                      src_net, src_geoip, dst_geoip,
                                      is_disabled, rule, options, app_name=None):
        """Generate a TLS SNI + HTTP host rule pair for an FQDN destination.
        
        This is the standard FQDN conversion — generates two rules:
        1. TLS rule with tls.sni content matching
        2. HTTP rule with http.host content matching
        
        Args:
            rule_name: PA rule name
            fqdn: Domain name (e.g., 'ftp.example.com')
            suricata_action: Mapped action
            src_net: Source network
            src_geoip, dst_geoip: Country codes
            is_disabled: Whether disabled
            rule: Original rule dict
            options: Conversion options
            app_name: Optional application name for msg
            
        Returns:
            dict with 'lines', 'rule_count', 'notes'
        """
        lines = []
        notes = []
        rule_count = 0
        
        # Ensure domain has a dot prefix for matching subdomains
        domain_content = fqdn if fqdn.startswith('.') else fqdn
        
        # TLS rule
        tls_result = self._generate_single_fqdn_rule(
            rule_name, domain_content, 'tls', 'tls.sni', '443',
            suricata_action, src_net, src_geoip, dst_geoip,
            is_disabled, rule, app_name=app_name, suffix='TLS'
        )
        lines.extend(tls_result['lines'])
        rule_count += tls_result['rule_count']
        
        # HTTP rule
        http_result = self._generate_single_fqdn_rule(
            rule_name, domain_content, 'http', 'http.host', 'any',
            suricata_action, src_net, src_geoip, dst_geoip,
            is_disabled, rule, app_name=app_name, suffix='HTTP'
        )
        lines.extend(http_result['lines'])
        rule_count += http_result['rule_count']
        
        return {'lines': lines, 'rule_count': rule_count, 'notes': notes}

    def _generate_single_fqdn_rule(self, rule_name, domain, protocol, content_keyword,
                                    port, suricata_action, src_net, src_geoip, dst_geoip,
                                    is_disabled, rule, app_name=None, suffix=None):
        """Generate a single FQDN-based Suricata rule.
        
        Args:
            rule_name: PA rule name
            domain: Domain to match
            protocol: 'tls' or 'http'
            content_keyword: 'tls.sni' or 'http.host'
            port: Destination port
            suricata_action: Action string
            src_net: Source network
            src_geoip, dst_geoip: Country codes
            is_disabled: Whether disabled
            rule: Original rule dict
            app_name: Optional app name for msg
            suffix: Optional suffix for msg (e.g., 'TLS', 'HTTP')
            
        Returns:
            dict with 'lines', 'rule_count'
        """
        lines = []
        
        disabled_prefix = ''
        if is_disabled:
            disabled_prefix = '# [DISABLED] '
            self.stats['disabled_imported'] += 1
        
        msg_text = self._build_msg_text(rule_name, app_name, 1 if app_name else None, suffix)
        
        keywords = [f'msg:"{msg_text}"']
        keywords.append(f'{content_keyword}; content:"{domain}"; endswith; nocase')
        
        # Add geoip if needed
        if dst_geoip:
            keywords.append(f'geoip:dst,{",".join(dst_geoip)}')
        if src_geoip:
            keywords.append(f'geoip:src,{",".join(src_geoip)}')
        
        keywords.append('flow:to_server')
        
        # Handle logging
        log_end = rule.get('log_end', 'yes')
        if log_end == 'no' and suricata_action == 'pass':
            keywords.append('noalert')
        
        sid = self._next_sid()
        keywords.append(f'sid:{sid}')
        keywords.append('rev:1')
        
        rule_str = self._build_suricata_rule_string(
            action=suricata_action,
            protocol=protocol,
            src_net=src_net,
            src_port='any',
            dst_net='any',
            dst_port=port,
            keywords_list=keywords,
            disabled_prefix=disabled_prefix,
        )
        lines.append(rule_str)
        
        return {'lines': lines, 'rule_count': 1}

    def _generate_fqdn_manual_ip_rule(self, rule_name, fqdn, fqdn_obj_name, protocol,
                                       port, suricata_action, src_net, src_geoip,
                                       dst_geoip, is_disabled, rule, options,
                                       app_name=None):
        """Generate a commented-out rule for FQDN + non-HTTP/TLS protocol.
        
        This handles the critical limitation where Suricata cannot match
        domain names for protocols that don't carry hostname fields
        (SSH, FTP, SMTP, etc.).
        
        Generates:
        - Warning comment explaining the limitation
        - ACTION REQUIRED comment with instructions
        - Commented-out rule with # [NEEDS MANUAL IP] prefix
        - Creates a variable for the FQDN that needs manual IP resolution
        
        Args:
            rule_name: PA rule name
            fqdn: Domain name
            fqdn_obj_name: PA address object name
            protocol: Non-domain-matchable protocol (e.g., 'ftp', 'ssh')
            port: Destination port
            suricata_action: Mapped action
            src_net: Source network
            src_geoip, dst_geoip: Country codes
            is_disabled: Whether disabled
            rule: Original rule dict
            options: Conversion options
            app_name: Optional application name
            
        Returns:
            dict with 'lines', 'rule_count', 'notes'
        """
        lines = []
        notes = []
        
        # Create a variable for the FQDN that needs manual IP resolution
        var_name = self._make_variable_name(fqdn_obj_name)
        if var_name not in self.variables:
            self.variables[var_name] = ''  # Empty — user must define with IP
        
        # Warning comments
        if options.get('include_conversion_notes', True):
            lines.append(f'# WARNING: FQDN "{fqdn}" cannot be used with {protocol} protocol.')
            lines.append(f'# Suricata only supports domain matching for HTTP (http.host) and TLS (tls.sni).')
            lines.append(f'# Palo Alto resolves FQDNs to IP addresses at the firewall - Suricata cannot.')
            lines.append(f'#')
            lines.append(f'# ACTION REQUIRED: Replace ${var_name} with the server\'s IP address or CIDR.')
            lines.append(f'# Example: In the Variables tab, set ${var_name} = <resolved_ip>/32')
        
        # Build the commented-out rule
        msg_text = self._build_msg_text(rule_name, app_name, 1 if app_name else None)
        
        keywords = [f'msg:"{msg_text}"']
        
        if dst_geoip:
            keywords.append(f'geoip:dst,{",".join(dst_geoip)}')
        if src_geoip:
            keywords.append(f'geoip:src,{",".join(src_geoip)}')
        
        # Add flow keyword (except for icmp which has no client/server flow concept)
        if protocol not in ('icmp',):
            keywords.append('flow:to_server')
        
        log_end = rule.get('log_end', 'yes')
        if log_end == 'no' and suricata_action == 'pass':
            keywords.append('noalert')
        
        sid = self._next_sid()
        keywords.append(f'sid:{sid}')
        keywords.append('rev:1')
        
        # For ICMP, ports must be 'any'
        if protocol == 'icmp':
            port = 'any'
        
        rule_str = self._build_suricata_rule_string(
            action=suricata_action,
            protocol=protocol,
            src_net=src_net,
            src_port='any',
            dst_net=f'${var_name}',
            dst_port=port if port else 'any',
            keywords_list=keywords,
            disabled_prefix='# [NEEDS MANUAL IP] ',
        )
        lines.append(rule_str)
        
        note = (f'FQDN "{fqdn}" cannot be used with {protocol} protocol. '
                f'Suricata only supports domain matching for HTTP/TLS. '
                f'Needs manual IP resolution in ${var_name} variable.')
        notes.append(note)
        
        return {'lines': lines, 'rule_count': 1, 'notes': notes}

    def _generate_url_category_rules(self, rule, categories, suricata_action,
                                      src_net, dst_net, src_geoip, dst_geoip,
                                      is_disabled, options):
        """Generate Suricata rules for URL category filtering.
        
        Implements the category disambiguation logic:
        1. Check if category is a built-in PA URL category → aws_domain_category
        2. Check if category is a custom URL category list → extract domains → domain rules
        3. Otherwise → unresolved reference warning
        
        Built-in categories generate a single aws_domain_category rule with
        comma-separated AWS category names.
        
        Custom URL categories extract individual domains and generate
        TLS SNI + HTTP host matching rule pairs for each domain.
        
        Args:
            rule: Parsed rule dict
            categories: List of category names from the rule
            suricata_action: Mapped action string
            src_net, dst_net: Network fields
            src_geoip, dst_geoip: Country codes
            is_disabled: Whether rule is disabled
            options: Conversion options
            
        Returns:
            dict with 'lines', 'rule_count', 'notes'
        """
        lines = []
        notes = []
        rule_count = 0
        rule_name = rule.get('name', 'unnamed')
        
        # Separate built-in categories from custom categories
        builtin_aws_categories = []
        builtin_confidences = []
        custom_category_domains = []
        unresolved_categories = []
        
        for cat_name in categories:
            if cat_name == 'any':
                continue
            
            # Step 1: Check built-in PA URL category
            resolved = self.app_mapper.resolve_category(cat_name)
            if resolved:
                builtin_aws_categories.append(resolved['aws_category'])
                builtin_confidences.append(resolved['confidence'])
                continue
            
            # Step 2: Check custom URL category list
            if cat_name in self.custom_url_categories:
                custom_cat = self.custom_url_categories[cat_name]
                domains = custom_cat.get('domains', [])
                if domains:
                    custom_category_domains.append({
                        'category_name': cat_name,
                        'domains': domains,
                    })
                else:
                    note = (f'Custom URL category "{cat_name}" has no domains. '
                            f'No rules generated for this category.')
                    notes.append(note)
                    if options.get('include_conversion_notes', True):
                        lines.append(f'# Note: {note}')
                continue
            
            # Step 3: Unresolved
            unresolved_categories.append(cat_name)
        
        # Generate aws_domain_category rule for built-in categories
        if builtin_aws_categories:
            cat_result = self._generate_builtin_category_rule(
                rule_name, builtin_aws_categories, builtin_confidences,
                suricata_action, src_net, dst_net, src_geoip, dst_geoip,
                is_disabled, rule, options, categories
            )
            lines.extend(cat_result['lines'])
            rule_count += cat_result['rule_count']
            notes.extend(cat_result['notes'])
        
        # Generate domain-matching rules for custom URL categories
        for custom_cat in custom_category_domains:
            cat_name = custom_cat['category_name']
            domains = custom_cat['domains']
            
            if options.get('include_conversion_notes', True):
                lines.append(f'# Custom URL category "{cat_name}" - domains extracted:')
            
            for domain in domains:
                domain_result = self._generate_fqdn_tls_http_pair(
                    rule_name, domain, suricata_action, src_net,
                    src_geoip, dst_geoip, is_disabled, rule, options
                )
                lines.extend(domain_result['lines'])
                rule_count += domain_result['rule_count']
            
            note = (f'Custom URL category "{cat_name}" expanded to {len(domains)} '
                    f'domain(s): {", ".join(domains)}')
            notes.append(note)
        
        # Handle unresolved categories
        for cat_name in unresolved_categories:
            note = (f'URL category "{cat_name}" not found in built-in PA categories '
                    f'or custom URL category lists. No rule generated.')
            notes.append(note)
            if options.get('include_conversion_notes', True):
                lines.append(f'# WARNING: {note}')
        
        return {'lines': lines, 'rule_count': rule_count, 'notes': notes}

    def _generate_builtin_category_rule(self, rule_name, aws_categories, confidences,
                                         suricata_action, src_net, dst_net,
                                         src_geoip, dst_geoip, is_disabled,
                                         rule, options, original_pa_categories):
        """Generate a Suricata rule using aws_domain_category for built-in URL categories.
        
        Multiple AWS categories are combined into a single rule with
        comma-separated category names.
        
        Args:
            rule_name: PA rule name
            aws_categories: List of mapped AWS category names
            confidences: List of confidence levels per category
            suricata_action: Mapped action
            src_net, dst_net: Network fields
            src_geoip, dst_geoip: Country codes
            is_disabled: Whether disabled
            rule: Original rule dict
            options: Conversion options
            original_pa_categories: Original PA category names (for notes)
            
        Returns:
            dict with 'lines', 'rule_count', 'notes'
        """
        lines = []
        notes = []
        
        disabled_prefix = ''
        if is_disabled:
            disabled_prefix = '# [DISABLED] '
            self.stats['disabled_imported'] += 1
        
        # Build PA category reference for msg
        pa_cat_str = ', '.join(c for c in original_pa_categories if c != 'any')
        msg_text = f'{rule_name} [PA URL Categories: {pa_cat_str}]'
        msg_text = msg_text.replace('"', '\\"')
        
        # Build keywords
        keywords = [f'msg:"{msg_text}"']
        
        # aws_domain_category with comma-separated category names
        aws_cat_str = ','.join(aws_categories)
        keywords.append(f'aws_domain_category:{aws_cat_str}')
        
        # Add geoip if needed
        if dst_geoip:
            keywords.append(f'geoip:dst,{",".join(dst_geoip)}')
        if src_geoip:
            keywords.append(f'geoip:src,{",".join(src_geoip)}')
        
        keywords.append('flow:to_server')
        
        # Handle logging
        log_end = rule.get('log_end', 'yes')
        if log_end == 'no' and suricata_action == 'pass':
            keywords.append('noalert')
        
        sid = self._next_sid()
        keywords.append(f'sid:{sid}')
        keywords.append('rev:1')
        
        rule_str = self._build_suricata_rule_string(
            action=suricata_action,
            protocol='tls',
            src_net=src_net,
            src_port='any',
            dst_net=dst_net,
            dst_port='any',
            keywords_list=keywords,
            disabled_prefix=disabled_prefix,
        )
        
        # Add confidence notes for medium/low confidence mappings
        for i, confidence in enumerate(confidences):
            if confidence in ('medium', 'low'):
                cat_name = original_pa_categories[i] if i < len(original_pa_categories) else '?'
                aws_cat = aws_categories[i] if i < len(aws_categories) else '?'
                conf_note = (f'PA category "{cat_name}" mapped to AWS "{aws_cat}" '
                             f'({confidence} confidence). Verify category coverage.')
                notes.append(conf_note)
                if options.get('include_conversion_notes', True):
                    lines.append(f'# Note: {conf_note}')
        
        lines.append(rule_str)
        
        return {'lines': lines, 'rule_count': 1, 'notes': notes}


class PaloAltoImporter:
    """Main orchestrator for Palo Alto Networks configuration import workflow.

    Manages the multi-step UI dialog flow:
    - Beta warning dialog (once per session)
    - Step 1: File selection + options
    - Step 1.5: Zone-to-CIDR mapping (if zones found)
    - Step 2: Configuration scope selection (vsys, rules)
    - Step 3: Conversion preview (stats, rules, notes, SID, test mode)
    - Import execution: apply rules to editor, create variables, metadata header

    Integration:
    - Change tracking (log import operation)
    - Undo support (save undo state before import)
    - Test mode (convert all actions to alert)
    - Rule analyzer integration (optional post-import analysis)
    """

    def __init__(self, parent_app):
        """Initialize PaloAltoImporter with reference to parent application.

        Args:
            parent_app: Reference to main SuricataRuleGenerator instance
        """
        self.parent = parent_app
        self._beta_warning_shown = False
        self._beta_warning_suppressed = False
        self.app_mapper = None  # Lazy-loaded

    def _ensure_app_mapper(self):
        """Lazy-load the PaloAltoAppMapper."""
        if self.app_mapper is None:
            self.app_mapper = PaloAltoAppMapper()

    # =================================================================
    # Main Entry Point
    # =================================================================

    def import_configuration(self):
        """Main entry point for Palo Alto configuration import.

        Called from File menu. Checks for unsaved changes, shows beta
        warning, then launches the multi-step import wizard.
        """
        # Check for unsaved changes (same pattern as stateful rule importer)
        if self.parent.modified:
            save_result = self.parent.ask_save_changes()
            if save_result is False:
                return  # User cancelled

        # Show beta warning (once per session, unless suppressed)
        if not self._beta_warning_suppressed:
            if not self._show_beta_warning():
                return  # User cancelled

        # Lazy-load app mapper
        self._ensure_app_mapper()

        # Launch Step 1: File selection
        self._show_step1_file_selection()

    # =================================================================
    # Beta Warning Dialog
    # =================================================================

    def _show_beta_warning(self):
        """Show beta warning dialog. Returns True to proceed, False to cancel."""
        if self._beta_warning_shown and self._beta_warning_suppressed:
            return True

        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Beta Feature")
        dialog.geometry("500x320")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)

        # Center dialog
        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 200,
            self.parent.root.winfo_rooty() + 150
        ))

        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Warning icon and title
        ttk.Label(main_frame, text="⚠️ Beta Feature",
                 font=("TkDefaultFont", 14, "bold")).pack(pady=(0, 15))

        # Warning text
        warning_text = (
            "The Palo Alto Configuration Import feature is currently in BETA.\n\n"
            "While the converter handles many common PA rule patterns, you should "
            "carefully review all generated Suricata rules before deploying to production.\n\n"
            "Palo Alto App-ID uses proprietary deep packet inspection that cannot be "
            "fully replicated in Suricata. Some rules may require manual adjustment."
        )
        ttk.Label(main_frame, text=warning_text,
                 font=("TkDefaultFont", 9), wraplength=450,
                 justify=tk.LEFT).pack(pady=(0, 15))

        # Suppress checkbox
        suppress_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(main_frame, text="Don't show this warning again this session",
                        variable=suppress_var).pack(anchor=tk.W, pady=(0, 15))

        # Result tracking
        result = [False]

        def on_ok():
            result[0] = True
            self._beta_warning_shown = True
            if suppress_var.get():
                self._beta_warning_suppressed = True
            dialog.destroy()

        def on_close():
            dialog.destroy()

        # OK button
        ttk.Button(main_frame, text="OK - I Understand",
                  command=on_ok).pack()

        dialog.protocol("WM_DELETE_WINDOW", on_close)
        dialog.wait_window()

        return result[0]

    # =================================================================
    # Step 1: File Selection + Options
    # =================================================================

    def _show_step1_file_selection(self):
        """Show Step 1 dialog: file selection and import options."""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Import Palo Alto Configuration - Step 1")
        dialog.geometry("600x400")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)

        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 150,
            self.parent.root.winfo_rooty() + 100
        ))

        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(main_frame, text="Import Palo Alto Configuration",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 15))

        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="Select XML Configuration File")
        file_frame.pack(fill=tk.X, pady=(0, 15))

        file_content = ttk.Frame(file_frame)
        file_content.pack(fill=tk.X, padx=10, pady=10)

        file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_content, textvariable=file_path_var, width=50)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        def browse_file():
            filename = filedialog.askopenfilename(
                title="Select Palo Alto XML Configuration",
                filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
            )
            if filename:
                file_path_var.set(filename)

        ttk.Button(file_content, text="Browse...", command=browse_file).pack(side=tk.RIGHT)

        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Options")
        options_frame.pack(fill=tk.X, pady=(0, 15))

        opts_content = ttk.Frame(options_frame)
        opts_content.pack(padx=10, pady=10)

        include_disabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts_content, text="Import disabled rules as comments",
                        variable=include_disabled_var).pack(anchor=tk.W, pady=2)

        include_descriptions_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts_content, text="Include rule descriptions as comments",
                        variable=include_descriptions_var).pack(anchor=tk.W, pady=2)

        include_zone_info_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts_content, text="Include zone information in comments",
                        variable=include_zone_info_var).pack(anchor=tk.W, pady=2)

        include_notes_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts_content, text="Include conversion notes for unmapped items",
                        variable=include_notes_var).pack(anchor=tk.W, pady=2)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        def on_next():
            xml_path = file_path_var.get().strip()
            if not xml_path:
                messagebox.showerror("Validation Error", "Please select an XML configuration file.")
                return
            if not os.path.isfile(xml_path):
                messagebox.showerror("File Not Found", f"File not found:\n{xml_path}")
                return

            # Store options
            options = {
                'include_disabled': include_disabled_var.get(),
                'include_descriptions': include_descriptions_var.get(),
                'include_zone_info': include_zone_info_var.get(),
                'include_conversion_notes': include_notes_var.get(),
            }

            dialog.destroy()

            # Parse the XML file
            self._parse_and_proceed(xml_path, options)

        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Next >", command=on_next).pack(side=tk.RIGHT)

    def _parse_and_proceed(self, xml_path, options):
        """Parse the XML file and proceed to next step."""
        try:
            parser = PaloAltoParser(self.app_mapper)
            # First parse with default vsys to get vsys list
            parsed = parser.parse_config(xml_path, vsys_name='vsys1')
        except ValueError as e:
            messagebox.showerror("Parse Error", f"Failed to parse configuration:\n\n{str(e)}")
            return
        except FileNotFoundError as e:
            messagebox.showerror("File Error", str(e))
            return
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred:\n\n{str(e)}")
            return

        # Check if zones were found — show zone mapping dialog
        zones = parsed.get('zones', {})
        zones_referenced = parsed.get('summary', {}).get('zones_referenced', [])

        if zones_referenced:
            self._show_step1_5_zone_mapping(xml_path, parsed, options, zones_referenced)
        else:
            # No zones — skip to Step 2
            options['zone_cidrs'] = {}
            self._show_step2_scope_selection(xml_path, parsed, options)

    # =================================================================
    # Step 1.5: Zone-to-CIDR Mapping
    # =================================================================

    def _show_step1_5_zone_mapping(self, xml_path, parsed, options, zones_referenced):
        """Show zone-to-CIDR mapping dialog."""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Import Palo Alto Configuration - Zone Mapping")
        dialog.geometry("600x420")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)

        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 130,
            self.parent.root.winfo_rooty() + 80
        ))

        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(main_frame, text="Zone Network Mapping",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 10))

        ttk.Label(main_frame,
                 text="The following zones were found in the PA config.\n"
                      "Define network CIDRs for each zone, or leave blank to fill in later\n"
                      "from the Variables tab.",
                 font=("TkDefaultFont", 9), justify=tk.LEFT).pack(pady=(0, 15))

        # Zone entries
        zone_frame = ttk.Frame(main_frame)
        zone_frame.pack(fill=tk.X, pady=(0, 15))

        # Column headers
        ttk.Label(zone_frame, text="Zone Name", font=("TkDefaultFont", 9, "bold"),
                 width=15).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(zone_frame, text="Network CIDR(s)", font=("TkDefaultFont", 9, "bold")).grid(
            row=0, column=1, sticky=tk.W, padx=5, pady=2)

        zone_vars = {}
        for i, zone_name in enumerate(sorted(zones_referenced)):
            ttk.Label(zone_frame, text=zone_name, width=15).grid(
                row=i + 1, column=0, sticky=tk.W, padx=5, pady=3)
            var = tk.StringVar()
            entry = ttk.Entry(zone_frame, textvariable=var, width=45)
            entry.grid(row=i + 1, column=1, sticky=tk.W + tk.E, padx=5, pady=3)
            zone_vars[zone_name] = var

        zone_frame.columnconfigure(1, weight=1)

        # Info note
        ttk.Label(main_frame,
                 text="Zones with empty definitions will be created as variables with no value.\n"
                      "You can define them later in the Variables tab before saving or exporting.",
                 font=("TkDefaultFont", 8), foreground="#666666",
                 justify=tk.LEFT).pack(pady=(0, 15))

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        def on_back():
            dialog.destroy()
            self._show_step1_file_selection()

        def on_next():
            # Collect zone CIDRs
            zone_cidrs = {}
            for zone_name, var in zone_vars.items():
                cidr_val = var.get().strip()
                if cidr_val:
                    zone_cidrs[zone_name] = cidr_val
            options['zone_cidrs'] = zone_cidrs
            dialog.destroy()
            self._show_step2_scope_selection(xml_path, parsed, options)

        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Next >", command=on_next).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="< Back", command=on_back).pack(side=tk.RIGHT, padx=(0, 5))

    # =================================================================
    # Step 2: Configuration Scope Selection
    # =================================================================

    def _show_step2_scope_selection(self, xml_path, parsed, options):
        """Show Step 2 dialog: scope selection (vsys, rules)."""
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Import Palo Alto Configuration - Step 2")
        dialog.geometry("620x580")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)

        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 120,
            self.parent.root.winfo_rooty() + 60
        ))

        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(main_frame, text="Import Scope",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 15))

        # Configuration summary
        summary = parsed.get('summary', {})
        metadata = parsed.get('metadata', {})

        summary_frame = ttk.LabelFrame(main_frame, text="Configuration Summary")
        summary_frame.pack(fill=tk.X, pady=(0, 15))

        summary_content = ttk.Frame(summary_frame)
        summary_content.pack(padx=10, pady=10)

        summary_items = [
            f"Virtual System: {parsed.get('vsys_name', 'vsys1')}",
            f"PAN-OS Version: {metadata.get('panos_version', 'unknown')}",
            f"Security Rules: {summary.get('rule_count', 0)} ({summary.get('disabled_count', 0)} disabled)",
            f"Address Objects: {summary.get('address_object_count', 0)}",
            f"Address Groups: {summary.get('address_group_count', 0)}",
            f"Service Objects: {summary.get('service_object_count', 0)}",
            f"Service Groups: {summary.get('service_group_count', 0)}",
            f"FQDN Objects: {summary.get('fqdn_object_count', 0)}",
        ]

        apps = summary.get('applications_referenced', [])
        if apps:
            summary_items.append(f"Applications Referenced: {len(apps)}")

        cats = summary.get('categories_referenced', [])
        if cats:
            summary_items.append(f"URL Categories Referenced: {len(cats)}")

        zones_ref = summary.get('zones_referenced', [])
        if zones_ref:
            summary_items.append(f"Zones Referenced: {len(zones_ref)} ({', '.join(zones_ref)})")

        for item_text in summary_items:
            ttk.Label(summary_content, text=item_text,
                     font=("TkDefaultFont", 9)).pack(anchor=tk.W, pady=1)

        # Virtual System selector (if multiple)
        vsys_list = parsed.get('vsys_list', [])
        if len(vsys_list) > 1:
            vsys_frame = ttk.Frame(main_frame)
            vsys_frame.pack(fill=tk.X, pady=(0, 10))
            ttk.Label(vsys_frame, text="Virtual System:").pack(side=tk.LEFT, padx=(0, 5))
            vsys_names = [v['name'] for v in vsys_list]
            vsys_var = tk.StringVar(value=parsed.get('vsys_name', 'vsys1'))
            ttk.Combobox(vsys_frame, textvariable=vsys_var, values=vsys_names,
                        state="readonly", width=15).pack(side=tk.LEFT)
        else:
            vsys_var = tk.StringVar(value=parsed.get('vsys_name', 'vsys1'))

        # Rule selection
        rules = parsed.get('security_rules', [])
        rule_select_frame = ttk.LabelFrame(main_frame, text="Import Rules")
        rule_select_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        import_mode_var = tk.StringVar(value="all")
        ttk.Radiobutton(rule_select_frame, text=f"All rules ({len(rules)} rules)",
                        variable=import_mode_var, value="all").pack(anchor=tk.W, padx=10, pady=(10, 5))
        ttk.Radiobutton(rule_select_frame, text="Select rules to import...",
                        variable=import_mode_var, value="select").pack(anchor=tk.W, padx=10, pady=(0, 5))

        # Rule checklist (shown when "select" is chosen)
        rule_list_frame = ttk.Frame(rule_select_frame)
        rule_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Create scrollable listbox with checkboxes
        rule_canvas = tk.Canvas(rule_list_frame, height=150)
        rule_scrollbar = ttk.Scrollbar(rule_list_frame, orient=tk.VERTICAL, command=rule_canvas.yview)
        rule_inner = ttk.Frame(rule_canvas)

        rule_inner.bind("<Configure>",
                       lambda e: rule_canvas.configure(scrollregion=rule_canvas.bbox("all")))
        rule_canvas.create_window((0, 0), window=rule_inner, anchor="nw")
        rule_canvas.configure(yscrollcommand=rule_scrollbar.set)

        rule_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rule_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Enable mousewheel scrolling
        def on_rule_mousewheel(event):
            rule_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        rule_canvas.bind("<Enter>", lambda e: rule_canvas.bind_all("<MouseWheel>", on_rule_mousewheel))
        rule_canvas.bind("<Leave>", lambda e: rule_canvas.unbind_all("<MouseWheel>"))

        rule_check_vars = {}
        for rule_data in rules:
            rule_name = rule_data.get('name', 'unnamed')
            action = rule_data.get('action', 'deny')
            disabled = rule_data.get('disabled', False)
            desc = rule_data.get('description', '')

            label_text = f"{rule_name} [{action}]"
            if disabled:
                label_text += " (disabled)"
            if desc:
                label_text += f" - {desc[:50]}"

            var = tk.BooleanVar(value=True)
            rule_check_vars[rule_name] = var
            ttk.Checkbutton(rule_inner, text=label_text, variable=var).pack(anchor=tk.W, pady=1)

        # Show/hide rule list based on selection mode
        def on_mode_change(*args):
            if import_mode_var.get() == "select":
                rule_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
            else:
                rule_list_frame.pack_forget()

        import_mode_var.trace_add('write', on_mode_change)
        # Initially hide if "all" selected
        if import_mode_var.get() == "all":
            rule_list_frame.pack_forget()

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        def on_back():
            dialog.destroy()
            zones_ref = parsed.get('summary', {}).get('zones_referenced', [])
            if zones_ref:
                self._show_step1_5_zone_mapping(xml_path, parsed, options, zones_ref)
            else:
                self._show_step1_file_selection()

        def on_next():
            # Determine selected rules
            if import_mode_var.get() == "select":
                selected_rule_names = {name for name, var in rule_check_vars.items() if var.get()}
                if not selected_rule_names:
                    messagebox.showwarning("No Rules Selected",
                                          "Please select at least one rule to import.")
                    return
                # Filter parsed rules
                filtered_rules = [r for r in rules if r.get('name', 'unnamed') in selected_rule_names]
                parsed['security_rules'] = filtered_rules
            else:
                selected_rule_names = None  # All rules

            # Check if vsys changed (re-parse needed)
            new_vsys = vsys_var.get()
            if new_vsys != parsed.get('vsys_name', 'vsys1') and len(vsys_list) > 1:
                try:
                    parser = PaloAltoParser(self.app_mapper)
                    parsed_new = parser.parse_config(xml_path, vsys_name=new_vsys)
                    if selected_rule_names is not None:
                        parsed_new['security_rules'] = [
                            r for r in parsed_new.get('security_rules', [])
                            if r.get('name', 'unnamed') in selected_rule_names
                        ]
                    parsed.update(parsed_new)
                except Exception as e:
                    messagebox.showerror("Parse Error", f"Failed to parse vsys '{new_vsys}':\n\n{str(e)}")
                    return

            dialog.destroy()
            self._show_step3_preview(xml_path, parsed, options)

        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Next >", command=on_next).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="< Back", command=on_back).pack(side=tk.RIGHT, padx=(0, 5))

    # =================================================================
    # Step 3: Conversion Preview
    # =================================================================

    def _show_step3_preview(self, xml_path, parsed, options):
        """Show Step 3 dialog: conversion preview with summary, rules, notes."""
        # Perform conversion
        from src.core.version import get_main_version, get_palo_alto_importer_version

        # Get starting SID default
        existing_sids = [r.sid for r in self.parent.rules
                        if not getattr(r, 'is_comment', False)
                        and not getattr(r, 'is_blank', False)
                        and hasattr(r, 'sid')]
        default_start_sid = max(existing_sids, default=99) + 1 if existing_sids else 100

        # Build dialog
        dialog = tk.Toplevel(self.parent.root)
        dialog.title("Import Palo Alto Configuration - Step 3")
        dialog.geometry("850x750")
        dialog.transient(self.parent.root)
        dialog.grab_set()
        dialog.resizable(True, True)

        dialog.geometry("+%d+%d" % (
            self.parent.root.winfo_rootx() + 50,
            self.parent.root.winfo_rooty() + 30
        ))

        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(main_frame, text="Conversion Preview",
                 font=("TkDefaultFont", 12, "bold")).pack(pady=(0, 10))

        # Options row: Starting SID, Test mode, Run analyzer
        opts_row = ttk.Frame(main_frame)
        opts_row.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(opts_row, text="Starting SID:").pack(side=tk.LEFT, padx=(0, 5))
        sid_var = tk.StringVar(value=str(default_start_sid))
        sid_entry = ttk.Entry(opts_row, textvariable=sid_var, width=8)
        sid_entry.pack(side=tk.LEFT, padx=(0, 15))

        test_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts_row, text="Test mode (convert all actions to alert)",
                        variable=test_mode_var).pack(side=tk.LEFT, padx=(0, 15))

        run_analyzer_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts_row, text="Run rule analyzer after import",
                        variable=run_analyzer_var).pack(side=tk.LEFT)

        # Refresh button
        def refresh_preview():
            try:
                start_sid = int(sid_var.get())
            except ValueError:
                messagebox.showerror("Validation Error", "Starting SID must be a valid number.")
                return
            run_conversion(start_sid, test_mode_var.get())

        ttk.Button(opts_row, text="Refresh Preview", command=refresh_preview).pack(side=tk.RIGHT)

        # Conversion summary panel
        summary_frame = ttk.LabelFrame(main_frame, text="Conversion Summary")
        summary_frame.pack(fill=tk.X, pady=(0, 10))

        summary_label = ttk.Label(summary_frame, text="Converting...",
                                 font=("TkDefaultFont", 9), justify=tk.LEFT)
        summary_label.pack(padx=10, pady=10, anchor=tk.W)

        # Rules preview (scrollable text)
        preview_frame = ttk.LabelFrame(main_frame, text="Rules Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        preview_text = tk.Text(preview_frame, wrap=tk.NONE, font=("Consolas", 9),
                              height=15, state=tk.DISABLED)
        preview_v_scroll = ttk.Scrollbar(preview_frame, orient=tk.VERTICAL, command=preview_text.yview)
        preview_h_scroll = ttk.Scrollbar(preview_frame, orient=tk.HORIZONTAL, command=preview_text.xview)
        preview_text.configure(yscrollcommand=preview_v_scroll.set,
                              xscrollcommand=preview_h_scroll.set)

        preview_text.grid(row=0, column=0, sticky="nsew", padx=(5, 0), pady=(5, 0))
        preview_v_scroll.grid(row=0, column=1, sticky="ns", pady=(5, 0))
        preview_h_scroll.grid(row=1, column=0, sticky="ew", padx=(5, 0))

        preview_frame.grid_rowconfigure(0, weight=1)
        preview_frame.grid_columnconfigure(0, weight=1)

        # Conversion notes panel (scrollable)
        notes_frame = ttk.LabelFrame(main_frame, text="Conversion Notes")
        notes_frame.pack(fill=tk.X, pady=(0, 10))

        notes_text = tk.Text(notes_frame, wrap=tk.WORD, font=("TkDefaultFont", 9),
                            height=6, state=tk.DISABLED)
        notes_scroll = ttk.Scrollbar(notes_frame, orient=tk.VERTICAL, command=notes_text.yview)
        notes_text.configure(yscrollcommand=notes_scroll.set)

        notes_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        notes_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 5), pady=5)

        # Store conversion result for import
        conversion_result = [None]

        def run_conversion(start_sid, test_mode):
            """Run the conversion and update preview panels."""
            conv_options = dict(options)
            conv_options['starting_sid'] = start_sid
            conv_options['test_mode'] = test_mode

            try:
                converter = PaloAltoConverter(parsed, self.app_mapper, conv_options)
                result = converter.convert()
                conversion_result[0] = result
            except Exception as e:
                messagebox.showerror("Conversion Error",
                                    f"Failed to convert rules:\n\n{str(e)}")
                return

            # Update summary
            stats = result['stats']
            app_stats = result['app_stats']
            summary_text = (
                f"PA Rules Processed: {stats['pa_rules_processed']}   |   "
                f"Suricata Rules Generated: {stats['suricata_rules_generated']}\n"
                f"  Fully Converted: {stats['fully_converted']}   |   "
                f"  Partially Converted: {stats['partially_converted']}   |   "
                f"  Not Convertible: {stats['not_convertible']}\n"
                f"Variables Created: {len(result['variables'])}   |   "
                f"App Mappings: Tier1={app_stats['tier1_protocol']}, "
                f"Tier2={app_stats['tier2_domain']}, "
                f"Tier3={app_stats['tier3_unmappable']}, "
                f"Wildcard={app_stats['tier5_wildcard']}"
            )
            if stats.get('disabled_imported', 0) > 0:
                summary_text += f"\nDisabled rules imported as comments: {stats['disabled_imported']}"
            if stats.get('disabled_skipped', 0) > 0:
                summary_text += f"   |   Disabled rules skipped: {stats['disabled_skipped']}"

            summary_label.config(text=summary_text)

            # Update rules preview
            preview_text.config(state=tk.NORMAL)
            preview_text.delete("1.0", tk.END)
            for line in result['lines']:
                preview_text.insert(tk.END, line + '\n')
            preview_text.config(state=tk.DISABLED)

            # Update notes
            notes_text.config(state=tk.NORMAL)
            notes_text.delete("1.0", tk.END)
            if result['notes']:
                for note in result['notes']:
                    notes_text.insert(tk.END, f"• {note}\n")
            else:
                notes_text.insert(tk.END, "No conversion notes — all rules converted successfully.")
            notes_text.config(state=tk.DISABLED)

        # Run initial conversion
        try:
            start_sid = int(sid_var.get())
        except ValueError:
            start_sid = 100
        run_conversion(start_sid, test_mode_var.get())

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(5, 0))

        def on_back():
            dialog.destroy()
            self._show_step2_scope_selection(xml_path, parsed, options)

        def on_export_report():
            if conversion_result[0] is None:
                messagebox.showerror("No Conversion", "No conversion results available. Please refresh the preview.")
                return
            self._export_conversion_report(conversion_result[0], parsed, options)

        def on_import():
            if conversion_result[0] is None:
                messagebox.showerror("No Conversion", "No conversion results available. Please refresh the preview.")
                return

            # Validate starting SID
            try:
                final_start_sid = int(sid_var.get())
            except ValueError:
                messagebox.showerror("Validation Error", "Starting SID must be a valid number.")
                return

            # Re-run conversion with final settings if they changed
            current_test_mode = test_mode_var.get()
            result = conversion_result[0]

            dialog.destroy()

            # Execute the import
            self._execute_import(
                result, parsed, options,
                run_analyzer=run_analyzer_var.get(),
                test_mode=current_test_mode
            )

        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Import", command=on_import).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Export Report...", command=on_export_report).pack(side=tk.RIGHT, padx=(0, 5))
        ttk.Button(button_frame, text="< Back", command=on_back).pack(side=tk.RIGHT, padx=(0, 5))

    # =================================================================
    # Import Execution
    # =================================================================

    def _execute_import(self, conversion_result, parsed, options, run_analyzer=False, test_mode=False):
        """Execute the import: apply converted rules to the editor.

        Args:
            conversion_result: Dict from PaloAltoConverter.convert()
            parsed: Parsed config dict
            options: Import options
            run_analyzer: Whether to run rule analyzer after import
            test_mode: Whether test mode is enabled
        """
        from src.core.suricata_rule import SuricataRule

        # Save undo state before import
        self.parent.save_undo_state()

        # Clear current rules, variables, and tags (same pattern as stateful_rule_importer)
        self.parent.rules.clear()
        self.parent.variables.clear()
        self.parent.tags.clear()

        # Parse the output lines into SuricataRule objects
        rules_to_import = []
        for line in conversion_result['lines']:
            line = line.rstrip()

            # Blank lines
            if not line:
                blank_rule = SuricataRule()
                blank_rule.is_blank = True
                rules_to_import.append(blank_rule)
                continue

            # Comment lines (including # [DISABLED], # [UNCONVERTIBLE APP-ID], # [NEEDS MANUAL IP])
            if line.startswith('#'):
                comment_rule = SuricataRule()
                comment_rule.is_comment = True
                comment_rule.comment_text = line
                rules_to_import.append(comment_rule)
                continue

            # Try to parse as a Suricata rule
            try:
                rule = SuricataRule.from_string(line)
                if rule:
                    rules_to_import.append(rule)
                else:
                    # Could not parse — add as comment
                    comment_rule = SuricataRule()
                    comment_rule.is_comment = True
                    comment_rule.comment_text = f"# [PARSE ERROR] {line}"
                    rules_to_import.append(comment_rule)
            except Exception:
                # Parse failed — add as comment
                comment_rule = SuricataRule()
                comment_rule.is_comment = True
                comment_rule.comment_text = f"# [PARSE ERROR] {line}"
                rules_to_import.append(comment_rule)

        # Set rules
        self.parent.rules = rules_to_import

        # Import variables with descriptions
        converter_vars = conversion_result.get('variables', {})
        for var_name_raw, var_value in converter_vars.items():
            # Ensure variable name has $ prefix for storage
            if not var_name_raw.startswith('$') and not var_name_raw.startswith('@'):
                var_name = f'${var_name_raw}'
            else:
                var_name = var_name_raw

            # Determine description based on zone CIDRs or address objects
            description = ''
            # Check if this is a zone variable
            zones = parsed.get('zones', {})
            zone_cidrs = options.get('zone_cidrs', {})
            for zone_name in zones:
                expected_var = var_name_raw.upper().replace('-', '_').replace(' ', '_')
                zone_upper = zone_name.upper().replace('-', '_').replace(' ', '_')
                if expected_var == zone_upper:
                    description = f'PA Zone: {zone_name}'
                    if not var_value:
                        description += ' - define the CIDR(s) for this zone'
                    break

            # Check address objects for descriptions
            if not description:
                for addr_name, addr_obj in parsed.get('address_objects', {}).items():
                    expected_var = addr_name.upper().replace('-', '_').replace(' ', '_')
                    clean_raw = var_name_raw.upper().replace('-', '_').replace(' ', '_')
                    if clean_raw == expected_var:
                        addr_desc = addr_obj.get('description', '')
                        if addr_desc:
                            description = f'PA: {addr_desc}'
                        else:
                            description = f'PA address object: {addr_name}'
                        break

            # Store in new dict format
            self.parent.variables[var_name] = {
                "definition": var_value if var_value else "",
                "description": description,
            }

        # Detect and add any additional variables used in rules
        detected_vars = set()
        for rule in self.parent.rules:
            if getattr(rule, 'is_comment', False) or getattr(rule, 'is_blank', False):
                continue
            rule_str = rule.to_string() if hasattr(rule, 'to_string') else ''
            import re as re_mod
            found = re_mod.findall(r'\$[A-Za-z_][A-Za-z0-9_]*', rule_str)
            detected_vars.update(found)

        for var in detected_vars:
            if var not in self.parent.variables:
                if var == '$HOME_NET':
                    self.parent.variables[var] = {
                        "definition": "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]",
                        "description": "",
                    }
                elif var == '$EXTERNAL_NET':
                    # Will be auto-generated
                    pass
                else:
                    self.parent.variables[var] = {
                        "definition": "",
                        "description": "",
                    }

        # Update UI
        self.parent.current_file = None
        self.parent.modified = True
        self.parent.refresh_table(preserve_selection=False)
        self.parent.auto_detect_variables()
        self.parent.refresh_tags_table()
        self.parent.update_status_bar()

        # Log import operation if tracking enabled
        if self.parent.tracking_enabled:
            stats = conversion_result.get('stats', {})
            self.parent.add_history_entry('palo_alto_import', {
                'source_file': parsed.get('metadata', {}).get('source_file', 'unknown'),
                'panos_version': parsed.get('metadata', {}).get('panos_version', 'unknown'),
                'vsys': parsed.get('vsys_name', 'vsys1'),
                'pa_rules_processed': stats.get('pa_rules_processed', 0),
                'suricata_rules_generated': stats.get('suricata_rules_generated', 0),
                'fully_converted': stats.get('fully_converted', 0),
                'partially_converted': stats.get('partially_converted', 0),
                'not_convertible': stats.get('not_convertible', 0),
                'variables_created': len(converter_vars),
                'test_mode': test_mode,
            })

        # Show success message
        stats = conversion_result.get('stats', {})
        success_msg = (
            f"Palo Alto configuration imported successfully!\n\n"
            f"PA Rules Processed: {stats.get('pa_rules_processed', 0)}\n"
            f"Suricata Rules Generated: {stats.get('suricata_rules_generated', 0)}\n"
            f"Variables Created: {len(converter_vars)}\n\n"
            f"Review the imported rules in the editor.\n"
            f"Define any empty zone variables in the Variables tab."
        )
        messagebox.showinfo("Import Complete", success_msg)

        # Run rule analyzer if requested
        if run_analyzer:
            try:
                self.parent.review_rules()
            except Exception as e:
                messagebox.showwarning("Analyzer Warning",
                                      f"Import completed but rule analyzer encountered an error:\n\n{str(e)}")

    # =================================================================
    # Conversion Report Export
    # =================================================================

    def _export_conversion_report(self, conversion_result, parsed, options):
        """Show save dialog and export the conversion report.

        Supports text (.txt) and HTML (.html) formats.

        Args:
            conversion_result: Dict from PaloAltoConverter.convert()
            parsed: Parsed config dict
            options: Import options
        """
        filename = filedialog.asksaveasfilename(
            title="Export Conversion Report",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("HTML files", "*.html"),
                ("All files", "*.*"),
            ],
            initialfile="pa_conversion_report",
        )
        if not filename:
            return

        try:
            if filename.lower().endswith('.html') or filename.lower().endswith('.htm'):
                content = self._generate_html_report(conversion_result, parsed, options)
            else:
                content = self._generate_text_report(conversion_result, parsed, options)

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)

            messagebox.showinfo("Report Exported",
                                f"Conversion report saved to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Export Error",
                                 f"Failed to export report:\n\n{str(e)}")

    def _generate_text_report(self, conversion_result, parsed, options):
        """Generate a plain text conversion report.

        Returns the full report as a string.
        """
        from src.core.version import get_main_version, get_palo_alto_importer_version

        stats = conversion_result.get('stats', {})
        app_stats = conversion_result.get('app_stats', {})
        notes = conversion_result.get('notes', [])
        variables = conversion_result.get('variables', {})
        rules_by_pa = conversion_result.get('rules_by_pa_name', {})
        metadata = parsed.get('metadata', {})
        summary = parsed.get('summary', {})

        lines = []
        sep = '=' * 72

        # Header
        lines.append(sep)
        lines.append('PALO ALTO CONFIGURATION CONVERSION REPORT')
        lines.append(sep)
        lines.append('')
        lines.append(f'Generated:       {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        lines.append(f'Tool Version:    Suricata Generator v{get_main_version()} '
                      f'(PA Importer v{get_palo_alto_importer_version()})')
        lines.append(f'Mapping Version: {self.app_mapper.get_mapping_version() if self.app_mapper else "N/A"}')
        lines.append(f'Source File:     {metadata.get("source_file", "unknown")}')
        lines.append(f'PAN-OS Version:  {metadata.get("panos_version", "unknown")} '
                      f'(detail: {metadata.get("detail_version", "unknown")})')
        lines.append(f'Virtual System:  {parsed.get("vsys_name", "vsys1")}')
        lines.append('')

        # Summary Statistics
        lines.append(sep)
        lines.append('CONVERSION SUMMARY')
        lines.append(sep)
        lines.append('')
        lines.append(f'PA Rules Processed:       {stats.get("pa_rules_processed", 0)}')
        lines.append(f'Suricata Rules Generated: {stats.get("suricata_rules_generated", 0)}')
        lines.append(f'  Fully Converted:        {stats.get("fully_converted", 0)}')
        lines.append(f'  Partially Converted:    {stats.get("partially_converted", 0)}')
        lines.append(f'  Not Convertible:        {stats.get("not_convertible", 0)}')
        if stats.get('disabled_imported', 0) > 0:
            lines.append(f'  Disabled (imported):    {stats["disabled_imported"]}')
        if stats.get('disabled_skipped', 0) > 0:
            lines.append(f'  Disabled (skipped):     {stats["disabled_skipped"]}')
        lines.append(f'Variables Created:        {len(variables)}')
        lines.append('')

        # Source Configuration Summary
        lines.append(f'Source Configuration:')
        lines.append(f'  Security Rules:      {summary.get("rule_count", 0)} '
                      f'({summary.get("disabled_count", 0)} disabled)')
        lines.append(f'  Address Objects:     {summary.get("address_object_count", 0)}')
        lines.append(f'  Address Groups:      {summary.get("address_group_count", 0)}')
        lines.append(f'  Service Objects:     {summary.get("service_object_count", 0)}')
        lines.append(f'  Service Groups:      {summary.get("service_group_count", 0)}')
        lines.append(f'  FQDN Objects:        {summary.get("fqdn_object_count", 0)}')
        lines.append(f'  Custom URL Categories: {summary.get("custom_url_category_count", 0)}')
        zones_ref = summary.get('zones_referenced', [])
        if zones_ref:
            lines.append(f'  Zones Referenced:    {len(zones_ref)} ({", ".join(zones_ref)})')
        lines.append('')

        # Application Mapping Statistics
        lines.append(sep)
        lines.append('APPLICATION MAPPING RESULTS')
        lines.append(sep)
        lines.append('')
        lines.append(f'Tier 1 - Direct Protocol Mapped (high confidence):  {app_stats.get("tier1_protocol", 0)}')
        lines.append(f'Tier 2 - Domain-Based Mapped (medium confidence):   {app_stats.get("tier2_domain", 0)}')
        lines.append(f'Tier 3 - Unmappable (commented out):                {app_stats.get("tier3_unmappable", 0)}')
        lines.append(f'Tier 5 - Wildcard/any (port-based):                 {app_stats.get("tier5_wildcard", 0)}')
        lines.append('')

        # Per-Rule Conversion Details
        lines.append(sep)
        lines.append('PER-RULE CONVERSION DETAILS')
        lines.append(sep)
        lines.append('')

        for rule in parsed.get('security_rules', []):
            rule_name = rule.get('name', 'unnamed')
            pa_action = rule.get('action', 'unknown')
            disabled = rule.get('disabled', False)
            description = rule.get('description', '')

            rule_result = rules_by_pa.get(rule_name, {})
            status = rule_result.get('status', 'unknown')
            rule_count = rule_result.get('rule_count', 0)
            rule_notes = rule_result.get('notes', [])

            status_icon = {'full': '[OK]', 'partial': '[WARN]', 'none': '[FAIL]',
                           'skipped': '[SKIP]'}.get(status, '[?]')

            lines.append(f'  {status_icon} {rule_name}')
            lines.append(f'      PA Action: {pa_action}' +
                          (' (DISABLED)' if disabled else ''))
            if description:
                lines.append(f'      Description: {description}')
            lines.append(f'      Suricata Rules Generated: {rule_count}')

            apps = rule.get('applications', [])
            if apps and apps != ['any']:
                lines.append(f'      Applications: {", ".join(apps)}')

            if rule_notes:
                for note in rule_notes:
                    lines.append(f'      Note: {note}')

            lines.append('')

        # Object Mapping Table
        lines.append(sep)
        lines.append('VARIABLE MAPPINGS')
        lines.append(sep)
        lines.append('')

        if variables:
            max_name_len = max(len(n) for n in variables.keys()) + 1
            for var_name, var_value in sorted(variables.items()):
                display_val = var_value if var_value else '(undefined)'
                lines.append(f'  ${var_name:<{max_name_len}} = {display_val}')
        else:
            lines.append('  (no variables created)')
        lines.append('')

        # URL Category Mapping Table
        cats_referenced = summary.get('categories_referenced', [])
        if cats_referenced:
            lines.append(sep)
            lines.append('URL CATEGORY MAPPINGS')
            lines.append(sep)
            lines.append('')

            for cat_name in cats_referenced:
                if self.app_mapper:
                    resolved = self.app_mapper.resolve_category(cat_name)
                    if resolved:
                        lines.append(f'  {cat_name:<40} -> {resolved["aws_category"]} '
                                      f'({resolved["confidence"]} confidence)')
                    else:
                        custom_cats = parsed.get('custom_url_categories', {})
                        if cat_name in custom_cats:
                            domains = custom_cats[cat_name].get('domains', [])
                            lines.append(f'  {cat_name:<40} -> Custom URL List '
                                          f'({len(domains)} domain(s))')
                        else:
                            lines.append(f'  {cat_name:<40} -> NOT MAPPED')
            lines.append('')

        # Conversion Notes
        if notes:
            lines.append(sep)
            lines.append('ALL CONVERSION NOTES')
            lines.append(sep)
            lines.append('')

            for i, note in enumerate(notes, 1):
                lines.append(f'  {i}. {note}')
            lines.append('')

        # Recommendations
        lines.append(sep)
        lines.append('RECOMMENDATIONS')
        lines.append(sep)
        lines.append('')

        recs = []
        if stats.get('not_convertible', 0) > 0:
            recs.append('Review rules marked [FAIL] above. These contain PA App-ID '
                         'applications with no Suricata equivalent. Consider port-based '
                         'blocking or AWS domain categories as alternatives.')
        if stats.get('partially_converted', 0) > 0:
            recs.append('Review rules marked [WARN] above. These were partially converted '
                         'and may need manual adjustment for full coverage.')

        empty_vars = [n for n, v in variables.items() if not v]
        if empty_vars:
            recs.append(f'{len(empty_vars)} variable(s) have no definition '
                         f'(e.g., zone variables). Define their CIDR values in the '
                         f'Variables tab before saving or exporting.')

        if app_stats.get('tier2_domain', 0) > 0:
            recs.append('Domain-based rules (Tier 2) approximate PA App-ID by matching '
                         'on TLS SNI / HTTP Host. Verify the domain patterns cover all '
                         'traffic for those applications.')

        recs.append('Run the Rule Analyzer after import to check for syntax issues, '
                     'best practice violations, and optimization opportunities.')

        recs.append('Test imported rules in alert-only mode before deploying to '
                     'production. Use the "Test mode" checkbox to convert all actions to alert.')

        for i, rec in enumerate(recs, 1):
            lines.append(f'  {i}. {rec}')
        lines.append('')

        # Footer
        lines.append(sep)
        lines.append('END OF REPORT')
        lines.append(sep)

        return '\n'.join(lines)

    def _generate_html_report(self, conversion_result, parsed, options):
        """Generate an HTML formatted conversion report.

        Returns the full HTML document as a string.
        """
        from src.core.version import get_main_version, get_palo_alto_importer_version

        stats = conversion_result.get('stats', {})
        app_stats = conversion_result.get('app_stats', {})
        notes = conversion_result.get('notes', [])
        variables = conversion_result.get('variables', {})
        rules_by_pa = conversion_result.get('rules_by_pa_name', {})
        metadata = parsed.get('metadata', {})
        summary = parsed.get('summary', {})

        def esc(text):
            """Escape HTML special characters."""
            if not isinstance(text, str):
                text = str(text)
            return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        main_ver = get_main_version()
        pa_ver = get_palo_alto_importer_version()
        map_ver = self.app_mapper.get_mapping_version() if self.app_mapper else 'N/A'

        # Build HTML
        html = []
        html.append('<!DOCTYPE html>')
        html.append('<html lang="en"><head><meta charset="UTF-8">')
        html.append('<title>Palo Alto Conversion Report</title>')
        html.append('<style>')
        html.append('body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; '
                     'margin: 20px; color: #333; background: #fafafa; }')
        html.append('h1 { color: #1a5276; border-bottom: 3px solid #2980b9; padding-bottom: 10px; }')
        html.append('h2 { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }')
        html.append('table { border-collapse: collapse; width: 100%; margin: 10px 0; }')
        html.append('th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }')
        html.append('th { background-color: #2980b9; color: white; }')
        html.append('tr:nth-child(even) { background-color: #f2f2f2; }')
        html.append('.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); '
                     'gap: 10px; margin: 15px 0; }')
        html.append('.stat-card { background: white; border: 1px solid #ddd; border-radius: 8px; '
                     'padding: 15px; text-align: center; }')
        html.append('.stat-card .number { font-size: 28px; font-weight: bold; color: #2980b9; }')
        html.append('.stat-card .label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; }')
        html.append('.status-ok { color: #27ae60; font-weight: bold; }')
        html.append('.status-warn { color: #f39c12; font-weight: bold; }')
        html.append('.status-fail { color: #e74c3c; font-weight: bold; }')
        html.append('.status-skip { color: #95a5a6; font-weight: bold; }')
        html.append('.note { background: #fef9e7; border-left: 4px solid #f39c12; padding: 8px 12px; '
                     'margin: 5px 0; font-size: 13px; }')
        html.append('.rec { background: #eaf2f8; border-left: 4px solid #2980b9; padding: 8px 12px; '
                     'margin: 5px 0; font-size: 13px; }')
        html.append('.meta { color: #7f8c8d; font-size: 13px; }')
        html.append('code { background: #ecf0f1; padding: 2px 5px; border-radius: 3px; font-size: 13px; }')
        html.append('</style>')
        html.append('</head><body>')

        # Title
        html.append(f'<h1>Palo Alto Configuration Conversion Report</h1>')
        html.append(f'<p class="meta">Generated: {esc(now)} &nbsp;|&nbsp; '
                     f'Suricata Generator v{esc(main_ver)} (PA Importer v{esc(pa_ver)}) &nbsp;|&nbsp; '
                     f'Mapping v{esc(map_ver)}</p>')
        html.append(f'<p class="meta">Source: <strong>{esc(metadata.get("source_file", "unknown"))}</strong> '
                     f'&nbsp;|&nbsp; PAN-OS: {esc(metadata.get("panos_version", "unknown"))} '
                     f'&nbsp;|&nbsp; vsys: {esc(parsed.get("vsys_name", "vsys1"))}</p>')

        # Summary Cards
        html.append('<h2>Conversion Summary</h2>')
        html.append('<div class="stat-grid">')
        cards = [
            (stats.get('pa_rules_processed', 0), 'PA Rules'),
            (stats.get('suricata_rules_generated', 0), 'Suricata Rules'),
            (stats.get('fully_converted', 0), 'Fully Converted'),
            (stats.get('partially_converted', 0), 'Partially Converted'),
            (stats.get('not_convertible', 0), 'Not Convertible'),
            (len(variables), 'Variables Created'),
        ]
        for num, label in cards:
            html.append(f'<div class="stat-card"><div class="number">{num}</div>'
                         f'<div class="label">{esc(label)}</div></div>')
        html.append('</div>')

        # App Mapping Stats
        html.append('<h2>Application Mapping Results</h2>')
        html.append('<table><tr><th>Tier</th><th>Description</th><th>Count</th></tr>')
        tier_rows = [
            ('1', 'Direct Protocol Mapped (high confidence)', app_stats.get('tier1_protocol', 0)),
            ('2', 'Domain-Based Mapped (medium confidence)', app_stats.get('tier2_domain', 0)),
            ('3', 'Unmappable (commented out)', app_stats.get('tier3_unmappable', 0)),
            ('5', 'Wildcard/any (port-based)', app_stats.get('tier5_wildcard', 0)),
        ]
        for tier, desc, count in tier_rows:
            html.append(f'<tr><td>{tier}</td><td>{esc(desc)}</td><td>{count}</td></tr>')
        html.append('</table>')

        # Per-Rule Details
        html.append('<h2>Per-Rule Conversion Details</h2>')
        html.append('<table><tr><th>Status</th><th>PA Rule Name</th><th>Action</th>'
                     '<th>Rules Gen.</th><th>Notes</th></tr>')

        for rule in parsed.get('security_rules', []):
            rule_name = rule.get('name', 'unnamed')
            pa_action = rule.get('action', 'unknown')
            disabled = rule.get('disabled', False)

            rule_result = rules_by_pa.get(rule_name, {})
            status = rule_result.get('status', 'unknown')
            rule_count = rule_result.get('rule_count', 0)
            rule_notes = rule_result.get('notes', [])

            status_class = {'full': 'status-ok', 'partial': 'status-warn',
                            'none': 'status-fail', 'skipped': 'status-skip'}.get(status, '')
            status_label = {'full': 'OK', 'partial': 'WARN', 'none': 'FAIL',
                            'skipped': 'SKIP'}.get(status, '?')

            action_display = esc(pa_action)
            if disabled:
                action_display += ' <em>(disabled)</em>'

            notes_html = ''
            if rule_notes:
                notes_html = '<br>'.join(esc(n) for n in rule_notes)
            else:
                notes_html = '—'

            html.append(f'<tr><td class="{status_class}">{status_label}</td>'
                         f'<td>{esc(rule_name)}</td><td>{action_display}</td>'
                         f'<td>{rule_count}</td><td style="font-size:12px">{notes_html}</td></tr>')

        html.append('</table>')

        # Variable Mappings
        html.append('<h2>Variable Mappings</h2>')
        if variables:
            html.append('<table><tr><th>Variable</th><th>Value</th></tr>')
            for var_name, var_value in sorted(variables.items()):
                display_val = esc(var_value) if var_value else '<em>(undefined)</em>'
                html.append(f'<tr><td><code>${esc(var_name)}</code></td><td>{display_val}</td></tr>')
            html.append('</table>')
        else:
            html.append('<p>No variables created.</p>')

        # URL Category Mappings
        cats_referenced = summary.get('categories_referenced', [])
        if cats_referenced:
            html.append('<h2>URL Category Mappings</h2>')
            html.append('<table><tr><th>PA Category</th><th>AWS Category</th><th>Confidence</th></tr>')
            for cat_name in cats_referenced:
                if self.app_mapper:
                    resolved = self.app_mapper.resolve_category(cat_name)
                    if resolved:
                        html.append(f'<tr><td>{esc(cat_name)}</td>'
                                     f'<td>{esc(resolved["aws_category"])}</td>'
                                     f'<td>{esc(resolved["confidence"])}</td></tr>')
                    else:
                        custom_cats = parsed.get('custom_url_categories', {})
                        if cat_name in custom_cats:
                            domains = custom_cats[cat_name].get('domains', [])
                            html.append(f'<tr><td>{esc(cat_name)}</td>'
                                         f'<td>Custom URL List ({len(domains)} domain(s))</td>'
                                         f'<td>—</td></tr>')
                        else:
                            html.append(f'<tr><td>{esc(cat_name)}</td>'
                                         f'<td class="status-fail">NOT MAPPED</td>'
                                         f'<td>—</td></tr>')
            html.append('</table>')

        # Conversion Notes
        if notes:
            html.append('<h2>All Conversion Notes</h2>')
            for note in notes:
                html.append(f'<div class="note">{esc(note)}</div>')

        # Recommendations
        html.append('<h2>Recommendations</h2>')

        recs = []
        if stats.get('not_convertible', 0) > 0:
            recs.append('Review rules marked FAIL above. These contain PA App-ID '
                         'applications with no Suricata equivalent. Consider port-based '
                         'blocking or AWS domain categories as alternatives.')
        if stats.get('partially_converted', 0) > 0:
            recs.append('Review rules marked WARN above. These were partially converted '
                         'and may need manual adjustment for full coverage.')
        empty_vars = [n for n, v in variables.items() if not v]
        if empty_vars:
            recs.append(f'{len(empty_vars)} variable(s) have no definition '
                         f'(e.g., zone variables). Define their CIDR values in the '
                         f'Variables tab before saving or exporting.')
        if app_stats.get('tier2_domain', 0) > 0:
            recs.append('Domain-based rules (Tier 2) approximate PA App-ID by matching '
                         'on TLS SNI / HTTP Host. Verify the domain patterns cover all '
                         'traffic for those applications.')
        recs.append('Run the Rule Analyzer after import to check for syntax issues, '
                     'best practice violations, and optimization opportunities.')
        recs.append('Test imported rules in alert-only mode before deploying to '
                     'production. Use the "Test mode" checkbox to convert all actions to alert.')

        for rec in recs:
            html.append(f'<div class="rec">{esc(rec)}</div>')

        # Footer
        html.append(f'<hr><p class="meta" style="text-align:center">Report generated by '
                     f'Suricata Generator v{esc(main_ver)} (PA Importer v{esc(pa_ver)})</p>')
        html.append('</body></html>')

        return '\n'.join(html)

