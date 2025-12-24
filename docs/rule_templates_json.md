# rule_templates.json Documentation

## Overview

The `rule_templates.json` file contains a library of pre-configured rule templates for common security policies and use cases. These templates enable users to quickly generate Suricata rules without writing them from scratch, supporting both static and parameterized rule generation.

## File Location

`rule_templates.json` (in the root directory of the application)

## Purpose

- Provides pre-built rule templates for common security scenarios
- Enables rapid deployment of security policies
- Supports parameterized rule generation with user input
- Maintains consistency across similar rule implementations
- Reduces errors from manual rule creation

## File Structure

The JSON file contains metadata and a templates array:

```json
{
  "version": "1.0",
  "description": "Rule Templates Library for Suricata Rule Generator",
  "templates": [
    {
      "id": "unique_template_id",
      "name": "Display Name",
      "category": "Category Name",
      "description": "What this template does",
      "template_type": "policy|parameterized",
      "rules": [...],
      "parameters": [...],
      ...
    }
  ]
}
```

## Template Entry Structure

Each template entry contains the following fields:

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | String | Unique identifier (lowercase, underscore-separated) |
| `name` | String | Human-readable template name |
| `category` | String | Template category for organization |
| `description` | String | Brief explanation of template purpose |
| `template_type` | String | "policy" or "parameterized" |
| `rules` | Array | Rule definitions (see Rule Structure below) |
| `rule_generation` | String | "static", "dynamic", or "conditional" |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `icon` | String | Emoji icon for visual identification |
| `complexity` | String | "beginner", "intermediate", or "advanced" |
| `test_mode_supported` | Boolean | Whether test mode (alert action) is supported |
| `parameters` | Array | User input parameters (for parameterized templates) |
| `variables` | Object | Suricata variables used in rules |
| `notes` | String | Additional usage notes and warnings |
| `insertion_point` | String | "end" or "dual" (where to insert rules) |
| `top_rules` | Array | Rules to insert at top (for dual insertion) |
| `sid_range` | String | Suggested SID range for rules |

## Template Types

### 1. Policy Templates (`template_type: "policy"`)

Static rule sets that don't require user input.

**Characteristics:**
- Fixed rule definitions
- `rule_generation: "static"`
- No `parameters` array
- Rules generated as-is from template

**Example:**
```json
{
  "id": "force_route53_resolver",
  "name": "Force Route 53 Resolver",
  "template_type": "policy",
  "rule_generation": "static",
  "rules": [
    {
      "action": "drop",
      "protocol": "dns",
      "src_net": "$HOME_NET",
      "src_port": "any",
      "direction": "->",
      "dst_net": "any",
      "dst_port": "any",
      "content": "flow:to_server",
      "message": "Block direct DNS query"
    }
  ]
}
```

### 2. Parameterized Templates (`template_type: "parameterized"`)

Templates that accept user input to customize rule generation.

**Characteristics:**
- Dynamic rule generation
- `rule_generation: "dynamic"` or `"conditional"`
- Has `parameters` array
- Uses placeholders like `{PARAMETER_NAME}`

**Example:**
```json
{
  "id": "rate_limit_ssh",
  "name": "Rate Limit SSH Attempts",
  "template_type": "parameterized",
  "rule_generation": "dynamic",
  "parameters": [
    {
      "name": "COUNT",
      "type": "text_input",
      "required": true,
      "label": "Connection Count Threshold",
      "placeholder": "5"
    }
  ],
  "rules": [
    {
      "action": "alert",
      "protocol": "ssh",
      "content": "detection_filter:track by_dst, count {COUNT}, seconds {SECONDS}",
      "message": "SSH brute force ({COUNT}+ attempts)"
    }
  ]
}
```

## Rule Structure

Each rule in the `rules` array contains:

| Field | Type | Description |
|-------|------|-------------|
| `action` | String | Rule action: "pass", "drop", "reject", "alert" |
| `protocol` | String | Protocol: "tcp", "udp", "icmp", "ip", "tls", "http", etc. |
| `src_net` | String | Source network/IP or placeholder |
| `src_port` | String | Source port or placeholder |
| `direction` | String | Traffic direction: "->" or "<>" |
| `dst_net` | String | Destination network/IP or placeholder |
| `dst_port` | String | Destination port or placeholder |
| `content` | String | Rule content/keywords |
| `message` | String | Rule message (can include placeholders) |
| `sid` | Integer | (Optional) Fixed SID for rule |

**Placeholders:**
- Use `{PARAMETER_NAME}` syntax
- Replaced with user input during generation
- Can be used in any string field

## Parameter Types

Templates can define various parameter types for user input:

### 1. Radio Buttons (`type: "radio"`)

Single selection from predefined options.

```json
{
  "name": "DIRECTION",
  "type": "radio",
  "description": "Select traffic direction",
  "required": true,
  "options": [
    {
      "value": "egress",
      "label": "Egress (outbound)",
      "src_net": "$HOME_NET",
      "dst_net": "any"
    },
    {
      "value": "ingress",
      "label": "Ingress (inbound)",
      "src_net": "any",
      "dst_net": "$HOME_NET"
    }
  ]
}
```

**Fields:**
- `name`: Parameter identifier
- `type`: "radio"
- `description`: Help text
- `required`: Whether selection is mandatory
- `options`: Array of choices with `value`, `label`, and optional data fields

### 2. Text Input (`type: "text_input"`)

Free-form text entry with validation.

```json
{
  "name": "HASH",
  "type": "text_input",
  "required": true,
  "label": "JA3 Hash",
  "description": "Enter 32-character hex hash",
  "placeholder": "27e9c7cc45ae47dc50f51400db8a4099",
  "pattern": "^[a-f0-9]{32}$",
  "validation_message": "Must be 32 hexadecimal characters",
  "min_length": 32,
  "max_length": 32
}
```

**Fields:**
- `name`: Parameter identifier
- `type`: "text_input"
- `required`: Whether input is mandatory
- `label`: Field label
- `description`: Help text
- `placeholder`: Example input
- `pattern`: Regex validation pattern (optional)
- `validation_message`: Error message for invalid input
- `min_length`/`max_length`: Length constraints

### 3. Multi-Select Port (`type: "multi_select_port"`)

Checkbox selection of multiple ports.

```json
{
  "name": "PORTS",
  "type": "multi_select_port",
  "description": "Select ports to block",
  "required": true,
  "min_selections": 1,
  "options": [
    {
      "value": "53",
      "label": "DNS (53)",
      "description": "DNS tunneling",
      "default_checked": true
    },
    {
      "value": "445",
      "label": "SMB (445)",
      "description": "Ransomware spread"
    }
  ]
}
```

**Fields:**
- `name`: Parameter identifier
- `type`: "multi_select_port"
- `description`: Help text
- `min_selections`: Minimum required selections
- `options`: Array with `value`, `label`, `description`, `default_checked`

### 4. Multi-Select Protocol (`type: "multi_select_protocol"`)

Checkbox selection of multiple protocols.

```json
{
  "name": "PROTOCOLS",
  "type": "multi_select_protocol",
  "description": "Select protocols to enforce",
  "required": true,
  "min_selections": 1,
  "options": [
    {
      "value": "tls",
      "label": "TLS (HTTPS)",
      "protocol": "tls",
      "port": "443",
      "transport": "tcp",
      "protocol_upper": "TLS"
    }
  ]
}
```

**Fields:**
- Similar to multi_select_port
- Additional metadata: `protocol`, `port`, `transport`, `protocol_upper`

### 5. Multi-Select Country (`type: "multi_select_country"`)

Checkbox selection of countries with regional grouping.

```json
{
  "name": "COUNTRIES",
  "type": "multi_select_country",
  "description": "Select countries to control",
  "required": true,
  "min_selections": 1,
  "options": [
    {
      "value": "CN",
      "label": "China",
      "region": "Asia"
    },
    {
      "value": "RU",
      "label": "Russia",
      "region": "Europe"
    }
  ]
}
```

**Regions:**
- Asia
- Americas
- Africa
- Middle East
- Europe
- Oceania

### 6. Checkbox (`type: "checkbox"`)

Boolean on/off selection.

```json
{
  "name": "ENABLE_FEATURE",
  "type": "checkbox",
  "label": "Enable advanced detection",
  "description": "Use advanced pattern matching",
  "default": false
}
```

## Template Categories

Templates are organized into categories:

### 1. Protocol Enforcement
Rules that enforce proper protocol usage.

Examples:
- Force Route 53 Resolver
- Enforce TLS Version
- Enforce Protocol Port Usage

### 2. Cloud Security
AWS-specific security policies.

Examples:
- Enforce HTTPS for AWS Services

### 3. Threat Protection
Security rules for threat detection/prevention.

Examples:
- Block Cryptocurrency Mining
- Block Malware C2 Ports
- Block Direct-to-IP Connections
- Rate Limit SSH Attempts

### 4. Geographic Control
GeoIP-based access control.

Examples:
- Geographic Country Control

### 5. Application Control
Application-level security policies.

Examples:
- JA3 Fingerprint Control
- Block File Sharing Protocols

### 6. Default Deny
Comprehensive default deny rulesets.

Examples:
- Default Egress Block Rules
- Default Ingress Block Rules

## Rule Generation Types

### Static (`rule_generation: "static"`)

Rules are generated exactly as defined in template.

**Use when:**
- No user input needed
- Fixed policy implementation
- Simple rule sets

**Example:** Force Route 53 Resolver

### Dynamic (`rule_generation: "dynamic"`)

Rules are generated using parameter substitution.

**Use when:**
- User input customizes rules
- Multiple similar rules generated
- Parameters fill placeholders

**Example:** Rate Limit SSH (uses COUNT and SECONDS parameters)

### Conditional (`rule_generation: "conditional"`)

Different rules generated based on parameter values.

**Use when:**
- Logic determines which rules to generate
- Mode selection affects rule structure
- Single vs. multiple rule generation

**Example:** Geographic Country Control (block vs. allow mode)

## Special Insertion Points

### Standard Insertion (`insertion_point: "end"` or omitted)

Rules inserted at user-selected position or end of file.

### Dual Insertion (`insertion_point: "dual"`)

Rules inserted at both top and bottom of file.

**Structure:**
```json
{
  "insertion_point": "dual",
  "top_rules": [
    {
      "action": "pass",
      "message": "Rule at top",
      "sid": 202501021
    }
  ],
  "rules": [
    {
      "action": "drop",
      "message": "Rule at bottom",
      "sid": 999991
    }
  ]
}
```

**Use for:**
- Default deny policies (allow handshakes at top, deny rest at bottom)
- Foundational rules that must bracket other rules

## Adding New Templates

### Step 1: Design the Template

Determine:
1. **Purpose**: What security policy does this implement?
2. **Type**: Policy (static) or parameterized?
3. **Category**: Which category fits best?
4. **Complexity**: Beginner, intermediate, or advanced?
5. **Parameters**: What user inputs are needed?

### Step 2: Create Template Structure

```json
{
  "id": "descriptive_template_id",
  "name": "Human Readable Name",
  "category": "Appropriate Category",
  "description": "Clear description of functionality",
  "icon": "🔒",
  "complexity": "beginner",
  "template_type": "policy",
  "test_mode_supported": true,
  "rule_generation": "static",
  "rules": [],
  "parameters": [],
  "variables": {
    "$HOME_NET": "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
  },
  "notes": "Important usage notes"
}
```

### Step 3: Define Rules

Add rule definitions to `rules` array:

```json
"rules": [
  {
    "action": "drop",
    "protocol": "tcp",
    "src_net": "$HOME_NET",
    "src_port": "any",
    "direction": "->",
    "dst_net": "any",
    "dst_port": "[22,23,3389]",
    "content": "flow:to_server",
    "message": "Block remote admin protocols"
  }
]
```

### Step 4: Add Parameters (if parameterized)

Define user input parameters:

```json
"parameters": [
  {
    "name": "ACTION_TYPE",
    "type": "radio",
    "required": true,
    "description": "Select action",
    "options": [
      {
        "value": "drop",
        "label": "Block (drop)",
        "action": "drop"
      },
      {
        "value": "alert",
        "label": "Alert only",
        "action": "alert"
      }
    ]
  }
]
```

### Step 5: Use Placeholders in Rules

Replace fixed values with parameter placeholders:

```json
{
  "action": "{ACTION}",
  "message": "{ACTION_MSG} suspicious traffic"
}
```

### Step 6: Test the Template

1. Add template to `rule_templates.json`
2. Restart application
3. Test rule generation with various parameter combinations
4. Verify generated rules are syntactically correct
5. Test in AWS Network Firewall if possible

## Example: Creating a Custom Template

Let's create a template to block specific user agents:

```json
{
  "id": "block_user_agents",
  "name": "Block Malicious User Agents",
  "category": "Threat Protection",
  "description": "Block HTTP requests with known malicious user agent strings",
  "icon": "🕷️",
  "complexity": "beginner",
  "template_type": "parameterized",
  "test_mode_supported": true,
  "rule_generation": "dynamic",
  "rules": [
    {
      "action": "drop",
      "protocol": "http",
      "src_net": "any",
      "src_port": "any",
      "direction": "->",
      "dst_net": "$HOME_NET",
      "dst_port": "any",
      "content": "http.user_agent; content:\"{USER_AGENT}\"; nocase; flow:to_server",
      "message": "Block user agent: {USER_AGENT}"
    }
  ],
  "parameters": [
    {
      "name": "USER_AGENT",
      "type": "text_input",
      "required": true,
      "label": "User Agent String",
      "description": "Enter malicious user agent to block",
      "placeholder": "malware-scanner",
      "min_length": 3,
      "max_length": 100
    }
  ],
  "variables": {
    "$HOME_NET": "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
  },
  "notes": "Blocks HTTP requests with specified user agent. Case-insensitive matching."
}
```

## Best Practices

### 1. Clear Naming

Use descriptive names that indicate the template's purpose.

✅ Good: "Force Route 53 Resolver (Block Direct DNS)"  
❌ Bad: "DNS Template 1"

### 2. Appropriate Icons

Choose relevant emoji icons:
- 🔒 Security/encryption
- 🌍 Geographic
- 🚫 Blocking
- ⚠️ Warnings
- 🔍 Detection

### 3. Accurate Complexity Rating

- **Beginner**: Simple, single-purpose rules
- **Intermediate**: Multiple coordinated rules
- **Advanced**: Complex logic, flowbits, dual insertion

### 4. Comprehensive Notes

Include important information:
- Deployment considerations
- Performance impact
- Testing recommendations
- Interaction with other rules

### 5. Sensible Defaults

For parameters with `default_checked`:
- Check commonly used options
- Leave potentially disruptive options unchecked

### 6. Validate Parameters

Use validation patterns to ensure correct input:

```json
{
  "pattern": "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$",
  "validation_message": "Must be valid IPv4 address"
}
```

### 7. Test Mode Support

Enable test mode when appropriate:

```json
"test_mode_supported": true
```

This allows users to generate rules with "alert" action for testing.

## Integration with Application

The application uses `rule_templates.json` via `template_manager.py`:

1. **Load Templates**: Reads and parses JSON on startup
2. **Display UI**: Shows templates in categorized dialog
3. **Collect Parameters**: Presents parameter entry UI
4. **Generate Rules**: Applies parameter substitution
5. **Insert Rules**: Places generated rules in editor

## File Validation

Before modifying `rule_templates.json`, verify:

1. **Valid JSON**: No syntax errors
2. **Required Fields**: All templates have id, name, category, etc.
3. **Unique IDs**: Template IDs are unique
4. **Valid Placeholders**: All placeholders have corresponding parameters
5. **Syntax Correctness**: Generated rules are valid Suricata syntax

## Troubleshooting

### Common Issues

**Issue**: Template not appearing in UI

**Solution**:
- Check JSON syntax validity
- Verify all required fields present
- Ensure template ID is unique
- Restart application

**Issue**: Parameters not working

**Solution**:
- Verify placeholder syntax: `{PARAM_NAME}`
- Check parameter `name` matches placeholder
- Ensure parameter type is valid
- Test with simple input first

**Issue**: Generated rules have syntax errors

**Solution**:
- Test placeholder values manually
- Check for missing brackets/quotes
- Validate against Suricata syntax
- Review parameter validation patterns

**Issue**: Rules inserted at wrong location

**Solution**:
- Check `insertion_point` field
- For dual insertion, ensure `top_rules` and `rules` are correct
- Verify user's cursor position in editor

## Related Files

- **template_manager.py**: Code that processes templates
- **content_keywords.json**: Keywords used in template rules
- **common_ports.json**: Port variables referenced in templates
- **suricata_generator.py**: Main application that uses templates

## Version Control

Update version when making changes:

```json
{
  "version": "1.1",
  "description": "Rule Templates Library for Suricata Rule Generator"
}
```

Version increment guidelines:
- **Minor (1.X)**: New templates added
- **Major (X.0)**: Structural changes to template format

## Additional Resources

- [Suricata Rule Format](https://docs.suricata.io/en/latest/rules/intro.html)
- [AWS Network Firewall Examples](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html)
- [Template Manager Code](../template_manager.py)

## Template Design Guidelines

When creating templates, consider:

1. **Scope**: Single purpose vs. comprehensive policy
2. **Flexibility**: Fixed vs. parameterized
3. **Safety**: Default deny vs. default allow
4. **Performance**: Rule count and complexity
5. **Maintenance**: How easy to update
6. **Documentation**: Clear notes and examples

Well-designed templates make security policy deployment faster, more consistent, and less error-prone.
