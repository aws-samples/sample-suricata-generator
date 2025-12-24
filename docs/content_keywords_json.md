# content_keywords.json Documentation

## Overview

The `content_keywords.json` file is a comprehensive reference library of AWS Network Firewall compatible Suricata content keywords. This file documents the syntax, modifiers, examples, and usage notes for keywords that can be used in Suricata rule content sections.

## File Location

`content_keywords.json` (in the root directory of the application)

## Purpose

- Documents AWS Network Firewall supported Suricata keywords
- Provides syntax examples and usage patterns
- Serves as a reference for rule creation
- Helps users understand keyword modifiers and values
- Validates keyword compatibility with AWS Network Firewall

## File Structure

The JSON file contains metadata and a keywords array:

```json
{
  "version": "1.1.0",
  "last_updated": "2025-12-15",
  "description": "AWS Network Firewall Suricata Content Keywords",
  "note": "User-extensible keyword library",
  "keywords": [
    {
      "name": "keyword_name",
      "syntax": "keyword_name:<value>",
      "description": "What this keyword does",
      "category": "category_name",
      "example": "keyword_name:value;",
      ...
    }
  ]
}
```

## Keyword Entry Structure

Each keyword entry can contain the following fields:

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Keyword identifier (e.g., "flow", "content", "tls.sni") |
| `syntax` | String | How to use the keyword in a rule |
| `description` | String | Explanation of keyword functionality |
| `category` | String | Keyword grouping (flow, tls, http, dns, etc.) |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `example` | String | Single example usage |
| `examples` | Array | Multiple example usages |
| `values` | Array | Valid values for the keyword |
| `modifiers` | Array | Compatible modifiers (nocase, startswith, etc.) |
| `notes` | Array | Important usage notes |
| `multi_value` | Boolean | Whether multiple values can be comma-separated |
| `required` | Boolean | Whether keyword is mandatory in rules |

## Keyword Categories

Keywords are organized into the following categories:

### 1. General
Basic rule structure keywords used in all rules.

- `msg` - Rule message/description
- `sid` - Signature ID (required)
- `rev` - Revision number
- `metadata` - Organizational tags
- `priority` - Rule priority level
- `classtype` - Rule classification
- `reference` - External references

### 2. Flow
Keywords related to traffic direction and connection state.

- `flow` - Match on direction and state
- `flowbits` - Flow-based state tracking
- `xbits` - Extended state tracking

### 3. TLS/SSL
Keywords for matching TLS/SSL traffic.

- `tls.sni` - Server Name Indication
- `tls.cert_issuer` - Certificate issuer field
- `ja3.hash` - JA3 client fingerprint
- `ja3s.hash` - JA3S server fingerprint
- `ja4.hash` - JA4 fingerprint
- `ssl_state` - SSL handshake state
- `ssl_version` - SSL/TLS version

### 4. HTTP
Keywords for matching HTTP traffic.

- `http.host` - HTTP host header
- `http.uri` - HTTP URI path
- `http.method` - HTTP method (GET, POST, etc.)
- `http.header_names` - HTTP header names

### 5. DNS
Keywords for matching DNS traffic.

- `dns.query` - DNS query name

### 6. Network
Network layer keywords.

- `geoip` - Geographic IP matching
- `ip_proto` - IP protocol matching

### 7. Protocol
Application layer protocol keywords.

- `app-layer-protocol` - Application protocol detection

### 8. Payload
Payload inspection keywords.

- `content` - Pattern matching in payload
- `byte_test` - Test byte values
- `byte_jump` - Jump in payload
- `dsize` - Payload data size
- `flags` - TCP flags
- `pcre` - Perl Compatible Regular Expressions
- `isdataat` - Check for data at position

### 9. Modifier
Content modifiers that enhance pattern matching.

- `nocase` - Case-insensitive matching
- `startswith` - Match at buffer start
- `endswith` - Match at buffer end
- `dotprefix` - Match domain and subdomains
- `offset` - Skip bytes before matching
- `depth` - Limit search depth
- `distance` - Skip after previous match
- `within` - Limit search after previous match

## Adding New Keywords

### Step 1: Verify AWS Network Firewall Support

Before adding a keyword, verify it's supported:

1. Check [AWS Network Firewall documentation](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html)
2. Test the keyword in a test rule group
3. Consult [Suricata documentation](https://docs.suricata.io/en/latest/rules/)

### Step 2: Create the Keyword Entry

Add a new entry to the `keywords` array:

```json
{
  "name": "your_keyword",
  "syntax": "your_keyword:<value>",
  "description": "Clear explanation of functionality",
  "category": "appropriate_category",
  "example": "your_keyword:example_value;"
}
```

### Step 3: Add Optional Fields

Include additional fields based on the keyword:

**For keywords with specific values:**
```json
{
  "name": "http.method",
  "syntax": "http.method; content:\"<method>\"",
  "values": ["GET", "POST", "PUT", "DELETE"],
  "description": "Match HTTP method",
  "category": "http",
  "example": "http.method; content:\"POST\";"
}
```

**For keywords with modifiers:**
```json
{
  "name": "content",
  "syntax": "content:\"<pattern>\"",
  "modifiers": ["nocase", "startswith", "endswith", "offset", "depth"],
  "description": "Match specific content in payload",
  "category": "general",
  "example": "content:\"example.com\"; nocase; endswith;"
}
```

**For keywords with multiple examples:**
```json
{
  "name": "flow",
  "syntax": "flow:<value>[,<value>]",
  "values": ["to_server", "to_client", "established"],
  "multi_value": true,
  "examples": [
    "flow:to_server;",
    "flow:to_client, established;",
    "flow:to_server, established, only_stream;"
  ],
  "description": "Match on direction and state of flow",
  "category": "flow"
}
```

**For keywords with usage notes:**
```json
{
  "name": "xbits",
  "syntax": "xbits:<operation>,<name>,track <track_type>",
  "values": ["set", "unset", "isset", "isnotset", "toggle"],
  "description": "Extended state tracking",
  "category": "flow",
  "examples": [
    "xbits:set,badssh,track ip_src;",
    "xbits:set,badssh,track ip_src,expire 3600;"
  ],
  "notes": [
    "Track types: ip_src, ip_dst, ip_pair, tx",
    "Optional: expire <seconds> parameter",
    "Use with noalert to track without alerting"
  ]
}
```

## Example: Adding a New Keyword

Let's add documentation for a hypothetical new keyword:

```json
{
  "name": "quic.version",
  "syntax": "quic.version; content:\"<version>\"",
  "modifiers": ["content", "!"],
  "description": "Match QUIC protocol version",
  "category": "protocol",
  "example": "quic.version; content:\"Q046\";",
  "examples": [
    "quic.version; content:\"Q046\";",
    "quic.version; content:!\"Q039\";"
  ],
  "notes": [
    "Matches QUIC version in client hello",
    "Can be negated with ! modifier",
    "Common versions: Q043, Q046, Q050"
  ]
}
```

## Keyword Syntax Patterns

### Basic Syntax

Most keywords follow one of these patterns:

**1. Sticky Buffer (no value):**
```
keyword_name; content:"pattern";
```
Example: `tls.sni; content:"example.com";`

**2. Keyword with Value:**
```
keyword_name:value;
```
Example: `ssl_version:tls1.2;`

**3. Keyword with Multiple Values:**
```
keyword_name:value1,value2;
```
Example: `flow:to_server,established;`

**4. Keyword with Negation:**
```
keyword_name:!value;
```
Example: `app-layer-protocol:!tls;`

### Modifier Syntax

Modifiers are applied after content keywords:

```
content:"pattern"; modifier1; modifier2;
```

Example:
```
content:"example.com"; nocase; endswith;
```

### Combining Keywords

Multiple keywords are separated by semicolons:

```
flow:to_server; tls.sni; content:"example.com"; nocase;
```

## Best Practices

### 1. Accurate Syntax Documentation

Ensure syntax strings accurately represent keyword usage:

✅ Good:
```json
"syntax": "geoip:<direction>,<country_code>"
```

❌ Bad:
```json
"syntax": "geoip:country_code"
```

### 2. Comprehensive Examples

Provide examples that demonstrate real-world usage:

✅ Good:
```json
"examples": [
  "http.header_names; content:\"|0d 0a|Host|0d 0a|\";",
  "http.header_names; content:!\"|0d 0a|User-Agent|0d 0a|\";"
]
```

### 3. Document Limitations

Note AWS Network Firewall specific limitations:

```json
"notes": [
  "AWS Network Firewall requires $ prefix for port variables",
  "@ variables not supported for ports in AWS Network Firewall"
]
```

### 4. Include Value Lists

For keywords with limited valid values, list them all:

```json
"values": [
  "client_hello",
  "server_hello",
  "client_keyx",
  "server_keyx",
  "unknown"
]
```

### 5. Explain Complex Behaviors

For keywords with non-obvious behavior, provide detailed notes:

```json
"notes": [
  "Buffer starts with \\r\\n and ends with extra \\r\\n",
  "Format: |0d 0a|HeaderName|0d 0a|",
  "Use flow:to_server for request headers, flow:to_client for response"
]
```

## Keyword Categories Explained

### General Keywords

These keywords are used for rule metadata and basic structure:

- **msg**: Human-readable description (appears in logs)
- **sid**: Unique identifier (1-999999999)
- **rev**: Version number for tracking rule updates
- **metadata**: Key-value pairs for organization
- **classtype**: Categorizes the type of threat
- **reference**: Links to external information (CVE, URL, etc.)

### Flow Keywords

Control when rules match based on connection state:

- **flow**: Direction (to_server, to_client) and state (established, not_established)
- **flowbits**: Set/check flags within a flow
- **xbits**: Extended tracking across IPs or transactions

### Sticky Buffer Keywords

Position subsequent content matches:

- **tls.sni**, **http.host**, **dns.query**: Set buffer for content matching
- Must be followed by content keyword
- Subsequent content matches apply to this buffer until next sticky buffer

### Content Modifiers

Refine how content matches work:

- **nocase**: Ignore case sensitivity
- **startswith**: Must match at buffer start
- **endswith**: Must match at buffer end
- **offset**: Skip N bytes before searching
- **depth**: Search only first N bytes
- **distance**: For chaining matches
- **within**: Limit search range after previous match

## Integration with Application

The application uses `content_keywords.json` for:

1. **Syntax Highlighting**: Recognizes valid keywords in rule editor
2. **Auto-completion**: Suggests keywords and their syntax
3. **Validation**: Verifies keyword usage matches documented syntax
4. **Help System**: Displays keyword descriptions and examples
5. **Template Generation**: Uses keywords in rule templates

## File Validation

Before modifying `content_keywords.json`, verify:

1. **Valid JSON**: Use a JSON validator
2. **Required Fields**: All keywords have name, syntax, description, category
3. **Consistent Format**: Follow existing patterns for similar keywords
4. **Accurate Syntax**: Test keywords in actual Suricata rules
5. **AWS Compatibility**: Verify support in AWS Network Firewall

## Troubleshooting

### Common Issues

**Issue**: Keyword not recognized by application

**Solution**:
- Verify JSON syntax is valid
- Check that all required fields are present
- Restart application to reload JSON file

**Issue**: Keyword works in Suricata but not AWS Network Firewall

**Solution**:
- Check AWS Network Firewall documentation for supported keywords
- Some Suricata keywords are not supported by AWS
- Consider alternative keywords or approaches

**Issue**: Syntax examples not displaying correctly

**Solution**:
- Ensure proper JSON escaping for special characters
- Use `\"` for quotes within strings
- Use `\\` for backslashes

## Version Control

The file includes version information:

```json
{
  "version": "1.1.0",
  "last_updated": "2025-12-15",
  "description": "AWS Network Firewall Suricata Content Keywords"
}
```

Update these fields when making changes:
- **Patch version** (1.1.X): Bug fixes, clarifications
- **Minor version** (1.X.0): New keywords added
- **Major version** (X.0.0): Structural changes

## Related Files

- **rule_templates.json**: Uses keywords documented here in templates
- **common_ports.json**: Complements with port definitions
- **suricata_rule.py**: Code that validates keyword syntax
- **template_manager.py**: Generates rules using these keywords

## Additional Resources

- [Suricata Rules Documentation](https://docs.suricata.io/en/latest/rules/)
- [AWS Network Firewall Suricata Rules](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html)
- [Suricata Keywords Reference](https://docs.suricata.io/en/latest/rules/intro.html#rule-keywords)
- [AWS Network Firewall Supported Features](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html)

## Extension Guidelines

When AWS or Suricata adds new keywords:

1. **Document thoroughly**: Include all relevant fields
2. **Test first**: Verify in AWS Network Firewall test environment
3. **Provide examples**: Show common use cases
4. **Note limitations**: Document any AWS-specific restrictions
5. **Update version**: Increment version number appropriately
6. **Add notes**: Include any special considerations or gotchas

This extensibility ensures the file remains current as Suricata and AWS Network Firewall evolve.
