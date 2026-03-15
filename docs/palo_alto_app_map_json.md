# palo_alto_app_map.json Documentation

## Overview

The `palo_alto_app_map.json` file is the core mapping data file for the Palo Alto Networks Configuration Import feature. It contains all the lookup tables needed to convert Palo Alto security policy objects into equivalent Suricata rule components for use with AWS Network Firewall.

## File Location

`palo_alto_app_map.json` (in the root directory of the application)

## Purpose

- Maps Palo Alto App-ID application names to Suricata protocols (Tier 1) or domain-based rules (Tier 2)
- Maps Palo Alto URL filtering categories to AWS Network Firewall domain categories
- Provides default ports for `application-default` service resolution
- Contains the complete ISO 3166-1 alpha-2 country code list for GeoIP detection
- Maps built-in PAN-OS service names (e.g., `service-http`) to protocol/port definitions
- User-extensible without code changes

## File Structure

The JSON file contains metadata and seven data sections:

```json
{
    "version": "1.0.0",
    "last_updated": "2026-03-11",
    "description": "Human-readable description of the file",
    "panos_versions_tested": ["10.1", "10.2", "11.0", "11.1"],

    "protocol_mappings": { ... },
    "domain_mappings": { ... },
    "url_category_mappings": { ... },
    "application_default_ports": { ... },
    "builtin_services": { ... },
    "country_codes": { ... }
}
```

### Metadata Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | String | Semantic version of the mapping file (e.g., `"1.0.0"`) |
| `last_updated` | String | Date of last update (e.g., `"2026-03-11"`) |
| `description` | String | Human-readable description of the file's purpose |
| `panos_versions_tested` | Array | PAN-OS versions the mappings have been validated against |

---

## Section 1: protocol_mappings (Tier 1)

**Purpose:** Maps Palo Alto App-ID application names directly to Suricata protocol keywords. These are high-confidence, 1:1 mappings where the PA application name IS the protocol (e.g., `ssl` → `tls`, `dns` → `dns`).

**How it's used:** When the converter encounters a PA rule with a specific application (e.g., `application: ssh`), it looks up that application in `protocol_mappings` first. If found, the Suricata rule uses the mapped protocol.

### Entry Structure

```json
"ssh": {
    "suricata_protocol": "ssh",
    "default_port": "22",
    "app_layer": true,
    "deny_action": "reject",
    "description": "Secure Shell"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `suricata_protocol` | String | Yes | Suricata rule protocol keyword (e.g., `tls`, `http`, `dns`, `tcp`, `udp`) |
| `default_port` | String/null | Yes | Port used when PA service is `application-default`. Set to `null` for protocols like ICMP that don't use ports. |
| `app_layer` | Boolean | Yes | `true` if Suricata has app-layer detection for this protocol (port can be `any`). `false` for transport-layer only (must specify port). |
| `deny_action` | String | No | Suricata action to use when PA action is `deny`. Values: `"reject"` (TCP RST/ICMP unreachable, like PA deny for TCP apps) or `"drop"` (silent drop, like PA deny for UDP apps). Defaults to `"drop"` if omitted. PA deny behavior varies by application — TCP apps send a RST, UDP apps silently drop. |
| `description` | String | No | Human-readable description |

### App-Layer vs Transport-Layer

This distinction is critical for correct rule generation:

- **`app_layer: true`** — Suricata identifies this protocol by inspecting packet content, not by port number. Rules use `any` as the destination port, providing port-independent detection equivalent to PA's App-ID behavior. Examples: `dns`, `tls`, `http`, `ssh`, `smb`, `ftp`.

- **`app_layer: false`** — Suricata cannot identify this protocol by packet inspection. Rules must specify the well-known port from `default_port`. Examples: `tcp` (for ms-rdp → port 3389), `udp` (for snmp → port 161).

### Adding a New Protocol Mapping

```json
"my-protocol": {
    "suricata_protocol": "tcp",
    "default_port": "9090",
    "app_layer": false,
    "deny_action": "reject",
    "description": "My custom protocol on TCP/9090"
}
```

**Important:** The `suricata_protocol` value must be a valid protocol from the Suricata Generator's supported protocols list (`constants.py SUPPORTED_PROTOCOLS`). Invalid protocols will cause rule validation errors.

### Current Supported Suricata Protocols

App-layer (use `any` port): `dcerpc`, `dhcp`, `dns`, `ftp`, `http`, `http2`, `ikev2`, `imap`, `krb5`, `msn`, `ntp`, `quic`, `smb`, `smtp`, `ssh`, `tftp`, `tls`

Transport/network-layer (use specific port): `tcp`, `udp`, `icmp`, `ip`

---

## Section 2: domain_mappings (Tier 2)

**Purpose:** Maps Palo Alto App-ID applications for well-known SaaS/cloud services to domain-based TLS SNI matching rules. These are medium-confidence mappings that approximate PA's App-ID detection by matching the service's domain name.

**How it's used:** If an application is NOT found in `protocol_mappings`, the converter checks `domain_mappings`. If found, it generates a TLS rule with `tls.sni; dotprefix; content:"<domain>"; endswith` and an HTTP companion rule with `http.host`.

### Entry Structure

```json
"slack-base": {
    "domain": ".slack.com",
    "deny_action": "reject",
    "description": "Slack messaging platform"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | String | Yes | Domain to match in TLS SNI / HTTP Host. Typically starts with `.` for subdomain matching. |
| `deny_action` | String | No | Suricata action for PA `deny`. Defaults to `"reject"` for Tier 2 (all TLS/TCP-based). |
| `description` | String | No | Human-readable description |

### Domain Format

- **`.example.com`** — Matches `example.com` and all subdomains (e.g., `app.example.com`, `api.example.com`). The `dotprefix` and `endswith` keywords in the generated rule handle this.
- **`specific.example.com`** — Matches only that exact hostname and its subdomains.

### Adding a New Domain Mapping

```json
"my-saas-app": {
    "domain": ".myapp.example.com",
    "description": "My SaaS application"
}
```

**Note:** When adding a domain mapping, also add a corresponding entry in `application_default_ports` (typically `"tcp/443"` for HTTPS services):

```json
"application_default_ports": {
    "my-saas-app": "tcp/443"
}
```

### Conversion Notes

Domain-based mappings generate a conversion note (⚠️) because:
- PA App-ID may match traffic on non-standard ports or via IP; Suricata only matches on the specified port + domain
- The domain list may not be exhaustive (e.g., Microsoft Teams uses `*.teams.microsoft.com`, `*.skype.com`, `*.office.com`)
- PA App-ID can detect the app inside encrypted tunnels it decrypts; Suricata relies on the TLS SNI field

---

## Section 3: url_category_mappings

**Purpose:** Maps Palo Alto URL filtering category names to AWS Network Firewall domain category names. Used when PA rules reference URL categories in their `<category>` field.

**How it's used:** When a PA rule has `<category><member>malware</member></category>`, the converter looks up `malware` in this section to find the equivalent AWS category name for the `aws_domain_category` keyword.

### Entry Structure

```json
"malware": {
    "aws_category": "Malware",
    "confidence": "high"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `aws_category` | String | Yes | AWS Network Firewall domain category name (exact match required, case-sensitive) |
| `confidence` | String | No | Mapping quality: `high` (direct match), `medium` (close equivalent), `low` (loose approximation). Defaults to `medium` if omitted. |

### Confidence Levels

- **`high`** — The PA category and AWS category are direct equivalents (e.g., `malware` → `Malware`)
- **`medium`** — Close but not exact match. The converter adds a note recommending review (e.g., `streaming-media` → `Entertainment`)
- **`low`** — Loose approximation. The converter adds a prominent warning (e.g., `drugs` → `Marijuana`)

### Adding a New URL Category Mapping

```json
"my-category": {
    "aws_category": "My AWS Category Name",
    "confidence": "high"
}
```

**Important:** The `aws_category` value must be a valid AWS Network Firewall managed domain list name. Invalid category names will not match any traffic. Check the [AWS documentation](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html) for the current list.

### Category Disambiguation

The converter uses this section to distinguish **built-in PA URL categories** from **custom URL category lists** defined in the PA configuration:

1. If a category name is found in `url_category_mappings` → It's a built-in category → Generate `aws_domain_category` rule
2. If NOT found here → Check PA config's `<custom-url-category>` definitions → Extract domains → Generate domain-matching rules
3. If not found anywhere → Generate an unresolved reference warning

---

## Section 4: application_default_ports

**Purpose:** Provides the default protocol and port for each application when the PA rule uses `service: application-default`. This tells the converter what port to use in the Suricata rule.

**How it's used:** When a PA rule specifies `<service><member>application-default</member></service>`, the converter uses the application name to look up the default port.

### Entry Format

```json
"ssh": "tcp/22",
"dns": "udp/53",
"ssl": "tcp/443"
```

The value format is `protocol/port` where:
- `protocol` is `tcp`, `udp`, or `icmp`
- `port` is the well-known port number, or `any` for protocols like ICMP

### Adding a New Entry

Add both a `protocol_mappings` (or `domain_mappings`) entry AND an `application_default_ports` entry:

```json
"application_default_ports": {
    "my-app": "tcp/8080"
}
```

### Interaction with app_layer Flag

For app-layer protocols (`app_layer: true` in `protocol_mappings`), the Suricata rule uses `any` as the port instead of the value from this section. The `application_default_ports` value is only directly used when `app_layer: false`.

---

## Section 5: builtin_services

**Purpose:** Maps PAN-OS built-in service names to their protocol and port definitions. These services (e.g., `service-http`, `service-https`) are predefined in PAN-OS and are NOT included in the `<service>` section of configuration exports.

**How it's used:** When the converter encounters a service member like `service-http` and cannot find it in the PA configuration's custom `<service>` objects, it looks up the built-in service here.

### Entry Structure

```json
"service-http": {
    "protocol": "tcp",
    "port": "80"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `protocol` | String | Yes | `tcp` or `udp` |
| `port` | String | Yes | Port number |

### Service Resolution Precedence

When the converter resolves a service member, it follows this order:
1. `any` → port `any`
2. `application-default` → deferred to application lookup
3. Custom service object (from PA config `<service>` section)
4. **Built-in service (from this section)**
5. Service group (from PA config `<service-group>` section)
6. Unresolved reference warning

### Adding a New Built-in Service

```json
"service-my-protocol": {
    "protocol": "tcp",
    "port": "9090"
}
```

---

## Section 6: country_codes

**Purpose:** Contains the complete list of ISO 3166-1 alpha-2 country codes (249 codes) used to detect GeoIP references in PA rule `<source>` and `<destination>` member fields.

**How it's used:** When the converter encounters a source/destination member value (e.g., `CN`), it checks whether the value is a country code by looking it up in this section. If it is, the converter generates a Suricata `geoip` keyword instead of treating it as an address object name.

### Entry Format

```json
"CN": "China",
"RU": "Russian Federation",
"US": "United States of America"
```

Keys are the two-letter country codes; values are human-readable country names (for reference only — not used in conversion).

### Detection Precedence

Country code detection is step 5 of the 6-step member classification:
1. Check if value is `any` → Use `any`
2. Check if value matches a defined address object name → Use address object
3. Check if value matches a defined address group name → Use address group
4. Check if value is a raw IP address/CIDR → Use directly
5. **Check if value is a country code (from this section)** → Generate `geoip` keyword
6. Otherwise → Unresolved reference warning

This means if a PA address object is named `CN` (unusual but possible), it takes precedence over country code detection.

### Modifying Country Codes

This section should rarely need modification. It follows the ISO 3166-1 standard. You might add entries if:
- A new country code is assigned by ISO
- A territory gains independent country code status

---

## Adding Custom Mappings

### Example: Adding a Custom Application

If your organization uses a PA application that isn't in the default mappings:

**Scenario:** PA application `my-internal-app` runs on TCP port 8443 with no Suricata app-layer detection.

1. Add to `protocol_mappings`:
```json
"my-internal-app": {
    "suricata_protocol": "tcp",
    "default_port": "8443",
    "app_layer": false,
    "description": "Internal application on TCP/8443"
}
```

2. Add to `application_default_ports`:
```json
"my-internal-app": "tcp/8443"
```

### Example: Adding a SaaS Application Domain

**Scenario:** PA application `my-saas` should be matched by domain `myapp.example.com`.

1. Add to `domain_mappings`:
```json
"my-saas": {
    "domain": ".myapp.example.com",
    "description": "My SaaS Application"
}
```

2. Add to `application_default_ports`:
```json
"my-saas": "tcp/443"
```

### Example: Adding a URL Category Mapping

**Scenario:** PA URL category `internal-sites` should map to AWS category `Business and Economy`.

Add to `url_category_mappings`:
```json
"internal-sites": {
    "aws_category": "Business and Economy",
    "confidence": "medium"
}
```

---

## Versioning

Update the metadata fields when making changes:

- **Patch version** (1.0.X): Bug fixes, description corrections
- **Minor version** (1.X.0): New mappings added (new applications, categories, services)
- **Major version** (X.0.0): Structural changes, field renames, breaking changes

Always update `last_updated` with the current date.

---

## Validation Tips

Before modifying `palo_alto_app_map.json`:

1. **Valid JSON:** Use a JSON validator to check syntax before saving
2. **No trailing commas:** JSON does not allow trailing commas in arrays or objects
3. **Suricata protocol validity:** Ensure `suricata_protocol` values are in the supported protocols list
4. **AWS category accuracy:** Verify `aws_category` values match exact AWS domain category names
5. **Port format:** Ports must be strings (e.g., `"80"` not `80`)
6. **Country code format:** Must be exactly 2 uppercase letters

## Troubleshooting

### Application Shows as "Unmappable" (Tier 3)

If an application you expect to be mapped shows as unmappable:
- Check that the PA application name matches exactly (case-sensitive)
- Verify the entry exists in either `protocol_mappings` or `domain_mappings`
- The PA application name may differ from what you expect (e.g., `web-browsing` not `http`)

### Built-in Service Not Resolved

If a built-in service like `service-http` is not resolving:
- Check that the service name matches exactly (case-sensitive, including the `service-` prefix)
- Verify the entry exists in `builtin_services`

### URL Category Not Mapping

If a PA URL category is not mapping to an AWS category:
- Check that the PA category name matches exactly (case-sensitive, use hyphens not spaces)
- If it's a custom URL category list, it won't be in `url_category_mappings` — the converter extracts domains directly from the PA configuration

---

## Related Files

- **`palo_alto_importer.py`** — Python module that loads and uses this mapping file
- **`constants.py`** — Contains `SUPPORTED_PROTOCOLS` list (must match available `suricata_protocol` values)
- **`content_keywords.json`** — Documents Suricata content keywords used in generated rules
- **`common_ports.json`** — Complements with additional port definitions
- **`docs/content_keywords_json.md`** — Documentation for content keywords (similar pattern)
- **`docs/common_ports_json.md`** — Documentation for common ports (similar pattern)

## Additional Resources

- [Palo Alto App-ID Research Center](https://applipedia.paloaltonetworks.com/)
- [AWS Network Firewall Managed Domain Lists](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html)
- [ISO 3166-1 Country Codes](https://www.iso.org/iso-3166-country-codes.html)
- [Suricata Protocols Documentation](https://docs.suricata.io/en/latest/rules/intro.html)