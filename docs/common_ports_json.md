# common_ports.json Documentation

## Overview

The `common_ports.json` file provides a library of pre-defined port variable sets for common services and security scenarios. This file is used by the Suricata Rule Generator to help users quickly define port variables without memorizing port numbers.

## File Location

`common_ports.json` (in the root directory of the application)

## Purpose

- Provides categorized port definitions for common services
- Enables quick insertion of port variables into Suricata rules
- Standardizes port variable naming across rulesets
- Reduces errors from manually typing port numbers

## File Structure

The JSON file uses a hierarchical structure with version information and categorized port definitions:

```json
{
  "version": "1.0.0",
  "last_updated": "2025-12-21",
  "description": "Common port definitions for Suricata rule generation",
  "categories": {
    "Category Name": [
      {
        "name": "$VARIABLE_NAME",
        "definition": "[port1,port2,port3]",
        "description": "Human-readable description"
      }
    ]
  }
}
```

### Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | String | Version number (follows semantic versioning) |
| `last_updated` | String | Date of last modification (YYYY-MM-DD format) |
| `description` | String | Brief description of the file's purpose |
| `categories` | Object | Contains all port definition categories |

### Structure Elements

- **Category Name** (String): Grouping for related port sets (under `categories` object)
  - Examples: "Windows/Active Directory", "Web Services", "Databases"
- **name** (String): The Suricata variable name (must start with `$`)
  - Format: `$VARIABLE_NAME` (uppercase with underscores)
- **definition** (String): Comma-separated port list in brackets
  - Single port: `[80]`
  - Multiple ports: `[80,443,8080]`
  - Port range: `[49152:65535]`
- **description** (String): Brief explanation of the ports' purpose

## Current Categories

### 1. Windows/Active Directory
Port variables for Microsoft Windows and Active Directory services.

| Variable | Ports | Description |
|----------|-------|-------------|
| `$AD` | 53,88,123,135,389,445,464,636,9389,3268,3269,49152:65535 | Active Directory services |
| `$SMB` | 139,445 | NetBIOS and SMB file sharing |
| `$RPC` | 135 | RPC Endpoint Mapper |
| `$WINDOWS_MGMT` | 3389,5985,5986 | RDP and WinRM |

### 2. Web Services
HTTP/HTTPS and proxy server ports.

| Variable | Ports | Description |
|----------|-------|-------------|
| `$WEB` | 80,443 | Standard HTTP/HTTPS |
| `$WEB_ALT` | 8080,8443 | Alternative web ports |
| `$PROXY` | 3128,8080,8888 | HTTP proxy servers |

### 3. Databases
Common database server ports.

| Variable | Ports | Description |
|----------|-------|-------------|
| `$SQL_SERVER` | 1433,1434 | Microsoft SQL Server |
| `$MYSQL` | 3306 | MySQL/MariaDB |
| `$POSTGRES` | 5432 | PostgreSQL |
| `$ORACLE` | 1521,1522 | Oracle Database |
| `$REDIS` | 6379 | Redis cache |
| `$MONGODB` | 27017,27018,27019 | MongoDB cluster |

### 4. Email
Email protocol ports.

| Variable | Ports | Description |
|----------|-------|-------------|
| `$SMTP` | 25,465,587 | SMTP (plain, TLS, submission) |
| `$IMAP` | 143,993 | IMAP and IMAPS |
| `$POP3` | 110,995 | POP3 and POP3S |

### 5. Security/Threat Detection
Ports commonly associated with malware and threats.

| Variable | Ports | Description |
|----------|-------|-------------|
| `$MALWARE_C2_COMMON` | 1080,4444,5555,6666,7777,8888,9999 | Common malware C2 ports |
| `$CRYPTO_MINING` | 3333,4444,5555,8332,8333,9332,9333 | Cryptocurrency mining |
| `$BRUTE_FORCE_TARGETS` | 22,23,3389 | SSH, Telnet, RDP |

### 6. VPN
VPN protocol ports.

| Variable | Ports | Description |
|----------|-------|-------------|
| `$VPN` | 500,1194,1701,4500 | IPsec, OpenVPN, L2TP |

### 7. DevOps
Development and DevOps tool ports.

| Variable | Ports | Description |
|----------|-------|-------------|
| `$GIT` | 22,443,9418 | Git SSH, HTTPS, protocol |
| `$DOCKER` | 2375,2376 | Docker HTTP/HTTPS |

## Adding New Port Definitions

### Step 1: Identify the Category

Determine which existing category your port definition belongs to, or create a new category if needed.

**Existing categories:**
- Windows/Active Directory
- Web Services
- Databases
- Email
- Security/Threat Detection
- VPN
- DevOps

**Creating a new category:**
```json
{
  "version": "1.0.0",
  "last_updated": "2025-12-21",
  "description": "Common port definitions for Suricata rule generation",
  "categories": {
    "Your Category Name": []
  }
}
```

### Step 2: Define the Port Variable

Create a new port variable entry with the required fields:

```json
{
  "name": "$YOUR_VARIABLE_NAME",
  "definition": "[port_numbers_here]",
  "description": "Brief description of the service"
}
```

### Step 3: Format the Port Definition

Port definitions must follow Suricata syntax:

**Single port:**
```json
"definition": "[3306]"
```

**Multiple ports (comma-separated):**
```json
"definition": "[80,443,8080]"
```

**Port range (colon-separated):**
```json
"definition": "[8000:8999]"
```

**Mixed (ports and ranges):**
```json
"definition": "[80,443,8000:8999]"
```

### Step 4: Follow Naming Conventions

**Variable names should:**
- Start with `$` (required for Suricata variables)
- Use UPPERCASE letters
- Use underscores `_` to separate words
- Be descriptive but concise
- Follow existing naming patterns

**Good examples:**
- `$WEB_SERVERS`
- `$MAIL_SUBMISSION`
- `$ADMIN_PORTS`

**Bad examples:**
- `$web` (not uppercase)
- `$WEB-SERVERS` (use underscore, not hyphen)
- `$WEBSERVERS` (harder to read without underscore)

### Step 5: Add to the Appropriate Category

Insert your new definition into the category array within the `categories` object:

```json
{
  "version": "1.0.0",
  "last_updated": "2025-12-21",
  "description": "Common port definitions for Suricata rule generation",
  "categories": {
    "Web Services": [
      {
        "name": "$WEB",
        "definition": "[80,443]",
        "description": "Standard HTTP/HTTPS"
      },
      {
        "name": "$YOUR_NEW_VARIABLE",
        "definition": "[your_ports]",
        "description": "Your description"
      }
    ]
  }
}
```

## Example: Adding a Custom Port Definition

Let's add a port variable for Elasticsearch:

```json
{
  "version": "1.0.0",
  "last_updated": "2025-12-21",
  "description": "Common port definitions for Suricata rule generation",
  "categories": {
    "Databases": [
      {
        "name": "$SQL_SERVER",
        "definition": "[1433,1434]",
        "description": "Microsoft SQL Server"
      },
      {
        "name": "$ELASTICSEARCH",
        "definition": "[9200,9300]",
        "description": "Elasticsearch HTTP and transport"
      }
    ]
  }
}
```

## Best Practices

### 1. Use Descriptive Names
Choose variable names that clearly indicate the service or purpose.

✅ Good: `$DATABASE_CLUSTER`  
❌ Bad: `$DB1`

### 2. Group Related Ports
If a service uses multiple related ports, include them in one variable.

```json
{
  "name": "$KUBERNETES",
  "definition": "[6443,2379,2380,10250,10251,10252]",
  "description": "Kubernetes API and control plane"
}
```

### 3. Provide Clear Descriptions
Descriptions should explain what the ports are used for.

✅ Good: "Kubernetes API server and etcd cluster"  
❌ Bad: "K8s ports"

### 4. Avoid Overlapping Variables
Don't create variables with significant port overlap unless there's a clear distinction.

❌ Bad:
```json
{
  "name": "$WEB_COMMON",
  "definition": "[80,443,8080]"
},
{
  "name": "$WEB_ALL",
  "definition": "[80,443,8080,8443]"
}
```

### 5. Consider Security Implications
When creating threat-related variables, document the risk clearly.

```json
{
  "name": "$REMOTE_ADMIN",
  "definition": "[22,23,3389]",
  "description": "Remote admin protocols - common brute force targets"
}
```

## Integration with Application

The application uses `common_ports.json` in several ways:

1. **Port Variable Suggestions**: When users create rules, they can select from these predefined variables
2. **Template Generation**: Rule templates may reference these variables
3. **Documentation**: The UI can display port definitions and descriptions to users
4. **Validation**: The application validates that port variables follow the correct format

## File Validation

Before modifying `common_ports.json`, ensure:

1. **Valid JSON syntax**: Use a JSON validator to check
2. **Required fields present**: All entries have `name`, `definition`, and `description`
3. **Variable name format**: Names start with `$` and use valid characters
4. **Port format**: Definitions use brackets `[...]` and valid port numbers (1-65535)
5. **No duplicates**: Variable names are unique across all categories

## Troubleshooting

### Common Issues

**Issue**: Application fails to load port definitions

**Solution**: 
- Validate JSON syntax using an online JSON validator
- Check for missing commas, brackets, or quotes
- Ensure all required fields are present

**Issue**: Port variable not appearing in UI

**Solution**:
- Verify the variable name starts with `$`
- Check that the entry is in the correct category array
- Restart the application to reload the JSON file

**Issue**: Port syntax errors in rules

**Solution**:
- Ensure port definitions use brackets: `[80,443]` not `80,443`
- Use commas (not spaces) between ports: `[80,443]` not `[80, 443]`
- Verify port ranges use colons: `[8000:8999]` not `[8000-8999]`

## Related Files

- **rule_templates.json**: Uses port variables from this file in templates
- **content_keywords.json**: Documents Suricata syntax for port specifications
- **template_manager.py**: Code that reads and processes this file

## Version History

The `common_ports.json` file includes version information at the top level:

```json
{
  "version": "1.0.0",
  "last_updated": "2025-12-21",
  "description": "Common port definitions for Suricata rule generation",
  "categories": {
    ...
  }
}
```

### Version Control Guidelines

When making changes to `common_ports.json`, update the version and last_updated fields:

**Version Numbering (Semantic Versioning):**
- **Patch version (1.0.X)**: Bug fixes, description updates, minor corrections
- **Minor version (1.X.0)**: New port definitions or categories added
- **Major version (X.0.0)**: Structural changes to the JSON format

**Last Updated:**
- Always update the `last_updated` field to reflect the current date
- Use YYYY-MM-DD format

**Example version progression:**
- Initial release: `1.0.0`
- Added new port definitions: `1.1`
- Fixed port number errors: `1.1.1`
- Changed JSON structure: `2.0`

## Additional Resources

- [Suricata Documentation - Variables](https://docs.suricata.io/en/latest/rules/intro.html#variables)
- [AWS Network Firewall - Port Sets](https://docs.aws.amazon.com/network-firewall/latest/developerguide/stateful-rule-groups-port-sets.html)
- [IANA Port Numbers Registry](https://www.iana.org/assignments/service-names-port-numbers/)
