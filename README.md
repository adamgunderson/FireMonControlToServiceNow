# FireMon to ServiceNow Integration

This script sends FireMon Security Manager control failures to ServiceNow, creating incidents or records in a specified table.

## Features

- Fetches control failures from FireMon Security Manager API
- **Handles both rule-level and device-level control failures**
  - Rule-level: Control checks that fail on specific firewall rules
  - Device-level: Control checks on device properties, configurations, regex patterns, etc.
- **Process multiple devices and assessments in a single run**
- **Support for device groups and all devices in domain**
- Creates records in ServiceNow using the Table API
- Deduplication based on correlation ID to avoid duplicate records
- **Severity filtering to reduce noise** (supports both text and numeric severity levels)
- Update existing records or skip duplicates
- Comprehensive logging and error handling
- SSL certificate verification (can be disabled for testing)
- Pagination support for large result sets

## Prerequisites

- Python 3.8+
- Access to FireMon Security Manager API
- Access to ServiceNow Table API
- Required Python packages: `requests`

## Installation

1. Ensure Python 3.8 or higher is installed
2. Install required packages:
   ```bash
   pip install requests
   ```

## Usage

### Using Environment Variables (Recommended for Security)

To avoid exposing credentials in command-line arguments or scripts, use environment variables:

#### Linux/macOS

```bash
# Set environment variables
export FIREMON_URL="https://firemon.example.com"
export FIREMON_USER="admin"
export FIREMON_PASS="your_password"
export SNOW_URL="https://instance.service-now.com"
export SNOW_USER="snow_admin"
export SNOW_PASS="snow_password"

# Run the script using environment variables
python firemon_to_servicenow.py \
  --firemon-url "$FIREMON_URL" \
  --firemon-user "$FIREMON_USER" \
  --firemon-pass "$FIREMON_PASS" \
  --snow-url "$SNOW_URL" \
  --snow-user "$SNOW_USER" \
  --snow-pass "$SNOW_PASS" \
  --device-id 123 \
  --assessment abc-123-def-456
```

#### Windows (Command Prompt)

```cmd
# Set environment variables
set FIREMON_URL=https://firemon.example.com
set FIREMON_USER=admin
set FIREMON_PASS=your_password
set SNOW_URL=https://instance.service-now.com
set SNOW_USER=snow_admin
set SNOW_PASS=snow_password

# Run the script using environment variables
python firemon_to_servicenow.py ^
  --firemon-url %FIREMON_URL% ^
  --firemon-user %FIREMON_USER% ^
  --firemon-pass %FIREMON_PASS% ^
  --snow-url %SNOW_URL% ^
  --snow-user %SNOW_USER% ^
  --snow-pass %SNOW_PASS% ^
  --device-id 123 ^
  --assessment abc-123-def-456
```

#### Windows (PowerShell)

```powershell
# Set environment variables
$env:FIREMON_URL = "https://firemon.example.com"
$env:FIREMON_USER = "admin"
$env:FIREMON_PASS = "your_password"
$env:SNOW_URL = "https://instance.service-now.com"
$env:SNOW_USER = "snow_admin"
$env:SNOW_PASS = "snow_password"

# Run the script using environment variables
python firemon_to_servicenow.py `
  --firemon-url $env:FIREMON_URL `
  --firemon-user $env:FIREMON_USER `
  --firemon-pass $env:FIREMON_PASS `
  --snow-url $env:SNOW_URL `
  --snow-user $env:SNOW_USER `
  --snow-pass $env:SNOW_PASS `
  --device-id 123 `
  --assessment abc-123-def-456
```

#### Persistent Environment Variables

To make environment variables persist across sessions:

**Linux/macOS:**
Add to `~/.bashrc`, `~/.bash_profile`, or `~/.zshrc`:
```bash
export FIREMON_URL="https://firemon.example.com"
export FIREMON_USER="admin"
export FIREMON_PASS="your_password"
export SNOW_URL="https://instance.service-now.com"
export SNOW_USER="snow_admin"
export SNOW_PASS="snow_password"
```

Then reload: `source ~/.bashrc`

**Windows:**
Set persistent environment variables using System Properties or PowerShell:
```powershell
[System.Environment]::SetEnvironmentVariable('FIREMON_URL', 'https://firemon.example.com', 'User')
[System.Environment]::SetEnvironmentVariable('FIREMON_USER', 'admin', 'User')
[System.Environment]::SetEnvironmentVariable('FIREMON_PASS', 'your_password', 'User')
[System.Environment]::SetEnvironmentVariable('SNOW_URL', 'https://instance.service-now.com', 'User')
[System.Environment]::SetEnvironmentVariable('SNOW_USER', 'snow_admin', 'User')
[System.Environment]::SetEnvironmentVariable('SNOW_PASS', 'snow_password', 'User')
```

### Basic Example (Direct Credentials - Not Recommended for Production)

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass your_password \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-id 123 \
  --assessment abc-123-def-456
```

**Warning:** Avoid hardcoding credentials in scripts or command history. Use environment variables or a secure credential management system.

### Command Line Arguments

#### Required Arguments

**FireMon Connection:**
- `--firemon-url`: FireMon base URL (e.g., https://firemon.example.com)
- `--firemon-user`: FireMon username
- `--firemon-pass`: FireMon password

**Device Selection** (choose one):
- `--device-id`: FireMon device ID (can be specified multiple times for multiple devices)
- `--device-group-id`: FireMon device group ID (processes all devices in the group)
- `--all-devices`: Process all devices in the domain

**Assessment Selection:**
- `--assessment`: FireMon assessment UUID (can be specified multiple times for multiple assessments)

**ServiceNow Connection:**
- `--snow-url`: ServiceNow instance URL (e.g., https://instance.service-now.com)
- `--snow-user`: ServiceNow username
- `--snow-pass`: ServiceNow password

#### Optional Arguments

- `--snow-table`: ServiceNow table name (default: `incident`)
  - Supported tables: `incident`, `em_event` (Event Management), or any custom table
  - The script automatically formats payloads based on the table type
- `--min-severity`: Minimum severity level to process (choices: INFO, LOW, MEDIUM, HIGH, CRITICAL; default: INFO)
- `--update-existing`: Update existing records instead of skipping them
- `--no-verify`: Disable SSL certificate verification (not recommended for production)
- `-v, --verbose`: Enable verbose debug output

### Examples

#### Single Device, Single Assessment

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-id 123 \
  --assessment abc-123-def-456
```

#### Multiple Devices, Multiple Assessments

Process multiple specific devices against multiple assessments:

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-id 123 --device-id 456 --device-id 789 \
  --assessment abc-123 --assessment def-456 --assessment ghi-789
```

#### Device Group with Multiple Assessments

Process all devices in a device group against multiple assessments:

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-group-id 5 \
  --assessment abc-123 --assessment def-456
```

#### All Devices in Domain

Process all devices in the domain against a single assessment:

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --all-devices \
  --assessment abc-123-def-456
```

#### Use Custom Table

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-id 123 \
  --assessment abc-123-def-456 \
  --snow-table u_firemon_violations
```

#### Use Event Management Table

Send control failures to ServiceNow Event Management:

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-id 123 \
  --assessment abc-123-def-456 \
  --snow-table em_event
```

#### Update Existing Records

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-id 123 \
  --assessment abc-123-def-456 \
  --update-existing
```

#### Filter by Severity Level

Only process control failures with MEDIUM severity or higher:

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-id 123 \
  --assessment abc-123-def-456 \
  --min-severity MEDIUM
```

Only process CRITICAL control failures:

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-id 123 \
  --assessment abc-123-def-456 \
  --min-severity CRITICAL
```

#### Enable Verbose Logging

```bash
python firemon_to_servicenow.py \
  --firemon-url https://firemon.example.com \
  --firemon-user admin \
  --firemon-pass password123 \
  --snow-url https://instance.service-now.com \
  --snow-user snow_admin \
  --snow-pass snow_password \
  --device-id 123 \
  --assessment abc-123-def-456 \
  --verbose
```

## ServiceNow Table Schema

The script automatically formats payloads based on the target table type.

### Incident Table (`incident`)

Standard fields populated for the incident table:

- `short_description`: Brief description of the control failure
- `description`: Detailed information about the rule and control violation
- `correlation_id`: Unique identifier for deduplication (format: `FM-{device_id}-{assessment_uuid}-{rule_uid}-{control_code}`)
- `impact`: Severity mapped from FireMon (1=Critical, 2=High, 3=Medium, 4=Low, 5=Info)
- `urgency`: Same as impact
- `category`: Set to "Security"
- `subcategory`: Set to "Firewall Policy Violation" or "Firewall Configuration Violation"

### Event Management Table (`em_event`)

Standard fields populated for the em_event table:

- `source`: Set to "FireMon Security Manager"
- `node`: Device name
- `type`: "Rule Control Failure" or "Device Control Failure"
- `severity`: Severity mapped from FireMon (1=Critical, 2=High, 3=Medium, 4=Low, 5=Info)
- `description`: Detailed information about the rule and control violation
- `message_key`: Unique identifier for deduplication (format: `FM-{device_id}-{assessment_uuid}-{rule_uid}-{control_code}`)
- `resource`: Device ID or Rule identifier
- `additional_info`: Summary of control, code, and rule/device details
- `time_of_event`: Timestamp when the event was created

### Custom Fields (Optional - Incident Table Only)

If you're using a custom incident table, you may want to add these fields:

- `u_firemon_device_id` (String): FireMon device ID
- `u_firemon_assessment` (String): FireMon assessment UUID
- `u_firemon_rule_uid` (String): FireMon rule UID
- `u_firemon_control_code` (String): FireMon control code
- `u_firemon_severity` (String): Original FireMon severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)

**Note**: If these custom fields don't exist in your table, ServiceNow will ignore them. The script will still work with just the standard fields.

## Control Types

FireMon assessments can identify two types of control failures:

### Rule-Level Controls
These are control checks that fail on specific firewall rules. Examples:
- "ANY in Service with Action of Accept" - Rules using "any" service
- "Shadowed Rules" - Rules that are never matched due to earlier rules
- "Unused Rules" - Rules with no hit counts

### Device-Level Controls
These are control checks that fail on device-wide settings or configurations. Examples:
- "Allow Forwarding of Decrypted Content" - Device property settings
- "Password Complexity Requirements" - Device configuration settings
- "Logging Configuration" - System-level logging settings
- Regular expression pattern checks on device config

The script automatically detects and processes both types, creating appropriately formatted ServiceNow records for each.

## Deduplication

The script prevents duplicate records using a unique identifier field:

- **Incident table**: Uses `correlation_id` field
- **Event Management table**: Uses `message_key` field

The unique identifier formats are:

**Rule-level controls:**
```
FM-{device_id}-{assessment_uuid}-{rule_uid}-{control_code}
```

**Device-level controls:**
```
FM-{device_id}-{assessment_uuid}-DEVICE-{control_code}
```

By default:
- If a record with the same unique identifier exists, it will be skipped
- Use `--update-existing` to update existing records instead

## Record Format

### Rule-Level Control Failures

**Short Description:**
```
FireMon Control Failure: {control_name} - {rule_name}
```

**Description:**
```
FireMon Security Manager Rule-Level Control Failure

Assessment: {assessment_uuid}
Device ID: {device_id}

Rule Information:
- Rule Name: {rule_name}
- Rule Number: {rule_number}
- Policy: {policy_name}
- Severity: {rule_severity}
- Action: {action}

Rule Details:
- Sources: {sources with IPs}
- Destinations: {destinations with IPs}
- Services: {services with protocols/ports}

Control Violation:
- Control: {control_name}
- Code: {control_code}
- Severity: {control_severity}
- Description: {control_description}
```

### Device-Level Control Failures

**Short Description:**
```
FireMon Device Control Failure: {control_name} - {device_name}
```

**Description:**
```
FireMon Security Manager Device-Level Control Failure

Assessment: {assessment_uuid}
Device ID: {device_id}
Device Name: {device_name}

Control Violation:
- Control: {control_name}
- Code: {control_code}
- Type: {control_type} (e.g., Device Property, Regex Config)
- Severity: {control_severity}
- Description: {control_description}
```

## Severity Mapping

FireMon severity levels are mapped to ServiceNow severity values. The script supports both text-based and numeric severity values:

### Text-Based Severity
| FireMon Severity | ServiceNow Severity | Description |
|-----------------|---------------------|-------------|
| CRITICAL        | 1                   | Critical    |
| HIGH            | 2                   | High        |
| MEDIUM          | 3                   | Medium      |
| LOW             | 4                   | Low         |
| INFO            | 5                   | Info        |

**Note**: For the `incident` table, severity values map to both `impact` and `urgency` fields. For the `em_event` table, they map to the `severity` field.

### Numeric Severity (automatically converted)
| FireMon Numeric | Converted To | ServiceNow Severity |
|----------------|--------------|---------------------|
| 9-10           | CRITICAL     | 1 - Critical        |
| 7-8            | HIGH         | 2 - High            |
| 5-6            | MEDIUM       | 3 - Medium          |
| 3-4            | LOW          | 4 - Low             |
| 0-2            | INFO         | 5 - Info            |

## Output

The script provides a summary upon completion:

```
Integration Summary:
  Devices processed: 3
  Assessments processed: 6
  Total control failures found: 45
    - Rule-level failures: 32
    - Device-level failures: 13
  Filtered (below minimum severity): 12
  Records created: 30
  Records updated: 0
  Records skipped: 3
  Errors: 0
```

The summary shows:
- **Devices processed**: Number of devices that were processed
- **Assessments processed**: Number of device/assessment combinations checked (devices × assessments)
- **Total control failures found**: All control failures discovered across all devices/assessments
  - **Rule-level failures**: Control failures tied to specific firewall rules
  - **Device-level failures**: Control failures tied to device properties/configurations
- **Filtered**: Control failures ignored due to severity filtering
- **Records created/updated/skipped**: Actions taken in ServiceNow

## Severity Filtering

Use `--min-severity` to only process control failures at or above a specific severity level:

- `--min-severity INFO`: Process all control failures (default)
- `--min-severity LOW`: Process LOW, MEDIUM, HIGH, and CRITICAL failures (filter out INFO)
- `--min-severity MEDIUM`: Process MEDIUM, HIGH, and CRITICAL failures (filter out INFO and LOW)
- `--min-severity HIGH`: Process HIGH and CRITICAL failures only
- `--min-severity CRITICAL`: Process only CRITICAL failures

This is useful to reduce noise and focus ServiceNow tickets on higher-priority issues.

## Error Handling

- Authentication failures are logged and cause the script to exit
- API errors are logged but processing continues for remaining records
- The script exits with code 1 if any errors occurred, 0 otherwise

## Logging

Logs include timestamps, severity levels, and detailed messages:

```
2025-10-07 10:30:45 - INFO - Authenticating to FireMon at https://firemon.example.com/securitymanager/api/authentication/validate
2025-10-07 10:30:46 - INFO - Successfully authenticated to FireMon as admin
2025-10-07 10:30:47 - INFO - Retrieved 45 rules with failed controls
2025-10-07 10:30:48 - INFO - Processing rule: Allow_Internet_Access
2025-10-07 10:30:49 - INFO - Successfully created record in incident
```

## Bulk Processing

The script can process multiple devices and assessments efficiently:

- **Device Groups**: Use `--device-group-id` to automatically process all devices in a group
- **All Devices**: Use `--all-devices` to process every device in the domain
- **Multiple Assessments**: Specify `--assessment` multiple times to run against multiple assessments
- **Combinations**: Each device will be checked against each assessment (cartesian product)

For example, processing 3 devices against 2 assessments will result in 6 device/assessment combinations being checked.

## Security Considerations

1. **Credentials**: Never hardcode credentials. Use environment variables or a secure credential store.
2. **SSL Verification**: Always verify SSL certificates in production. Only use `--no-verify` for testing.
3. **API Permissions**: Ensure service accounts have minimal required permissions:
   - FireMon: Read access to devices, device groups, assessments, and controls
   - ServiceNow: Create/Update access to target table

## Troubleshooting

### Authentication Failure
- Verify credentials are correct
- Check that the user has API access enabled
- Ensure the URLs are correct and accessible

### No Records Created
- Verify the device ID and assessment UUID are correct
- Check that there are failed controls in the assessment
- Use `--verbose` to see detailed API responses

### SSL Certificate Errors
- For testing: Use `--no-verify` (not recommended for production)
- For production: Install proper certificates or update your certificate store

### Custom Fields Not Populated
- Verify the fields exist in the target ServiceNow table
- Check field permissions for the ServiceNow user
- Fields prefixed with `u_` are custom fields and must be created manually

## Related Files

- `firemon_assessment_export.py`: Original script that exports control failures to CSV
- `openapi-sm.json`: FireMon Security Manager API specification
- `servicenow_table_api_latest_spec.json`: ServiceNow Table API specification

## License

This script is provided as-is for integration purposes.
