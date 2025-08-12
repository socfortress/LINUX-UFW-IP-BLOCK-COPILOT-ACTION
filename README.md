## Block-IP

This script blocks a specified IP address using UFW (Uncomplicated Firewall), providing a JSON-formatted output for integration with security tools like OSSEC/Wazuh.

### Overview

The `Block-IP` script checks if an IP address is already blocked by UFW and adds a deny rule if not present. It logs all actions and outputs the result in JSON format for active response workflows.

### Script Details

#### Core Features

1. **IP Blocking**: Adds UFW deny rules for a specified IP address.
2. **Status Reporting**: Reports whether the IP was blocked, already blocked, or if an error occurred.
3. **JSON Output**: Generates a structured JSON report for integration with security tools.
4. **Logging Framework**: Provides detailed logs for script execution.
5. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
ARG1="1.2.3.4" ./Block-IP
```

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `ARG1`    | string | The IP address to block (required) |
| `LOG`     | string | `/var/ossec/active-response/active-responses.log` (output JSON log) |
| `LogPath` | string | `/tmp/Block-IP.log` (detailed execution log) |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

### Script Execution Flow

#### 1. Initialization Phase
- Rotates the detailed log file if it exceeds the size limit
- Clears the active response log file
- Logs the start of the script execution

#### 2. Block Logic
- Checks if the IP is provided
- Checks if the IP is already blocked by UFW
- Adds the deny rule if not present
- Logs the result and status

#### 3. JSON Output Generation
- Formats the result into a JSON object
- Writes the JSON result to the active response log

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Block-IP",
  "ip": "1.2.3.4",
  "status": "blocked",
  "reason": "IP blocked successfully",
  "copilot_soar": true
}
```

#### Already Blocked Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Block-IP",
  "ip": "1.2.3.4",
  "status": "already_blocked",
  "reason": "IP was already blocked",
  "copilot_soar": true
}
```

#### Error Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Block-IP",
  "ip": "",
  "status": "error",
  "reason": "No IP provided",
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to manage UFW rules
- Validate the JSON output for compatibility with your security tools
- Test the script in isolated environments

#### Security Considerations
- Ensure minimal required privileges
- Protect the output log files

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has privileges to modify UFW rules
2. **Missing IP**: Provide the IP address via the `ARG1` environment variable
3. **Log File Issues**: Check write permissions

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ARG1="1.2.3.4" ./Block-IP
```

### Contributing

When modifying this script:
1. Maintain the IP blocking and JSON output structure
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
