# python-firewall-simulator

A command-line Python simulator that evaluates manually entered source
IP addresses, destination ports, and protocols against JSON-defined
firewall rules.

Developed as an extension of my cybersecurity capstone work. This project demonstrates Python scripting, configuration validation, IP subnet matching, rule evaluation, and activity logging.

## Features

- Loads firewall rules from a JSON file
- Validates configuration structure and required fields before accepting packet input
- Includes rule names and positions in configuration error messages
- Supports CIDR subnet matching and an `ANY` source option
- Evaluates rules in order and uses the first matching rule
- Blocks packets that do not match any rule
- Validates user-entered IP addresses, ports, and protocols
- Appends packet decisions to an activity log
- Handles configuration file-reading and log-writing errors

## Requirements

- Python 3
- No third-party packages required

The program uses the Python standard library:
- `json`
- `ipaddress`
- `datetime`

## How It Works

The simulator loads rules from firewall_rules.json and asks the user for a source IP address, destination port, and protocol.

Rules are checked in order. The first matching rule determines whether the simulated traffic is allowed or blocked. If no rule is matched, the traffic is blocked by default.

Each decision is appended to firewall_activities.log.

## Running the Simulator

1. Download the Python script and firewall_rules.json
2. Put both files in the same folder
3. Open a terminal in that folder
4. Run the Python script
5. Enter the requested traffic information

## Rule Configuration

The configuration file must contain a JSON list of rule objects.

### Required Fields

| Field | Accepted value |
|---|---|
| `rule_name` | A nonempty string that is not only whitespace |
| `source_subnet` | A valid network in CIDR notation, or `"ANY"` |
| `port` | A JSON integer from 1 through 65535, not a quoted string |
| `protocol` | `"TCP"` or `"UDP"` |
| `action` | `"ALLOW"` or `"BLOCK"` |

Configuration values for protocol, action, and `ANY` are case-sensitive.

Subnet validation uses strict network checking. For example, use `192.168.1.0/24` rather than `192.168.1.5/24`, which has host bits set.

An empty rules list produces a warning. The simulator continues, but all entered packets receive an implicit deny.

## How the Rule Matching Works

A rule matches only when all three conditions are satisfied:

1. The source IP address belongs to the configured subnet, or the source is `"ANY"`
2. The destination port matches the configured port
3. The protocol matches the configured protocol

Rules are checked from top to bottom. The first matching rule determines the result, and evaluation stops.

If no rule matches, the packet is blocked using:

```text
Implicit Deny (No Matching Rules)
```
## Configuration Validation

Before prompting for packet information, the simulator checks:

- Whether the configuration file exists and can be read
- Whether the file contains valid UTF-8 and valid JSON
- Whether the top-level JSON value is a list
- Whether each rule is an object
- Whether each rule includes all required fields
- Whether rule names are nonempty strings
- Whether subnets, ports, protocols, and actions are valid

Validation stops at the first configuration error.

Rule-specific errors identify the rule's position and name when available.

## User Input Validation

The simulator checks that:

- Source IP address is valid
- Destination port is a whole number from 1 through 65535
- Protocol is TCP or UDP

Invalid input prompts the user to try again. User-entered protocols are converted to uppercase.

## Activity Logging

Each successfully processed packet decision is appended to:

```text
firewall_activities.log
```

Each entry includes:

- Local timestamp
- Action: `ALLOW` or `BLOCK`
- Source IP address
- Destination port
- Protocol
- Matching rule name or implicit-deny description

If the log cannot be written, the program reports a logging error and exits. The packet decision may already have been displayed, but it has not been successfully recorded.

## Limitations

- This is solely an educational simulator, not a functioning network firewall
- It does not capture or block real traffic
- It evaluates user-entered packet information; it does not capture or filter live network traffic
- It does not modify operating-system firewall rules
- Each rule supports one destination port and one protocol
- It does not implement connection tracking or stateful inspection
- Configuration validation reports the first error rather than collecting all errors
- It does not evaluate destination IP addresses or verify application protocols such as HTTPS

## Planned Improvements

- Automated tests
- Batch evaluation of sample traffic
- Separate functions for input, rule evaluation, and logging

## Author

Shaun McCrimmon
