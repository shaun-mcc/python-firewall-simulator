# python-firewall-simulator

A command-line Python simulator that evaluates manually entered source
IP addresses, destination ports, and protocols against JSON-defined
firewall rules.

Developed as an extension of my cybersecurity capstone work.

## Features

- Source IP address validation
- Destination port validation (1–65535)
- Protocol validation (TCP or UDP)
- Source subnet matching
- First-match rule processing
- Implicit deny when no rule matches
- Timestamped decision logging

## How It Works

The simulator loads rules from firewall_rules.json and asks the user for a source IP address, destination port, and protocol.

Rules are checked in order. The first matching rule determines whether the simulated traffic is allowed or blocked. If no rule is matched, the traffic is blocked by default.

Each decision is appended to firewall_activities.log.

## Running the Simulator

1. Download the Python script and firewall_rules.json.
2. Put both files in the same folder.
3. Open a terminal in that folder.
4. Run the Python script.
5. Enter the requested traffic information.

## Limitations

This is solely an educational simulator, not a functioning network firewall. It does not capture or block real traffic.

It currently evaluates source IP addresses, destination ports, and protocols. It does not evaluate destination IP addresses or verify application protocols such as HTTPS.

## Planned Improvements

- JSON rule configuration validation
- Automated tests
- Batch evaluation of sample traffic
- Separate functions for input, rule evaluation, and logging

## Author

Shaun McCrimmon
