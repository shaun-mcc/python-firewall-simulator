import json
import ipaddress
from datetime import datetime

try:
    with open('firewall_rules.json') as f:
        rules = json.load(f)

except FileNotFoundError:
    print('firewall_rules.json not found')
    rules = []

#IP Address input validation
while True:
    user_ip = input("Enter Source IP address (ex. 192.168.1.1): ").strip()
    try:
        packet_ip = ipaddress.ip_address(user_ip)
        break

    except ValueError:
        print("Invalid IP Address format. Please try again.")

#Destination port validation
while True:
    try:
        user_port = int(input("Enter Destination Port (1-65535): "))
        if 1 <= user_port <= 65535:
            break

        print("Port must be between 1-65535")

    except ValueError:
        print("Invalid port. Please enter a whole number.")

#Protocol validation
while True:
    user_protocol = input("Enter Destination Protocol (TCP or UDP): ").strip().upper()
    if user_protocol in ("TCP", "UDP"):
        break

    print("Protocol must be either TCP or UDP")


incoming_packet = {
    "source_ip": user_ip,
    "port": user_port,
    "protocol": user_protocol
}

print(f"Analyzing packet from {incoming_packet['source_ip']} on port {incoming_packet['port']}")

allowed = False
matched_rule = "Implicit Deny (No Matching Rules)"

for rule in rules:
    #check if rule matches packet criteria
    if rule['source_subnet'] == "ANY":
        ip_match = True
    else:
        rule_network = ipaddress.ip_network(rule['source_subnet'])
        ip_match = packet_ip in rule_network

    port_match = (rule['port'] == incoming_packet['port'])
    protocol_match = (rule['protocol'] == incoming_packet['protocol'])

    if ip_match and port_match and protocol_match:
        if rule['action'] == "ALLOW":
            allowed = True
        matched_rule = rule['rule_name']
        break

action_result = "ALLOW" if allowed else "BLOCK"
access_status = "GRANTED" if allowed else "DENIED"

print(f"ACCESS {access_status}: Packet processed via rule '{matched_rule}'")

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
log_entry = f"[{timestamp}] ACTION={action_result} SRC={user_ip} DST_PORT={user_port} PROTOCOL={user_protocol} RULE='{matched_rule}'\n"

#append to log file
with open("firewall_activities.log", "a") as log_file:
    log_file.write(log_entry)

print("Event appended to 'firewall_activities.log'")