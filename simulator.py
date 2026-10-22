import json
import ipaddress
from datetime import datetime

#class creation
class FirewallSimulator:
    def __init__(self, configured_rules):
        self.rules = configured_rules
        
    #check packet against stored rules
    def evaluate_packet(self, packet):
        source_address = ipaddress.ip_address(packet['source_ip'])

        for firewall_rule in self.rules:
            if firewall_rule['source_subnet'] == "ANY":
                ip_match = True
            else:
                rule_network = ipaddress.ip_network(firewall_rule['source_subnet'])
                ip_match = source_address in rule_network

            port_match = firewall_rule["port"] == packet["port"]
            protocol_match = firewall_rule["protocol"] == packet["protocol"]

            # return decision and matching rule name
            if ip_match and port_match and protocol_match:
                is_allowed = firewall_rule["action"] == "ALLOW"

                return is_allowed, firewall_rule["rule_name"]

        return False, "Implicit Deny (No Matching Rules)"

def main():
    
    #JSON file loading and error catching
    try:
        with open('firewall_rules.json', encoding='utf-8') as f:
            rules = json.load(f)

    except FileNotFoundError:
        print('Configuration error: firewall_rules.json not found')
        raise SystemExit(1)

    except json.JSONDecodeError as error:
        print(
            f'Invalid JSON on line {error.lineno}, '
            f'column {error.colno}: {error.msg}'
        )
        raise SystemExit(1)

    except UnicodeDecodeError:
        print("Configuration error: firewall_rules.json must use UTF-8 encoding.")
        raise SystemExit(1)

    except OSError as error:
        print(f"Could not read firewall_rules.json: {error}")
        raise SystemExit(1)

    #check for required fields for JSON file
    required_fields = [
        "rule_name",
        "source_subnet",
        "port",
        "protocol",
        "action"
    ]
    
    #JSON file list check
    if not isinstance(rules, list):
        print("Configuration error: the JSON must contain a list of rules")
        raise SystemExit(1)

    #JSON file rule warning
    if not rules:
        print("Warning: no rules configured. All simulated traffic will be blocked")

    #JSON file rule validation
    for rule_number, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            print(
                f"Configuration error: rule {rule_number} "
                "must be an object"
            )
            raise SystemExit(1)

        rule_name = rule.get('rule_name', 'unnamed rule')
        rule_label = f'rule {rule_number} ({rule_name!r})'

        #JSON file required field validation
        for field in required_fields:
            if field not in rule:
                print(
                    f"Configuration error: {rule_label} "
                    f"is missing '{field}'"
                )
                raise SystemExit(1)

        #JSON file rule name validation
        if not isinstance(rule_name, str) or not rule_name.strip():
            print(
                f"Configuration error: {rule_label} "
                "rule name must be a nonempty string"
            )
            raise SystemExit(1)

        #JSON file subnet validation
        subnet = rule['source_subnet']

        if not isinstance(subnet, str) or not subnet.strip():
            print(
                f"Configuration error: {rule_label} "
                f"has invalid source_subnet {subnet!r}"
                "source_subnet must be a nonempty string"
            )
            raise SystemExit(1)

        if subnet != "ANY":
            try:
                ipaddress.ip_network(subnet, strict=True)

            except ValueError as error:
                print(
                    f"Configuration error: {rule_label} "
                    f"has invalid subnet {subnet!r}: {error}"
                )
                raise SystemExit(1)

        #JSON file action validation
        if rule["action"] not in ("ALLOW", "BLOCK"):
            print(
                f"Configuration error: {rule_label} "
                f"has invalid action {rule['action']!r} "
                "Action must be either ALLOW or BLOCK"
            )
            raise SystemExit(1)

        #JSON file port validation
        port = rule['port']

        if type(port) is not int or not 1 <= port <= 65535:
            print(
                f"Configuration error: {rule_label} "
                f"has invalid port {port!r} "
                "Port must be an integer between 1-65535"
            )
            raise SystemExit(1)

        #JSON file protocol validation
        if rule["protocol"] not in ("TCP", "UDP"):
            print(
                f"Configuration error: {rule_label} "
                f"has invalid protocol {rule['protocol']!r} "
                "protocol must be either TCP or UDP"
            )
            raise SystemExit(1)

    simulator = FirewallSimulator(rules)

    #IP Address input validation
    while True:
        user_ip = input("Enter Source IP address (ex. 192.168.1.1): ").strip()
        try:
            ipaddress.ip_address(user_ip)
            break

        except ValueError:
            print("Invalid IP Address format. Please try again.")

    #Destination port input validation
    while True:
        try:
            user_port = int(input("Enter Destination Port (1-65535): "))
            if 1 <= user_port <= 65535:
                break

            print("Port must be between 1-65535")

        except ValueError:
            print("Invalid port. Please enter a whole number.")

    #Protocol input validation
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

    allowed, matched_rule = simulator.evaluate_packet(incoming_packet)


    action_result = "ALLOW" if allowed else "BLOCK"
    access_status = "GRANTED" if allowed else "DENIED"

    print(f"ACCESS {access_status}: Packet processed via rule '{matched_rule}'")

    #assign time and packet info for log creation
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] ACTION={action_result} SRC={user_ip} DST_PORT={user_port} PROTOCOL={user_protocol} RULE='{matched_rule}'\n"

    #append to log file
    try:
        with open("firewall_activities.log", "a", encoding="utf-8") as log_file:
            log_file.write(log_entry)

    except OSError as error:
        print(f"Logging error: could not write event: {error}")
        raise SystemExit(1)

    print("Event appended to 'firewall_activities.log'")

if __name__ == "__main__":
    main()
