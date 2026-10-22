# unit tests for packet matching
# tests use in-memory rules and packets
# rather than JSON configuration, user prompts, or activity log

import unittest

from simulator import FirewallSimulator


class TestFirewallSimulator(unittest.TestCase):

    # create baseline rule, packet, expected implicit deny result
    def setUp(self):
        self.allow_rule = {
            "rule_name": "Allow Admin SSH",
            "source_subnet": "192.168.1.0/24",
            "port": 22,
            "protocol": "TCP",
            "action": "ALLOW"
        }

        self.packet = {
            "source_ip": "192.168.1.10",
            "port": 22,
            "protocol": "TCP"
         }

        self.implicit_deny = (
            False,
            "Implicit Deny (No Matching Rules)"
        )

    def test_matching_allow_rule(self):
        simulator = FirewallSimulator([self.allow_rule])

        result = simulator.evaluate_packet(self.packet)

        self.assertEqual(result, (True, "Allow Admin SSH"))

    def test_matching_block_rule(self):
        block_rule = {
            **self.allow_rule,
            "rule_name": "Block Admin SSH",
            "action": "BLOCK"
        }
        simulator = FirewallSimulator([block_rule])

        result = simulator.evaluate_packet(self.packet)

        self.assertEqual(result, (False, "Block Admin SSH"))

    def test_source_outside_subnet_is_denied(self):
        simulator = FirewallSimulator([self.allow_rule])
        packet = {
            **self.packet,
            "source_ip": "10.0.0.10"
        }

        result = simulator.evaluate_packet(packet)

        self.assertEqual(result, self.implicit_deny)

    def test_wrong_port_is_denied(self):
        simulator = FirewallSimulator([self.allow_rule])
        packet = {
            **self.packet,
            "port": 443
        }

        result = simulator.evaluate_packet(packet)

        self.assertEqual(result, self.implicit_deny)

    def test_wrong_protocol_is_denied(self):
        simulator = FirewallSimulator([self.allow_rule])
        packet = {
            **self.packet,
            "protocol": "UDP"
        }

        result = simulator.evaluate_packet(packet)

        self.assertEqual(result, self.implicit_deny)

    def test_any_source_matches(self):
        any_source_rule = {
            **self.allow_rule,
            "rule_name": "Allow SSH From Any Source",
            "source_subnet": "ANY"
        }
        simulator = FirewallSimulator([any_source_rule])
        packet = {
            **self.packet,
            "source_ip": "10.0.0.10"
        }

        result = simulator.evaluate_packet(packet)

        self.assertEqual(result, (True, "Allow SSH From Any Source"))

    def test_first_matching_allow_rule_wins(self):
        block_rule = {
            **self.allow_rule,
            "rule_name": "Block SSH",
            "action": "BLOCK"
        }
        simulator = FirewallSimulator([self.allow_rule, block_rule])

        result = simulator.evaluate_packet(self.packet)

        self.assertEqual(result, (True, "Allow Admin SSH"))

    def test_first_matching_block_rule_wins(self):
        block_rule = {
            **self.allow_rule,
            "rule_name": "Block SSH",
            "action": "BLOCK"
        }
        
        #both rules match first rule determines decision
        simulator = FirewallSimulator([block_rule, self.allow_rule])

        result = simulator.evaluate_packet(self.packet)

        self.assertEqual(result, (False, "Block SSH"))

    def test_nonmatching_rule_is_skipped(self):
        unrelated_rule = {
            **self.allow_rule,
            "rule_name": "Allow HTTPS",
            "port": 443
        }
        simulator = FirewallSimulator([unrelated_rule, self.allow_rule])

        result = simulator.evaluate_packet(self.packet)

        self.assertEqual(result, (True, "Allow Admin SSH"))

    def test_empty_rules_use_implicit_deny(self):
        simulator = FirewallSimulator([])

        result = simulator.evaluate_packet(self.packet)

        self.assertEqual(result, self.implicit_deny)

if __name__ == '__main__':
    unittest.main()

