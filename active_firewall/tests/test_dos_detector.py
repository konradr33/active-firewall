import unittest
from unittest.mock import MagicMock

from active_firewall.packets_consumers.dos_detector import DosDetector
from active_firewall.packets_consumers.packets_consumer import PacketsConsumer
from active_firewall.iptables_adapter import IptablesAdapter

from active_firewall.tests.utils import get_packet

class TestDosDetectorMethods(unittest.TestCase):
    def setUp(self):
        self.ip = ["192.168.10.10","192.168.10.11"]        
        self.scanning_interval = 2
        self.allowed_large_packets_per_interval = 12
        self.rule_timeout = 4
        self.allowed_packets_per_interval = 4
        self.large_packet_size = 100
        self.iptables_adapter = IptablesAdapter('INPUT')
        self.large_packet = get_packet(ip_scr= self.ip[0], dst_port=8085)
        self.dos_detector = DosDetector(self.iptables_adapter,self.allowed_packets_per_interval,self.large_packet_size ,self.allowed_large_packets_per_interval,self.rule_timeout,self.scanning_interval)

    def test_count_packets(self):
        self.dos_detector.consume_packet(self.large_packet)
        self.assertEqual(self.dos_detector.large_packet_cnt, {self.ip[0]: 1})
        self.assertNotEqual(self.dos_detector.packet_cnt, {self.ip[0]: 1})

    def test_add_rule_with_timeout_large_packets(self):
        self.iptables_adapter.add_rule_with_timeout = MagicMock()
        self.dos_detector.large_packet_cnt={self.ip[0]:self.allowed_large_packets_per_interval}
        self.dos_detector.start = self.dos_detector.start - self.scanning_interval
        self.dos_detector.consume_packet(self.large_packet)       
        self.iptables_adapter.add_rule_with_timeout.assert_called_with(["-s", self.ip[0]], self.rule_timeout)
    
    def test_add_rule_with_timeout_normall_packets(self):
        self.iptables_adapter.add_rule_with_timeout = MagicMock()
        self.dos_detector.packet_cnt={self.ip[0]:self.allowed_packets_per_interval}
        self.dos_detector.start = self.dos_detector.start - self.scanning_interval
        self.dos_detector.consume_packet(self.large_packet)       
        self.iptables_adapter.add_rule_with_timeout.assert_called_with(["-s", self.ip[0]], self.rule_timeout)    
    
if __name__ == '__main__':
    unittest.main()