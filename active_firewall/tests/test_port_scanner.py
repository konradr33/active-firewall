import time
import unittest
from unittest.mock import MagicMock

from active_firewall.packets_consumers.port_scan_detector import PortScanDetector
from active_firewall.tests.utils import get_packet


class TestPortScanDetectorMethods(unittest.TestCase):
    def setUp(self):
        self.rule_timeout = 1
        self.scanning_interval = 1.0
        self.ip = "192.168.10.10"
        self.allowed_ports_per_interval = 10
        self.mock_ip_tables = MagicMock()
        self.detector = PortScanDetector(self.mock_ip_tables, self.allowed_ports_per_interval,
                                         self.rule_timeout, self.scanning_interval)

    def test_port_counting(self):
        for i in range(20):
            packet = get_packet(ip_scr=self.ip, dst_port=8080 + i)
            self.detector.consume_packet(packet)

        assert len(self.detector.ip_set[self.ip]) == 20

    def test_scan_many_ports_with_single_host(self):
        for i in range(20):
            packet = get_packet(ip_scr=self.ip, dst_port=8080 + i)
            self.detector.consume_packet(packet)

        time.sleep(2)
        packet = get_packet(ip_scr=self.ip, dst_port=8080)
        self.detector.consume_packet(packet)

        self.mock_ip_tables.add_rule_with_timeout.assert_called()
        call_args = self.mock_ip_tables.add_rule_with_timeout.call_args.args
        assert call_args[0][1] == self.ip
        assert call_args[1] == self.rule_timeout

    def test_scan_many_ports_with_many_hosts(self):
        ip = "192.168.10."
        self.detector = PortScanDetector(self.mock_ip_tables, self.allowed_ports_per_interval,
                                         self.rule_timeout, self.scanning_interval)

        for i in range(20):
            packet = get_packet(ip_scr=ip + str(i), dst_port=8080 + i)
            self.detector.consume_packet(packet)

        time.sleep(1)
        packet = get_packet(ip_scr=ip + str(1), dst_port=8080)
        self.detector.consume_packet(packet)

        self.mock_ip_tables.add_rule_with_timeout.assert_not_called()
