import time
from unittest.mock import MagicMock

from active_firewall.packets_consumers.port_scan_detector import PortScanDetector
from active_firewall.tests.utils import get_packet


def test_scan_many_ports_with_single_host():
    mock_ip_tables = MagicMock()
    rule_timeout = 1
    ip = "192.168.10.10"

    detector = PortScanDetector(mock_ip_tables, 10, rule_timeout, 1.0)

    for i in range(20):
        packet = get_packet(ip_scr=ip, dst_port=8080 + i)
        detector.consume_packet(packet)

    time.sleep(1)
    packet = get_packet(ip_scr=ip, dst_port=8080)
    detector.consume_packet(packet)

    mock_ip_tables.add_rule_with_timeout.assert_called()
    call_args = mock_ip_tables.add_rule_with_timeout.call_args.args
    assert call_args[0][1] == ip
    assert call_args[1] == rule_timeout


def test_scan_many_ports_with_many_hosts():
    mock_ip_tables = MagicMock()
    rule_timeout = 1
    ip = "192.168.10."

    detector = PortScanDetector(mock_ip_tables, 10, rule_timeout, 1.0)

    for i in range(20):
        packet = get_packet(ip_scr=ip + str(i), dst_port=8080 + i)
        detector.consume_packet(packet)

    time.sleep(1)
    packet = get_packet(ip_scr=ip + str(1), dst_port=8080)
    detector.consume_packet(packet)

    mock_ip_tables.add_rule_with_timeout.assert_not_called()
