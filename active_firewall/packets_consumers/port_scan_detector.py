import time

from active_firewall.packets_consumers.packets_consumer import PacketsConsumer


class PortScanDetector(PacketsConsumer):

    def __init__(self, allowed_ports_per_second, iptables_adapter):
        self.iptables_adapter = iptables_adapter
        self.start = time.time()
        self.packet_cnt = {}
        self.allowed_ports_per_second = allowed_ports_per_second

    def __reset(self):
        self.start = time.time()
        self.packet_cnt = {}

    def __find_alerts(self):
        for ip in self.packet_cnt:
            if len(self.packet_cnt[ip]) > self.allowed_ports_per_second:
                print("Alert PortScanning: " + ip + " scanner " + str(len(self.packet_cnt[ip])) + " ports")
                self.iptables_adapter.add_rule_with_timeout(["-s", ip])

    def consume_packet(self, packet):
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            if packet.ip.src in self.packet_cnt:
                self.packet_cnt[packet.ip.src].add(packet.tcp.dstport)
            else:
                self.packet_cnt[packet.ip.src] = {packet.tcp.dstport}

        if time.time() - self.start >= 1:
            self.__find_alerts()
            self.__reset()
