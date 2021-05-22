import time

from active_firewall.packets_consumers.packets_consumer import PacketsConsumer


class PortScanDetector(PacketsConsumer):

    def __init__(self, iptables_adapter, allowed_ports_per_interval, rule_timeout, scanning_interval):
        self.iptables_adapter = iptables_adapter
        self.start = time.time()
        self.ip_set = {}
        self.allowed_ports_per_interval = allowed_ports_per_interval
        self.scanning_interval = scanning_interval
        self.rule_timeout = rule_timeout

    def __reset(self):
        self.start = time.time()
        self.ip_set = {}

    def __find_alerts(self):
        for ip in self.ip_set:
            if len(self.ip_set[ip]) > self.allowed_ports_per_interval:
                print("Alert PortScanning: " + ip + " scanner " + str(len(self.ip_set[ip])) + " ports")
                self.iptables_adapter.add_rule_with_timeout(["-s", ip], self.rule_timeout)

    def consume_packet(self, packet):
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            if packet.ip.src in self.ip_set:
                self.ip_set[packet.ip.src].add(packet.tcp.dstport)
            else:
                self.ip_set[packet.ip.src] = {packet.tcp.dstport}

        if time.time() - self.start >= self.scanning_interval:
            self.__find_alerts()
            self.__reset()
