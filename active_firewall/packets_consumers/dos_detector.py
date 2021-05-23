import time

from active_firewall.packets_consumers.packets_consumer import PacketsConsumer

class DosDetector(PacketsConsumer):

    def __init__(self, iptables_adapter, allowed_packets_per_interval, large_packet_size,
                 allowed_large_packets_per_interval,
                 rule_timeout, scanning_interval):
        self.iptables_adapter = iptables_adapter
        self.start = time.time()
        self.packet_cnt = {}
        self.allowed_packets_per_interval = allowed_packets_per_interval
        self.large_packet_cnt = {}
        self.large_packet_size = large_packet_size
        self.allowed_large_packets_per_interval = allowed_large_packets_per_interval
        self.scanning_interval = scanning_interval
        self.rule_timeout = rule_timeout

    def __reset(self):
        self.start = time.time()
        self.packet_cnt = {}
        self.large_packet_cnt = {}

    def __find_alerts(self):
        for ip in {k: v for k, v in self.packet_cnt.items() if v > self.allowed_packets_per_interval}:
            self.iptables_adapter.add_rule_with_timeout(["-s", ip], self.rule_timeout)
        for ip in {k: v for k, v in self.large_packet_cnt.items() if v > self.allowed_large_packets_per_interval}:
            self.iptables_adapter.add_rule_with_timeout(["-s", ip], self.rule_timeout)

    def consume_packet(self, packet):
        if hasattr(packet, 'ip'):
            if int(packet.length) >= self.large_packet_size:
                if packet.ip.src in self.large_packet_cnt:
                    self.large_packet_cnt[packet.ip.src] += 1
                else:
                    self.large_packet_cnt[packet.ip.src] = 1
            if int(packet.length) < self.large_packet_size:
                if packet.ip.src in self.packet_cnt:
                    self.packet_cnt[packet.ip.src] += 1
                else:
                    self.packet_cnt[packet.ip.src] = 1

        if time.time() - self.start >= self.scanning_interval:
            print('scan')
            self.__find_alerts()
            self.__reset()
