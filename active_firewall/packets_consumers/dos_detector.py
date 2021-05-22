import time

from active_firewall.packets_consumers.packets_consumer import PacketsConsumer


class DosDetector(PacketsConsumer):

    def __init__(self, allowed_packets_per_second, large_packet_size, allowed_large_packets_per_second,
                 iptables_adapter):
        self.iptables_adapter = iptables_adapter
        self.start = time.time()
        self.packet_cnt = {}
        self.allowed_packets_per_second = allowed_packets_per_second
        self.large_packet_cnt = {}
        self.large_packet_size = large_packet_size
        self.allowed_large_packets_per_second = allowed_large_packets_per_second

    def __reset(self):
        self.start = time.time()
        self.packet_cnt = {}
        self.large_packet_cnt = {}

    def __find_alerts(self):
        for ip in {k: v for k, v in self.packet_cnt.items() if v > self.allowed_packets_per_second}:
            print("Alert DoS: " + ip + " " + str(self.packet_cnt[ip]))
            self.iptables_adapter.add_rule_with_timeout(["-s", ip])
        for ip in {k: v for k, v in self.large_packet_cnt.items() if v > self.allowed_large_packets_per_second}:
            print("Alert DoS: " + ip + " " + str(self.packet_cnt[ip]))
            self.iptables_adapter.add_rule_with_timeout(["-s", ip])

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
        if time.time() - self.start >= 1:
            self.__find_alerts()
            self.__reset()
