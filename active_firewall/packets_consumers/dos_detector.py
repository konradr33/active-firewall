import time
import datetime

from active_firewall.packets_consumers.packets_consumer import PacketsConsumer


class DosDetector(PacketsConsumer):
    """
    A class that analyzes packets for a DoS attacks.
    """

    def __init__(self, iptables_adapter, allowed_packets_per_interval, large_packet_size,
                 allowed_large_packets_per_interval,
                 rule_timeout, scanning_interval):
        """
        Constructor method

        :param iptables_adapter: an instance of the iptables Adapter class to which the rules preventing
            detected attacks will be passed
        :type iptables_adapter: IptablesAdapter
        :param allowed_packets_per_interval: allowable number of incoming packets from one sender
        :type allowed_packets_per_interval: int
        :param large_packet_size: the size above which the packet is large
        :type large_packet_size: int
        :param allowed_large_packets_per_interval: allowable number of incoming big packets from one sender
        :type allowed_large_packets_per_interval: int
        :param rule_timeout: number of seconds for which the rule will be added when an attack is detected
        :type rule_timeout: int
        :param scanning_interval: time interval in seconds at which packet analysis will be performed
        :type scanning_interval: float
        """
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
        """
        Resets internal state after performed analysis
        """
        self.start = time.time()
        self.packet_cnt = {}
        self.large_packet_cnt = {}

    def __find_alerts(self):
        """
        Performs an packet analysis, looking for DoS attacks
        """
        for ip in {k: v for k, v in self.packet_cnt.items() if v > self.allowed_packets_per_interval}:
            print(str(datetime.datetime.now()) + "\tAlert DoS: " + ip + " send " + str(self.packet_cnt[ip]))
            self.iptables_adapter.add_rule_with_timeout(["-s", ip], self.rule_timeout)
        for ip in {k: v for k, v in self.large_packet_cnt.items() if v > self.allowed_large_packets_per_interval}:
            print(str(datetime.datetime.now()) + "\tAlert DoS (Big packet): " + ip)
            self.iptables_adapter.add_rule_with_timeout(["-s", ip], self.rule_timeout)

    def consume_packet(self, packet):
        """
        Function for handling captured packets

        :param packet: packet captured on the network interface
        """
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
            self.__find_alerts()
            self.__reset()
