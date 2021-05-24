import time

from active_firewall.packets_consumers.packets_consumer import PacketsConsumer


class PortScanDetector(PacketsConsumer):
    """
    A class that analyzes packets for a Port Scanning attacks.
    """

    def __init__(self, iptables_adapter, allowed_ports_per_interval, rule_timeout, scanning_interval):
        """
        Constructor method

        :param iptables_adapter: an instance of the iptables Adapter class to which the rules preventing
            detected attacks will be passed
        :type iptables_adapter: IptablesAdapter
        :param allowed_ports_per_interval: number of ports that can be used in the time scanning_interval
        :type allowed_ports_per_interval: int
        :param rule_timeout:number of seconds for which the rule will be added when an attack is detected
        :type rule_timeout: int
        :param scanning_interval: time interval in seconds at which packet analysis will be performed
        :type scanning_interval: float
        """
        self.iptables_adapter = iptables_adapter
        self.start = time.time()
        self.ip_set = {}
        self.allowed_ports_per_interval = allowed_ports_per_interval
        self.scanning_interval = scanning_interval
        self.rule_timeout = rule_timeout

    def __reset(self):
        """
        Resets internal state after performed analysis
        """
        self.start = time.time()
        self.ip_set = {}

    def __find_alerts(self):
        """
        Performs an packet analysis, looking for Port Scanning attacks
        """
        for ip in self.ip_set:
            if len(self.ip_set[ip]) > self.allowed_ports_per_interval:
                print("Alert PortScanning: " + ip + " scanner " + str(len(self.ip_set[ip])) + " ports")
                self.iptables_adapter.add_rule_with_timeout(["-s", ip], self.rule_timeout)

    def consume_packet(self, packet):
        """
        Function for handling captured packets

        :param packet: packet captured on the network interface
        """
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            if packet.ip.src in self.ip_set:
                self.ip_set[packet.ip.src].add(packet.tcp.dstport)
            else:
                self.ip_set[packet.ip.src] = {packet.tcp.dstport}

        if time.time() - self.start >= self.scanning_interval:
            self.__find_alerts()
            self.__reset()
