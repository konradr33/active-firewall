import pyshark


class PacketsInterceptor:
    """
    The class whose instance will listen on the network interface and forward packets to listening consumers.
    """

    def __init__(self):
        """Constructor method"""
        self.consumers = []
        self.isIntercepting = False

    def add_consumer(self, consumer):
        """
        Add a client to whom incoming packets will be forwarded.

        :param consumer: new customer of packets
        :type consumer: PacketsConsumer
        """
        self.consumers.append(consumer)

    def start_intercepting(self, interface, only_incoming_traffic=False, host_ip=None):
        """
        Configures an sniffing tool, starts listening on interface, forwarding packets to consumers.

        :param interface: name of the interface that sniffing is applied
        :type interface: str
        :param only_incoming_traffic: flag defining if outgoing traffic is ignored
        :type only_incoming_traffic: bool, optional
        :param host_ip: ip address of host, it's packets will be ignored
        :type host_ip: str, optional
        """
        print('start_intercepting')
        if self.isIntercepting:
            return

        self.isIntercepting = True
        bpf_filter = 'ip'

        if only_incoming_traffic and host_ip is not None:
            bpf_filter += f' dst host {host_ip}'

        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)

        for packet in capture.sniff_continuously():
            for consumer in self.consumers:
                consumer.consume_packet(packet)
