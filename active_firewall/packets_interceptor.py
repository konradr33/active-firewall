import pyshark


class PacketsInterceptor:
    def __init__(self):
        self.consumers = []
        self.isIntercepting = False

    def add_consumer(self, consumer):
        print('add_consumer')
        self.consumers.append(consumer)

    def start_intercepting(self, interface, only_incoming_traffic=False, host_ip=None):
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
