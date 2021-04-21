import pyshark


class PacketsInterceptor:
    def __init__(self):
        self.consumers = []
        self.isIntercepting = False

    def add_consumer(self, consumer):
        print('add_consumer')
        self.consumers.append(consumer)

    def start_intercepting(self, interface):
        print('start_intercepting')
        if self.isIntercepting:
            return

        self.isIntercepting = True

        capture = pyshark.LiveCapture(interface=interface)

        for packet in capture.sniff_continuously():
            for consumer in self.consumers:
                consumer.consume_packet(packet)
