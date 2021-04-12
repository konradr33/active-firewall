import pyshark


class PacketsInterceptor:
    def __init__(self):
        self.consumers = []
        self.isIntercepting = False
        self.counter = 0

    def add_consumer(self, consumer):
        print('add_consumer')
        self.consumers.append(consumer)

    def start_intercepting(self):
        print('start_intercepting')
        if self.isIntercepting:
            return

        self.isIntercepting = True

        capture = pyshark.LiveCapture(interface='wlp8s0')

        for packet in capture.sniff_continuously():
            self.counter += 1
            print('packet', self.counter)
            for consumer in self.consumers:
                consumer.consume_packet(packet)
