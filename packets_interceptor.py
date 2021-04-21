import pyshark
from config import Config


class PacketsInterceptor:
    def __init__(self):
        self.consumers = []
        self.isIntercepting = False

    def add_consumer(self, consumer):
        print('add_consumer')
        self.consumers.append(consumer)

    def start_intercepting(self):
        print('start_intercepting')
        if self.isIntercepting:
            return

        self.isIntercepting = True

        capture = pyshark.LiveCapture(interface=Config.get_config('ListeningInterface'))

        for packet in capture.sniff_continuously():
            print('packet')
            for consumer in self.consumers:
                consumer.consume_packet(packet)
