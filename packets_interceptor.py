import pyshark
import time

class PacketsInterceptor:
    def __init__(self):
        self.consumers = []
        self.isIntercepting = False
        self.counter = 0

    def add_consumer(self, consumer):
        print('add_consumer')
        self.consumers.append(consumer)

    def consume(self):
        capture = pyshark.LiveCapture(interface='enp0s3')
        timeout = 1     
        for packet in capture.sniff_continuously():
            self.counter += 1
            for consumer in self.consumers:
                consumer.consume_packet(packet)
            if (time.time()-consumer.start>timeout): 
                for consumer in self.consumers:
                    consumer.findAlerts()                
                    consumer.reset()

    def start_intercepting(self):
        print('start_intercepting')
        if self.isIntercepting:
            return

        self.isIntercepting = True
        self.consume()
