from packets_consumer import PacketsConsumer


class ExamplePacketsConsumer(PacketsConsumer):

    def consume_packets(self, packets):
        print('ExamplePacketsConsumer.consume_packets', packets)
