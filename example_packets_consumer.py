from packets_consumer import PacketsConsumer


class ExamplePacketsConsumer(PacketsConsumer):

    def consume_packets(self, packets):
        print('ExamplePacketsConsumer.consume_packets', packets)

    def consume_packet(self, packet):
        print('ExamplePacketsConsumer.consume_packet from',packet.ip.src,", to:", packet.ip.dst)
