from abc import abstractmethod, ABC


class PacketsConsumer(ABC):
    """
    Abstract class defining common functions of the PacketInterceptor consumer
    """

    @abstractmethod
    def consume_packet(self, packet):
        """
        Function for passing packet for analysis from PacketInterceptor instance.

        :param packet: incoming packet from PacketInterceptor
        """
        pass
