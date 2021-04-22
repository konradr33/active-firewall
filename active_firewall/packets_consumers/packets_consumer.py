from abc import abstractmethod, ABC


class PacketsConsumer(ABC):

    @abstractmethod
    def consume_packet(self, packet):
        pass
