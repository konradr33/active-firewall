from abc import abstractmethod, ABC


class PacketsConsumer(ABC):

    @abstractmethod
    def consume_packets(self, packets):
        pass
