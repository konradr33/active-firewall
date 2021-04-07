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

        for consumer in self.consumers:
            consumer.consume_packets([])
