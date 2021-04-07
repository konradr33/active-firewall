from packets_interceptor import PacketsInterceptor
from example_packets_consumer import ExamplePacketsConsumer

if __name__ == '__main__':
    consumer = ExamplePacketsConsumer()
    interceptor = PacketsInterceptor()

    interceptor.add_consumer(consumer)

    interceptor.start_intercepting()
