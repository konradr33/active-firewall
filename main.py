from packets_interceptor import PacketsInterceptor
from packets_consumer import PacketsConsumer

if __name__ == '__main__':
    consumer = PacketsConsumer()
    interceptor = PacketsInterceptor()

    interceptor.add_consumer(consumer)
    interceptor.start_intercepting()
