from packets_interceptor import PacketsInterceptor
from packets_consumer_DOS import PacketsConsumerDOS

if __name__ == '__main__':
    consumer = PacketsConsumerDOS()
    interceptor = PacketsInterceptor()

    interceptor.add_consumer(consumer)

    interceptor.start_intercepting()
