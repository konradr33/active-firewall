from active_firewall.config import Config
from active_firewall.packets_consumers.dos_detector import DosDetector
from active_firewall.packets_interceptor import PacketsInterceptor


def activate_firewall():
    consumer = DosDetector(int(Config.get_config('AllowedPacketsPerSecond')))
    interceptor = PacketsInterceptor()

    interceptor.add_consumer(consumer)

    interceptor.start_intercepting(Config.get_config('ListeningInterface'))
