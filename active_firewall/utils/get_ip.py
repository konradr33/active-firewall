import os
import sys


def get_ip(interface):
    try:
        return os.popen(f'ip addr show {interface}').read().split("inet ")[1].split("/")[0]
    except IndexError:
        sys.exit(f'Could not find {interface} network interface.')
