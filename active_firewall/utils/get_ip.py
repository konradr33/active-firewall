import os
import sys


def get_ip(interface):
    """
    Obtain the host's ip address

    :param interface: The name of the interface from which we want to get the ip address
    :type interface: str
    :return: Host's IP address
    :rtype str
    """
    try:
        return os.popen(f'ip addr show {interface}').read().split("inet ")[1].split("/")[0]
    except IndexError:
        sys.exit(f'Could not find {interface} network interface.')
