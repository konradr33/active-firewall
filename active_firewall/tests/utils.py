class Packet:
    def __init__(self, ip=None, tcp=None):
        self.ip = ip
        self.tcp = tcp


class Tcp:
    def __init__(self, dstport):
        self.dstport = dstport


class Ip:
    def __init__(self, src):
        self.src = src


def get_packet(ip_scr=None, dst_port=None):
    ip = Ip(ip_scr)
    tcp = Tcp(dst_port)
    return Packet(ip, tcp)
