import socket
import random

UDP_IP = "192.168.100.1"
MESSAGE = ""

sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP

while True:
    sock.sendto(MESSAGE.encode(), (UDP_IP, random.randint(1, 65535)))
