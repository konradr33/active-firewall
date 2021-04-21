from packets_consumer import PacketsConsumer
import time
from config import Config

class PacketsConsumerDOS(PacketsConsumer):

    def __init__(self, pps):
        self.start=time.time()
        self.packetCnt = {} 
        self.allowedPacketsPerSecond = int(Config.get_config('AllowedPacketsPerSecond'))

    def _reset(self):        
        self.start=time.time()
        self.packetCnt = {} 

    def _findAlerts(self):               
        for ip in {k:v for k,v in self.packetCnt.items() if v>self.allowedPacketsPerSecond}:    	    
    	    print("Alert: "+ip+" "+str(self.packetCnt[ip]))  

    def consume_packets(self, packets):
        print('ExamplePacketsConsumer.consume_packets', packets)

    def consume_packet(self, packet):
        if(hasattr(packet,'ip')):            
            if (packet.ip.src in self.packetCnt): self.packetCnt[packet.ip.src] +=1
            else: self.packetCnt[packet.ip.src] = 1
        if(time.time()-self.start >= 1):
            self._findAlerts()
            self._reset()