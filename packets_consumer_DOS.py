from packets_consumer import PacketsConsumer
import time

class PacketsConsumerDOS(PacketsConsumer):

    def __init__(self):
        self.start=time.time()
        self.packetCnt = {} 

    def _reset(self):        
        self.start=time.time()
        self.packetCnt = {} 

    def _findAlerts(self):               
        for ip in {k:v for k,v in self.packetCnt.items() if v>100}:    	    
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