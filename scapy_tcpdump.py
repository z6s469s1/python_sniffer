#ref:https://www.thepythoncode.com/article/sniff-http-packets-scapy-python?fbclid=IwAR0uiMVeA2RSj4vL0Ioaec-BOhUwiTfXXhxSceNQs4twW_xzqiGsrlcyXV4
import  scapy
from scapy.all import *
import  time

conf.L2listen=L2ListenTcpdump
pks=[]
def process_packet(packet):
    pks.append(packet)

t=AsyncSniffer(prn=process_packet,store=True,iface="lo")
t.start()
time.sleep(30)
t.stop()
print(len(pks))

