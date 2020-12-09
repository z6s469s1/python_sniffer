# -*- encoding: utf-8 -*-
import binascii
import socket
import struct
import sys
 
 
def arp_parser(packet):
    arp_length = 28  # fixed
    arp = struct.unpack("!2s2s1s1s2s6s4s6s4s", packet[0:arp_length])
 
    print ("ARP Header :")
    print (" |_ SHA: {0} -> THA: {1}".format(binascii.hexlify(arp[5]), binascii.hexlify(arp[7])))
    print (" |_ SPA: {0} -> TPA: {1}".format(socket.inet_ntoa(arp[6]), socket.inet_ntoa(arp[8])))
    print (" |_ HTYPE          : {0}".format(binascii.hexlify(arp[0])))
    print (" |_ PTYPE          : {0}".format(binascii.hexlify(arp[1])))
    print (" |_ HLEN           : {0}".format(binascii.hexlify(arp[2])))
    print (" |_ PLEN           : {0}".format(binascii.hexlify(arp[3])))
    print (" |_ OPER           : {0}".format(binascii.hexlify(arp[4])))
    #print (" |_ SHA            : {0}".format(binascii.hexlify(arp[5])))
    #print (" |_ SPA            : {0}".format(socket.inet_ntoa(arp[6])))
    #print (" |_ THA            : {0}".format(binascii.hexlify(arp[7])))
    #print (" |_ TPA            : {0}".format(socket.inet_ntoa(arp[8])))
 
    # Padding dump packet[arp_length:]
    print (" |_ Data           : {0}".format(binascii.hexlify(packet[arp_length:])))
 
 
def icmp_parser(packet):
    icmp_length = 4
    icmp = struct.unpack("!BBH", packet[0:icmp_length])
 
    print ("ICMP Header :")
    print (" |_ Type           : {0}".format(icmp[0]))
    print (" |_ Code           : {0}".format(icmp[1]))
    print (" |_ Checksum       : {0} ({1})".format(icmp[2], hex(icmp[2])))
 
    # Padding dump packet[icmp_length:]
    print (" |_ Data           : {0}".format(binascii.hexlify(packet[icmp_length:])))
 
 
def tcp_parser(packet):
    tcp_length = 20
    tcp = struct.unpack("!HHLLBBHHH", packet[0:tcp_length])
 
    # Real tcp header length
    tcp_length = (tcp[4] >> 4) * 4
    Flags = ((tcp[4] & 0x0f) << 8) + tcp[5]
 
    print ("TCP Header :")
    print (" |_ Src Port: {0} -> Dst Port: {1}".format(tcp[0], tcp[1]))
    print (" |_ Sequence       : {0} ({1})".format(tcp[2], hex(tcp[2])))
    print (" |_ Acknowledgment : {0} ({1})".format(tcp[3], hex(tcp[3])))
    print (" |_ Length         : {0}".format(tcp_length))
    print (" |_ Flags          : {0}".format(hex(Flags)))
    print (" |_ Window size    : {0}".format(tcp[6]))
    print (" |_ Checksum       : {0} ({1})".format(tcp[7], hex(tcp[7])))
    print (" |_ Urgent pointer : {0}".format(tcp[8]))
 
    # Padding dump packet[icmp_length:]
    print (" |_ Data           : {0}".format(binascii.hexlify(packet[tcp_length:])))
 
 
def udp_parser(packet):
    udp_length = 8
    udp = struct.unpack("!HHHH", packet[0:udp_length])
 
    print ("UDP Header :")
    print (" |_ Src Port: {0} -> Dst Port: {1}".format(udp[0], udp[1]))
    print (" |_ Length         : {0}".format(udp[2]))
    print (" |_ Checksum       : {0} ({1})".format(udp[3], hex(udp[3])))
 
    # Padding dump packet[icmp_length:]
    print (" |_ Data           : {0}".format(binascii.hexlify(packet[udp_length:])))
 
 
def ip_parser(packet):
    ip_length = 20
    ip = struct.unpack("!BBHHHBBH4s4s", packet[0:ip_length])
 
    version = ip[0] >> 4
    IHL = (ip[0] & 0xf) * 4
    DiffServ = ip[1] >> 2
    ECN = ip[1] & 0x03
    Flags = ip[4] >> 13
    Frag_offset = ip[4] & 0x1fff
 
    print ("IP Header :")
    print (" |_ From: {0} -> To: {1}".format(socket.inet_ntoa(ip[8]), socket.inet_ntoa(ip[9])))
    print (" |_ Version        : {0}".format(version))
    print (" |_ Header Length  : {0}".format(IHL))
    print (" |_ DiffServ       : {0}".format(DiffServ))
    print (" |_ ECN            : {0}".format(ECN))
    print (" |_ Total Length   : {0}".format(ip[2]))
    print (" |_ Identification : {0} ({1})".format(ip[3], hex(ip[3])))
    print (" |_ Flags          : {0}".format(Flags))
    print (" |_ Fragment Offset: {0}".format(Frag_offset))
    print (" |_ TTL            : {0}".format(ip[5]))
    print (" |_ Protocol       : {0}".format(hex(ip[6])))
    print (" |_ Checksum       : {0} ({1})".format(ip[7], hex(ip[7])))
 
    # next header
    if ip[6] == 1:
        # ICMP = 0x01
        icmp_parser(packet[IHL:])
    elif ip[6] == 6:
        # TCP = 0x06
        tcp_parser(packet[IHL:])
    elif ip[6] == 17:
        # UDP = 0x11
        udp_parser(packet[IHL:])
    else:
        pass
 
 
def ethernet_parser(packet):
    eth_length = 14  # fixed
    eth = struct.unpack("!6s6s2s", packet[0:eth_length])
 
    print ("ETHERNET Header :")
    print (" |_ From: {1} -> To: {0}".format(binascii.hexlify(eth[0]), binascii.hexlify(eth[1])))
    print (" |_ Type: {0}".format(binascii.hexlify(eth[2])))
 
    # parser next header
    if eth[2] == b'\x08\x06':
        arp_parser(packet[eth_length:])
    elif eth[2] == b'\x08\x00':
        ip_parser(packet[eth_length:])
    else:
        pass
 
 
def linux_main():
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
 
    # Bind the interface, likes eth0
    rawSocket.bind(("lo", 0))
    i=0
    while True:
        packet = rawSocket.recvfrom(2048)[0]
        
        
        i+=1
        if i%10000==0:
            ethernet_parser(packet)
            print(i)
            
 
    rawSocket.close()
 
 
def windows_main():
    # create a raw socket and bind it to the public interface
    rawSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
 
    # Bind a interface with public IP
    HOST = socket.gethostbyname(socket.gethostname())
    rawSocket.bind((HOST, 0))
    print ("Bind a interface : {0}".format(HOST))
 
    rawSocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Include IP headers
    rawSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # receive all packages
 
    while True:
        packet = rawSocket.recvfrom(2048)[0]
        ip_parser(packet)
        print ("")
 
    rawSocket.close()
 
 
if __name__ == '__main__':
    if sys.platform.lower().startswith("win"):
        windows_main()
    else:
        linux_main()
 