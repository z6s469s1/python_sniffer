import dpkt, pcap

pc = pcap.pcap(name="lo")
pc.setfilter('tcp')
print("Device Name:", pc.name, "|Filter:",pc.filter)

for ts, pkt in pc:
    eth = dpkt.ethernet.Ethernet(pkt)    
    print(eth.dst, eth.src, eth.pack_hdr)
    print("raw data : ", eth)
