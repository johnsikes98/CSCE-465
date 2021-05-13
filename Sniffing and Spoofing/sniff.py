#!/usr/bin/env python3
from scapy.all import *

def spoof_pkt(pkt):
	a = IP(src=pkt[IP].dst, dst=pkt[IP].src)
	icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
	data = pkt[Raw].load
	newpkt = a/icmp/data
	send(newpkt)
	print(pkt[IP].dst)
	
pkt = sniff(filter='icmp', prn=spoof_pkt)



