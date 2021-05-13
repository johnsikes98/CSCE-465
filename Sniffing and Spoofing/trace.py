from scapy.all import *

a = IP()
a.dst = '1.2.3.4'
a.ttl = 6
b = ICMP()
send(a/b)

ls(a)

#Jump 1 = 10.0.2.1
#Jump 2 = 10.228.0.5
#Jump 3 = 10.0.72.10
#Jump 4 = 10.0.72.15
#Jump 5 = 10.3.3.209
#Jump 6 = 10.0.2.4
