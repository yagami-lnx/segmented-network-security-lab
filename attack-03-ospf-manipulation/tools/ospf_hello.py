#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.ospf import *
import time
ospf_hello = (Ether(dst="01:00:5e:00:00:05") / IP(dst="224.0.0.5", ttl=1) / 
              OSPF_Hdr(area="0.0.0.0", authtype=0, src="192.168.10.3") / 
              OSPF_Hello(mask="255.255.255.0", hellointerval=10, deadinterval=40, 
                         options="E", neighbors=["192.168.30.1"]))
while True:
    sendp(ospf_hello, iface="eth0")
    time.sleep(10)
