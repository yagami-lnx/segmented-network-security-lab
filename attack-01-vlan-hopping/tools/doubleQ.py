#!/usr/bin/env python3

from scapy.all import *

packet = (Ether() / Dot1Q(vlan=1) / Dot1Q(vlan=30) / IP(dst="192.168.30.10") / ICMP())

sendp(packet, iface="eth0")
