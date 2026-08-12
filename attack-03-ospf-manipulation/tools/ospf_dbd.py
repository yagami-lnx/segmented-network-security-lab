#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.ospf import *
def handle_dbd(packet):
    if packet.haslayer(OSPF_DBDesc) and packet[IP].src == "192.168.10.1":
        lsa = packet[OSPF_DBDesc].lsaheaders
        seq_dd = packet[OSPF_DBDesc].ddseq
        r1_flags = packet[OSPF_DBDesc].dbdescr
        my_flags = "M" if "M" in r1_flags else ""
        ospf_dbd = (Ether(dst="ca:01:0a:4c:00:00") / IP(dst="192.168.10.1") / 
                    OSPF_Hdr(area="0.0.0.0", authtype=0, src="192.168.10.3") / 
                    OSPF_DBDesc(mtu=1500, options="E", dbdescr=my_flags, 
                               ddseq=seq_dd, lsaheaders=lsa))
        sendp(ospf_dbd, iface="eth0")
sniff(iface="eth0", filter="ip host 192.168.10.1", prn=handle_dbd, count=0)
