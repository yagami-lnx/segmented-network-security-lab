## Objective

Bypass VLAN segmentation between VLAN 10 (ATTACKER) and VLAN 30 (SERVERS) — which 
was explicitly blocked via an inbound ACL on the router — using a VLAN hopping 
technique known as double-tagging (802.1Q double encapsulation).

## Attack Mechanism

Double-tagging exploits how trunk links handle native VLAN traffic. An attacker 
crafts a frame with two stacked 802.1Q tags: an outer tag matching the trunk's 
native VLAN, and an inner tag matching the target VLAN. Because native VLAN 
traffic is expected to be untagged on the wire, the first switch strips the outer 
tag as the frame crosses the trunk — leaving only the inner tag, which the next 
device (switch or router) reads as the frame's real VLAN membership. This is a 
one-way, blind attack: it doesn't establish a return path, since there's no 
equivalent stripping mechanism for a response.

[More on VLAN hopping/double-tagging →](https://www.imperva.com/learn/availability/vlan-hopping/)

## Recon

An initial ACL was applied to block VLAN 10 → VLAN 30 traffic (see [topology 
README](../topology/README.md) for details). A follow-up nmap scan confirmed the 
block was effective:
```

nmap -sn 192.168.30.0/24

```

![Baseline nmap scan showing VLAN 30 unreachable](screenshots/nmap-baseline-blocked.png)

Result: 0 hosts detected, confirming VLAN 10 has no visibility into VLAN 30 
under normal conditions.

## Exploitation

To execute the double-tagging attack, a custom Python script was written using 
the `scapy` library to craft a raw, double-tagged Ethernet frame — no existing 
tool performs this exact frame construction, making it a good candidate for a 
first custom security tool.

**`doubleQ.py`:**
```python
#!/usr/bin/env python3

from scapy.all import *

packet = (Ether() / Dot1Q(vlan=1) / Dot1Q(vlan=30) / IP(dst="192.168.30.10") / ICMP())

sendp(packet, iface="eth0")
```

The script constructs a frame with two stacked 802.1Q tags — an outer tag 
matching the trunk's native VLAN (1), and an inner tag matching the target VLAN 
(30) — carrying a single ICMP echo request destined for Metasploitable.

**Result:** the crafted frame successfully reached Metasploitable (192.168.30.10), 
confirmed via `tcpdump` on the target — despite the ACL on R1's f0/0.10 
explicitly blocking VLAN 10 → VLAN 30 traffic. Metasploitable also sent an ICMP 
echo reply back to Kali. This does *not* indicate double-tagging is bidirectional 
— it simply reflects that no ACL exists restricting VLAN 30 → VLAN 10 traffic, so 
the reply traveled back via a completely separate, unrestricted path.

![Successful ICMP bypass — tcpdump capture on Metasploitable](screenshots/exploit-tcpdump-success.png)

## Impact

While this proof-of-concept used a simple ICMP packet to demonstrate the bypass, 
double-tagging can deliver any single crafted frame past VLAN segmentation — 
making it a delivery mechanism for other blind, one-way attacks rather than an 
attack in itself. The most realistic and effective payload is ARP spoofing: an 
attacker sends a frame with a forged ARP reply claiming a chosen IP address maps 
to their own MAC address. Since most operating systems passively trust unsolicited 
ARP replies, the target updates its ARP cache with false information — for 
example, an attacker could claim to be the network's own router, redirecting 
traffic through their machine and enabling man-in-the-middle interception.
