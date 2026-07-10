# Topology Overview

## Network Design

The lab uses a segmented topology built around Router-on-a-Stick inter-VLAN routing, 
with a single Layer 2 switch handling VLAN separation and trunking.

- **1x Router** — performs inter-VLAN routing via sub-interfaces (Router-on-a-Stick)
- **1x Layer 2 Switch** — VLAN-aware, 802.1Q trunking configured to the router

## VLAN Segmentation

| VLAN ID | Name     | Subnet          | Gateway        | Connected Host(s)  |
|---------|----------|-----------------|-----------------|---------------------|
| 10      | ATTACKER | 192.168.10.0/24 | 192.168.10.1   | Kali Linux          |
| 20      | INTERNAL | 192.168.20.0/24 | 192.168.20.1   | *(unassigned)*       |
| 30      | SERVERS  | 192.168.30.0/24 | 192.168.30.1   | Metasploitable 2     |

## Current Security Posture

**No ACLs or firewall rules are currently applied.** All VLANs can freely route to 
one another through the router. This represents the baseline "before" state — access 
controls will be introduced as part of each attack's hardening phase, tied to specific 
findings rather than applied speculatively.
