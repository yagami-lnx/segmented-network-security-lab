# Segmented Network Security Lab

A hands-on security lab built in GNS3, simulating a segmented network with 
intentionally vulnerable components. Each attack follows a full 
**recon → exploit → document → harden → re-verify** cycle, treating security 
as an iterative process rather than a one-time fix.

## Overview

The lab consists of a VLAN-segmented network (via a router-on-a-stick topology) 
with Kali Linux positioned as the attacker and Metasploitable2 as an intentionally 
vulnerable target, connected across separate VLANs. Each case study documents a 
specific attack against this environment, the real-world impact it represents, 
and the hardening measures applied afterward — verified by re-attempting the 
attack post-patch.

See [`/topology`](./topology) for the full network diagram and addressing scheme.

## Skills Demonstrated

- Network segmentation (VLANs, 802.1Q trunking, inter-VLAN routing)
- Systematic troubleshooting of GNS3/VMware integration issues (vmrun/VIX 
  communication, hypervisor networking services, virtual disk conversion)
- Custom security tool development in Python *(in progress)*

## Case Studies

- [Attack 01 — VLAN Hopping (Double-Tagging)](./attack-01-vlan-hopping/) — 
  bypassing VLAN segmentation via 802.1Q double-tagging, with an unexpected 
  detour into debugging a lab-environment quirk.

## Tools

- GNS3 — network simulation
- Kali Linux 2025.2 — attack platform
- Metasploitable2 — vulnerable target
- Python — custom tooling built per attack (see individual case study folders)
