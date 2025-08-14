# ARP Spoofing Educational Tool

> Running it on any network without explicit permission is **illegal** and may result in severe legal consequences.

## Overview
This Python script demonstrates the basic principles of **ARP spoofing** and **Man-in-the-Middle (MITM)** attacks within a local network.  
It is designed as an educational example to help security students and researchers understand how ARP table manipulation can redirect network traffic.

## Features
- **Enable/disable IP forwarding** on the attacker machine to allow packet forwarding.
- **Automatic MAC address resolution** for target and gateway.
- **Periodic ARP spoofing packets** to maintain ARP cache poisoning.
- **Automatic ARP table restoration** when the script stops.
- Command-line arguments for:
  - Target IP address
  - Gateway IP address
  - Network interface

## Intended Use
- Simulating ARP spoofing in a safe lab environment.
- Demonstrating ARP vulnerabilities during cybersecurity lectures.
- Capturing and analyzing traffic with Wireshark to study MITM implications.

## Requirements
- Python 3.x
- [Scapy](https://scapy.net/)
- Root/Administrator privileges

## Example Usage
```bash
python3 fmitm.py -t 192.168.1.10 -g 192.168.1.1 -i eth0
```

## Architecture & Flow
```plaintext
┌────────────┐       ┌────────────┐
│   Target   │ <───> │  Gateway   │
└────────────┘       └────────────┘
       ▲                    ▲
       │    Spoofed ARP     │
       ▼                    ▼
   ┌────────────────────────────┐
   │    Attacker (This Tool)    │
   └────────────────────────────┘
```
1. The attacker sends forged ARP replies to both the target and the gateway.
2. Both parties believe the attacker’s MAC address is associated with the other’s IP.
3. All traffic between target and gateway is routed through the attacker.
4. When stopped, the script sends correct ARP entries to restore normal communication.

## Legal Notice
- **Only** run this script on networks where you have **written authorization**.
- Recommended environment: virtual machines, isolated network segments, or test labs.
- Misuse outside of authorized scenarios is a criminal offense in most jurisdictions.
