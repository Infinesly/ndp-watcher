#!/usr/bin/env python3
from scapy.all import sniff, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA
def handle_packet(pkt):
    if pkt.haslayer(ICMPv6ND_RA):
        print(f"[RA] Router Advertisement from {pkt.src}")
    elif pkt.haslayer(ICMPv6ND_RS):
        print(f"[RS] Router Solicitation from {pkt.src}")
    elif pkt.haslayer(ICMPv6ND_NA):
        print(f"[NA] Neighbor Advertisement from {pkt.src}")
    elif pkt.haslayer(ICMPv6ND_NS):
        print(f"[NS] Neighbor Solicitation from {pkt.src}")

sniff(iface="eth0", filter="icmp6", prn=handle_packet, store=False)