#!/usr/bin/env python3
from scapy.all import sniff, Ether, IPv6
from scapy.layers.inet6 import (
    ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA,
    ICMPv6NDOptPrefixInfo
)

# The "notebook" — two dictionaries acting as our baseline memory
known_routers = {}      # maps router MAC -> {lifetime, prefix}
known_neighbors = {}    # maps IPv6 address -> MAC that owns it

def handle_packet(pkt):
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"
    src_ip = pkt[IPv6].src if pkt.haslayer(IPv6) else "unknown"

    if pkt.haslayer(ICMPv6ND_RA):
        ra = pkt[ICMPv6ND_RA]
        prefix = None
        if pkt.haslayer(ICMPv6NDOptPrefixInfo):
            prefix = pkt[ICMPv6NDOptPrefixInfo].prefix

        if src_mac not in known_routers:
            # First time ever seeing this router — just remember it
            known_routers[src_mac] = {"lifetime": ra.routerlifetime, "prefix": prefix}
            print(f"[RA] New router learned: {src_mac} lifetime={ra.routerlifetime}s prefix={prefix}")
        else:
            # We've seen this router before — check if anything changed
            old = known_routers[src_mac]
            if old["prefix"] != prefix:
                print(f"[!] ALERT: Router {src_mac} changed prefix from {old['prefix']} to {prefix}")
            if ra.routerlifetime == 0:
                print(f"[!] ALERT: Router {src_mac} sent lifetime=0 (possible DoS attempt)")
            known_routers[src_mac] = {"lifetime": ra.routerlifetime, "prefix": prefix}

    elif pkt.haslayer(ICMPv6ND_NA):
        na = pkt[ICMPv6ND_NA]
        target_ip = na.tgt

        if target_ip not in known_neighbors:
            # First time seeing this IP claimed — just remember it
            known_neighbors[target_ip] = src_mac
            print(f"[NA] New mapping learned: {target_ip} -> {src_mac}")
        else:
            # We've seen this IP claimed before — does the MAC match?
            old_mac = known_neighbors[target_ip]
            if old_mac != src_mac:
                print(f"[!] ALERT: Possible NDP spoofing! {target_ip} was {old_mac}, now claimed by {src_mac}")
            # else: same device re-confirming, nothing to flag

    elif pkt.haslayer(ICMPv6ND_RS):
        print(f"[RS] from {src_mac} — requesting router info")

    elif pkt.haslayer(ICMPv6ND_NS):
        ns = pkt[ICMPv6ND_NS]
        print(f"[NS] from {src_mac} — asking who has {ns.tgt}")

sniff(iface="eth0", filter="icmp6", prn=handle_packet, store=False)