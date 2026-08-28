#!/usr/bin/env python3
from scapy.all import sniff, Ether, IPv6
from scapy.layers.inet6 import (
    ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA,
    ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr
)

def handle_packet(pkt):
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"
    src_ip = pkt[IPv6].src if pkt.haslayer(IPv6) else "unknown"

    if pkt.haslayer(ICMPv6ND_RA):
        ra = pkt[ICMPv6ND_RA]
        print(f"[RA] from {src_mac} ({src_ip})")
        print(f"     Router lifetime: {ra.routerlifetime}s")
        print(f"     M flag (managed/DHCPv6): {ra.M}  O flag (other config): {ra.O}")

        if pkt.haslayer(ICMPv6NDOptPrefixInfo):
            prefix_opt = pkt[ICMPv6NDOptPrefixInfo]
            print(f"     Advertised prefix: {prefix_opt.prefix}/{prefix_opt.prefixlen}")

    elif pkt.haslayer(ICMPv6ND_RS):
        print(f"[RS] from {src_mac} ({src_ip}) — requesting router info")

    elif pkt.haslayer(ICMPv6ND_NA):
        na = pkt[ICMPv6ND_NA]
        print(f"[NA] from {src_mac} — claims to own target address {na.tgt}")

    elif pkt.haslayer(ICMPv6ND_NS):
        ns = pkt[ICMPv6ND_NS]
        print(f"[NS] from {src_mac} — asking who has {ns.tgt}")

sniff(iface="eth0", filter="icmp6", prn=handle_packet, store=False)