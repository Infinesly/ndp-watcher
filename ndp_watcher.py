#!/usr/bin/env python3
import csv
from datetime import datetime
from scapy.all import sniff, Ether, IPv6
from scapy.layers.inet6 import (
    ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA,
    ICMPv6NDOptPrefixInfo
)
from rich.live import Live
from rich.table import Table
from collections import deque

known_routers = {}
known_neighbors = {}

LOG_FILE = "ndp_watcher_log.csv"
MAX_ROWS = 15  # how many recent events to show on screen at once

# A deque is like a list, but with a max size — old items automatically
# fall off the end when new ones are added past the limit
recent_events = deque(maxlen=MAX_ROWS)

def init_log():
    try:
        with open(LOG_FILE, "x", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "event_type", "source_mac", "details"])
    except FileExistsError:
        pass

def log_event(event_type, source_mac, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, event_type, source_mac, details])
    recent_events.append((timestamp, event_type, source_mac, details))

def build_table():
    table = Table(title="NDP Watcher — Live Feed")
    table.add_column("Time", style="cyan")
    table.add_column("Event", style="bold")
    table.add_column("MAC")
    table.add_column("Details")

    for timestamp, event_type, source_mac, details in recent_events:
        # Color alerts red so they visually stand out from normal events
        style = "red bold" if "ALERT" in event_type else "white"
        table.add_row(timestamp, event_type, source_mac, details, style=style)

    return table

def handle_packet(pkt, live):
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"

    if pkt.haslayer(ICMPv6ND_RA):
        ra = pkt[ICMPv6ND_RA]
        prefix = None
        if pkt.haslayer(ICMPv6NDOptPrefixInfo):
            prefix = pkt[ICMPv6NDOptPrefixInfo].prefix

        if src_mac not in known_routers:
            known_routers[src_mac] = {"lifetime": ra.routerlifetime, "prefix": prefix}
            log_event("RA_NEW", src_mac, f"lifetime={ra.routerlifetime}s prefix={prefix}")
        else:
            old = known_routers[src_mac]
            if old["prefix"] != prefix:
                log_event("ALERT_PREFIX_CHANGE", src_mac, f"old={old['prefix']} new={prefix}")
            if ra.routerlifetime == 0:
                log_event("ALERT_ZERO_LIFETIME", src_mac, "possible DoS attempt")
            known_routers[src_mac] = {"lifetime": ra.routerlifetime, "prefix": prefix}

    elif pkt.haslayer(ICMPv6ND_NA):
        na = pkt[ICMPv6ND_NA]
        target_ip = na.tgt

        if target_ip not in known_neighbors:
            known_neighbors[target_ip] = src_mac
            log_event("NA_NEW", src_mac, f"claims {target_ip}")
        else:
            old_mac = known_neighbors[target_ip]
            if old_mac != src_mac:
                log_event("ALERT_SPOOFING", src_mac, f"{target_ip} was {old_mac}")

    live.update(build_table())

init_log()

with Live(build_table(), refresh_per_second=4) as live:
    sniff(iface="eth0", filter="icmp6",
          prn=lambda pkt: handle_packet(pkt, live), store=False)