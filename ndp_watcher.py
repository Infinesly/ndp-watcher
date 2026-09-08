#!/usr/bin/env python3
import csv
import json
import os
from datetime import datetime, timedelta
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
BASELINE_FILE = "ndp_baseline.json"
MAX_ROWS = 15
SPOOF_WINDOW = timedelta(seconds=30)

recent_events = deque(maxlen=MAX_ROWS)

def init_log():
    try:
        with open(LOG_FILE, "x", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "event_type", "source_mac", "details"])
    except FileExistsError:
        pass

def load_baseline():
    global known_routers, known_neighbors
    if not os.path.exists(BASELINE_FILE):
        return  # no saved baseline yet, start fresh

    with open(BASELINE_FILE, "r") as f:
        data = json.load(f)

    known_routers = data.get("routers", {})

    # known_neighbors stores "last_seen" as a datetime object during runtime,
    # but JSON can only store plain text — so we convert it back from a string
    loaded_neighbors = data.get("neighbors", {})
    for ip, record in loaded_neighbors.items():
        record["last_seen"] = datetime.fromisoformat(record["last_seen"])
    known_neighbors = loaded_neighbors

    print(f"Loaded baseline: {len(known_routers)} routers, {len(known_neighbors)} neighbors")

def save_baseline():
    # Build a JSON-safe copy of known_neighbors, converting datetime -> string
    neighbors_to_save = {}
    for ip, record in known_neighbors.items():
        neighbors_to_save[ip] = {
            "mac": record["mac"],
            "last_seen": record["last_seen"].isoformat()
        }

    data = {
        "routers": known_routers,
        "neighbors": neighbors_to_save
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Saved baseline: {len(known_routers)} routers, {len(known_neighbors)} neighbors")

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
        now = datetime.now()

        if target_ip not in known_neighbors:
            known_neighbors[target_ip] = {"mac": src_mac, "last_seen": now}
            log_event("NA_NEW", src_mac, f"claims {target_ip}")
        else:
            record = known_neighbors[target_ip]
            if record["mac"] != src_mac:
                time_since_last_seen = now - record["last_seen"]
                if time_since_last_seen < SPOOF_WINDOW:
                    log_event("ALERT_SPOOFING", src_mac,
                              f"{target_ip} was {record['mac']} ({time_since_last_seen.seconds}s ago), now claimed by {src_mac}")
                else:
                    log_event("INFO_MAC_CHANGE", src_mac,
                              f"{target_ip} previously {record['mac']}, now {src_mac} (after {time_since_last_seen})")
            known_neighbors[target_ip] = {"mac": src_mac, "last_seen": now}

    elif pkt.haslayer(ICMPv6ND_RS):
        log_event("RS", src_mac, "requesting router info")

    elif pkt.haslayer(ICMPv6ND_NS):
        ns = pkt[ICMPv6ND_NS]
        log_event("NS", src_mac, f"asking who has {ns.tgt}")

    live.update(build_table())

init_log()
load_baseline()

try:
    with Live(build_table(), refresh_per_second=4) as live:
        sniff(iface="eth0", filter="icmp6",
              prn=lambda pkt: handle_packet(pkt, live), store=False)
except KeyboardInterrupt:
    pass
finally:
    save_baseline()