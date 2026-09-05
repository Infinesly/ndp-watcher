# NDP Watcher

A Python + Scapy tool for monitoring IPv6 Neighbor Discovery Protocol (NDP)
traffic — the IPv6 equivalent of ARP — to detect rogue router advertisements
and NDP spoofing (the IPv6 analog of ARP spoofing).

## Why this matters

NDP has no built-in authentication. Any device on a local network can send
Router Advertisement (RA) or Neighbor Advertisement (NA) messages, and other
devices will trust them by default. This opens the door to:

- **Rogue RA attacks** — an attacker impersonates the network's router,
  potentially redirecting traffic through themselves (man-in-the-middle)
  or knocking devices offline (denial-of-service via a fake zero-lifetime RA)
- **NDP/NA spoofing** — an attacker falsely claims ownership of another
  device's IPv6 address, poisoning neighbor caches on the network

Most networks monitor ARP spoofing closely (IPv4), but IPv6 is often enabled
by default and left unmonitored — a real, common blind spot.

## Status

🚧 **v0.4** — baseline detection with persistent logging and a live dashboard view

- Captures and classifies all four NDP message types: RS, RA, NS, NA
- Extracts RA details: router lifetime, M/O flags, advertised prefix
- Extracts NS/NA target addresses (the actual IP being resolved/claimed)
- Baseline tracking: learns known routers and IP-to-MAC mappings, alerts on
  prefix changes, zero-lifetime RAs (possible DoS), and mismatched MAC
  claims on a known IP (possible NDP spoofing)
- Persistent CSV logging with timestamps for every event
- Live, auto-refreshing terminal table (via `rich`) showing the most recent
  events, with alerts highlighted in red

## Requirements

- Python 3
- [Scapy](https://scapy.net/)
- [rich](https://github.com/Textualize/rich)
- Root privileges (raw packet capture requires elevated access)

Install dependencies:
```bash
pip install scapy rich --break-system-packages
```

## Usage

```bash
sudo python3 ndp_watcher.py
```

By default, the script listens on `eth0` — edit the `iface` parameter in the
final `sniff()` call if your interface has a different name (check with `ip a`).

Every event is also written to `ndp_watcher_log.csv` in the same folder,
so you have a full historical record beyond what's shown on screen.

## Example output
