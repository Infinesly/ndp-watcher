NDP Watcher
A Python + Scapy tool for monitoring IPv6 Neighbor Discovery Protocol (NDP) traffic — the IPv6 equivalent of ARP — to lay the groundwork for detecting rogue router advertisements and NDP spoofing (the IPv6 analog of ARP spoofing).

🛡️ Why This Matters
NDP has no built-in authentication. Any device on a local network can send Router Advertisement (RA) or Neighbor Advertisement (NA) messages, and other devices will trust them by default. This opens the door to:

Rogue RA attacks — An attacker impersonates the network's router, potentially redirecting traffic through themselves (man-in-the-middle) or knocking devices offline (denial-of-service via a fake zero-lifetime RA).

NDP/NA spoofing — An attacker falsely claims ownership of another device's IPv6 address, poisoning neighbor caches on the network.

Most networks monitor ARP spoofing closely (IPv4), but IPv6 is often enabled by default and left unmonitored — a real, common blind spot.

🚧 Status: v0.2 — Parsing Real NDP Content
Captures and classifies all four NDP message types: RS, RA, NS, NA

Extracts RA details: router lifetime, M/O flags, advertised prefix

Extracts NS/NA target addresses (the actual IP being resolved/claimed)

Coming next (v0.3): Baseline tracking of known router/device IP-to-MAC mappings to enable actual spoofing detection.

📋 Requirements
Python 3

Scapy

Root privileges (raw packet capture requires elevated access)

Installation
Bash
pip install scapy --break-system-packages
💻 Usage
Bash
sudo python3 ndp_watcher.py
By default, the script listens on eth0 — edit the iface parameter in the final sniff() call if your interface has a different name (check with ip a).

🖥️ Example Output
Plaintext
[RA] from 86:7d:5a:08:65:bd (fe80::847d:5aff:fe08:65bd)
     Router lifetime: 7200s
     M flag (managed/DHCPv6): 0  O flag (other config): 0
     Advertised prefix: 2409:40e6:25:c947::/64

[NS] from 08:00:27:8a:35:d2 — asking who has fe80::847d:5aff:fe08:65bd
[NA] from 86:7d:5a:08:65:bd — claims to own target address fe80::847d:5aff:fe08:65bd
🗺️ Roadmap
[x] v0.1 — Basic packet capture and message-type classification

[x] v0.2 — Parse RA lifetime/flags/prefix and NS/NA target addresses

[ ] v0.3 — Baseline tracking (known routers, known IP-to-MAC mappings)

[ ] v0.4 — Spoofing/rogue-RA detection logic

[ ] v0.5 — Structured logging (CSV/JSON output)

[ ] v1.0 — CLI arguments, polish, full documentation

👤 Author
Built by infinesly as part of a self-directed cybersecurity learning path toward SOC analyst work.
