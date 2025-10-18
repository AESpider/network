#!/usr/bin/env python3
import sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <IP> \"Message\"")
    sys.exit(1)

dst = sys.argv[1]
msg = sys.argv[2]

from scapy.all import IP, ICMP, send

print(f"Sending: {msg} to {dst}")

for c in msg:
    ip_id = (0xAB << 8) | ord(c) # ID = 0xAB..
    send(IP(dst=dst, id=ip_id) / ICMP(), verbose=0)
    print(f"  Sent: '{c}' (IP ID: 0x{ip_id:X})")

print("Done!")