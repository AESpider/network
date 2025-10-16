#!/usr/bin/env python3
"""
ICMP Payload Extractor
Extracts ICMP payloads from PCAP files
"""
import sys
import struct
import argparse


def read_pcap(path):
    """Read PCAP file and return list of packets"""
    with open(path, "rb") as f:
        # Read global header (24 bytes)
        header = f.read(24)
        if len(header) < 24:
            raise SystemExit("Invalid or too small PCAP file")
        
        # Check magic number for endianness
        magic = struct.unpack("<I", header[:4])[0]
        if magic == 0xa1b2c3d4:
            endian = "<"
        elif magic == 0xd4c3b2a1:
            endian = ">"
        else:
            raise SystemExit(f"Unknown PCAP magic: 0x{magic:08x}")
        
        packets = []
        while True:
            # Read packet header (16 bytes)
            pkt_header = f.read(16)
            if not pkt_header or len(pkt_header) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", pkt_header)
            
            # Read packet data
            data = f.read(incl_len)
            if not data:
                break
            
            packets.append((ts_sec + ts_usec / 1e6, data))
        
        return packets


def extract_icmp_payloads(packets, unique=False):
    """Extract ICMP payloads from packets"""
    payloads = []
    seen = set()
    
    for ts, frame in packets:
        # Check minimum frame size (Ethernet 14 + IP 20)
        if len(frame) < 34:
            continue
        
        # Check EtherType for IPv4 (0x0800)
        ethertype = struct.unpack(">H", frame[12:14])[0]
        if ethertype != 0x0800:
            continue
        
        # Parse IP packet
        ip_packet = frame[14:]
        if len(ip_packet) < 20:
            continue
        
        # Check IP version (should be 4)
        version = ip_packet[0] >> 4
        if version != 4:
            continue
        
        # Check protocol (1 = ICMP)
        protocol = ip_packet[9]
        if protocol != 1:
            continue
        
        # Get IP header length
        ihl = (ip_packet[0] & 0x0f) * 4
        if ihl < 20 or len(ip_packet) < ihl + 4:
            continue
        
        # Extract ICMP packet
        icmp_packet = ip_packet[ihl:]
        if len(icmp_packet) < 8:
            continue
        
        # Check ICMP type (0 = Echo Reply, 8 = Echo Request)
        icmp_type = icmp_packet[0]
        if icmp_type not in (0, 8):
            continue
        
        # Extract payload (after 8-byte ICMP header)
        payload = icmp_packet[8:]
        if not payload:
            continue
        
        # Handle unique option
        if unique:
            if payload in seen:
                continue
            seen.add(payload)
        
        payloads.append(payload)
    
    return payloads


def main():
    parser = argparse.ArgumentParser(description="Extract ICMP payloads from PCAP files")
    parser.add_argument("pcap", help="PCAP file to read")
    parser.add_argument("-u", "--unique", action="store_true", help="Keep only unique payloads")
    parser.add_argument("-o", "--output", help="Output file (one payload per line in hex)")
    args = parser.parse_args()
    
    # Read PCAP file
    packets = read_pcap(args.pcap)
    print(f"Packets read: {len(packets)}")
    
    # Extract ICMP payloads
    payloads = extract_icmp_payloads(packets, unique=args.unique)
    
    # Display stats
    unique_text = " (unique)" if args.unique else ""
    print(f"ICMP payloads extracted: {len(payloads)}{unique_text}")
    
    total_size = sum(len(p) for p in payloads)
    print(f"Total size: {total_size} bytes")
    
    if not payloads:
        print("No ICMP payloads found.")
        return 1
    
    # Output to file or display
    if args.output:
        with open(args.output, "w") as f:
            for payload in payloads:
                f.write(payload.hex() + "\n")
        print(f"\nPayloads written to: {args.output}")
    else:
        print()
        for i, payload in enumerate(payloads, 1):
            hex_data = payload.hex()
            preview = hex_data[:64] + "..." if len(hex_data) > 64 else hex_data
            print(f"{i}. [{len(payload)} bytes] {preview}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())