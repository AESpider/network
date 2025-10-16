#!/usr/bin/env python3
"""
Scapy-based TCP port scanner

Supports: SYN scan, XMAS scan, NULL scan
  - single-host scanning of a list or range of ports
  - saves responses to a pcap file
  - simple interpretation (open / closed / filtered)
  - basic OS detection by TTL/window size heuristic (optional)
  - randomization of the source port by probe (optional, configurable)
  - random delay between probes to reduce fingerprintability (optional)
  - randomization of port order for stealth
  - rate limiting to avoid overwhelming targets

Usage examples:
  sudo python3 port_scanner.py -t nile -p 22,80 -s syn --random-srcport -o results.pcap --os-detect
  sudo python3 port_scanner.py -t 10.0.0.5 -p 1-1024 -s xmas --srcport-range 2000-40000 --hidden --hidden-range 0.05-0.5
  sudo python3 port_scanner.py -t 192.168.1.1 -p 1-1000 --randomize-ports --rate-limit 100 -q

Note: must be run as root (Scapy raw sockets).
"""

import argparse
import sys
import time
import random
from collections import Counter
from scapy.all import IP, TCP, ICMP, sr1, conf, wrpcap

conf.verb = 0

def parse_ports(portspec):
    """Parse port spec like "22,80,100-200" into a sorted list of ints."""
    ports = set()
    for part in portspec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            a = int(a)
            b = int(b)
            if a > b:
                a, b = b, a
            ports.update(range(a, b+1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def parse_range(rng):
    """Parse a simple integer range like '1024-65535' into (min,max)."""
    if '-' in rng:
        a, b = rng.split('-', 1)
        a = int(a)
        b = int(b)
        if a > b:
            a, b = b, a
        return a, b
    v = int(rng)
    return v, v


def parse_float_range(rng):
    """Parse a simple float range like '0.05-0.5' into (min,max)."""
    if '-' in rng:
        a, b = rng.split('-', 1)
        a = float(a)
        b = float(b)
        if a > b:
            a, b = b, a
        return a, b
    v = float(rng)
    return v, v


def make_flags(scan_type):
    """Return TCP flags string for a given scan type."""
    st = scan_type.lower()
    if st in ('syn', 's'):
        return 'S'
    if st in ('xmas', 'x'):
        return 'FPU'
    if st in ('null', 'n'):
        return ''
    raise ValueError(f'Unknown scan type: {scan_type}')


def os_guess_from_packet(resp):
    """Basic heuristic OS guess using IP.ttl and TCP.window.
    This is intentionally very simple - real fingerprinting is
    much more elaborate (see nmap OS fingerprinting).
    """
    if resp is None:
        return 'unknown'
    
    ttl = None
    win = None
    
    if resp.haslayer('IP'):
        ttl = resp['IP'].ttl
    if resp.haslayer('TCP'):
        win = resp['TCP'].window

    guesses = []
    if ttl is not None:
        if ttl >= 200:
            guesses.append('network-device')
        elif ttl >= 100:
            guesses.append('windows')
        elif ttl >= 50:
            guesses.append('linux/unix')
        else:
            guesses.append('unknown')

    if win is not None:
        if win in (5840, 29200, 27144):
            guesses.append('linux-like')
        if win in (64240, 65535, 8192):
            guesses.append('windows-like')

    if not guesses:
        return 'unknown'

    c = Counter(guesses)
    most, _ = c.most_common(1)[0]
    return most


def choose_source_port(randomize, rng_min, rng_max):
    """Choose a source port according to options. Return an int or None."""
    if not randomize:
        return None
    return random.randint(rng_min, rng_max)


def choose_delay(hidden_enabled, dmin, dmax):
    """Return a randomized delay in seconds if hidden_enabled else None."""
    if not hidden_enabled:
        return None
    return random.uniform(dmin, dmax)


def scan_port(target, port, flags, timeout=1.0, iface=None, src_port=None):
    """Send a single TCP probe and interpret the result.
    Returns a tuple: (port, status_string, response_packet_or_None)
    status_string in {"open", "closed", "filtered", "unknown"}
    
    Note: The Linux kernel automatically sends RST for unexpected SYN+ACK,
    so no RST is needed to close connections.
    """
    ip = IP(dst=target)
    tcp_kwargs = {'dport': port}
    if src_port is not None:
        tcp_kwargs['sport'] = src_port
    tcp = TCP(**tcp_kwargs)
    if flags:
        tcp.flags = flags
    pkt = ip/tcp
    
    try:
        resp = sr1(pkt, timeout=timeout, iface=iface)
    except PermissionError:
        print("Permission error: you must run as root to send raw packets.")
        sys.exit(1)
    except KeyboardInterrupt:
        raise
    except OSError as e:
        print(f"Error sending packet to {target}:{port} -> {e}")
        return (port, 'unknown', None)

    if resp is None:
        return (port, 'filtered', None)

    # TCP response analysis
    if resp.haslayer(TCP):
        rflags = resp[TCP].flags
        # SYN+ACK -> open (0x12 = SYN | ACK)
        if rflags & 0x12 == 0x12:
            # Note: Linux kernel has already sent RST automatically
            return (port, 'open', resp)
        # RST -> closed
        if rflags & 0x04:
            return (port, 'closed', resp)
        return (port, 'unknown', resp)

    # ICMP Type 3 (Destination Unreachable) -> filtered
    if resp.haslayer(ICMP):
        if resp[ICMP].type == 3:
            return (port, 'filtered', resp)

    return (port, 'unknown', resp)


def main():
    parser = argparse.ArgumentParser(
        description='Simple Scapy TCP scanner (educational) - clean & optimized',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-t', '--target', required=True, 
                        help='target IP or hostname')
    parser.add_argument('-p', '--ports', required=True,
                        help='ports list, e.g. 22,80,443 or 1-1024')
    parser.add_argument('-s', '--scan', choices=['syn','xmas','null'], default='syn',
                        help='scan type (default: syn)')
    parser.add_argument('-o', '--pcap', default=None, 
                        help='save responses to pcap file')
    parser.add_argument('--timeout', type=float, default=1.0, 
                        help='timeout per probe in seconds (default: 1.0)')
    parser.add_argument('--iface', default=None, 
                        help='interface to send on (optional)')

    # Randomization options
    parser.add_argument('--random-srcport', action='store_true', 
                        help='randomize source port for each probe')
    parser.add_argument('--srcport-range', default='1024-65535', 
                        help='source port range when randomizing (default: 1024-65535)')
    parser.add_argument('--randomize-ports', action='store_true', 
                        help='randomize the order of port scanning for stealth')

    # Timing options
    parser.add_argument('--hidden', action='store_true', 
                        help='enable randomized delay between probes')
    parser.add_argument('--hidden-range', default='0.05-0.5', 
                        help='min-max seconds for randomized delay (default: 0.05-0.5)')
    parser.add_argument('--rate-limit', type=int, default=None, 
                        help='maximum packets per second (optional)')

    # Detection options
    parser.add_argument('--os-detect', action='store_true', 
                        help='enable basic OS detection heuristics (TTL/window)')

    # Output options
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='verbose output (show all details)')
    parser.add_argument('-q', '--quiet', action='store_true', 
                        help='quiet mode (minimal output)')

    args = parser.parse_args()

    # Root check
    try:
        import os
        if os.geteuid() != 0:
            print('Warning: You are not root. Scapy raw sockets require root privileges.')
            sys.exit(1)
    except AttributeError:
        pass  # Windows doesn't have geteuid

    # Parse arguments
    ports = parse_ports(args.ports)
    flags = make_flags(args.scan)
    rng_min, rng_max = parse_range(args.srcport_range)
    dmin, dmax = parse_float_range(args.hidden_range)

    # Randomize port order if requested
    if args.randomize_ports:
        random.shuffle(ports)
        if not args.quiet:
            print("[*] Port order randomized for stealth")

    # Print scan configuration
    if not args.quiet:
        print(f"[*] Target: {args.target}")
        print(f"[*] Scan type: {args.scan}")
        print(f"[*] Ports to probe: {len(ports)}")
        print(f"[*] Timeout: {args.timeout}s")
        if args.random_srcport:
            print(f"[*] Source port randomization: {rng_min}-{rng_max}")
        if args.os_detect:
            print("[*] OS detection: ENABLED")
        if args.hidden:
            print(f"[*] Hidden timing: {dmin}-{dmax}s delay")
        if args.rate_limit:
            print(f"[*] Rate limiting: {args.rate_limit} pps")
        print()

    responses = []
    results = []
    os_guesses = []
    start = time.time()
    last_packet_time = 0.0
    
    try:
        for i, p in enumerate(ports):
            # Rate limiting
            if args.rate_limit:
                min_interval = 1.0 / args.rate_limit
                time_since_last = time.time() - last_packet_time
                if time_since_last < min_interval:
                    time.sleep(min_interval - time_since_last)
            
            srcp = choose_source_port(args.random_srcport, rng_min, rng_max)
            delay = choose_delay(args.hidden, dmin, dmax)
            
            if delay:
                time.sleep(delay)
            
            last_packet_time = time.time()
            port, status, resp = scan_port(args.target, p, flags, 
                                          timeout=args.timeout, 
                                          iface=args.iface, 
                                          src_port=srcp)
            
            results.append((port, status))
            
            if resp is not None:
                responses.append(resp)
                if args.os_detect:
                    guess = os_guess_from_packet(resp)
                    os_guesses.append(guess)
                    if args.verbose:
                        ttl = resp['IP'].ttl if resp.haslayer('IP') else '?'
                        win = resp['TCP'].window if resp.haslayer('TCP') else '?'
                        delay_info = f" delay={delay:.3f}s" if delay else ""
                        print(f"{port:5d}: {status:8s}  (src={srcp or 'auto'} ttl={ttl} win={win} os={guess}){delay_info}")
                    elif not args.quiet:
                        print(f"{port:5d}: {status:8s}  (os={guess})")
                else:
                    if args.verbose:
                        delay_info = f" delay={delay:.3f}s" if delay else ""
                        print(f"{port:5d}: {status:8s}  (src={srcp or 'auto'}){delay_info}")
                    elif not args.quiet:
                        print(f"{port:5d}: {status:8s}")
            else:
                if args.verbose:
                    delay_info = f" delay={delay:.3f}s" if delay else ""
                    print(f"{port:5d}: {status:8s}  (src={srcp or 'auto'}){delay_info}")
                elif not args.quiet:
                    print(f"{port:5d}: {status:8s}")
            
            # Progress for quiet mode
            if args.quiet and (i + 1) % 100 == 0:
                print(f"Progress: {i + 1}/{len(ports)}", end='\r')
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    
    duration = time.time() - start

    if not args.quiet:
        print(f"\n[*] Scan completed in {duration:.2f}s")

    # Save to pcap
    if args.pcap and responses:
        try:
            wrpcap(args.pcap, responses)
            if not args.quiet:
                print(f"[*] Saved {len(responses)} packets to {args.pcap}")
        except IOError as e:
            print(f"[!] Failed to write pcap: {e}")

    # Summary
    open_ports = [p for p, s in results if s == 'open']
    closed_ports = [p for p, s in results if s == 'closed']
    filtered_ports = [p for p, s in results if s == 'filtered']

    print('\nSummary')
    print(f'Open:     {len(open_ports):4d} ports', end='')
    if open_ports:
        print(f' -> {open_ports if len(open_ports) <= 20 else open_ports[:20] + ["..."]}')
    else:
        print()
    
    if args.verbose:
        print(f'Closed:   {len(closed_ports):4d} ports', end='')
        if closed_ports and len(closed_ports) <= 20:
            print(f' -> {closed_ports}')
        else:
            print()
        print(f'Filtered: {len(filtered_ports):4d} ports', end='')
        if filtered_ports and len(filtered_ports) <= 20:
            print(f' -> {filtered_ports}')
        else:
            print()
    else:
        print(f'Closed:   {len(closed_ports):4d} ports')
        print(f'Filtered: {len(filtered_ports):4d} ports')
    
    print(f'Total:    {len(results):4d} ports in {duration:.2f}s')
    
    if args.rate_limit:
        actual_rate = len(results) / duration if duration > 0 else 0
        print(f'Rate:     {actual_rate:.2f} pps (limit: {args.rate_limit} pps)')

    if args.os_detect and os_guesses:
        c = Counter(os_guesses)
        print('\nOS Detection')
        for k, v in c.most_common():
            print(f'{k}: {v}')


if __name__ == '__main__':
    main()