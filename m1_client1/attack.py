#!/usr/bin/env python3
from scapy.all import *
import random

src_ip = "10.9.70.136"
dst_ip = "10.9.70.137"
iface = "ens18"

# Define the allowed destination ports
dst_ports = [55690, 4561, 451, 48396, 4562]

print(f"Sending TCP RST packets from {src_ip} to {dst_ip} on selected random ports via {iface}...")

while True:
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(
        sport=random.randint(1024, 65535),              # Random source port
        dport=random.choice(dst_ports),                 # Random from given list
        flags="R",
        seq=random.randint(0, 4294967295)               # Random sequence number
    )

    pkt = ip / tcp
    send(pkt, verbose=False, iface=iface)
