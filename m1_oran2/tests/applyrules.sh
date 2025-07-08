#!/bin/bash

# Flush existing rules
iptables -F
iptables -X

# Set default policy to DROP for INPUT only
iptables -P INPUT DROP

# Accept all traffic on loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Accept incoming traffic for established or related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "iptables rules applied: INPUT default DROP, only established/related allowed."
