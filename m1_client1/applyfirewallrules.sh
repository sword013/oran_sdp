#!/bin/bash

echo "Applying iptables rules..."

# Flush existing rules
sudo iptables -F
sudo iptables -X
sudo iptables -Z

# Set default policy to DROP
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -s 10.9.65.55 -j ACCEPT

# Allow loopback traffic
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established and related connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow traffic from 10.9.65.54 (any port/protocol)
sudo iptables -A INPUT -s 10.9.65.54 -j ACCEPT

# Allow traffic from 10.9.70.137 (any port/protocol)
sudo iptables -A INPUT -s 10.9.70.137 -j ACCEPT

echo "iptables rules applied."
