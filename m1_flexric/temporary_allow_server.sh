#!/bin/bash

# Add temporary rule
sudo iptables -I INPUT 1 -s 10.9.65.55 -j ACCEPT
echo "[+] Temporarily allowed 10.9.65.55"

# Wait 30 seconds
sleep 30

# Remove the rule (note: exact match deletion)
sudo iptables -D INPUT -s 10.9.65.55 -j ACCEPT
echo "[+] Rule removed after 30 seconds"
