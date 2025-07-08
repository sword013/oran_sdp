#!/bin/bash

# Script to set up basic nftables rules for the SDP Controller

echo "--- Setting up SDP Controller nftables rules ---"

echo "Attempting to flush relevant chains (sdp_rules_chain, input) if they exist..."
sudo nft flush chain inet filter sdp_rules_chain > /dev/null 2>&1 || echo "Info: sdp_rules_chain did not exist or was already empty."
# For initial setup, let's ensure 'input' is clean before defining it
sudo nft flush chain inet filter input > /dev/null 2>&1         || echo "Info: input chain (inet filter) did not exist or was already empty."
sudo nft delete chain inet filter sdp_rules_chain > /dev/null 2>&1 || echo "Info: sdp_rules_chain did not exist."


echo "1. Adding 'inet filter' table (if it doesn't exist)..."
sudo nft add table inet filter

echo "2. Defining 'input' chain with default drop policy..."
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }

echo "3. Defining 'forward' chain with default accept policy (adjust if controller is a router)..."
sudo nft add chain inet filter forward { type filter hook forward priority 0 \; policy accept \; }

echo "4. Defining 'output' chain with default accept policy..."
sudo nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }

echo "5. Adding essential allow rules to 'input' chain (MUST BE ADDED AFTER CHAIN DEFINITION)..."
# Ensure the comment string is correctly quoted for the shell executing the nft command
sudo nft add rule inet filter input ct state related,established accept comment "\"Allow established/related connections\""
sudo nft add rule inet filter input iifname lo accept comment "\"Allow loopback traffic\""
sudo nft add rule inet filter input tcp dport 22 accept comment "\"Allow SSH\""

echo "6. Adding static rule to allow SPA packets (UDP 62201) to 'input' chain..."
sudo nft add rule inet filter input udp dport 62201 accept comment "\"ALLOW_SPA_TO_CTRL\""

echo "7. Creating custom chain 'sdp_rules_chain' for dynamic SPA rules..."
sudo nft add chain inet filter sdp_rules_chain

echo "8. Adding jump from 'input' to 'sdp_rules_chain'..."
sudo nft add rule inet filter input jump sdp_rules_chain comment "\"Jump to dynamic SDP rules\""

echo ""
echo "--- Current nftables ruleset: ---"
sudo nft list ruleset
echo ""
echo "--- Setup complete. ---"
echo "IMPORTANT: Test connectivity to essential services (like SSH from your admin machine)."
echo "           Packets not matching an accept rule in 'input' or 'sdp_rules_chain' will be dropped."


