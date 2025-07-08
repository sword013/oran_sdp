#!/bin/bash

# Script to tear down SDP Controller specific nftables rules (Simplified)

echo "--- Tearing down SDP Controller nftables rules (Simplified Version) ---"

echo "1. Flushing and deleting 'sdp_rules_chain'..."
sudo nft flush chain inet filter sdp_rules_chain > /dev/null 2>&1 || echo "Info: sdp_rules_chain was already empty or did not exist."
sudo nft delete chain inet filter sdp_rules_chain > /dev/null 2>&1 || echo "Info: sdp_rules_chain did not exist."

echo ""
echo "--- Dynamic rule chain 'sdp_rules_chain' has been flushed and deleted. ---"
echo "--- Static rules in 'input' chain (like SPA listener allow, jump rule, SSH) are NOT removed by this script. ---"
echo "--- 'input' chain policy remains DROP. ---"
echo ""
echo "--- Current nftables ruleset: ---"
sudo nft list ruleset
echo ""


