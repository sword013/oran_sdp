sudo nft flush chain inet filter input
sudo nft flush chain inet filter sdp_rules_chain
sudo nft delete chain inet filter sdp_rules_chain # Delete the chain to recreate it cleanly


