# --- Flush rules (Optional - CAUTION) ---
# sudo iptables -F INPUT
# sudo iptables -F OUTPUT
# sudo iptables -F FORWARD

# --- Allow Established/Related (MUST BE EARLY) ---
sudo iptables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# --- Allow Loopback (MUST BE EARLY) ---
sudo iptables -I INPUT 2 -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT # Usually okay if OUTPUT policy is ACCEPT

# --- Allow Incoming SPA UDP Port (Essential Entry Point) ---
# Allows the first SPA packet to reach the listener process
sudo iptables -I INPUT 3 -p udp --dport 62201 -j ACCEPT

# --- Allow Incoming SSH (Optional but Recommended for Management) ---
# Replace YOUR_MGMT_IP if needed
# sudo iptables -I INPUT 4 -p tcp -s YOUR_MGMT_IP --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# --- Set Default Policies to DROP (MUST BE LAST for INPUT/FORWARD) ---
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT # Keep OUTPUT open for simplicity

# --- Save/Verify ---
# (Save rules using distro-specific method)
#sudo iptables -L INPUT -v -n --line-numbers

# Allow all INPUT from admin (10.9.70.137)
sudo iptables -I INPUT 1 -s 10.9.70.137 -j ACCEPT

# Allow all OUTPUT to admin (10.9.70.137)
sudo iptables -I OUTPUT 1 -d 10.9.70.137 -j ACCEPT
sudo iptables -L INPUT -v -n --line-numbers
