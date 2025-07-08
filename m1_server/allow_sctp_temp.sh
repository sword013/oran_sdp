sudo iptables -I INPUT 1 -p sctp -s 10.9.70.136 --dport 38472 -j ACCEPT
sleep 30
sudo iptables -D INPUT -p sctp -s 10.9.70.136 --dport 38472 -j ACCEPT

