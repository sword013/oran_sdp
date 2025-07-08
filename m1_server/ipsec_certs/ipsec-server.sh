#!/bin/bash
#Assuming you have ca.crt, server.key and server.crt sent from controller machine already in current directory

#1. Convert client.key + client.crt -> server.pkcs12 :
sudo openssl pkcs12 -export -in server.crt -inkey server.key -certfile ca.crt  -name "server" -out server.p12 -passout pass:

#2. Import client certificate(pkcs12) and ca.crt in NSS db :
sudo certutil -A -d sql:/var/lib/ipsec/nss -n "MyCA" -t "CT,," -a -i ca.crt
sudo pk12util -i server.p12 -d sql:/var/lib/ipsec/nss/ -n "server" -W ''
#sudo certutil -A -d sql:/var/lib/ipsec/nss -n "MyCA" -t "CT,," -a -i ca.crt

#3. Show nss db loaded certs:
echo "Showing NSS db certificates:\n"
sudo certutil -L -d sql:/var/lib/ipsec/nss

#4. Add tunnel :
sudo ipsec auto --add server-to-client

#5. Up tunnel :
#sudo ipsec auto --up server-to-client

#6. Send all client server traffic, observe ESP !
read -p "Press Enter to shutdown ipsec after sending client-server traffic ESP !...."

#7. Cleanup: down tunnel and delete it, also remove certificates
sudo ipsec auto --down server-to-client
#sudo ipsec auto --delete server-to-client
sudo certutil -D -d sql:/var/lib/ipsec/nss -n 'server'
sudo certutil -D -d sql:/var/lib/ipsec/nss -n 'MyCA'


