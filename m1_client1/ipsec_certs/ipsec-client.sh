#!/bin/bash
#Assuming you have ca.crt, client.key and client.crt sent from controller machine already in current directory

#1. Convert client.key + client.crt -> server.pkcs12 :
sudo openssl pkcs12 -export -in client.crt -inkey client.key -certfile ca.crt  -name "client" -out client.p12 -passout pass:

#2. Import client certificate(pkcs12) and ca.crt in NSS db :
#sudo pk12util -i client.p12 -d sql:/var/lib/ipsec/nss/ -n "client" -W ''
sudo certutil -A -d sql:/var/lib/ipsec/nss -n "MyCA" -t "CT,," -a -i ca.crt
sudo pk12util -i client.p12 -d sql:/var/lib/ipsec/nss/ -n "client" -W ''


#3. Show nss db loaded certs:
echo "Showing NSS db certificates:\n"
sudo certutil -L -d sql:/var/lib/ipsec/nss

#4. Add tunnel : 
sudo ipsec auto --add client-to-server

#5. Up tunnel :
sudo ipsec auto --up client-to-server

#6. Send all client server traffic, observe ESP !
read -p "Press Enter to shutdown ipsec after sending client-server traffic ESP !...."

#7. Cleanup: down tunnel and delete it, also remove certificates
sudo ipsec auto --down client-to-server
sudo ipsec auto --delete client-to-server
sudo certutil -D -d sql:/var/lib/ipsec/nss -n 'client'
sudo certutil -D -d sql:/var/lib/ipsec/nss -n 'MyCA'

