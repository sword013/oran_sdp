# 1. Create a CA (Certificate Authority)
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=My Test CA"

# 2. Create Gateway Key and CSR (Certificate Signing Request)
openssl genrsa -out gateway.key 2048
openssl req -new -key gateway.key -out gateway.csr -subj "/CN=gateway.example.com" # CN important for client

# 3. Sign Gateway CSR with CA
openssl x509 -req -days 365 -in gateway.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out gateway.crt

# 4. Create Client Key and CSR
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client.example.com" # CN important for gateway

# 5. Sign Client CSR with CA
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

# Clean up CSRs and serial file (optional)
# rm *.csr *.srl

