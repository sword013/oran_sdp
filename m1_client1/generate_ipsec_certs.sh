#!/bin/bash

set -e

# Directories
mkdir -p ipsec_certs/{ca,server,client}

# 1. Create OpenSSL config with no prompts
cat > openssl.cnf <<EOF
[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
distinguished_name  = dn

[ dn ]
CN = IPsec VPN

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:TRUE
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
EOF

# 2. Generate CA key and cert
openssl req -x509 -nodes -days 3650 \
  -newkey rsa:2048 \
  -keyout ipsec_certs/ca/ca.key \
  -out ipsec_certs/ca/ca.crt \
  -config openssl.cnf \
  -extensions v3_ca

# 3. Generate server key and CSR
openssl req -nodes -newkey rsa:2048 \
  -keyout ipsec_certs/server/server.key \
  -out ipsec_certs/server/server.csr \
  -config openssl.cnf

# 4. Sign server cert
openssl x509 -req -in ipsec_certs/server/server.csr \
  -CA ipsec_certs/ca/ca.crt -CAkey ipsec_certs/ca/ca.key -CAcreateserial \
  -out ipsec_certs/server/server.crt -days 3650 -sha256 -extfile openssl.cnf -extensions v3_req

# 5. Generate client key and CSR
openssl req -nodes -newkey rsa:2048 \
  -keyout ipsec_certs/client/client.key \
  -out ipsec_certs/client/client.csr \
  -config openssl.cnf

# 6. Sign client cert
openssl x509 -req -in ipsec_certs/client/client.csr \
  -CA ipsec_certs/ca/ca.crt -CAkey ipsec_certs/ca/ca.key -CAcreateserial \
  -out ipsec_certs/client/client.crt -days 3650 -sha256 -extfile openssl.cnf -extensions v3_req

# 7. Cleanup
rm openssl.cnf ipsec_certs/*/*.csr ipsec_certs/ca/ca.srl

echo -e "\n✅ Certificates generated in ./ipsec_certs/"
