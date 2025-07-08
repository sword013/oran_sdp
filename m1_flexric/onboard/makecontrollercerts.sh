#!/bin/bash

# Run these commands on the Controller machine
# --- USE THE NEW CONTROLLER IP ---
CONTROLLER_IP="10.9.70.137"

CA_KEY="controller_ca.key"
CA_CERT="controller_ca.crt"

# --- Check if CA files exist ---
if [ ! -f "$CA_KEY" ]; then
    echo "Error: CA Private Key '$CA_KEY' not found!"
    exit 1
fi
if [ ! -f "$CA_CERT" ]; then
    echo "Error: CA Certificate '$CA_CERT' not found!"
    exit 1
fi

# Exit on any error
set -e

echo "Generating Controller mTLS credentials for IP: $CONTROLLER_IP..."

# Define filenames
KEY_FILE="controller_${CONTROLLER_IP}.key"
CSR_FILE="controller_${CONTROLLER_IP}.csr"
CERT_FILE="controller_${CONTROLLER_IP}.crt"

# 1. Generate Controller private key
echo "Generating private key: $KEY_FILE"
openssl genpkey -algorithm RSA -out "$KEY_FILE" -pkeyopt rsa_keygen_bits:2048

# Set restrictive permissions on the key
chmod 600 "$KEY_FILE"

# 2. Create Controller CSR with NEW IP in CN
echo "Generating CSR: $CSR_FILE"
openssl req -new -key "$KEY_FILE" \
    -subj "/C=US/ST=State/L=City/O=MyOrg/CN=${CONTROLLER_IP}" \
    -out "$CSR_FILE"

# 3. Sign Controller CSR with Root CA
echo "Signing CSR to create certificate: $CERT_FILE"
openssl x509 -req -in "$CSR_FILE" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$CERT_FILE" -days 730 -sha256

# 4. Cleanup CSR and serial file
echo "Cleaning up temporary files..."
rm "$CSR_FILE"
rm "${CA_CERT%.*}.srl" # Removes controller_ca.srl (adjust if CA name differs)

echo "-----------------------------------------------------"
echo "Generated Controller mTLS credentials:"
echo "  Private Key: $KEY_FILE (Permissions set to 600)"
echo "  Certificate: $CERT_FILE"
echo "Ensure these filenames match the paths defined in handle_connections_controller.c"
echo "-----------------------------------------------------"

exit 0
