#!/bin/bash

# --- Configuration: Set NEW IP Addresses ---
NEW_CONTROLLER_IP="10.9.70.137"
NEW_IH_IP="10.9.70.136"
NEW_AH_IP="10.9.65.55"

# --- Location of your CA files ---
CA_KEY="controller_ca.key"
CA_CERT="controller_ca.crt"

# Exit on any error
set -e

# --- Regenerate Controller's mTLS Credentials ---
echo "Regenerating Controller credentials for IP: $NEW_CONTROLLER_IP..."
KEY_FILE_CTRL="controller_${NEW_CONTROLLER_IP}.key"
CSR_FILE_CTRL="controller_${NEW_CONTROLLER_IP}.csr"
CERT_FILE_CTRL="controller_${NEW_CONTROLLER_IP}.crt"
openssl genpkey -algorithm RSA -out "$KEY_FILE_CTRL" -pkeyopt rsa_keygen_bits:2048
chmod 600 "$KEY_FILE_CTRL"
openssl req -new -key "$KEY_FILE_CTRL" -subj "/C=US/ST=State/L=City/O=MyOrg/CN=${NEW_CONTROLLER_IP}" -out "$CSR_FILE_CTRL"
openssl x509 -req -in "$CSR_FILE_CTRL" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$CERT_FILE_CTRL" -days 730 -sha256
echo "Generated: $KEY_FILE_CTRL, $CERT_FILE_CTRL"
echo "-----------------------------"


# --- Regenerate AH Onboarding Credentials (CERTIFICATE ONLY) ---
echo "Regenerating AH certificate for NEW IP: $NEW_AH_IP..."
# Assume old key is named ah_onboard_<OLD_IP>.key OR generate a new one if preferred
# Using NEW key generation here for consistency:
KEY_FILE_AH="ah_onboard_${NEW_AH_IP}.key"
CSR_FILE_AH="ah_onboard_${NEW_AH_IP}.csr"
CERT_FILE_AH="ah_onboard_${NEW_AH_IP}.crt"
openssl genpkey -algorithm RSA -out "$KEY_FILE_AH" -pkeyopt rsa_keygen_bits:2048
chmod 600 "$KEY_FILE_AH"
openssl req -new -key "$KEY_FILE_AH" -subj "/C=US/ST=State/L=City/O=MyOrg/CN=${NEW_AH_IP}" -out "$CSR_FILE_AH"
openssl x509 -req -in "$CSR_FILE_AH" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$CERT_FILE_AH" -days 365 -sha256

# --- IMPORTANT: DO NOT REGENERATE THESE KEYS ---
# AH_ONBOARD_ENC_KEY=$(openssl rand -hex 32)
# AH_ONBOARD_HMAC_KEY=$(openssl rand -hex 32)
# AH_ONBOARD_HOTP_SEED=$AH_ONBOARD_HMAC_KEY
# --- Use the ORIGINAL SPA/HMAC/HOTP keys generated previously ---

echo "--- AH (${NEW_AH_IP}) Cert Regeneration ---"
echo "Generated NEW Key: $KEY_FILE_AH"
echo "Generated NEW Cert: $CERT_FILE_AH"
echo "!!! REMEMBER to use the ORIGINAL SPA/HMAC/HOTP keys for config files !!!"
echo "------------------------------------------"


# --- Regenerate IH Onboarding Credentials (CERTIFICATE ONLY) ---
echo "Regenerating IH certificate for NEW IP: $NEW_IH_IP..."
# Using NEW key generation here:
KEY_FILE_IH="ih_onboard_${NEW_IH_IP}.key"
CSR_FILE_IH="ih_onboard_${NEW_IH_IP}.csr"
CERT_FILE_IH="ih_onboard_${NEW_IH_IP}.crt"
openssl genpkey -algorithm RSA -out "$KEY_FILE_IH" -pkeyopt rsa_keygen_bits:2048
chmod 600 "$KEY_FILE_IH"
openssl req -new -key "$KEY_FILE_IH" -subj "/C=US/ST=State/L=City/O=MyOrg/CN=${NEW_IH_IP}" -out "$CSR_FILE_IH"
openssl x509 -req -in "$CSR_FILE_IH" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$CERT_FILE_IH" -days 365 -sha256

# --- IMPORTANT: DO NOT REGENERATE THESE KEYS ---
# IH_ONBOARD_ENC_KEY=$(openssl rand -hex 32)
# IH_ONBOARD_HMAC_KEY=$(openssl rand -hex 32)
# IH_ONBOARD_HOTP_SEED=$IH_ONBOARD_HMAC_KEY
# --- Use the ORIGINAL SPA/HMAC/HOTP keys generated previously ---

echo "--- IH (${NEW_IH_IP}) Cert Regeneration ---"
echo "Generated NEW Key: $KEY_FILE_IH"
echo "Generated NEW Cert: $CERT_FILE_IH"
echo "!!! REMEMBER to use the ORIGINAL SPA/HMAC/HOTP keys for config files !!!"
echo "-----------------------------------------"


# --- Cleanup ---
echo "Cleaning up temporary CSR files..."
rm *.csr
# Safely remove serial file if it exists
if [ -f "${CA_CERT%.*}.srl" ]; then
    rm "${CA_CERT%.*}.srl"
fi

echo ""
echo "Regeneration complete. Update configs and distribute NEW keys/certs."
echo "Remember to use ORIGINAL SPA/HMAC/HOTP keys in config files."

exit 0
