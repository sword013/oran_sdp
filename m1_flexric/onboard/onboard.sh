# --- 1. Create Root CA ---
# Generate Root CA private key (keep this VERY secure)
openssl genpkey -algorithm RSA -out controller_ca.key -pkeyopt rsa_keygen_bits:4096

# Create Root CA certificate (self-signed, valid for e.g., 10 years)
openssl req -x509 -new -nodes -key controller_ca.key -sha256 -days 3650 \
    -subj "/C=US/ST=State/L=City/O=MyOrg/CN=MyOrg_SDP_Root_CA" \
    -out controller_ca.crt

echo "Created Root CA: controller_ca.key, controller_ca.crt"

# --- 2. Generate AH Onboarding Credentials ---
AH_IP="10.9.70.75" # Replace with actual AH IP if different
# Generate AH private key
openssl genpkey -algorithm RSA -out ah_onboard_${AH_IP}.key -pkeyopt rsa_keygen_bits:2048

# Create AH Certificate Signing Request (CSR)
openssl req -new -key ah_onboard_${AH_IP}.key \
    -subj "/C=US/ST=State/L=City/O=MyOrg/CN=${AH_IP}" \
    -out ah_onboard_${AH_IP}.csr

# Sign AH CSR with Root CA (valid for e.g., 1 year)
openssl x509 -req -in ah_onboard_${AH_IP}.csr -CA controller_ca.crt -CAkey controller_ca.key \
    -CAcreateserial -out ah_onboard_${AH_IP}.crt -days 365 -sha256

# Generate random onboarding SPA/HMAC keys (64 hex chars = 32 bytes)
AH_ONBOARD_ENC_KEY=$(openssl rand -hex 32)
AH_ONBOARD_HMAC_KEY=$(openssl rand -hex 32)
# For simplicity now, use HMAC key as initial HOTP seed
AH_ONBOARD_HOTP_SEED=$AH_ONBOARD_HMAC_KEY

echo "--- AH (${AH_IP}) Onboarding ---"
echo "Key: ah_onboard_${AH_IP}.key"
echo "Cert: ah_onboard_${AH_IP}.crt"
echo "SPA Enc Key: $AH_ONBOARD_ENC_KEY"
echo "SPA HMAC/HOTP Key: $AH_ONBOARD_HMAC_KEY"
echo "-----------------------------"
# Manually add these keys to controller_onboard.conf for the AH


# --- 3. Generate IH Onboarding Credentials ---
IH_IP="10.9.64.244" # Replace with actual IH IP if different
# Generate IH private key
openssl genpkey -algorithm RSA -out ih_onboard_${IH_IP}.key -pkeyopt rsa_keygen_bits:2048

# Create IH CSR
openssl req -new -key ih_onboard_${IH_IP}.key \
    -subj "/C=US/ST=State/L=City/O=MyOrg/CN=${IH_IP}" \
    -out ih_onboard_${IH_IP}.csr

# Sign IH CSR with Root CA
openssl x509 -req -in ih_onboard_${IH_IP}.csr -CA controller_ca.crt -CAkey controller_ca.key \
    -CAcreateserial -out ih_onboard_${IH_IP}.crt -days 365 -sha256

# Generate random onboarding SPA/HMAC keys
IH_ONBOARD_ENC_KEY=$(openssl rand -hex 32)
IH_ONBOARD_HMAC_KEY=$(openssl rand -hex 32)
IH_ONBOARD_HOTP_SEED=$IH_ONBOARD_HMAC_KEY

echo "--- IH (${IH_IP}) Onboarding ---"
echo "Key: ih_onboard_${IH_IP}.key"
echo "Cert: ih_onboard_${IH_IP}.crt"
echo "SPA Enc Key: $IH_ONBOARD_ENC_KEY"
echo "SPA HMAC/HOTP Key: $IH_ONBOARD_HMAC_KEY"
echo "-----------------------------"
# Manually add these keys to controller_onboard.conf for the IH


# --- Cleanup CSRs and serial file ---
rm *.csr *.srl

echo "Onboarding files generated. Manually distribute:"
echo "  To AH (${AH_IP}): controller_ca.crt, ah_onboard_${AH_IP}.key, ah_onboard_${AH_IP}.crt, AH onboarding SPA keys"
echo "  To IH (${IH_IP}): controller_ca.crt, ih_onboard_${IH_IP}.key, ih_onboard_${IH_IP}.crt, IH onboarding SPA keys"
echo "  To Controller: controller_ca.crt, controller_ca.key, and populate controller_onboard.conf"
