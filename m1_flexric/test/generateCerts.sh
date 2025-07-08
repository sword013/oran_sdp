# In sdp_project_certs/
# 1. Create the MASTER CA (Controller's CA)
openssl genrsa -out controller_ca.key 4096
openssl req -new -x509 -days 3650 -key controller_ca.key -out controller_ca.crt -subj "/CN=SDP Master CA"

# 2. Controller's mTLS Certificate (for listening to Clients & Gateways)
# The CN here will be used by clients/gateways to verify the controller.
# Let's say controller's IP is 10.9.70.137 or it has a hostname controller.sdp.
CONTROLLER_CN="controller.sdp.example" # Or the IP 10.9.70.137
openssl genrsa -out controller_mtls.key 2048
openssl req -new -key controller_mtls.key -out controller_mtls.csr -subj "/CN=${CONTROLLER_CN}"
openssl x509 -req -days 365 -in controller_mtls.csr -CA controller_ca.crt -CAkey controller_ca.key -CAcreateserial -out controller_mtls.crt

# 3. Client's ONBOARDING mTLS Certificate
# This is what the client uses to initially connect to the controller.
CLIENT_ONBOARD_CN="client_onboard_initial_identity"
openssl genrsa -out client_onboard.key 2048
openssl req -new -key client_onboard.key -out client_onboard.csr -subj "/CN=${CLIENT_ONBOARD_CN}"
openssl x509 -req -days 365 -in client_onboard.csr -CA controller_ca.crt -CAkey controller_ca.key -CAcreateserial -out client_onboard.crt

# 4. Gateway's ONBOARDING mTLS Certificate
# This is what the gateway uses to initially connect to the controller.
GATEWAY_ONBOARD_CN="gateway_onboard_initial_identity"
openssl genrsa -out gateway_onboard.key 2048
openssl req -new -key gateway_onboard.key -out gateway_onboard.csr -subj "/CN=${GATEWAY_ONBOARD_CN}"
openssl x509 -req -days 365 -in gateway_onboard.csr -CA controller_ca.crt -CAkey controller_ca.key -CAcreateserial -out gateway_onboard.crt

# Cleanup CSRs and serial file (optional)
rm *.csr *.srl


