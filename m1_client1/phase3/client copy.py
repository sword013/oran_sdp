# client.py
import socket
import ssl
import time
import hmac
import hashlib
import struct
import random
import os
import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# --- Configuration ---
# Controller Details (Onboarding)
CONTROLLER_IP = '10.9.70.137'
CONTROLLER_SPA_PORT = 62201
CONTROLLER_MTLS_PORT = 9999
CONTROLLER_SERVER_HOSTNAME = 'controller.sdp.example' # Must match CN in controller_mtls.crt

# Onboarding SPA Keys (must match controller's ONBOARD_SPA_PSK_HMAC)
ONBOARD_SPA_PSK_HMAC_TO_CONTROLLER = b"controller_onboard_spa_hmac_key_xyz!"

# Onboarding mTLS Certs for Client (to authenticate to Controller)
# Assumes a "certs_client/" directory relative to the script for these initial certs
SCRIPT_DIR_CLIENT = os.path.dirname(os.path.abspath(__file__))
CERTS_CLIENT_DIR = os.path.join(SCRIPT_DIR_CLIENT, "./") # Standardized

# CA cert to verify controller AND gateway (assuming same master CA)
CA_CERT_PATH_CLIENT = os.path.join(CERTS_CLIENT_DIR, 'controller_ca.crt') 
# Client's own cert/key for ONBOARDING mTLS to controller
CLIENT_ONBOARD_CERT_PATH = os.path.join(CERTS_CLIENT_DIR, 'client_onboard.crt')
CLIENT_ONBOARD_KEY_PATH = os.path.join(CERTS_CLIENT_DIR, 'client_onboard.key')

# Temporary storage for ephemeral certs/keys received from controller
EPH_CLIENT_CERT_FILE = os.path.join(SCRIPT_DIR_CLIENT, "_eph_client.crt")
EPH_CLIENT_KEY_FILE = os.path.join(SCRIPT_DIR_CLIENT, "_eph_client.key")
EPH_CA_CERT_FILE_FOR_GW = os.path.join(SCRIPT_DIR_CLIENT, "_eph_ca_gw.crt") # CA cert from controller for GW

BUFFER_SIZE = 4096

# --- Helper Functions ---
def create_onboard_spa_packet_to_controller():
    timestamp = time.time()
    nonce = random.randint(0, 0xFFFFFFFF) # 4-byte nonce
    # Payload: Timestamp (8b) | Nonce (4b)
    payload = struct.pack('!dI', timestamp, nonce)
    calculated_hmac = hmac.new(ONBOARD_SPA_PSK_HMAC_TO_CONTROLLER, payload, hashlib.sha256).digest()
    return payload + calculated_hmac

def create_ephemeral_spa_packet_to_gateway(eph_spa_hmac_key_hex, target_service_port, target_service_host):
    # For this example, SPA to gateway will also be simple: Timestamp | Nonce | TargetPort | TargetHostLen | TargetHost
    # HMAC will use the ephemeral key.
    timestamp = time.time()
    nonce = random.randint(0, 0xFFFFFFFF)
    target_host_bytes = target_service_host.encode('utf-8')
    target_host_len = len(target_host_bytes)

    # Payload: Timestamp (8b) | Nonce (4b) | Target Service Port (2b) | Target Host Len (1b) | Target Host (var)
    # This matches the Python gateway's SPA expectation (from previous working example)
    # If gateway SPA format changes due to controller, adjust this.
    # For now, let's assume a simple SPA to gateway if controller dictates keys but not full packet structure.
    # Let's simplify and make it same as controller's onboarding for now.
    # Payload: Timestamp (8b) | Nonce (4b) | TargetPort (2b) -- Controller needs to tell Gateway this format.
    # For the Python gateway we last built, it was:
    # Timestamp (8b) | Nonce (4b) | Target Port on Server (2b) | HMAC (32b)
    # Let's use THIS format for the ephemeral SPA knock to the Python gateway.
    
    payload_to_gw = struct.pack('!dIH', timestamp, nonce, target_service_port) # timestamp, nonce, target_port
    
    eph_hmac_key_bytes = bytes.fromhex(eph_spa_hmac_key_hex)
    calculated_hmac_to_gw = hmac.new(eph_hmac_key_bytes, payload_to_gw, hashlib.sha256).digest()
    return payload_to_gw + calculated_hmac_to_gw


def save_temp_pem_file(pem_data_str, file_path):
    try:
        with open(file_path, "w") as f:
            f.write(pem_data_str)
        os.chmod(file_path, 0o600) # Restrictive permissions for keys
        return True
    except Exception as e:
        print(f"[CLIENT_ERROR] Failed to save PEM to {file_path}: {e}")
        return False

def cleanup_temp_pem_files():
    for f_path in [EPH_CLIENT_CERT_FILE, EPH_CLIENT_KEY_FILE, EPH_CA_CERT_FILE_FOR_GW]:
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
            except:
                pass # Best effort

# --- Main Client Logic ---
def run_sdp_client(message_to_service, requested_target_host, requested_target_port):
    onboard_ssl_socket = None
    gateway_ssl_socket = None
    ephemeral_creds = None

    try:
        print("[PHASE 1] Onboarding with Controller...")
        # 1.1 SPA Knock to Controller
        onboard_spa_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            onboard_spa_packet = create_onboard_spa_packet_to_controller()
            onboard_spa_sock.sendto(onboard_spa_packet, (CONTROLLER_IP, CONTROLLER_SPA_PORT))
            print(f"[+] CLIENT_SPA_CTRL: Sent ONBOARD SPA knock to {CONTROLLER_IP}:{CONTROLLER_SPA_PORT}")
        except Exception as e_spa_ctrl:
            print(f"[!] CLIENT_SPA_CTRL: Error sending ONBOARD SPA: {e_spa_ctrl}")
            return
        finally:
            onboard_spa_sock.close()
        
        time.sleep(0.01) # Allow controller to process SPA & add iptables rule (tune this)

        # 1.2 mTLS to Controller (using onboarding certs)
        onboard_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        onboard_context.load_verify_locations(cafile=CA_CERT_PATH_CLIENT)
        onboard_context.load_cert_chain(certfile=CLIENT_ONBOARD_CERT_PATH, keyfile=CLIENT_ONBOARD_KEY_PATH)

        onboard_raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        onboard_raw_sock.settimeout(10.0)
        onboard_ssl_socket = onboard_context.wrap_socket(onboard_raw_sock, server_hostname=CONTROLLER_SERVER_HOSTNAME)
        
        print(f"[*] CLIENT_MTLS_CTRL: Attempting mTLS to Controller {CONTROLLER_IP}:{CONTROLLER_MTLS_PORT}...")
        onboard_ssl_socket.connect((CONTROLLER_IP, CONTROLLER_MTLS_PORT))
        print(f"[+] CLIENT_MTLS_CTRL: Connected to Controller.")
        # Controller cert details can be printed here if needed

        # 1.3 Send Access Request to Controller
        # For now, a simple request. In a real system, this would specify service, etc.
        # The controller's handle_client_onboard_connection expects a simple recv for now
        # and then provisions for a default service.
        access_request_msg = {"request_type": "GET_ACCESS", 
                              "client_identity_cn": "client_onboard_initial_identity", # From our onboarding cert
                              # Could add hints for desired service if controller policy uses it
                              "desired_backend_host": requested_target_host,
                              "desired_backend_port": requested_target_port
                             }
        onboard_ssl_socket.sendall(json.dumps(access_request_msg).encode())
        print(f"[>] CLIENT_MTLS_CTRL: Sent access request to Controller.")

        # 1.4 Receive Ephemeral Credentials from Controller
        controller_response_raw = onboard_ssl_socket.recv(8192) # Expect larger response with certs
        if not controller_response_raw:
            print("[!] CLIENT_MTLS_CTRL: Controller closed connection without sending credentials.")
            return
        
        ephemeral_creds = json.loads(controller_response_raw.decode())
        print(f"[<] CLIENT_MTLS_CTRL: Received from Controller: {json.dumps(ephemeral_creds, indent=2)}")

        if ephemeral_creds.get("status") != "success":
            print(f"[!] CLIENT_MTLS_CTRL: Controller denied access or error: {ephemeral_creds.get('message', 'Unknown error')}")
            return
        
        # Save ephemeral certs/keys to temporary files
        if not save_temp_pem_file(ephemeral_creds["eph_client_cert_pem"], EPH_CLIENT_CERT_FILE) or \
           not save_temp_pem_file(ephemeral_creds["eph_client_key_pem"], EPH_CLIENT_KEY_FILE) or \
           not save_temp_pem_file(ephemeral_creds["eph_ca_cert_pem"], EPH_CA_CERT_FILE_FOR_GW): # CA for gateway
            print("[!] CLIENT_MTLS_CTRL: Failed to save ephemeral credentials locally.")
            return
        
        print("[+] CLIENT_MTLS_CTRL: Ephemeral credentials saved locally.")
        onboard_ssl_socket.close()
        onboard_ssl_socket = None
        print("[PHASE 1] Onboarding with Controller COMPLETE.")

        # --- PHASE 2: Connect to Gateway using Ephemeral Credentials ---
        print("\n[PHASE 2] Connecting to Gateway...")
        gateway_ip = ephemeral_creds["gateway_ip"]
        gateway_mtls_port = ephemeral_creds["gateway_mtls_port"]
        gateway_spa_port = ephemeral_creds["gateway_spa_port"]
        eph_spa_hmac_key_hex_for_gw = ephemeral_creds["eph_spa_hmac_key_hex"]
        # The controller told us what service the gateway will proxy to for us.
        # This client doesn't need to send this info in data AGAIN, SPA to GW indicates this.
        # The SPA packet structure for the Python gateway expects target_service_port.
        # The policy on controller decided this, now we tell GW via SPA.
        gateway_proxied_target_port = requested_target_port # The service port client wants to reach via gateway

        # 2.1 Ephemeral SPA Knock to Gateway
        eph_spa_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # The Python gateway SPA format we built: Timestamp (8b) | Nonce (4b) | TargetPort (2b) | HMAC (32b)
            # TargetPort here is the *actual backend service port* the gateway should connect to.
            eph_spa_packet = create_ephemeral_spa_packet_to_gateway(eph_spa_hmac_key_hex_for_gw, 
                                                                    gateway_proxied_target_port,
                                                                    "dummy_host_not_used_by_python_gw_spa_format") # Host not in this SPA format
            eph_spa_sock.sendto(eph_spa_packet, (gateway_ip, gateway_spa_port))
            print(f"[+] CLIENT_SPA_GW: Sent EPHEMERAL SPA knock for service port {gateway_proxied_target_port} to {gateway_ip}:{gateway_spa_port}")
        except Exception as e_spa_gw:
            print(f"[!] CLIENT_SPA_GW: Error sending EPHEMERAL SPA: {e_spa_gw}")
            return
        finally:
            eph_spa_sock.close()

        time.sleep(0.01) # Allow gateway to process SPA & add iptables rule (tune this)

        # 2.2 mTLS to Gateway (using ephemeral certs)
        # For gateway verification, server_hostname should match CN in gateway's ephemeral cert.
        # Controller should generate gateway's ephemeral cert with a predictable CN, e.g., gateway_ip or specific hostname.
        # For simplicity, let's assume controller used gateway_ip as CN for gateway's eph cert.
        gateway_server_hostname_eph = gateway_ip 
        # If controller uses a fixed hostname like "gateway.eph.sdp", client needs to know/resolve it.

        gateway_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        gateway_context.load_verify_locations(cafile=EPH_CA_CERT_FILE_FOR_GW) # Use CA from controller
        gateway_context.load_cert_chain(certfile=EPH_CLIENT_CERT_FILE, keyfile=EPH_CLIENT_KEY_FILE) # Our ephemeral cert

        gateway_raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gateway_raw_sock.settimeout(10.0)
        gateway_ssl_socket = gateway_context.wrap_socket(gateway_raw_sock, server_hostname=gateway_server_hostname_eph)
        
        print(f"[*] CLIENT_MTLS_GW: Attempting EPHEMERAL mTLS to Gateway {gateway_ip}:{gateway_mtls_port}...")
        gateway_ssl_socket.connect((gateway_ip, gateway_mtls_port))
        print(f"[+] CLIENT_MTLS_GW: Connected to Gateway with ephemeral credentials.")
        # Gateway's ephemeral cert details can be printed here

        # 2.3 Send Application Data
        print(f"[>] CLIENT_MTLS_GW: Sending to service via Gateway: {message_to_service}")
        gateway_ssl_socket.sendall(message_to_service.encode())

        service_response = gateway_ssl_socket.recv(BUFFER_SIZE)
        if not service_response:
            print("[<] CLIENT_MTLS_GW: No response from service (connection closed by gateway/server?).")
        else:
            print(f"[<] CLIENT_MTLS_GW: Received from service: {service_response.decode()}")
        
        print("[PHASE 2] Connection to Gateway COMPLETE.")

    except ConnectionRefusedError as e:
        print(f"[!] CLIENT_ERROR: Connection Refused: {e}. Check if target is listening and SPA/firewall allowed access.")
    except socket.timeout as e:
        print(f"[!] CLIENT_ERROR: Socket Timeout: {e}. Target might not be responding or SPA failed.")
    except ssl.SSLCertVerificationError as e:
        print(f"[!] CLIENT_ERROR: SSL Certificate Verification Error: {e}")
        print(f"    Ensure correct CA is used and server_hostname matches cert's CN/SAN.")
    except ssl.SSLError as e:
        print(f"[!] CLIENT_ERROR: SSL Error: {e}")
    except Exception as e:
        print(f"[!] CLIENT_ERROR: An unexpected error occurred: {e} (Type: {type(e).__name__})")
    finally:
        if onboard_ssl_socket:
            onboard_ssl_socket.close()
        if gateway_ssl_socket:
            gateway_ssl_socket.close()
        cleanup_temp_pem_files()
        print("[-] CLIENT: Session finished and ephemeral files cleaned up.")


if __name__ == "__main__":
    # Ensure client's certs directory and necessary onboarding certs exist
    if not os.path.isdir(CERTS_CLIENT_DIR) or \
       not os.path.isfile(CA_CERT_PATH_CLIENT) or \
       not os.path.isfile(CLIENT_ONBOARD_CERT_PATH) or \
       not os.path.isfile(CLIENT_ONBOARD_KEY_PATH):
        print(f"[CLIENT_CRITICAL] Essential onboarding certificate files not found in {CERTS_CLIENT_DIR}. Please generate them. Exiting.")
        exit(1)

    # Client wants to access the service at 10.9.65.55:9999
    # The controller will tell it which gateway to use.
    # The SPA knock to the gateway will indicate port 9999.
    service_message = f"Hello secure service from SDP client via Controller and Gateway!"
    run_sdp_client(service_message, 
                   requested_target_host="10.9.65.55", # Hint for controller policy
                   requested_target_port=9999)         # Hint for controller policy


