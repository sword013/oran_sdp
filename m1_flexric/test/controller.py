# controller.py
import socket
import ssl
import threading
import time
import hmac
import hashlib
import struct
import subprocess
import os
import json 
from datetime import datetime, timedelta, timezone
import ipaddress # For IP address validation and SANs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# --- Configuration ---
CONTROLLER_IP_FOR_CLIENT_MTLS = '10.9.70.137' 
CONTROLLER_PORT_FOR_CLIENT_MTLS = 9999

CONTROLLER_IP_FOR_GATEWAY_MTLS = '10.9.70.137' 
CONTROLLER_PORT_FOR_GATEWAY_MTLS = 9998 

CONTROLLER_IP_FOR_SPA = '10.9.70.137'      
CONTROLLER_PORT_FOR_SPA = 62201 # Clients and Gateways knock this for onboarding

SCRIPT_DIR_CTRL = os.path.dirname(os.path.abspath(__file__))
CERTS_CTRL_DIR = os.path.join(SCRIPT_DIR_CTRL, "./") 

CA_KEY_PATH = os.path.join(CERTS_CTRL_DIR, 'controller_ca.key')
CA_CERT_PATH = os.path.join(CERTS_CTRL_DIR, 'controller_ca.crt')
CONTROLLER_MTLS_CERT_PATH = os.path.join(CERTS_CTRL_DIR, 'controller_mtls.crt') # For both client and GW facing mTLS
CONTROLLER_MTLS_KEY_PATH = os.path.join(CERTS_CTRL_DIR, 'controller_mtls.key')

# This PSK is used by clients AND gateways for their initial SPA knock to the controller
ONBOARD_SPA_PSK_HMAC = b"controller_onboard_spa_hmac_key_xyz!" 
SPA_PACKET_LIFETIME_SEC = 30 
IPTABLES_RULE_TIMEOUT_SEC_CTRL = 10 # For rules allowing connection to controller's mTLS ports

EPHEMERAL_CERT_VALIDITY_DAYS = 1
EPHEMERAL_KEY_SIZE = 2048

# --- Global State ---
# {ip_addr: (spa_knock_timestamp, rule_comment_str) }
# Separate caches if SPA logic or target ports differ for clients vs gateways
authorized_spa_for_client_mtls = {} 
authorized_spa_for_gateway_mtls = {} 
spa_ctrl_lock = threading.Lock()

# { gateway_ip: {'ssl_socket': ssl_socket, 'details':{...}} }
connected_gateways = {} 
gateway_conn_lock = threading.Lock()

# { client_ip: { ... session details ... }}
active_client_sessions = {} 
sessions_lock = threading.Lock()

g_ca_private_key = None
g_ca_public_cert = None
g_shutdown_flag_controller = threading.Event()

def load_ca_credentials():
    global g_ca_private_key, g_ca_public_cert
    try:
        with open(CA_KEY_PATH, "rb") as f:
            g_ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_PATH, "rb") as f:
            g_ca_public_cert = x509.load_pem_x509_certificate(f.read())
        print("[+] Controller: Master CA credentials loaded successfully.")
    except Exception as e:
        print(f"[CONTROLLER_CRITICAL] Failed to load CA key/cert from {CA_KEY_PATH} or {CA_CERT_PATH}: {e}. Exiting.")
        exit(1)

# --- Certificate Generation Functions ---
def generate_ephemeral_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=EPHEMERAL_KEY_SIZE,
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key, priv_pem

def generate_ephemeral_cert(private_key_obj, common_name_str, issuer_cert_obj, issuer_key_obj):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name_str)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert_obj.subject) 
        .public_key(private_key_obj.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=EPHEMERAL_CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False
            ), critical=True)
    )
    
    san_entries = []
    try:
        ip_addr_obj = ipaddress.ip_address(common_name_str)
        san_entries.append(x509.IPAddress(ip_addr_obj))
    except ValueError: 
        san_entries.append(x509.DNSName(common_name_str))
    
    if san_entries: # Only add SAN if we have entries
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    certificate = builder.sign(issuer_key_obj, hashes.SHA256())
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    return certificate, cert_pem

def generate_random_key(length=32):
    return os.urandom(length)

# --- iptables Helper Functions ---
def run_iptables_command_ctrl(command_args, check_stderr_for_no_match=False):
    try:
        cmd = ["sudo", "iptables"] + command_args 
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        if check_stderr_for_no_match and \
           ("No chain/target/match by that name" in e.stderr or \
            "doesn't match specified rule" in e.stderr or \
            "Bad rule (does a matching rule exist in that chain?)" in e.stderr):
            return False 
        print(f"[!] CTRL IPTables Error: Failed: {' '.join(cmd)} Stderr: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
        print("[!] CTRL IPTables Error: 'iptables' not found.")
        return False

def add_spa_iptables_rule_ctrl(client_ip, target_port, rule_prefix="ctrl_spa_allow_"):
    rule_comment = f"{rule_prefix}{client_ip}_{target_port}_{int(time.time())}"
    args = ["-I", "INPUT", "1", "-s", client_ip, "-p", "tcp", "--dport", str(target_port),
            "-j", "ACCEPT", "-m", "comment", "--comment", rule_comment]
    print(f"[*] CTRL IPTables: Adding rule for {client_ip} to TCP {target_port} (Comment: {rule_comment})")
    if run_iptables_command_ctrl(args):
        return rule_comment
    return None

def remove_spa_iptables_rule_ctrl_by_comment(rule_comment, client_ip, target_port):
    args = ["-D", "INPUT", "-s", client_ip, "-p", "tcp", "--dport", str(target_port),
            "-j", "ACCEPT", "-m", "comment", "--comment", rule_comment]
    if run_iptables_command_ctrl(args, check_stderr_for_no_match=True):
        return True 
    return False

# --- SPA Processing for Client/Gateway Onboarding ---
def handle_onboard_spa_packet(data, sender_addr):
    if g_shutdown_flag_controller.is_set(): return
    
    sender_ip = sender_addr[0]
    expected_len = 8 + 4 + 32 
    if len(data) != expected_len:
        return

    hmac_received = data[-32:]
    payload = data[:-32] 
    expected_hmac = hmac.new(ONBOARD_SPA_PSK_HMAC, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_hmac, hmac_received):
        print(f"[!] CTRL_SPA: Invalid ONBOARD HMAC from {sender_ip}. Ignoring.")
        return

    try:
        timestamp, nonce = struct.unpack('!dI', payload)
    except struct.error:
        print(f"[!] CTRL_SPA: Malformed ONBOARD SPA payload from {sender_ip}. Ignoring.")
        return

    current_time = time.time()
    if not (current_time - SPA_PACKET_LIFETIME_SEC < timestamp <= current_time + 5):
        print(f"[!] CTRL_SPA: Stale/future ONBOARD timestamp from {sender_ip}. Ignoring.")
        return
    
    print(f"[+] CTRL_SPA: VALID ONBOARD knock from {sender_ip}.")
    
    # Determine which port this SPA knock is intended for based on convention or future SPA data
    # For now: ALL knocks to CONTROLLER_PORT_FOR_SPA are for client onboarding to CONTROLLER_PORT_FOR_CLIENT_MTLS
    # Gateways connect to CONTROLLER_PORT_FOR_GATEWAY_MTLS WITHOUT SPA.
    
    target_port_for_rule = CONTROLLER_PORT_FOR_CLIENT_MTLS
    rule_cache = authorized_spa_for_client_mtls
    rule_prefix_for_comment = "ctrl_client_spa_"

    with spa_ctrl_lock:
        existing_knock_time, existing_rule_comment = rule_cache.get(sender_ip, (None, None))
        if existing_rule_comment and (time.time() - (existing_knock_time or 0) < IPTABLES_RULE_TIMEOUT_SEC_CTRL):
            rule_cache[sender_ip] = (time.time(), existing_rule_comment) 
            return 
            
        rule_comment_str = add_spa_iptables_rule_ctrl(sender_ip, target_port_for_rule, rule_prefix_for_comment)
        if rule_comment_str:
            rule_cache[sender_ip] = (time.time(), rule_comment_str)
            print(f"[+] CTRL_SPA: IPTables rule added for {sender_ip} to port {target_port_for_rule}. Authorized for {IPTABLES_RULE_TIMEOUT_SEC_CTRL}s.")
        else:
            print(f"[!] CTRL_SPA: FAILED to add IPTables rule for {sender_ip} for onboarding.")

def onboard_spa_listener_thread_func():
    spa_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        spa_socket.bind((CONTROLLER_IP_FOR_SPA, CONTROLLER_PORT_FOR_SPA))
        print(f"[*] Controller ONBOARD SPA Listener started on UDP {CONTROLLER_IP_FOR_SPA}:{CONTROLLER_PORT_FOR_SPA}")
        while not g_shutdown_flag_controller.is_set(): 
            spa_socket.settimeout(1.0)
            try:
                data, sender_addr = spa_socket.recvfrom(128) 
                spa_socket.settimeout(None)
                threading.Thread(target=handle_onboard_spa_packet, args=(data, sender_addr), daemon=True).start()
            except socket.timeout:
                continue
            except OSError as e_recv:
                 if g_shutdown_flag_controller.is_set(): break
                 print(f"[!] Controller ONBOARD SPA Listener: recvfrom error {e_recv}"); break
    except OSError as e_bind:
        print(f"[!!!] Controller ONBOARD SPA Listener: Bind error {e_bind}.")
    finally:
        if spa_socket:
            spa_socket.close()
        print("[*] Controller ONBOARD SPA Listener stopped.")

def cleanup_expired_controller_spa_rules():
    while not g_shutdown_flag_controller.is_set(): 
        time.sleep(IPTABLES_RULE_TIMEOUT_SEC_CTRL / 2 if IPTABLES_RULE_TIMEOUT_SEC_CTRL > 2 else 1)
        if g_shutdown_flag_controller.is_set(): break
        
        caches_to_clean = [
            (authorized_spa_for_client_mtls, CONTROLLER_PORT_FOR_CLIENT_MTLS),
            # (authorized_spa_for_gateway_mtls, CONTROLLER_PORT_FOR_GATEWAY_MTLS) # If gateways also use SPA
        ]

        with spa_ctrl_lock:
            current_time = time.time()
            for rule_cache, target_port in caches_to_clean:
                for ip_addr in list(rule_cache.keys()):
                    if g_shutdown_flag_controller.is_set(): return # Exit early if shutdown
                    knock_time, rule_comment = rule_cache.get(ip_addr, (None, None))
                    if knock_time is None: continue 
                    
                    if current_time - knock_time > IPTABLES_RULE_TIMEOUT_SEC_CTRL:
                        rule_type = "client" if target_port == CONTROLLER_PORT_FOR_CLIENT_MTLS else "gateway"
                        print(f"[-] CTRL_SPA Cleanup: Onboard SPA for {rule_type} {ip_addr} (Rule: {rule_comment}) timed out.")
                        if remove_spa_iptables_rule_ctrl_by_comment(rule_comment, ip_addr, target_port):
                            print(f"[+] CTRL_SPA Cleanup: Removed IPTables rule {rule_comment}")
                        else:
                            print(f"[-] CTRL_SPA Cleanup: Failed to remove or rule {rule_comment} not found for {ip_addr}")

                        if ip_addr in rule_cache: 
                            del rule_cache[ip_addr]
    print("[*] Controller SPA Rule Cleanup thread stopped.")

# --- mTLS Handling for Client Onboarding & Requests ---
def handle_client_onboard_connection(client_ssl_socket, client_addr):
    client_ip = client_addr[0]
    client_cn_onboard = "N/A_ONBOARD_ERROR"
    try:
        peer_cert_onboard = client_ssl_socket.getpeercert()
        if peer_cert_onboard:
            subject = dict(x[0] for x in peer_cert_onboard['subject'])
            client_cn_onboard = subject.get('commonName', 'N/A_ONBOARD_NO_CN')
            print(f"[+] CTRL_MTLS_CLIENT: Client '{client_cn_onboard}' ({client_ip}) authenticated with onboarding cert.")
        else:
            print(f"[!] CTRL_MTLS_CLIENT: No onboarding cert from {client_ip}. Closing.")
            return

        request_data_raw = client_ssl_socket.recv(1024)
        if not request_data_raw:
            print(f"[-] CTRL_MTLS_CLIENT: Client {client_ip} disconnected before sending request.")
            return
        
        try:
            client_request = json.loads(request_data_raw.decode())
        except json.JSONDecodeError:
            print(f"[!] CTRL_MTLS_CLIENT: Malformed JSON request from {client_ip}. Closing.")
            client_ssl_socket.sendall(json.dumps({"status": "error", "message": "Bad request format"}).encode())
            return

        print(f"[+] CTRL_MTLS_CLIENT: Received request from {client_ip} ({client_cn_onboard}): {client_request}")
        
        if client_request.get("request_type") != "GET_ACCESS":
            print(f"[!] CTRL_MTLS_CLIENT: Unknown request type from {client_ip}. Closing.")
            client_ssl_socket.sendall(json.dumps({"status": "error", "message": "Unknown request type"}).encode())
            return
        
        chosen_gateway_ip = None
        gateway_details_for_client = None

        with gateway_conn_lock:
            if not connected_gateways:
                print(f"[!] CTRL_MTLS_CLIENT: No gateways connected. Denying access for {client_ip}.")
                client_ssl_socket.sendall(json.dumps({"status": "error", "message": "No available gateways"}).encode())
                return
            for gw_ip, gw_data in connected_gateways.items():
                if gw_data.get('ssl_socket'): 
                    chosen_gateway_ip = gw_ip
                    gateway_details_for_client = gw_data.get('details', {})
                    break
        
        if not chosen_gateway_ip:
            print(f"[!] CTRL_MTLS_CLIENT: No gateways seem active. Denying access for {client_ip}.")
            client_ssl_socket.sendall(json.dumps({"status": "error", "message": "No active gateways"}).encode())
            return

        target_backend_host_via_gw = client_request.get("desired_backend_host", "10.9.65.55") 
        target_backend_port_via_gw = client_request.get("desired_backend_port", 9999)      

        print(f"[+] CTRL_MTLS_CLIENT: Policy: Client {client_ip} to use Gateway {chosen_gateway_ip} for service {target_backend_host_via_gw}:{target_backend_port_via_gw}")

        eph_client_priv_key, eph_client_priv_pem = generate_ephemeral_key()
        client_eph_cn_str = f"eph_client_{client_ip.replace('.', '-')}_{int(time.time())}"
        _, eph_client_cert_pem = generate_ephemeral_cert(eph_client_priv_key, client_eph_cn_str, g_ca_public_cert, g_ca_private_key)

        eph_gw_priv_key, eph_gw_priv_pem = generate_ephemeral_key()
        gateway_eph_cn_str = chosen_gateway_ip 
        _, eph_gw_cert_pem = generate_ephemeral_cert(eph_gw_priv_key, gateway_eph_cn_str, g_ca_public_cert, g_ca_private_key)
        
        eph_spa_hmac_key = generate_random_key(32) 

        print(f"[+] CTRL_MTLS_CLIENT: Generated ephemeral credentials for {client_ip} session to GW {chosen_gateway_ip}. GW Cert CN will be: {gateway_eph_cn_str}")

        client_response = {
            "status": "success", 
            "gateway_ip": chosen_gateway_ip,
            "gateway_mtls_port": gateway_details_for_client.get("listening_port_mtls", 8888),
            "gateway_spa_port": gateway_details_for_client.get("listening_port_spa", 62201),
            "eph_client_cert_pem": eph_client_cert_pem.decode(), 
            "eph_client_key_pem": eph_client_priv_pem.decode(),
            "eph_ca_cert_pem": g_ca_public_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "eph_spa_hmac_key_hex": eph_spa_hmac_key.hex(),
            "message": "Access granted. Use these ephemeral credentials for the gateway."
        }
        client_ssl_socket.sendall(json.dumps(client_response).encode())
        print(f"[+] CTRL_MTLS_CLIENT: Sent ephemeral credentials to client {client_ip}.")

        gateway_message = {
            "command": "SETUP_CLIENT_SESSION", 
            "client_ip": client_ip,
            "client_eph_cert_pem": eph_client_cert_pem.decode(), 
            "gateway_eph_cert_pem": eph_gw_cert_pem.decode(), 
            "gateway_eph_key_pem": eph_gw_priv_pem.decode(),
            "eph_spa_hmac_key_hex": eph_spa_hmac_key.hex(),
            "access_policy": {
                "allow_backend_host": target_backend_host_via_gw, 
                "allow_backend_port": target_backend_port_via_gw
            },
            "session_timeout": IPTABLES_RULE_TIMEOUT_SEC_CTRL + 120 
        }
        
        gateway_socket_to_use = None
        with gateway_conn_lock: 
            gw_data = connected_gateways.get(chosen_gateway_ip)
            if gw_data and gw_data.get('ssl_socket'):
                gateway_socket_to_use = gw_data['ssl_socket']
            else:
                print(f"[!] CTRL_MTLS_CLIENT: Gateway {chosen_gateway_ip} disconnected before session setup could be sent for client {client_ip}.")
                return 
        try:
            gateway_socket_to_use.sendall(json.dumps(gateway_message).encode() + b"\n<END_MSG>\n")
            print(f"[+] CTRL_MTLS_CLIENT: Sent session setup to Gateway {chosen_gateway_ip} for client {client_ip}.")
        except Exception as e_gw_send:
            print(f"[!] CTRL_MTLS_CLIENT: Error sending session setup to Gateway {chosen_gateway_ip} for client {client_ip}: {e_gw_send}")

        with sessions_lock:
            active_client_sessions[client_ip] = {
                "gateway_ip": chosen_gateway_ip, 
                "client_eph_cert_cn": client_eph_cn_str, 
                "provision_time": time.time()
            }
    except ssl.SSLError as e_ssl:
        print(f"[!] CTRL_MTLS_CLIENT: SSL Error with {client_ip} ({client_cn_onboard}): {e_ssl}")
    except ConnectionResetError:
        print(f"[-] CTRL_MTLS_CLIENT: Connection reset by {client_ip} ({client_cn_onboard}).")
    except Exception as e:
        print(f"[!] CTRL_MTLS_CLIENT: Error handling client {client_ip} ({client_cn_onboard}): {type(e).__name__} - {e}")
    finally:
        if client_ssl_socket:
            try:
                client_ssl_socket.close()
            except:
                pass
        print(f"[-] CTRL_MTLS_CLIENT: Connection with {client_ip} ({client_cn_onboard}) closed.")
        # Clean up SPA rule for this client immediately after mTLS session ends
        with spa_ctrl_lock:
            if client_ip in authorized_spa_for_client_mtls:
                _, rule_comment_to_remove = authorized_spa_for_client_mtls[client_ip]
                print(f"[*] CTRL_SPA Cleanup: Removing rule for client {client_ip} (Rule: {rule_comment_to_remove}) post-mTLS.")
                if remove_spa_iptables_rule_ctrl_by_comment(rule_comment_to_remove, client_ip, CONTROLLER_PORT_FOR_CLIENT_MTLS):
                     print(f"[+] CTRL_SPA Cleanup: Removed IPTables rule {rule_comment_to_remove}")
                else:
                     print(f"[-] CTRL_SPA Cleanup: Failed or rule {rule_comment_to_remove} not found for {client_ip}")

                if client_ip in authorized_spa_for_client_mtls: # Re-check before deleting
                    del authorized_spa_for_client_mtls[client_ip]

def client_onboard_mtls_listener_thread_func():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=CONTROLLER_MTLS_CERT_PATH, keyfile=CONTROLLER_MTLS_KEY_PATH)
        context.load_verify_locations(cafile=CA_CERT_PATH)
        context.verify_mode = ssl.CERT_REQUIRED 
    except Exception as e:
        print(f"[CONTROLLER_CRITICAL] Failed to load certs/keys for Client mTLS listener: {e}. Thread exiting.")
        return

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_socket.bind((CONTROLLER_IP_FOR_CLIENT_MTLS, CONTROLLER_PORT_FOR_CLIENT_MTLS))
        listen_socket.listen(5)
        print(f"[*] Controller mTLS Listener for CLIENTS started on TCP {CONTROLLER_IP_FOR_CLIENT_MTLS}:{CONTROLLER_PORT_FOR_CLIENT_MTLS}")

        while not g_shutdown_flag_controller.is_set(): 
            listen_socket.settimeout(1.0) # To allow checking shutdown flag
            try:
                client_conn, client_addr = listen_socket.accept()
                listen_socket.settimeout(None) # Reset timeout for the connection
            except socket.timeout:
                continue # Loop to check shutdown flag
            except OSError as e_accept_main: # Catch errors if socket is closed by shutdown
                if g_shutdown_flag_controller.is_set():
                    break
                print(f"[!] Controller Client mTLS Listener: accept error {e_accept_main}")
                break # Exit on other errors
            
            client_ip_for_log = client_addr[0]
            proceed_with_mtls = False
            with spa_ctrl_lock:
                if client_ip_for_log in authorized_spa_for_client_mtls:
                    proceed_with_mtls = True
                else:
                    print(f"[!] CTRL_MTLS_CLIENT: NO VALID SPA knock found for {client_ip_for_log}. Closing connection.")
                    client_conn.close()
            
            if proceed_with_mtls:
                try:
                    client_ssl_socket = context.wrap_socket(client_conn, server_side=True)
                    thread = threading.Thread(target=handle_client_onboard_connection, args=(client_ssl_socket, client_addr), daemon=True)
                    thread.start()
                except ssl.SSLError as e_wrap:
                    print(f"[!] CTRL_MTLS_CLIENT: SSL wrap error for {client_ip_for_log}: {e_wrap}")
                    client_conn.close()
                except Exception as e_accept_thr:
                    print(f"[!] CTRL_MTLS_CLIENT: Error starting thread for client {client_ip_for_log}: {e_accept_thr}")
                    client_conn.close()
    except OSError as e_bind:
        print(f"[!!!] Controller mTLS Listener for CLIENTS: Bind error {e_bind}.")
    finally:
        if listen_socket:
            listen_socket.close()
        print("[*] Controller mTLS Listener for CLIENTS stopped.")

# --- mTLS Handling for Gateway Persistent Connections ---
def handle_gateway_persistent_connection(gateway_ssl_socket, gateway_addr):
    gateway_ip = gateway_addr[0]
    gateway_cn_onboard = "N/A_GW_ONBOARD_ERROR"
    gateway_details_from_register = {}
    registered_successfully = False
    try:
        peer_cert_gw_onboard = gateway_ssl_socket.getpeercert()
        if peer_cert_gw_onboard:
            subject = dict(x[0] for x in peer_cert_gw_onboard['subject'])
            gateway_cn_onboard = subject.get('commonName', 'N/A_GW_ONBOARD_NO_CN')
            print(f"[+] CTRL_MTLS_GW: Gateway '{gateway_cn_onboard}' ({gateway_ip}) authenticated with onboarding cert.")
        else:
            print(f"[!] CTRL_MTLS_GW: No onboarding cert from gateway {gateway_ip}. Closing.")
            return

        buffer = ""
        gateway_ssl_socket.settimeout(10.0) 
        initial_msg_raw = gateway_ssl_socket.recv(1024) 
        gateway_ssl_socket.settimeout(None)

        if not initial_msg_raw:
            print(f"[-] CTRL_MTLS_GW: Gateway {gateway_ip} disconnected before sending REGISTER.")
            return
        
        buffer += initial_msg_raw.decode(errors='ignore')
        if "<END_MSG>\n" in buffer:
            msg_json = buffer[:buffer.find("<END_MSG>\n")]
            try:
                reg_msg = json.loads(msg_json)
                if reg_msg.get("type") == "GATEWAY_REGISTER":
                    gateway_details_from_register = {
                        "reported_ip": reg_msg.get("gateway_ip"),
                        "listening_port_mtls": reg_msg.get("listening_port_mtls"),
                        "listening_port_spa": reg_msg.get("listening_port_spa"),
                        "cn_onboard": gateway_cn_onboard
                    }
                    if gateway_details_from_register["reported_ip"] != gateway_ip:
                        print(f"[!] CTRL_MTLS_GW: Warning - Gateway {gateway_cn_onboard} connected from {gateway_ip} but reported IP {gateway_details_from_register['reported_ip']}")
                    
                    thread_obj = threading.current_thread() 
                    with gateway_conn_lock:
                        connected_gateways[gateway_ip] = { 
                            'ssl_socket': gateway_ssl_socket, 
                            'persistent_thread': thread_obj, 
                            'details': gateway_details_from_register
                        }
                    registered_successfully = True
                    print(f"[+] CTRL_MTLS_GW: Gateway {gateway_ip} (CN: {gateway_cn_onboard}) registered successfully with details: {gateway_details_from_register}.")
                else:
                    print(f"[!] CTRL_MTLS_GW: Gateway {gateway_ip} sent unknown initial message type: {reg_msg.get('type')}")
                    return
            except json.JSONDecodeError:
                print(f"[!] CTRL_MTLS_GW: Gateway {gateway_ip} sent malformed JSON for registration.")
                return
        else:
            print(f"[!] CTRL_MTLS_GW: Gateway {gateway_ip} did not send complete REGISTER message.")
            return

        while registered_successfully and not g_shutdown_flag_controller.is_set():
            try:
                gateway_ssl_socket.settimeout(15.0) 
                data = gateway_ssl_socket.recv(1024) 
                gateway_ssl_socket.settimeout(None)
                if not data:
                    print(f"[-] CTRL_MTLS_GW: Gateway {gateway_ip} disconnected (recv no data).")
                    break
            except socket.timeout:
                try: 
                    gateway_ssl_socket.sendall(json.dumps({"command":"PING"}).encode() + b"\n<END_MSG>\n")
                except Exception as e_ping:
                    print(f"[!] CTRL_MTLS_GW: Error sending PING to gateway {gateway_ip}: {e_ping}")
                    break 
            except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
                print(f"[-] CTRL_MTLS_GW: Gateway {gateway_ip} connection closed/reset.")
                break
            except Exception as e_gw_loop:
                print(f"[!] CTRL_MTLS_GW: Error in loop with gateway {gateway_ip}: {e_gw_loop}")
                break
        
    except ssl.SSLError as e_ssl_gw:
        print(f"[!] CTRL_MTLS_GW: SSL Error with gateway {gateway_ip} (CN: {gateway_cn_onboard}): {e_ssl_gw}")
    except ConnectionResetError: 
        print(f"[-] CTRL_MTLS_GW: Connection reset by gateway {gateway_ip} (CN: {gateway_cn_onboard}) during initial phase.")
    except Exception as e_gw:
        print(f"[!] CTRL_MTLS_GW: Error handling gateway {gateway_ip} (CN: {gateway_cn_onboard}): {type(e_gw).__name__} - {e_gw}")
    finally:
        if gateway_ssl_socket:
            try:
                gateway_ssl_socket.close()
            except:
                pass
        with gateway_conn_lock:
            if gateway_ip in connected_gateways:
                del connected_gateways[gateway_ip]
        print(f"[-] CTRL_MTLS_GW: Persistent connection with Gateway {gateway_ip} (CN: {gateway_cn_onboard}) closed and unregistered.")

def gateway_mtls_listener_thread_func():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=CONTROLLER_MTLS_CERT_PATH, keyfile=CONTROLLER_MTLS_KEY_PATH)
        context.load_verify_locations(cafile=CA_CERT_PATH)
        context.verify_mode = ssl.CERT_REQUIRED 
    except Exception as e:
        print(f"[CONTROLLER_CRITICAL] Failed to load certs/keys for Gateway mTLS listener: {e}. Thread exiting.")
        return

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_socket.bind((CONTROLLER_IP_FOR_GATEWAY_MTLS, CONTROLLER_PORT_FOR_GATEWAY_MTLS))
        listen_socket.listen(5)
        print(f"[*] Controller mTLS Listener for GATEWAYS started on TCP {CONTROLLER_IP_FOR_GATEWAY_MTLS}:{CONTROLLER_PORT_FOR_GATEWAY_MTLS}")

        while not g_shutdown_flag_controller.is_set(): 
            listen_socket.settimeout(1.0)
            try:
                gateway_conn, gateway_addr = listen_socket.accept()
                listen_socket.settimeout(None)
            except socket.timeout:
                continue
            except OSError as e_accept_main_gw:
                if g_shutdown_flag_controller.is_set():
                    break
                print(f"[!] Controller Gateway mTLS Listener: accept error {e_accept_main_gw}")
                break

            gateway_ip_for_log = gateway_addr[0]
            print(f"[+] CTRL_MTLS_GW: Accepted connection from Gateway candidate {gateway_ip_for_log}")
            try:
                gateway_ssl_socket = context.wrap_socket(gateway_conn, server_side=True)
                thread = threading.Thread(target=handle_gateway_persistent_connection, args=(gateway_ssl_socket, gateway_addr), daemon=True)
                thread.start()
            except ssl.SSLError as e_wrap_gw:
                print(f"[!] CTRL_MTLS_GW: SSL wrap error for gateway {gateway_ip_for_log}: {e_wrap_gw}")
                gateway_conn.close()
            except Exception as e_accept_gw_thr:
                print(f"[!] CTRL_MTLS_GW: Error starting thread for gateway {gateway_ip_for_log}: {e_accept_gw_thr}")
                gateway_conn.close()
    except OSError as e_bind:
        print(f"[!!!] Controller mTLS Listener for GATEWAYS: Bind error {e_bind}.")
    finally:
        if listen_socket:
            listen_socket.close()
        print("[*] Controller mTLS Listener for GATEWAYS stopped.")

# --- Main ---
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] Controller script must be run as root to manage iptables. Exiting.")
        exit(1)

    if not os.path.isdir(CERTS_CTRL_DIR) or \
       not os.path.isfile(CA_KEY_PATH) or \
       not os.path.isfile(CA_CERT_PATH) or \
       not os.path.isfile(CONTROLLER_MTLS_CERT_PATH) or \
       not os.path.isfile(CONTROLLER_MTLS_KEY_PATH):
        print(f"[CONTROLLER_CRITICAL] Essential certificate files not found in {CERTS_CTRL_DIR}. Exiting.")
        exit(1)
    
    load_ca_credentials() 
    if not g_ca_private_key or not g_ca_public_cert:
        print("[CONTROLLER_CRITICAL] CA credentials not available after load attempt. This should not happen. Exiting.")
        exit(1)

    print("[*] Starting SDP Controller...")

    onboard_spa_thread = threading.Thread(target=onboard_spa_listener_thread_func, daemon=True, name="OnboardSPAListener")
    onboard_spa_cleanup_thread = threading.Thread(target=cleanup_expired_controller_spa_rules, daemon=True, name="OnboardSPACleanup")
    client_mtls_thread = threading.Thread(target=client_onboard_mtls_listener_thread_func, daemon=True, name="ClientOnboardMTLSListener")
    gateway_mtls_thread = threading.Thread(target=gateway_mtls_listener_thread_func, daemon=True, name="GatewayMTLSListener")
    
    threads_to_start = [onboard_spa_thread, onboard_spa_cleanup_thread, client_mtls_thread, gateway_mtls_thread]
    for t in threads_to_start:
        t.start()
    
    print("[+] Controller All Listener Threads Started.")
    try:
        while not g_shutdown_flag_controller.is_set():
            time.sleep(1) 
            any_thread_dead = False
            for t_obj in threads_to_start:
                if not t_obj.is_alive():
                    print(f"[!!!] CONTROLLER: Thread '{t_obj.name}' has died! Initiating shutdown.")
                    any_thread_dead = True
                    break
            if any_thread_dead:
                g_shutdown_flag_controller.set() 
                break
            
    except KeyboardInterrupt:
        print("\n[*] Controller: KeyboardInterrupt received, initiating shutdown...")
        g_shutdown_flag_controller.set()
    finally:
        print("[*] Controller: Final cleanup initiated...")
        g_shutdown_flag_controller.set() # Ensure flag is set for all threads
        
        # Wait briefly for threads to notice the shutdown flag
        time.sleep(0.5) 

        # Cleanup any iptables rules added by controller on exit
        with spa_ctrl_lock:
            # Clean rules for clients
            for client_ip, (knock_time, rule_comment) in list(authorized_spa_for_client_mtls.items()):
                print(f"[*] Controller Exit Cleanup: Removing client SPA rule: {rule_comment}")
                remove_spa_iptables_rule_ctrl_by_comment(rule_comment, client_ip, CONTROLLER_PORT_FOR_CLIENT_MTLS)
            authorized_spa_for_client_mtls.clear()
            # Clean rules for gateways (if this cache was used)
            for gw_ip, (knock_time, rule_comment) in list(authorized_spa_for_gateway_mtls.items()):
                print(f"[*] Controller Exit Cleanup: Removing gateway SPA rule: {rule_comment}")
                remove_spa_iptables_rule_ctrl_by_comment(rule_comment, gw_ip, CONTROLLER_PORT_FOR_GATEWAY_MTLS)
            authorized_spa_for_gateway_mtls.clear()
        
        # Close gateway sockets
        with gateway_conn_lock:
            for gw_ip, gw_data in list(connected_gateways.items()):
                if gw_data and gw_data.get('ssl_socket'):
                    try:
                        gw_data['ssl_socket'].close()
                    except:
                        pass
            connected_gateways.clear()

        print("[*] Controller shutdown complete.")


