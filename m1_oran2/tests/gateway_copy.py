# gateway.py
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
import random 

# --- Configuration ---
GATEWAY_IP_FOR_CLIENT_MTLS = '10.9.70.42' 
GATEWAY_PORT_FOR_CLIENT_MTLS = 8888
GATEWAY_IP_FOR_SPA = '10.9.70.42' 
GATEWAY_PORT_FOR_SPA = 62201

CONTROLLER_IP = '10.9.70.137'
CONTROLLER_PORT_FOR_GATEWAY_MTLS = 9998 
CONTROLLER_SERVER_HOSTNAME_FOR_GW = 'controller.sdp.example' 
CONTROLLER_SPA_PORT_FOR_GW_ONBOARD = 62201 

SCRIPT_DIR_GW = os.path.dirname(os.path.abspath(__file__))
CERTS_GW_DIR = os.path.join(SCRIPT_DIR_GW, "./") 

CA_CERT_PATH_GW = os.path.join(CERTS_GW_DIR, 'controller_ca.crt') 
GATEWAY_ONBOARD_CERT_PATH = os.path.join(CERTS_GW_DIR, 'gateway_onboard.crt')
GATEWAY_ONBOARD_KEY_PATH = os.path.join(CERTS_GW_DIR, 'gateway_onboard.key')

GATEWAY_ONBOARD_SPA_PSK_HMAC_TO_CONTROLLER = b"controller_onboard_spa_hmac_key_xyz!" 

EPH_CERTS_TEMP_DIR_GW = os.path.join(SCRIPT_DIR_GW, "_gw_eph_session_certs/")
os.makedirs(EPH_CERTS_TEMP_DIR_GW, exist_ok=True)

BUFFER_SIZE = 4096
IPTABLES_RULE_TIMEOUT_SEC_GW = 60 
SPA_PACKET_LIFETIME_SEC = 30 

# --- Global State ---
active_sessions_on_gateway = {}
sessions_gw_lock = threading.Lock()
g_controller_ssl_socket = None
g_controller_conn_active = threading.Event()
g_shutdown_flag_gateway = threading.Event()

# --- Helper Function ---
def save_temp_pem_file(pem_data_str, file_path):
    try:
        dir_name = os.path.dirname(file_path)
        if dir_name and not os.path.exists(dir_name): 
            os.makedirs(dir_name, exist_ok=True)
        with open(file_path, "w") as f:
            f.write(pem_data_str)
        os.chmod(file_path, 0o600) 
        return True
    except Exception as e:
        print(f"[GW_ERROR] Failed to save PEM to {file_path}: {e}")
        return False

def create_gateway_onboard_spa_packet_to_controller():
    timestamp = time.time()
    nonce = random.randint(0, 0xFFFFFFFF) 
    payload = struct.pack('!dI', timestamp, nonce)
    calculated_hmac = hmac.new(GATEWAY_ONBOARD_SPA_PSK_HMAC_TO_CONTROLLER, payload, hashlib.sha256).digest()
    return payload + calculated_hmac

# --- iptables Helper Functions ---
def run_iptables_command_gw(command_args, check_stderr_for_no_match=False):
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
        print(f"[!] GW IPTables Error: Failed: {' '.join(cmd)} Stderr: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
        print("[!] GW IPTables Error: 'iptables' not found.")
        return False

def add_spa_iptables_rule_gw(client_ip, target_port):
    rule_comment = f"gw_spa_allow_{client_ip}_{target_port}_{int(time.time())}"
    args = ["-I", "INPUT", "1", "-s", client_ip, "-p", "tcp", "--dport", str(target_port), 
            "-j", "ACCEPT", "-m", "comment", "--comment", rule_comment]
    print(f"[*] GW IPTables: Adding rule for {client_ip} to TCP {target_port} (Comment: {rule_comment})")
    if run_iptables_command_gw(args):
        return rule_comment
    return None

def remove_spa_iptables_rule_gw_by_comment(rule_comment, client_ip, target_port):
    args = ["-D", "INPUT", "-s", client_ip, "-p", "tcp", "--dport", str(target_port), 
            "-j", "ACCEPT", "-m", "comment", "--comment", rule_comment]
    # print(f"[*] GW IPTables: Removing rule with comment: {rule_comment}") # Caller logs
    if run_iptables_command_gw(args, check_stderr_for_no_match=True):
        # print(f"[+] GW IPTables: Removed rule: {rule_comment}") # Caller logs
        return True
    else:
        # print(f"[-] GW IPTables: Rule {rule_comment} not found/failed remove.") # Caller logs
        return False

# --- Forwarding Logic ---
def forward_data(src_socket, dst_socket, direction_name):
    try:
        while not g_shutdown_flag_gateway.is_set(): 
            data = src_socket.recv(BUFFER_SIZE)
            if not data: 
                break 
            dst_socket.sendall(data)
    except ssl.SSLEOFError: 
        pass 
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        if hasattr(e, 'winerror') and e.winerror == 10038: # WSAENOTSOCK
            pass 
        elif hasattr(e, 'errno') and e.errno in [socket.EBADF, 107, 9, 32]: # EBADF, ENOTCONN, EPIPE
            pass 
        else:
            if src_socket and hasattr(src_socket, 'fileno') and src_socket.fileno() != -1: 
                print(f"[!] GW FORWARD: {direction_name} - Connection Error: {e} (Errno: {e.errno if hasattr(e, 'errno') else 'N/A'})")
    except Exception as e:
        if src_socket and hasattr(src_socket, 'fileno') and src_socket.fileno() != -1: 
             print(f"[!] GW FORWARD: {direction_name} - Unexpected Error: {e}")
    finally:
        for sock in [src_socket, dst_socket]:
            if sock:
                try: 
                    if hasattr(sock, 'fileno') and sock.fileno() != -1:
                        if isinstance(sock, ssl.SSLSocket): 
                            try:
                                sock.shutdown(socket.SHUT_RDWR)
                            except OSError as sd_err: 
                                if sd_err.errno != socket.ENOTCONN:
                                    pass
                        else: 
                             sock.shutdown(socket.SHUT_RDWR)
                except (OSError, ssl.SSLError, AttributeError): 
                    pass 
                finally: 
                    try: 
                        if hasattr(sock, 'fileno') and sock.fileno() != -1: 
                            sock.close()
                    except: 
                        pass

# --- Gateway SPA Processing ---
def handle_gateway_spa_packet(data, client_addr_spa):
    if g_shutdown_flag_gateway.is_set(): return

    client_ip_spa = client_addr_spa[0]
    session_info = None
    with sessions_gw_lock:
        session_info = active_sessions_on_gateway.get(client_ip_spa)
    
    if not session_info:
        print(f"[!] GW_SPA: No active session/keys for {client_ip_spa}. Ignoring.")
        return
    
    eph_spa_hmac_key_bytes = bytes.fromhex(session_info['eph_spa_hmac_key_hex'])
    expected_len = 8 + 4 + 2 + 32 
    if len(data) != expected_len:
        print(f"[!] GW_SPA: Eph SPA from {client_ip_spa} incorrect length. Ignoring.")
        return
    
    hmac_received = data[-32:]
    payload = data[:-32] 
    expected_hmac = hmac.new(eph_spa_hmac_key_bytes, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_hmac, hmac_received):
        print(f"[!] GW_SPA: Invalid EPHEMERAL HMAC from {client_ip_spa}. Ignoring.")
        return
    
    try:
        timestamp, nonce, spa_requested_target_port = struct.unpack('!dIH', payload)
    except struct.error:
        print(f"[!] GW_SPA: Malformed EPHEMERAL SPA payload from {client_ip_spa}. Ignoring.")
        return
    
    current_time = time.time()
    if not (current_time - SPA_PACKET_LIFETIME_SEC < timestamp <= current_time + 5): 
        print(f"[!] GW_SPA: Stale/future EPHEMERAL timestamp from {client_ip_spa}. Ignoring.")
        return
    
    policy_backend_port = session_info['policy']['allow_backend_port']
    if spa_requested_target_port != policy_backend_port: 
        print(f"[!] GW_SPA: SPA from {client_ip_spa} req port {spa_requested_target_port}, policy allows {policy_backend_port}. Denying.")
        return
    
    print(f"[+] GW_SPA: VALID EPHEMERAL knock from {client_ip_spa} for target port {spa_requested_target_port}.")
    with sessions_gw_lock: 
        current_session_info = active_sessions_on_gateway.get(client_ip_spa)
        if not current_session_info: 
             print(f"[!] GW_SPA: Session for {client_ip_spa} disappeared before rule add. Ignoring knock.")
             return

        if current_session_info.get('iptables_rule_comment'): 
            current_session_info['spa_knock_timestamp'] = time.time() 
        else:
            rule_comment_str = add_spa_iptables_rule_gw(client_ip_spa, GATEWAY_PORT_FOR_CLIENT_MTLS)
            if rule_comment_str:
                current_session_info['spa_knock_timestamp'] = time.time()
                current_session_info['iptables_rule_comment'] = rule_comment_str
                print(f"[+] GW_SPA: IPTables rule added for {client_ip_spa}.")
            else:
                print(f"[!] GW_SPA: FAILED to add IPTables rule for {client_ip_spa}.")

def gateway_spa_listener_thread_func():
    spa_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        spa_socket.bind((GATEWAY_IP_FOR_SPA, GATEWAY_PORT_FOR_SPA))
        print(f"[*] Gateway EPHEMERAL SPA Listener started on UDP {GATEWAY_IP_FOR_SPA}:{GATEWAY_PORT_FOR_SPA}")
        while not g_shutdown_flag_gateway.is_set():
            spa_socket.settimeout(1.0)
            try:
                data, client_addr_spa = spa_socket.recvfrom(128) 
                spa_socket.settimeout(None) 
                threading.Thread(target=handle_gateway_spa_packet, args=(data, client_addr_spa), daemon=True).start()
            except socket.timeout:
                continue
            except OSError as e_recv: 
                 if g_shutdown_flag_gateway.is_set():
                     break
                 print(f"[!] Gateway SPA Listener: recvfrom error {e_recv}")
                 break 
    except OSError as e_bind:
        print(f"[!!!] Gateway EPHEMERAL SPA Listener: Bind error {e_bind}.")
    finally:
        if spa_socket:
            spa_socket.close()
        print("[*] Gateway EPHEMERAL SPA Listener stopped.")

def cleanup_expired_gateway_sessions_and_rules():
    while not g_shutdown_flag_gateway.is_set(): 
        time.sleep(IPTABLES_RULE_TIMEOUT_SEC_GW / 2 if IPTABLES_RULE_TIMEOUT_SEC_GW > 2 else 1)
        if g_shutdown_flag_gateway.is_set():
            break

        with sessions_gw_lock:
            current_time = time.time()
            for client_ip in list(active_sessions_on_gateway.keys()):
                if g_shutdown_flag_gateway.is_set():
                    break 
                session = active_sessions_on_gateway.get(client_ip) 
                if not session:
                    continue
                rule_timed_out = False
                session_expired = False
                if session.get('iptables_rule_comment') and session.get('spa_knock_timestamp') and \
                   current_time - session['spa_knock_timestamp'] > IPTABLES_RULE_TIMEOUT_SEC_GW:
                    rule_timed_out = True
                if session.get('session_expiry') and current_time > session['session_expiry']:
                    session_expired = True
                
                if rule_timed_out or session_expired:
                    print(f"[-] GW_SESSION_CLEANUP: Cleaning for {client_ip}. RuleTimeout: {rule_timed_out}, SessionExpiry: {session_expired}")
                    if session.get('iptables_rule_comment'): 
                        # print(f"[*] GW_SESSION_CLEANUP: Removing IPTables rule: {session['iptables_rule_comment']}") # Verbose
                        if remove_spa_iptables_rule_gw_by_comment(session['iptables_rule_comment'], client_ip, GATEWAY_PORT_FOR_CLIENT_MTLS):
                            print(f"[+] GW_SESSION_CLEANUP: Removed IPTables rule for {client_ip}")
                    
                    for key_path_attr in ['my_eph_cert_path', 'my_eph_key_path', 'client_eph_cert_path']:
                        f_path = session.get(key_path_attr) 
                        if f_path and os.path.exists(f_path): 
                            try:
                                os.remove(f_path)
                            except Exception as e_del:
                                print(f"[!] GW_CLEANUP: Error removing {f_path}: {e_del}")
                    
                    if client_ip in active_sessions_on_gateway: 
                        del active_sessions_on_gateway[client_ip]
                    print(f"[-] GW_SESSION_CLEANUP: Session for {client_ip} removed.")
    print("[*] Gateway Session Cleanup thread stopped.")

# --- Gateway mTLS Handling for Client Connections ---
def handle_gateway_client_connection(client_conn_raw, client_addr_mtls):
    client_ip_mtls = client_addr_mtls[0]
    client_ssl_socket = None
    backend_server_socket = None
    session_info = None
    client_eph_cn = "N/A_EPH_CLIENT"
    sockets_to_close_in_finally = [] 
    
    with sessions_gw_lock:
        session_info = active_sessions_on_gateway.get(client_ip_mtls)

    if not session_info:
        print(f"[!] GW_MTLS_CLIENT: No active session for {client_ip_mtls} at mTLS attempt. Closing.")
        client_conn_raw.close()
        return
    
    my_eph_cert_path = session_info['my_eph_cert_path']
    my_eph_key_path = session_info['my_eph_key_path']
    
    if not os.path.exists(my_eph_cert_path) or not os.path.exists(my_eph_key_path):
        print(f"[!] GW_MTLS_CLIENT: Eph cert/key files missing for {client_ip_mtls}. Closing.")
        client_conn_raw.close()
        return
    try:
        eph_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        eph_context.load_cert_chain(certfile=my_eph_cert_path, keyfile=my_eph_key_path)
        eph_context.load_verify_locations(cafile=CA_CERT_PATH_GW) 
        eph_context.verify_mode = ssl.CERT_REQUIRED
        
        client_ssl_socket = eph_context.wrap_socket(client_conn_raw, server_side=True)
        sockets_to_close_in_finally.append(client_ssl_socket) 
        
        peer_cert_eph_client = client_ssl_socket.getpeercert()
        if peer_cert_eph_client:
            subject = dict(x[0] for x in peer_cert_eph_client['subject'])
            client_eph_cn = subject.get('commonName', 'N/A_EPH_NO_CN')
        else:
            print(f"[!] GW_MTLS_CLIENT: No EPHEMERAL cert from {client_ip_mtls}.")
            return 
            
        print(f"[+] GW_MTLS_CLIENT: Client '{client_eph_cn}' ({client_ip_mtls}) authenticated with EPHEMERAL cert.")
        policy = session_info['policy']
        target_backend_host = policy['allow_backend_host']
        target_backend_port = policy['allow_backend_port']
        
        backend_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_server_socket.settimeout(10.0)
        sockets_to_close_in_finally.append(backend_server_socket) 

        backend_server_socket.connect((target_backend_host, target_backend_port))
        backend_server_socket.settimeout(None)
        print(f"[+] GW_MTLS_CLIENT: Connected to backend {target_backend_host}:{target_backend_port} for '{client_eph_cn}'.")
        
        c2s_thread = threading.Thread(target=forward_data, args=(client_ssl_socket, backend_server_socket, f"EphC({client_eph_cn})->S"), daemon=True)
        s2c_thread = threading.Thread(target=forward_data, args=(backend_server_socket, client_ssl_socket, f"S->EphC({client_eph_cn})"), daemon=True)
        c2s_thread.start()
        s2c_thread.start()
        
        while c2s_thread.is_alive() or s2c_thread.is_alive():
            if g_shutdown_flag_gateway.is_set():
                print(f"[*] GW_MTLS_CLIENT: Shutdown signaled, interrupting forwarding for {client_eph_cn}.")
                break
            time.sleep(0.1)
        
    except ssl.SSLError as e_ssl:
        print(f"[!] GW_MTLS_CLIENT: SSL Error with {client_ip_mtls} ({client_eph_cn}): {e_ssl}")
    except FileNotFoundError as e_fnf:
        print(f"[!] GW_MTLS_CLIENT: Eph cert file error for {client_ip_mtls}: {e_fnf}")
    except (socket.timeout, ConnectionRefusedError) as e_conn:
        print(f"[!] GW_MTLS_CLIENT: Error connecting to backend for {client_eph_cn}: {e_conn}")
    except Exception as e:
        print(f"[!] GW_MTLS_CLIENT: Error handling client {client_ip_mtls} ({client_eph_cn}): {type(e).__name__} - {e}")
    finally: 
        for s in sockets_to_close_in_finally:
            if s:
                try:
                    s.close()
                except:
                    pass
        if not client_ssl_socket and client_conn_raw:
             try:
                 client_conn_raw.close()
             except:
                 pass

def gateway_client_mtls_listener_thread_func():
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_socket.bind((GATEWAY_IP_FOR_CLIENT_MTLS, GATEWAY_PORT_FOR_CLIENT_MTLS))
        listen_socket.listen(10)
        print(f"[*] Gateway mTLS Listener for CLIENTS (Ephemeral) started on TCP {GATEWAY_IP_FOR_CLIENT_MTLS}:{GATEWAY_PORT_FOR_CLIENT_MTLS}")
        while not g_shutdown_flag_gateway.is_set():
            listen_socket.settimeout(1.0) 
            try:
                client_conn, client_addr = listen_socket.accept()
                listen_socket.settimeout(None)
                client_ip_log = client_addr[0]
                threading.Thread(target=handle_gateway_client_connection, args=(client_conn, client_addr), daemon=True, name=f"GW_Client_Handler_{client_ip_log}").start()
            except socket.timeout:
                continue
            except OSError as e_accept_main_gw:
                if g_shutdown_flag_gateway.is_set():
                    break
                print(f"[!] Gateway Client mTLS Listener: accept error {e_accept_main_gw}")
                break
    except OSError as e_bind:
        print(f"[!!!] Gateway mTLS Listener for CLIENTS: Bind error {e_bind}.")
    finally:
        if listen_socket:
            listen_socket.close()
        print("[*] Gateway mTLS Listener for CLIENTS stopped.")

# --- Communication with Controller ---
def connect_to_controller():
    global g_controller_ssl_socket 
    
    if g_shutdown_flag_gateway.is_set():
        return None

    onboard_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try: 
        onboard_context.load_verify_locations(cafile=CA_CERT_PATH_GW)
        onboard_context.load_cert_chain(certfile=GATEWAY_ONBOARD_CERT_PATH, keyfile=GATEWAY_ONBOARD_KEY_PATH)
    except Exception as e: 
        print(f"[GW_CTRL_CONN] Error loading certs for controller connection: {e}")
        return None 

    gw_onboard_spa_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    spa_sent_successfully = False
    try:
        gw_onboard_spa_packet = create_gateway_onboard_spa_packet_to_controller()
        gw_onboard_spa_sock.sendto(gw_onboard_spa_packet, (CONTROLLER_IP, CONTROLLER_SPA_PORT_FOR_GW_ONBOARD)) 
        print(f"[+] GW_CTRL_CONN: Sent ONBOARD SPA knock to Controller {CONTROLLER_IP}:{CONTROLLER_SPA_PORT_FOR_GW_ONBOARD}")
        spa_sent_successfully = True
    except Exception as e_spa_ctrl:
        print(f"[!] GW_CTRL_CONN: Error sending ONBOARD SPA to Controller: {e_spa_ctrl}")
    finally:
        gw_onboard_spa_sock.close()
    
    if not spa_sent_successfully:
        print("[!] GW_CTRL_CONN: SPA knock to controller failed. Aborting mTLS attempt for this cycle.")
        return None 
    
    time.sleep(0.3) 
    
    temp_ssl_socket_for_connect = None 
    try:
        print(f"[*] GW_CTRL_CONN: Attempting mTLS connect to Controller {CONTROLLER_IP}:{CONTROLLER_PORT_FOR_GATEWAY_MTLS}...")
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(10.0)
        
        temp_ssl_socket_for_connect = onboard_context.wrap_socket(raw_sock, server_hostname=CONTROLLER_SERVER_HOSTNAME_FOR_GW)
        temp_ssl_socket_for_connect.connect((CONTROLLER_IP, CONTROLLER_PORT_FOR_GATEWAY_MTLS))
        
        g_controller_ssl_socket = temp_ssl_socket_for_connect 
        g_controller_conn_active.set()
        print(f"[+] GW_CTRL_CONN: Connected to Controller {CONTROLLER_IP}.")
        register_msg = {
            "type": "GATEWAY_REGISTER", 
            "gateway_ip": GATEWAY_IP_FOR_CLIENT_MTLS, 
            "listening_port_mtls": GATEWAY_PORT_FOR_CLIENT_MTLS,
            "listening_port_spa": GATEWAY_PORT_FOR_SPA
        }     
        g_controller_ssl_socket.sendall(json.dumps(register_msg).encode() + b"\n<END_MSG>\n") 
        print(f"[>] GW_CTRL_CONN: Sent GATEWAY_REGISTER to Controller.")
        return g_controller_ssl_socket 
    
    except Exception as e: 
        print(f"[!] GW_CTRL_CONN: Error mTLS connecting to Controller: {e}.")
        if temp_ssl_socket_for_connect:
            try:
                temp_ssl_socket_for_connect.close()
            except:
                pass
        if g_controller_ssl_socket: 
            try:
                g_controller_ssl_socket.close()
            except:
                pass
            g_controller_ssl_socket = None 
        g_controller_conn_active.clear()
        return None

def controller_communication_thread_func():
    global g_controller_ssl_socket 
    buffer = ""
    while not g_shutdown_flag_gateway.is_set(): 
        if not g_controller_conn_active.is_set() or g_controller_ssl_socket is None: 
            print("[GW_CTRL_COMM] No active controller socket, attempting to connect/reconnect...")
            if connect_to_controller() is None:
                print("[GW_CTRL_COMM] Failed to connect to controller after attempt. Will retry later.")
                for _ in range(10): 
                    if g_shutdown_flag_gateway.is_set():
                        break
                    time.sleep(1)
                if g_shutdown_flag_gateway.is_set():
                    break
                continue 
        
        current_socket_to_use = g_controller_ssl_socket 
        if current_socket_to_use is None: 
            g_controller_conn_active.clear()
            time.sleep(1)
            continue

        try:
            current_socket_to_use.settimeout(1.0) 
            chunk = current_socket_to_use.recv(BUFFER_SIZE)
            current_socket_to_use.settimeout(None)
            
            if not chunk: 
                print("[-] GW_CTRL_COMM: Controller closed connection (recv no data).")
                g_controller_conn_active.clear()
                if current_socket_to_use: 
                    try:
                        current_socket_to_use.close()
                    except:
                        pass
                if g_controller_ssl_socket == current_socket_to_use: # Ensure we nullify the correct global
                    g_controller_ssl_socket = None 
                buffer = ""
                continue 
            
            buffer += chunk.decode(errors='ignore')
            
            while "<END_MSG>\n" in buffer:
                if g_shutdown_flag_gateway.is_set():
                    break
                message_end_idx = buffer.find("<END_MSG>\n")
                full_message_json = buffer[:message_end_idx]
                buffer = buffer[message_end_idx + len("<END_MSG>\n"):]
                try:
                    message = json.loads(full_message_json)
                    if message.get("command") == "SETUP_CLIENT_SESSION":
                        client_ip = message["client_ip"]
                        my_eph_cert_path = os.path.join(EPH_CERTS_TEMP_DIR_GW, f"gw_eph_for_{client_ip}.crt")
                        my_eph_key_path = os.path.join(EPH_CERTS_TEMP_DIR_GW, f"gw_eph_for_{client_ip}.key")
                        client_eph_cert_path = os.path.join(EPH_CERTS_TEMP_DIR_GW, f"client_eph_{client_ip}.crt")
                        
                        if not save_temp_pem_file(message["gateway_eph_cert_pem"], my_eph_cert_path) or \
                           not save_temp_pem_file(message["gateway_eph_key_pem"], my_eph_key_path) or \
                           not save_temp_pem_file(message["client_eph_cert_pem"], client_eph_cert_path):
                            print(f"[!!!] GW_CTRL_COMM: Failed to save ephemeral certs for client {client_ip}. Session may fail.")
                            continue
                        with sessions_gw_lock:
                            active_sessions_on_gateway[client_ip] = {
                                'eph_spa_hmac_key_hex': message["eph_spa_hmac_key_hex"], 
                                'client_eph_cert_path': client_eph_cert_path, 
                                'my_eph_cert_path': my_eph_cert_path, 'my_eph_key_path': my_eph_key_path,
                                'policy': message["access_policy"],
                                'session_expiry': time.time() + message.get("session_timeout", IPTABLES_RULE_TIMEOUT_SEC_GW + 60)
                            }
                        print(f"[+] GW_CTRL_COMM: Session configured for client {client_ip}.")
                except json.JSONDecodeError:
                    print(f"[!] GW_CTRL_COMM: Malformed JSON from controller: '{full_message_json[:100]}...'")
                except Exception as e_proc:
                    print(f"[!] GW_CTRL_COMM: Error processing message from controller: {e_proc}")
            if g_shutdown_flag_gateway.is_set():
                break

        except socket.timeout:
            pass 
        except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError, OSError) as e_conn_loop: 
            print(f"[-] GW_CTRL_COMM: Connection to Controller lost/error: {type(e_conn_loop).__name__} - {e_conn_loop}.")
            g_controller_conn_active.clear()
            if current_socket_to_use: 
                try:
                    current_socket_to_use.close()
                except:
                    pass
            if g_controller_ssl_socket == current_socket_to_use:
                 g_controller_ssl_socket = None
            buffer = ""
        except Exception as e_loop: 
            print(f"[!] GW_CTRL_COMM: Unexpected error in controller comm loop: {e_loop}")
            g_controller_conn_active.clear()
            if current_socket_to_use:
                try:
                    current_socket_to_use.close()
                except:
                    pass
            if g_controller_ssl_socket == current_socket_to_use:
                 g_controller_ssl_socket = None
            buffer = ""
            time.sleep(5) 
    print("[*] Gateway Controller Communication thread stopped.")

# --- Main ---
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] Gateway script must be run as root to manage iptables. Exiting.")
        exit(1)

    if not os.path.isdir(CERTS_GW_DIR) or \
       not os.path.isfile(CA_CERT_PATH_GW) or \
       not os.path.isfile(GATEWAY_ONBOARD_CERT_PATH) or \
       not os.path.isfile(GATEWAY_ONBOARD_KEY_PATH):
        print(f"[GW_CRITICAL] Essential onboarding certificate files not found in {CERTS_GW_DIR}. Exiting.")
        exit(1)
    
    print("[*] Starting SDP Gateway...")

    ctrl_comm_thread = threading.Thread(target=controller_communication_thread_func, daemon=True, name="ControllerComm")
    gw_spa_thread = threading.Thread(target=gateway_spa_listener_thread_func, daemon=True, name="GatewaySPAListener")
    gw_client_mtls_thread = threading.Thread(target=gateway_client_mtls_listener_thread_func, daemon=True, name="GatewayClientMTLSListener")
    gw_cleanup_thread = threading.Thread(target=cleanup_expired_gateway_sessions_and_rules, daemon=True, name="GatewaySessionCleanup")
    
    all_threads = [ctrl_comm_thread, gw_spa_thread, gw_client_mtls_thread, gw_cleanup_thread]
    for t in all_threads:
        t.start()
    
    print("[+] Gateway All Listener Threads Started.")
    try:
        while not g_shutdown_flag_gateway.is_set():
            time.sleep(1) 
            any_thread_dead = False
            for t_obj in all_threads:
                if not t_obj.is_alive():
                    print(f"[!!!] GATEWAY: Thread '{t_obj.name}' has died! Initiating shutdown.")
                    any_thread_dead = True
                    break
            if any_thread_dead:
                g_shutdown_flag_gateway.set() 
                break
            
    except KeyboardInterrupt:
        print("\n[*] Gateway: KeyboardInterrupt received, initiating shutdown...")
        g_shutdown_flag_gateway.set()
    finally:
        print("[*] Gateway: Final cleanup initiated...")
        g_shutdown_flag_gateway.set() 
        
        # Give threads a moment to see the flag
        time.sleep(0.5)

        if g_controller_ssl_socket:
            try:
                g_controller_ssl_socket.close()
            except:
                pass
        
        with sessions_gw_lock:
            for client_ip, session_data in list(active_sessions_on_gateway.items()):
                if session_data.get('iptables_rule_comment'):
                    print(f"[*] GW Exit Cleanup: Removing rule for {client_ip} (Comment: {session_data['iptables_rule_comment']})")
                    remove_spa_iptables_rule_gw_by_comment(session_data['iptables_rule_comment'], client_ip, GATEWAY_PORT_FOR_CLIENT_MTLS)
                for key_path_attr in ['my_eph_cert_path', 'my_eph_key_path', 'client_eph_cert_path']:
                    f_path = session_data.get(key_path_attr) 
                    if f_path and os.path.exists(f_path):
                        try:
                            os.remove(f_path)
                        except:
                            pass
        print("[*] Gateway shutdown complete.")


