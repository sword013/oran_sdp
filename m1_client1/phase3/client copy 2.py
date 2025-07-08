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
import csv # For writing CSV files

# --- Configuration ---
# Controller Details (Onboarding)
CONTROLLER_IP = '10.9.70.137'
CONTROLLER_SPA_PORT = 62201
CONTROLLER_MTLS_PORT = 9999
# This MUST match the CN or a SAN in the controller's 'controller_mtls.crt'
CONTROLLER_SERVER_HOSTNAME = 'controller.sdp.example' 

# Onboarding SPA Keys (must match controller's ONBOARD_SPA_PSK_HMAC)
ONBOARD_SPA_PSK_HMAC_TO_CONTROLLER = b"controller_onboard_spa_hmac_key_xyz!"

# Onboarding mTLS Certs for Client (to authenticate to Controller)
SCRIPT_DIR_CLIENT = os.path.dirname(os.path.abspath(__file__))
CERTS_CLIENT_DIR = os.path.join(SCRIPT_DIR_CLIENT, "./") 

CA_CERT_PATH_CLIENT = os.path.join(CERTS_CLIENT_DIR, 'controller_ca.crt') 
CLIENT_ONBOARD_CERT_PATH = os.path.join(CERTS_CLIENT_DIR, 'client_onboard.crt')
CLIENT_ONBOARD_KEY_PATH = os.path.join(CERTS_CLIENT_DIR, 'client_onboard.key')

# Temporary storage for ephemeral certs/keys received from controller
EPH_CLIENT_CERT_FILE = os.path.join(SCRIPT_DIR_CLIENT, "_eph_client.crt")
EPH_CLIENT_KEY_FILE = os.path.join(SCRIPT_DIR_CLIENT, "_eph_client.key")
EPH_CA_CERT_FILE_FOR_GW = os.path.join(SCRIPT_DIR_CLIENT, "_eph_ca_gw.crt") 

BUFFER_SIZE = 4096

# --- Test Configuration for Latency Measurement ---
NUMBER_OF_RUNS = 100 
WAIT_BETWEEN_RUNS_SEC = 15 
CLIENT_DELAYS = { 
    "ctrl_spa_proc": 0.01,  # 50ms
    "gw_setup_sync": 0.01, # 150ms 
    "gw_spa_proc": 0.01    # 50ms
}
DETAILED_TIMINGS_CSV_FILE = "sdp_detailed_run_timings.csv"
SUMMARY_LATENCY_CSV_FILE = "sdp_summary_setup_latency.csv"


# --- Helper Functions ---
def create_onboard_spa_packet_to_controller():
    timestamp = time.time()
    nonce = random.randint(0, 0xFFFFFFFF) 
    payload = struct.pack('!dI', timestamp, nonce)
    calculated_hmac = hmac.new(ONBOARD_SPA_PSK_HMAC_TO_CONTROLLER, payload, hashlib.sha256).digest()
    return payload + calculated_hmac

def create_ephemeral_spa_packet_to_gateway(eph_spa_hmac_key_hex, target_service_port, target_service_host_dummy):
    timestamp = time.time()
    nonce = random.randint(0, 0xFFFFFFFF)
    payload_to_gw = struct.pack('!dIH', timestamp, nonce, target_service_port) 
    try:
        eph_hmac_key_bytes = bytes.fromhex(eph_spa_hmac_key_hex)
    except ValueError as e:
        print(f"[CLIENT_ERROR] Invalid hex string for ephemeral SPA HMAC key: {eph_spa_hmac_key_hex}")
        raise 
        
    calculated_hmac_to_gw = hmac.new(eph_hmac_key_bytes, payload_to_gw, hashlib.sha256).digest()
    return payload_to_gw + calculated_hmac_to_gw

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
        print(f"[CLIENT_ERROR] Failed to save PEM to {file_path}: {e}")
        return False

def cleanup_temp_pem_files():
    for f_path in [EPH_CLIENT_CERT_FILE, EPH_CLIENT_KEY_FILE, EPH_CA_CERT_FILE_FOR_GW]:
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
            except OSError as e: 
                print(f"[CLIENT_WARN] Could not remove temp file {f_path}: {e}")
            except: 
                print(f"[CLIENT_WARN] Unknown error removing temp file {f_path}")


# --- Main Client Logic with Timestamping ---
def run_sdp_client_latency_test(run_id, message_to_service, requested_target_host, requested_target_port):
    onboard_ssl_socket = None
    gateway_ssl_socket = None
    ephemeral_creds = None
    
    timings = {"run_id": run_id} 
    errors = []
    success_status = "FAIL" 
    t_start_run_abs = time.perf_counter() # Absolute start for this specific run attempt

    try:
        # --- PHASE 1: Onboarding with Controller ---
        # print(f"[Run {run_id}][PHASE 1] Onboarding with Controller...") # Verbose
        timings["p1_start_spa_to_ctrl"] = time.perf_counter()
        onboard_spa_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            onboard_spa_packet = create_onboard_spa_packet_to_controller()
            onboard_spa_sock.sendto(onboard_spa_packet, (CONTROLLER_IP, CONTROLLER_SPA_PORT))
        except Exception as e_spa_ctrl:
            errors.append(f"P1_SPA_CTRL_SEND_FAIL: {e_spa_ctrl}")
            raise 
        finally:
            onboard_spa_sock.close()
        timings["p1_end_spa_to_ctrl"] = time.perf_counter()
        
        time.sleep(CLIENT_DELAYS["ctrl_spa_proc"])

        timings["p1_start_mtls_to_ctrl"] = time.perf_counter()
        onboard_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        onboard_context.load_verify_locations(cafile=CA_CERT_PATH_CLIENT)
        onboard_context.load_cert_chain(certfile=CLIENT_ONBOARD_CERT_PATH, keyfile=CLIENT_ONBOARD_KEY_PATH)
        
        onboard_raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        onboard_raw_sock.settimeout(10.0) 
        onboard_ssl_socket = onboard_context.wrap_socket(onboard_raw_sock, server_hostname=CONTROLLER_SERVER_HOSTNAME)
        
        onboard_ssl_socket.connect((CONTROLLER_IP, CONTROLLER_MTLS_PORT))
        timings["p1_end_mtls_to_ctrl_connected"] = time.perf_counter()
        
        access_request_msg = {
            "request_type": "GET_ACCESS", 
            "client_identity_cn": "client_onboard_initial_identity", 
            "desired_backend_host": requested_target_host,
            "desired_backend_port": requested_target_port
        }
        onboard_ssl_socket.sendall(json.dumps(access_request_msg).encode())
        timings["p1_sent_auth_req_to_ctrl"] = time.perf_counter()

        controller_response_raw = onboard_ssl_socket.recv(8192) 
        timings["p1_recv_creds_from_ctrl"] = time.perf_counter()
        if not controller_response_raw:
            errors.append("P1_NO_CREDS_FROM_CTRL")
            raise ValueError("Controller sent no credentials")
        
        ephemeral_creds = json.loads(controller_response_raw.decode())
        
        if ephemeral_creds.get("status") != "success":
            error_msg = f"P1_CTRL_DENIED: {ephemeral_creds.get('message', 'Unknown controller error')}"
            errors.append(error_msg)
            raise ValueError(error_msg)
        
        if not save_temp_pem_file(ephemeral_creds["eph_client_cert_pem"], EPH_CLIENT_CERT_FILE) or \
           not save_temp_pem_file(ephemeral_creds["eph_client_key_pem"], EPH_CLIENT_KEY_FILE) or \
           not save_temp_pem_file(ephemeral_creds["eph_ca_cert_pem"], EPH_CA_CERT_FILE_FOR_GW):
            errors.append("P1_SAVE_EPH_CREDS_FAIL")
            raise ValueError("Failed to save ephemeral credentials locally")
        
        timings["p1_eph_creds_saved"] = time.perf_counter()
        onboard_ssl_socket.close()
        onboard_ssl_socket = None
        # print(f"[Run {run_id}][PHASE 1] Onboarding with Controller COMPLETE.") # Verbose

        # --- PHASE 2: Connect to Gateway using Ephemeral Credentials ---
        # print(f"[Run {run_id}][PHASE 2] Connecting to Gateway...") # Verbose
        
        time.sleep(CLIENT_DELAYS["gw_setup_sync"]) 
        
        gateway_ip = ephemeral_creds["gateway_ip"]
        gateway_mtls_port = ephemeral_creds["gateway_mtls_port"]
        gateway_spa_port = ephemeral_creds["gateway_spa_port"]
        eph_spa_hmac_key_hex_for_gw = ephemeral_creds["eph_spa_hmac_key_hex"]
        gateway_proxied_target_port = requested_target_port

        timings["p2_start_spa_to_gw"] = time.perf_counter()
        eph_spa_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            eph_spa_packet = create_ephemeral_spa_packet_to_gateway(
                eph_spa_hmac_key_hex_for_gw, 
                gateway_proxied_target_port,
                "dummy_host_for_spa_format" 
            )
            eph_spa_sock.sendto(eph_spa_packet, (gateway_ip, gateway_spa_port))
        except Exception as e_spa_gw:
            errors.append(f"P2_SPA_GW_SEND_FAIL: {e_spa_gw}")
            raise
        finally:
            eph_spa_sock.close()
        timings["p2_end_spa_to_gw"] = time.perf_counter()

        time.sleep(CLIENT_DELAYS["gw_spa_proc"])

        timings["p2_start_mtls_to_gw"] = time.perf_counter()
        gateway_server_hostname_eph = gateway_ip 
        
        gateway_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        gateway_context.load_verify_locations(cafile=EPH_CA_CERT_FILE_FOR_GW) 
        gateway_context.load_cert_chain(certfile=EPH_CLIENT_CERT_FILE, keyfile=EPH_CLIENT_KEY_FILE)
        
        gateway_raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gateway_raw_sock.settimeout(10.0) 
        gateway_ssl_socket = gateway_context.wrap_socket(gateway_raw_sock, server_hostname=gateway_server_hostname_eph)
        
        gateway_ssl_socket.connect((gateway_ip, gateway_mtls_port))
        timings["p2_end_mtls_to_gw_connected"] = time.perf_counter()
        
        success_status = "SUCCESS" # Mark as successful if we reached here
        print(f"[Run {run_id}] Successfully connected to Gateway (mTLS established).")
        # For this latency test, we don't send application data.
        
        # print(f"[Run {run_id}][PHASE 2] Connection to Gateway (mTLS established) COMPLETE.") # Verbose

    except ConnectionRefusedError as e:
        err_msg = f"CONN_REFUSED: {e}"
        if not errors or errors[-1] != err_msg : errors.append(err_msg)
        print(f"[Run {run_id}] FAILED: {errors[-1]}")
    except socket.timeout as e:
        err_msg = f"SOCKET_TIMEOUT: {e}"
        if not errors or errors[-1] != err_msg : errors.append(err_msg)
        print(f"[Run {run_id}] FAILED: {errors[-1]}")
    except ssl.SSLCertVerificationError as e:
        err_msg = f"SSL_CERT_VERIFY_FAIL: {e}"
        if not errors or errors[-1] != err_msg : errors.append(err_msg)
        print(f"[Run {run_id}] FAILED: {errors[-1]}")
    except ssl.SSLError as e:
        err_msg = f"SSL_ERROR: {e}"
        if not errors or errors[-1] != err_msg : errors.append(err_msg)
        print(f"[Run {run_id}] FAILED: {errors[-1]}")
    except ValueError as e: 
        err_msg = f"VALUE_ERROR: {e}"
        if not errors or errors[-1] != err_msg : errors.append(err_msg)
        print(f"[Run {run_id}] FAILED: {errors[-1]}")
    except Exception as e:
        err_msg = f"UNEXPECTED_ERROR: {type(e).__name__} - {e}"
        if not errors or errors[-1] != err_msg : errors.append(err_msg)
        print(f"[Run {run_id}] FAILED: {errors[-1]}")
    finally:
        if onboard_ssl_socket:
            try: onboard_ssl_socket.close()
            except: pass
        if gateway_ssl_socket:
            try: gateway_ssl_socket.close()
            except: pass
        cleanup_temp_pem_files()
        
        t_end_run_abs = time.perf_counter()
        # Store absolute end time of this attempt
        timings["_abs_end_run_attempt"] = t_end_run_abs 
        # Calculate duration of this attempt relative to its own start
        timings["total_run_duration_client_seen"] = (t_end_run_abs - t_start_run_abs) * 1000 # ms
        timings["status"] = success_status
        
        return timings, errors

if __name__ == "__main__":
    if not os.path.isdir(CERTS_CLIENT_DIR) or \
       not os.path.isfile(CA_CERT_PATH_CLIENT) or \
       not os.path.isfile(CLIENT_ONBOARD_CERT_PATH) or \
       not os.path.isfile(CLIENT_ONBOARD_KEY_PATH):
        print(f"[CLIENT_CRITICAL] Essential onboarding certificate files not found in {CERTS_CLIENT_DIR}. Please generate them. Exiting.")
        exit(1)

    all_run_timings_list = [] 
    all_run_errors_list = []  

    print(f"Starting {NUMBER_OF_RUNS} test runs with {WAIT_BETWEEN_RUNS_SEC}s interval...")
    print(f"Using internal client delays: Controller SPA Proc: {CLIENT_DELAYS['ctrl_spa_proc']*1000:.0f}ms, "
          f"GW Setup Sync: {CLIENT_DELAYS['gw_setup_sync']*1000:.0f}ms, "
          f"GW SPA Proc: {CLIENT_DELAYS['gw_spa_proc']*1000:.0f}ms")

    timing_keys_for_csv = [
        "run_id", "status",
        "p1_start_spa_to_ctrl", "p1_end_spa_to_ctrl", 
        "p1_start_mtls_to_ctrl", "p1_end_mtls_to_ctrl_connected",
        "p1_sent_auth_req_to_ctrl", "p1_recv_creds_from_ctrl", "p1_eph_creds_saved",
        "p2_start_spa_to_gw", "p2_end_spa_to_gw",
        "p2_start_mtls_to_gw", "p2_end_mtls_to_gw_connected",
        "total_run_duration_client_seen", # Overall wall-clock for this attempt
        # Calculated durations (relative to p1_start_spa_to_ctrl, in ms)
        "calc_p1_spa_send_dur_ms",
        "calc_p1_mtls_ctrl_connect_dur_ms", # From end of SPA send to mTLS connected
        "calc_p1_ctrl_processing_estimate_ms", # From auth_req_sent to creds_rcvd
        "calc_p1_total_onboard_dur_ms", # From start_spa_to_ctrl to eph_creds_saved
        "calc_p2_spa_send_dur_ms",
        "calc_p2_mtls_gw_connect_dur_ms", # From end of SPA_GW send to mTLS_GW connected
        "calc_overall_setup_success_dur_ms" # From start_spa_to_ctrl to mTLS_GW connected (only if successful)
    ]

    with open(DETAILED_TIMINGS_CSV_FILE, 'w', newline='') as f_detailed:
        detailed_writer = csv.DictWriter(f_detailed, fieldnames=timing_keys_for_csv)
        detailed_writer.writeheader()

        for i in range(1, NUMBER_OF_RUNS + 1):
            print(f"\n--- Starting Run {i}/{NUMBER_OF_RUNS} ---")
            current_timings, current_errors = run_sdp_client_latency_test(
                i, 
                f"Latency test run {i}", 
                "10.9.65.55", 
                9999
            )
            
            # Post-process timings to add calculated durations (in ms)
            # All timestamps in current_timings are perf_counter() absolute values except run_id and status
            base_time = current_timings.get("p1_start_spa_to_ctrl")
            if base_time is not None:
                current_timings["calc_p1_spa_send_dur_ms"] = (current_timings.get("p1_end_spa_to_ctrl", base_time) - base_time) * 1000
                
                # Duration from end of SPA send to controller mTLS connected (includes ctrl_spa_proc delay)
                if "p1_end_spa_to_ctrl" in current_timings and "p1_end_mtls_to_ctrl_connected" in current_timings:
                     current_timings["calc_p1_mtls_ctrl_connect_dur_ms"] = (current_timings["p1_end_mtls_to_ctrl_connected"] - current_timings["p1_end_spa_to_ctrl"]) * 1000
                
                # Estimate of controller processing + network for creds
                if "p1_sent_auth_req_to_ctrl" in current_timings and "p1_recv_creds_from_ctrl" in current_timings:
                    current_timings["calc_p1_ctrl_processing_estimate_ms"] = (current_timings["p1_recv_creds_from_ctrl"] - current_timings["p1_sent_auth_req_to_ctrl"]) * 1000

                if "p1_eph_creds_saved" in current_timings:
                    current_timings["calc_p1_total_onboard_dur_ms"] = (current_timings["p1_eph_creds_saved"] - base_time) * 1000

                if "p2_start_spa_to_gw" in current_timings and "p2_end_spa_to_gw" in current_timings: # Check if P2 started
                    current_timings["calc_p2_spa_send_dur_ms"] = (current_timings["p2_end_spa_to_gw"] - current_timings["p2_start_spa_to_gw"]) * 1000
                
                # Duration from end of SPA_GW send to mTLS_GW connected (includes gw_spa_proc delay)
                if "p2_end_spa_to_gw" in current_timings and "p2_end_mtls_to_gw_connected" in current_timings:
                     current_timings["calc_p2_mtls_gw_connect_dur_ms"] = (current_timings["p2_end_mtls_to_gw_connected"] - current_timings["p2_end_spa_to_gw"]) * 1000
                
                if current_timings.get("status") == "SUCCESS" and "p2_end_mtls_to_gw_connected" in current_timings:
                    current_timings["calc_overall_setup_success_dur_ms"] = (current_timings["p2_end_mtls_to_gw_connected"] - base_time) * 1000

            # Ensure all keys are present for CSV DictWriter
            output_row = {key: current_timings.get(key) for key in timing_keys_for_csv}
            detailed_writer.writerow(output_row)
            
            all_run_timings_list.append(current_timings) 
            if current_errors:
                all_run_errors_list.append({"run": i, "errors": current_errors})
            
            if i < NUMBER_OF_RUNS:
                print(f"--- Waiting {WAIT_BETWEEN_RUNS_SEC}s before next run ---")
                time.sleep(WAIT_BETWEEN_RUNS_SEC)
    
    print(f"\nDetailed run timings and calculated durations saved to: {DETAILED_TIMINGS_CSV_FILE}")
    
    print("\n\n--- SDP Connection Setup Latency Test Summary ---")
    
    successful_overall_setup_times_ms = []
    for t_data in all_run_timings_list:
        if t_data.get("status") == "SUCCESS" and "calc_overall_setup_success_dur_ms" in t_data:
            successful_overall_setup_times_ms.append(t_data["calc_overall_setup_success_dur_ms"])

    print(f"\nTotal Runs Attempted: {NUMBER_OF_RUNS}")
    print(f"Successful Full Connections to Gateway: {len(successful_overall_setup_times_ms)}")

    if all_run_errors_list:
        print("\nErrors Encountered During Runs:")
        for err_info in all_run_errors_list:
            print(f"  Run {err_info['run']}:")
            for err_detail in err_info['errors']:
                 print(f"    - {err_detail}")

    if successful_overall_setup_times_ms:
        print("\nLatency Metrics (ms) for Successful Full Setups to Gateway:")
        data = successful_overall_setup_times_ms
        avg = sum(data) / len(data) if data else 0
        median = sorted(data)[len(data) // 2] if data else 0
        
        # Handle P90/P99 for small N by taking max or near-max
        if len(data) > 0:
            p90_idx = min(int(len(data) * 0.9), len(data)-1)
            p90 = sorted(data)[p90_idx]
            p99_idx = min(int(len(data) * 0.99), len(data)-1)
            p99 = sorted(data)[p99_idx]
            min_t = min(data)
            max_t = max(data)
        else: # No successful runs
            p90, p99, min_t, max_t = 0,0,0,0

        print(f"  Total End-to-End Client Setup Time (SPA->Ctrl to mTLS->GW connected):")
        print(f"    Avg: {avg:.2f}ms, Median: {median:.2f}ms")
        print(f"    Min: {min_t:.2f}ms, Max: {max_t:.2f}ms")
        print(f"    P90: {p90:.2f}ms, P99: {p99:.2f}ms")
        
        with open(SUMMARY_LATENCY_CSV_FILE, 'w', newline='') as f_summary:
            summary_writer = csv.writer(f_summary)
            summary_writer.writerow(["successful_run_index", "total_setup_ms"])
            for idx, t_val in enumerate(successful_overall_setup_times_ms):
                summary_writer.writerow([idx+1, f"{t_val:.3f}"])
        print(f"\nSummary latency data for successful runs saved to: {SUMMARY_LATENCY_CSV_FILE}")
    else:
        print("\nNo successful full connections to Gateway were recorded to summarize latency.")

    # Optional: Print detailed breakdown for first few runs or failed runs
    # print("\n--- Example Detailed Timings (First 5 Runs) ---")
    # for i, run_times in enumerate(all_run_timings_list[:5]):
    #     print(f"Run {run_times.get('run_id', i+1)} (Status: {run_times.get('status', 'N/A')}):")
    #     for key, val in run_times.items():
    #         if key not in ["run_id", "status"] and isinstance(val, (int, float)):
    #              # If it's an absolute timestamp, convert to relative for this print
    #              base_t = run_times.get("p1_start_spa_to_ctrl", 0)
    #              if base_t > 0 and key.startswith("p"): 
    #                  print(f"  {key}: {(val - base_t) * 1000:8.2f} ms (abs)")
    #              elif key.startswith("calc_"):
    #                  print(f"  {key}: {val:8.2f} ms (calc)")
    #              elif key == "total_run_duration_client_seen":
    #                   print(f"  {key}: {val:8.2f} ms (wall_clock)")


