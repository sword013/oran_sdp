# client_controller_ нагрузка_test.py
import socket
import ssl
import time
import hmac
import hashlib
import struct
import random
import os
import json
import threading # For potential concurrent tests later
import subprocess # For cache clearing if desired between full test sets
import numpy as np
import csv
# --- Configuration ---
CONTROLLER_IP = '10.9.70.137'
CONTROLLER_SPA_PORT = 62201
CONTROLLER_MTLS_PORT = 9999
CONTROLLER_SERVER_HOSTNAME = 'controller.sdp.example' 
ONBOARD_SPA_PSK_HMAC_TO_CONTROLLER = b"controller_onboard_spa_hmac_key_xyz!"
SCRIPT_DIR_CLIENT = os.path.dirname(os.path.abspath(__file__))
CERTS_CLIENT_DIR = os.path.join(SCRIPT_DIR_CLIENT, "./") 
CA_CERT_PATH_CLIENT = os.path.join(CERTS_CLIENT_DIR, 'controller_ca.crt') 
CLIENT_ONBOARD_CERT_PATH = os.path.join(CERTS_CLIENT_DIR, 'client_onboard.crt')
CLIENT_ONBOARD_KEY_PATH = os.path.join(CERTS_CLIENT_DIR, 'client_onboard.key')

# --- Test Parameters ---
NUMBER_OF_REQUESTS = 100  # How many authorization requests to send
# Delay between sending SPA and attempting mTLS (seconds)
# Keep this minimal but reliable based on previous tests for a single client.
# This delay is for the CONTROLLER'S iptables to open.
SPA_TO_MTLS_DELAY_CONTROLLER = 0.05 # 50ms 

# If running multiple sets of N requests, clear caches and wait between sets
CLEAR_CACHES_BETWEEN_SETS = True # Set to False if not desired or not on Linux root
WAIT_BETWEEN_SETS_SEC = 20

# --- Helper Functions --- (Same as before)
def clear_linux_caches():
    if os.name != 'posix' or os.geteuid() != 0: return False 
    try:
        subprocess.run(["sync"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
        with open("/proc/sys/vm/drop_caches", "w") as f: f.write("3\n")
        time.sleep(0.05) 
        return True
    except Exception: return False

def create_onboard_spa_packet_to_controller():
    timestamp = time.time(); nonce = random.randint(0, 0xFFFFFFFF) 
    payload = struct.pack('!dI', timestamp, nonce)
    return payload + hmac.new(ONBOARD_SPA_PSK_HMAC_TO_CONTROLLER, payload, hashlib.sha256).digest()

# --- Core Request Function ---
def perform_onboarding_request(req_id, requested_target_host, requested_target_port):
    """Performs one full SPA -> Controller -> mTLS -> AuthReq -> RecvCreds sequence."""
    onboard_ssl_socket = None
    start_time = time.perf_counter()
    
    # 1. SPA Knock to Controller
    onboard_spa_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        onboard_spa_packet = create_onboard_spa_packet_to_controller()
        onboard_spa_sock.sendto(onboard_spa_packet, (CONTROLLER_IP, CONTROLLER_SPA_PORT))
    except Exception as e:
        print(f"[Req {req_id}] Error sending SPA to Controller: {e}")
        return False, time.perf_counter() - start_time
    finally:
        onboard_spa_sock.close()
    
    time.sleep(SPA_TO_MTLS_DELAY_CONTROLLER) # Wait for controller SPA processing/iptables

    # 2. mTLS to Controller
    try:
        onboard_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        onboard_context.load_verify_locations(cafile=CA_CERT_PATH_CLIENT)
        onboard_context.load_cert_chain(certfile=CLIENT_ONBOARD_CERT_PATH, keyfile=CLIENT_ONBOARD_KEY_PATH)
        
        onboard_raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        onboard_raw_sock.settimeout(10.0) # Connect timeout
        onboard_ssl_socket = onboard_context.wrap_socket(onboard_raw_sock, server_hostname=CONTROLLER_SERVER_HOSTNAME)
        onboard_ssl_socket.connect((CONTROLLER_IP, CONTROLLER_MTLS_PORT))
        
        # 3. Send Access Request
        access_request_msg = {
            "request_type": "GET_ACCESS", 
            "client_identity_cn": f"load_test_client_{req_id}", # Unique CN for each request
            "desired_backend_host": requested_target_host,
            "desired_backend_port": requested_target_port
        }
        onboard_ssl_socket.sendall(json.dumps(access_request_msg).encode())
        
        # 4. Receive Ephemeral Credentials (or error)
        controller_response_raw = onboard_ssl_socket.recv(8192) # Might need larger if certs are big
        if not controller_response_raw:
            print(f"[Req {req_id}] Controller sent no response.")
            return False, time.perf_counter() - start_time
        
        response_data = json.loads(controller_response_raw.decode())
        if response_data.get("status") == "success":
            # We don't need to save/use the creds for this test, just confirm receipt
            # print(f"[Req {req_id}] Successfully received credentials from controller.") # Verbose
            return True, time.perf_counter() - start_time
        else:
            print(f"[Req {req_id}] Controller returned error: {response_data.get('message')}")
            return False, time.perf_counter() - start_time

    except Exception as e:
        print(f"[Req {req_id}] Error during mTLS/AuthReq with Controller: {e}")
        return False, time.perf_counter() - start_time
    finally:
        if onboard_ssl_socket:
            try:
                onboard_ssl_socket.close()
            except:
                pass

if __name__ == "__main__":
    if not os.path.isdir(CERTS_CLIENT_DIR) or \
       not os.path.isfile(CA_CERT_PATH_CLIENT) or \
       not os.path.isfile(CLIENT_ONBOARD_CERT_PATH) or \
       not os.path.isfile(CLIENT_ONBOARD_KEY_PATH):
        print(f"[CLIENT_CRITICAL] Onboarding certs not found. Exiting."); exit(1)

    if CLEAR_CACHES_BETWEEN_SETS:
        if os.name == 'posix' and os.geteuid() != 0:
             print("[CLIENT_WARN] Cache clearing enabled but script not run as root. Caches will not be cleared.")


    print(f"--- Starting Controller Authorization Throughput Test ---")
    print(f"Number of sequential requests: {NUMBER_OF_REQUESTS}")
    print(f"Delay between SPA and mTLS to Controller: {SPA_TO_MTLS_DELAY_CONTROLLER*1000:.0f}ms")

    successful_requests = 0
    failed_requests = 0
    total_processing_time = 0
    request_durations = []

    overall_test_start_time = time.perf_counter()

    for i in range(1, NUMBER_OF_REQUESTS + 1):
        if CLEAR_CACHES_BETWEEN_SETS and i==1 : # Clear only at the very start of a SET
            print("Attempting to clear OS caches before starting request set...")
            clear_linux_caches()
        
        # print(f"Sending request {i}/{NUMBER_OF_REQUESTS}...") # Verbose
        
        # For this test, target host/port are just placeholders for the AuthReq message
        success, duration = perform_onboarding_request(i, "10.0.0.1", 8080) 
        
        total_processing_time += duration
        request_durations.append(duration * 1000) # Store in ms

        if success:
            successful_requests += 1
        else:
            failed_requests += 1
        
        # Optional: Small delay between sequential requests if desired,
        # but for throughput, we often want them as fast as possible.
        # time.sleep(0.01) # e.g., 10ms between requests
        if i % 10 == 0:
             print(f"Completed {i}/{NUMBER_OF_REQUESTS} requests...")


    overall_test_end_time = time.perf_counter()
    total_test_duration = overall_test_end_time - overall_test_start_time

    print("\n--- Controller Throughput Test Results ---")
    print(f"Total requests sent: {NUMBER_OF_REQUESTS}")
    print(f"Successful requests (got creds): {successful_requests}")
    print(f"Failed requests: {failed_requests}")
    print(f"Total wall-clock time for all requests: {total_test_duration:.2f} seconds")
    
    if successful_requests > 0 :
        # This throughput is based on the client's perception of when each request finished.
        # It includes network time for each request.
        # A controller-side measurement would be more accurate for pure controller processing.
        avg_time_per_successful_request = (sum(d for i,d in enumerate(request_durations) if i < successful_requests) / successful_requests) if successful_requests > 0 else 0
        
        if total_test_duration > 0:
             throughput_overall = NUMBER_OF_REQUESTS / total_test_duration
             throughput_successful = successful_requests / total_test_duration
             print(f"Overall throughput (all attempts): {throughput_overall:.2f} requests/second")
             print(f"Successful request throughput: {throughput_successful:.2f} requests/second")
        else:
            print("Test duration too short to calculate meaningful throughput.")
            
        print(f"Average time per successful request (client-side): {avg_time_per_successful_request:.2f} ms")
        if request_durations:
            successful_request_durations_ms = [d for i,d in enumerate(request_durations) if i < successful_requests] # Get only successful durations
            if successful_request_durations_ms:
                 print(f"Min time per successful request: {min(successful_request_durations_ms):.2f} ms")
                 print(f"Max time per successful request: {max(successful_request_durations_ms):.2f} ms")
                 print(f"Median time per successful request: {np.median(successful_request_durations_ms):.2f} ms")
                 print(f"P90 time per successful request: {np.percentile(successful_request_durations_ms, 90):.2f} ms")
    else:
        print("No requests were successful.")

    # Optional: Save individual request durations to CSV for plotting
    with open("controller_load_test_durations.csv", "w", newline="") as f_csv:
        writer = csv.writer(f_csv)
        writer.writerow(["request_id", "duration_ms", "status"])
        for i, dur_ms in enumerate(request_durations):
            status_str = "SUCCESS" if i < successful_requests else "FAIL" # This logic is simplistic if failures interleave
            writer.writerow([i+1, f"{dur_ms:.3f}", status_str])
    print(f"\nIndividual request durations saved to controller_load_test_durations.csv")


