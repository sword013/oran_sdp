#!/usr/bin/env python3
"""
dos_on_ric.py - A script to stress test a local environment by running multiple instances of trial.py
This is for educational and local testing purposes only.
"""

import argparse
import subprocess
import threading
import time
import os
import sys

# Global counter for statistics
counter_lock = threading.Lock()
total_requests = 0
successful_requests = 0
failed_requests = 0

def run_trial_repeatedly(thread_id, args, stop_event):
    """Run trial.py repeatedly until the stop event is set"""
    global total_requests, successful_requests, failed_requests
    
    cmd = ["python3", "dos_on_ric.py"] + args
    count = 0
    
    while not stop_event.is_set():
        try:
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            success = (result.returncode == 0)
            
            # Update statistics
            with counter_lock:
                total_requests += 1
                if success:
                    successful_requests += 1
                else:
                    failed_requests += 1
            
            count += 1
            
        except Exception:
            with counter_lock:
                failed_requests += 1
    
    print(f"Thread {thread_id} completed after {count} requests")

def main():
    parser = argparse.ArgumentParser(description="Stress test by running multiple instances of trial.py")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Duration of the test in seconds (default: 60)")
    parser.add_argument("--trial-args", nargs="*", default=[], help="Arguments to pass to trial.py")
    
    args = parser.parse_args()
    
    if not os.path.exists("dos_on_ric.py"):
        print("Error: trial.py not found in the current directory", file=sys.stderr)
        return 1
    
    print(f"Starting stress test with {args.threads} threads for {args.duration} seconds")
    print("Press Ctrl+C to stop the test early")
    
    # Create stop event
    stop_event = threading.Event()
    
    # Create and start threads
    threads = []
    for i in range(args.threads):
        thread = threading.Thread(
            target=run_trial_repeatedly,
            args=(i, args.trial_args, stop_event)
        )
        thread.daemon = True
        threads.append(thread)
        thread.start()
    
    # Start time
    start_time = time.time()
    last_total = 0
    
    try:
        # Run for the specified duration
        while time.time() - start_time < args.duration:
            time.sleep(1)  # Update stats every second
            
            # Calculate and display current statistics
            current_time = time.time()
            elapsed = current_time - start_time
            
            with counter_lock:
                current_total = total_requests
                current_successful = successful_requests
                current_failed = failed_requests
            
            # Calculate requests per second since last update
            requests_since_last = current_total - last_total
            last_total = current_total
            
            overall_rate = current_total / elapsed if elapsed > 0 else 0
            current_rate = requests_since_last / 1.0  # Over the last 1 second
            
            print(f"Time: {elapsed:.1f}s | Total: {current_total} | Success: {current_successful} | "
                  f"Failed: {current_failed} | Rate: {overall_rate:.2f} req/s | Current: {current_rate:.2f} req/s")
    
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    
    finally:
        # Signal threads to stop
        stop_event.set()
        
        # Wait for all threads to finish (with timeout)
        for thread in threads:
            thread.join(timeout=2)
        
        # Final statistics
        total_time = time.time() - start_time
        
        with counter_lock:
            final_total = total_requests
            final_successful = successful_requests
            final_failed = failed_requests
        
        print("\nFinal Statistics:")
        print(f"Total test time: {total_time:.2f} seconds")
        print(f"Total requests: {final_total}")
        print(f"Successful requests: {final_successful}")
        print(f"Failed requests: {final_failed}")
        print(f"Average request rate: {final_total / total_time:.2f} requests/second")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
