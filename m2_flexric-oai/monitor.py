#!/usr/bin/env python3
import psutil
import time
import csv
from datetime import datetime

def monitor_flexric(process_name="nearRT-RIC", interval=1, csv_file="ric_metrics.csv"):
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'CPU%', 'Memory%', 'Threads'])

        while True:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                    writer.writerow([
                        datetime.now().strftime("%H:%M:%S"),
                        proc.info['cpu_percent'],
                        proc.info['memory_percent'],
                        proc.num_threads()
                    ])
                    f.flush()
            time.sleep(interval)

if __name__ == "__main__":
    monitor_flexric()
