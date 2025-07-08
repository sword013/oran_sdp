import psutil
import time

def get_all_pids_by_name(target_name):
    matched = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['cmdline'] and target_name in ' '.join(proc.info['cmdline']):
                matched.append(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return matched

def get_total_cpu_mem_percent(pids):
    total_cpu = 0.0
    total_mem = 0.0
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            total_cpu += proc.cpu_percent(interval=1)  # sample over 1 sec
            total_mem += proc.memory_percent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total_cpu, total_mem

# ----------- CONFIG -----------
target_process = input("Enter target process name (e.g., spa_ctrl_listener): ").strip()
duration_seconds = 500
# ------------------------------

print(f"Searching for all processes with name matching '{target_process}'...")
pids = get_all_pids_by_name(target_process)
print(f"Matched PIDs: {pids}")

if not pids:
    print("❌ No matching processes found.")
    exit(1)

print(f"Monitoring these PIDs for {duration_seconds} seconds...")

max_cpu = 0.0
max_mem = 0.0

for i in range(duration_seconds):
    pids = get_all_pids_by_name(target_process)
    cpu, mem = get_total_cpu_mem_percent(pids)
    max_cpu = max(max_cpu, cpu)
    max_mem = max(max_mem, mem)
    print(f"[{i+1}s] CPU: {cpu:.2f}%, MEM: {mem:.2f}%")  # Optional: show progress

print(f"\n✅ Max CPU Usage: {max_cpu:.2f}%")
print(f"✅ Max Memory Usage: {max_mem:.2f}%")
