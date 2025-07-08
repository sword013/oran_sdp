import psutil
import time

def get_all_children_pids(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        return [p.pid for p in children if p.is_running()] + [pid]
    except psutil.NoSuchProcess:
        return []

def get_total_cpu_mem_percent(pids):
    total_cpu = 0.0
    total_mem = 0.0
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            total_cpu += proc.cpu_percent(interval=0)  # collect without waiting
            total_mem += proc.memory_percent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total_cpu, total_mem

# ----------- CONFIG -----------
main_pid = int(input("Enter main PID of FlexRIC: "))
duration_seconds = 300
# ------------------------------

print(f"Monitoring PID {main_pid} and all child processes for {duration_seconds} seconds...")

max_cpu = 0.0
max_mem = 0.0

# First call to initialize cpu_percent tracking
psutil.cpu_percent(interval=None)

for _ in range(duration_seconds):
    pids = get_all_children_pids(main_pid)
    cpu, mem = get_total_cpu_mem_percent(pids)
    max_cpu = max(max_cpu, cpu)
    max_mem = max(max_mem, mem)
    time.sleep(1)

print(f"\n✅ Max CPU Usage: {max_cpu:.2f}%")
print(f"✅ Max Memory Usage: {max_mem:.2f}%")
