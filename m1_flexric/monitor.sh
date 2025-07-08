import re

cpu_usages = []
mem_usages = []

with open("top.log", "r") as f:
    lines = f.readlines()
    for i in range(len(lines)):
        line = lines[i]

        # Parse CPU usage
        if line.startswith("%Cpu(s):"):
            match = re.search(r"(\d+\.\d+)\s+id", line)
            if match:
                idle = float(match.group(1))
                cpu_usage = 100.0 - idle
                cpu_usages.append(cpu_usage)

        # Parse Memory usage
        if "MiB Mem :" in line:
            match = re.search(r"(\d+\.\d+)\s+total,\s+(\d+\.\d+)\s+free,\s+(\d+\.\d+)\s+used", line)
            if match:
                total = float(match.group(1))
                used = float(match.group(3))
                mem_usage = (used / total) * 100
                mem_usages.append(mem_usage)

# Results
print(f"Max CPU Usage: {max(cpu_usages):.2f}%")
print(f"Max Memory Usage: {max(mem_usages):.2f}%")
