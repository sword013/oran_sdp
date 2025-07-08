import pandas as pd

# Load the data
df = pd.read_csv("usage.csv", skipinitialspace=True)
df.columns = ["Time", "PID", "CPU", "MEM"]
df["CPU"] = pd.to_numeric(df["CPU"], errors="coerce")
df["MEM"] = pd.to_numeric(df["MEM"], errors="coerce")

# Group by time, sum CPU and MEM usage across all PIDs
usage_by_time = df.groupby("Time")[["CPU", "MEM"]].sum()

# Find max usage values
max_cpu = usage_by_time["CPU"].max()
max_mem = usage_by_time["MEM"].max()

print(f"🔍 Max CPU Usage: {max_cpu:.2f}%")
print(f"🔍 Max Memory Usage: {max_mem:.2f}%")
