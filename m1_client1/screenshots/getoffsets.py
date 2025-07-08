from scapy.all import rdpcap

input_file = "run1.pcapng"
start_index = 36  # 0-based, 37th packet

packets = rdpcap(input_file)

# Ensure there are enough packets
if len(packets) <= start_index:
    raise ValueError("Not enough packets in the file.")

# Calculate deltas
offsets = []
for i in range(start_index + 1, len(packets)):
    delta = float(packets[i].time) - float(packets[i - 1].time)
    offsets.append(delta)

# Print offsets
for i, delta in enumerate(offsets):
    print(f"Offset between packet {start_index + i + 1} and {start_index + i}: {delta:.9f}")
