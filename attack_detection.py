from state_tracker import firewall_state
from collections import defaultdict

port_tracker = defaultdict(set)

def detect_attack(row):

    ip = row["src_ip"]
    port = row["port"]

    # DDoS detection
    if firewall_state.is_burst_attack(ip, threshold=15):
        return "DDOS"

    # Port scan detection
    port_tracker[ip].add(port)

    if len(port_tracker[ip]) > 10:
        return "PORT_SCAN"

    return "NORMAL"
