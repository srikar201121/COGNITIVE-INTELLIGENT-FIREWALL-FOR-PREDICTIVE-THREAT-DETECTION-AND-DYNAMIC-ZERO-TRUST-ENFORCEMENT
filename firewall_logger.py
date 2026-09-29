from datetime import datetime

def log_firewall_action(row):
    """
    Logs firewall decisions
    """

    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
        "protocol": row["protocol"],
        "port": row["port"],
        "packet_size": row["packet_size"],
        "risk_level": row["risk_level"],
        "action": row["policy_action"]
    }

    return log_entry
