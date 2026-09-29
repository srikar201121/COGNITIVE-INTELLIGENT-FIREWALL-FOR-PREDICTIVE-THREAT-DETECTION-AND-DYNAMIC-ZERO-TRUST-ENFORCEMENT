from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

traffic_data = []

def process_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)

        protocol = "OTHER"
        port = 0

        if packet.haslayer(TCP):
            protocol = "TCP"
            port = packet[TCP].dport

        elif packet.haslayer(UDP):
            protocol = "UDP"
            port = packet[UDP].dport

        traffic_data.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "port": port,
            "packet_size": packet_size,
            "timestamp": str(datetime.now())
        })


def capture_live_traffic(packet_count=20):

    traffic_data.clear()

    sniff(
        filter="ip",   # UPDATED FILTER
        prn=process_packet,
        count=packet_count,
        store=False
    )

    return traffic_data
