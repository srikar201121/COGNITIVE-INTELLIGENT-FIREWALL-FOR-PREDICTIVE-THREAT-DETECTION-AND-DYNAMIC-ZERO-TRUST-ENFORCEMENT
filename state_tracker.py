from collections import defaultdict
import time

class StatefulTracker:
    def __init__(self):
        # Dictionary of ip: list of timestamps
        # Specifically tracks when we saw a packet from an IP
        self.ip_history = defaultdict(list)
        
        # Keep track of globally banned IPs in memory so we don't spam Windows API
        self.banned_ips = set()
        
    def record_packet(self, src_ip):
        """
        Records the time a packet was received from src_ip.
        Returns the calculated packets per second (pps) for this IP.
        """
        current_time = time.time()
        
        # Add the current timestamp to the IP's history
        self.ip_history[src_ip].append(current_time)
        
        # Clean up history: remove timestamps older than 5 seconds
        # This keeps our memory footprint small and calculates accurate recent rates
        self.ip_history[src_ip] = [ts for ts in self.ip_history[src_ip] if current_time - ts <= 5.0]
        
        # Calculate packets per second effectively over the last 5 seconds
        # Return 0 if we somehow don't have history (should at least be 1)
        history_len = len(self.ip_history[src_ip])
        if history_len == 0:
            return 0
            
        rate = history_len / 5.0
        return rate
        
    def is_burst_attack(self, src_ip, threshold=20.0):
        """
        Returns True if the IP is sending packets faster than the threshold rate.
        For example, scanning ports rapidly or launching a DOS.
        """
        rate = self.record_packet(src_ip)
        return rate >= threshold

    def add_ban(self, ip_address):
        self.banned_ips.add(ip_address)
        
    def get_banned_ips(self):
        return list(self.banned_ips)
        
# Initialize a global tracker singleton
firewall_state = StatefulTracker()
