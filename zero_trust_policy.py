from windows_firewall import block_ip
from state_tracker import firewall_state

def apply_zero_trust_policy(risk_level, ip_address):
    """
    Applies Zero Trust rules based on risk level.
    Now actually enforces OS-level bans!
    """

    if risk_level == "LOW":
        action = "ALLOW"
    elif risk_level == "MEDIUM":
        action = "RESTRICT"
    else:
        action = "BLOCK"
        # 1. Block it physically in Windows
        success, msg = block_ip(ip_address)
        
        # 2. Track that we banned it globally in memory so frontend can see it
        # even if Windows CMD fails due to permissions
        firewall_state.add_ban(ip_address)
        
        # You could optionally append the msg to the action for logs but keep it simple
        if not success and "Administrator" in msg:
            action = "BLOCK_FAILED_NO_ADMIN"

    return action
