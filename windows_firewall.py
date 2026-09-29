import subprocess
import logging

def execute_cmd(command):
    """Executes a console command and returns success status."""
    try:
        # Hide the console window perfectly in Windows
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            startupinfo=startupinfo,
            check=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr
    except FileNotFoundError:
        return False, "Command not found (are you on Windows?)"

def block_ip(ip_address):
    """
    Creates a new Windows Firewall rule to block inbound traffic from the specified IP.
    Returns (success_boolean, message)
    """
    rule_name = f"Intelligent_Firewall_Block_{ip_address}"
    
    # First, check if rule already exists to avoid duplicates
    check_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
    success, _ = execute_cmd(check_cmd)
    
    if success:
        return True, f"IP {ip_address} is already blocked."
        
    # Create the block rule
    block_cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}"
    ]
    
    success, msg = execute_cmd(block_cmd)
    if success:
        logging.info(f"Successfully blocked IP: {ip_address}")
        return True, f"Successfully blocked {ip_address}"
    else:
        logging.error(f"Failed to block IP {ip_address}: {msg}")
        # Could be permission issue if not run as Admin
        if "requires elevation" in msg.lower() or "administrator" in msg.lower() or "access is denied" in msg.lower():
             return False, "Failed: Administrator privileges required block IPs."
        return False, f"Failed: {msg}"

def allow_ip(ip_address):
    """
    Removes the block rule for a specific IP.
    """
    rule_name = f"Intelligent_Firewall_Block_{ip_address}"
    
    delete_cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    
    success, msg = execute_cmd(delete_cmd)
    if success:
        logging.info(f"Successfully unblocked IP: {ip_address}")
        return True, f"Successfully unblocked {ip_address}"
    else:
        return False, f"Rule not found or failed to delete: {msg}"

def get_banned_ips():
    """
    Returns a list of IPs currently banned by the Intelligent Firewall.
    Note: For performance in the API, it's better to track this in memory.
    This function is primarily for startup syncing.
    """
    cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
    success, out = execute_cmd(cmd)
    banned = []
    
    if success:
        lines = out.split('\n')
        current_name = None
        for line in lines:
            if line.startswith("Rule Name:"):
                name = line.split(":", 1)[1].strip()
                if name.startswith("Intelligent_Firewall_Block_"):
                    current_name = name
            elif current_name and line.startswith("RemoteIP:"):
                ip = line.split(":", 1)[1].strip()
                banned.append(ip)
                current_name = None
                
    return banned
