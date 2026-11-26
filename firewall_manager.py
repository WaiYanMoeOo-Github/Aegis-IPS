import platform
import subprocess

def execute_firewall_action(action: str, ip: str) -> str:
    """
    Cross-platform firewall controller.
    Automatically detects Windows, Linux, or macOS and runs the appropriate command.
    """
    os_name = platform.system().lower()
    action = action.lower()

    if action not in ("block", "unblock"):
        return f"Invalid action: {action}"

    if os_name == "windows":
        rule_name = f"Aegis_Block_{ip}"
        if action == "block":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
            ]
        else:
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ]

    elif os_name == "linux":
        # Uses iptables (standard across Linux distributions)
        if action == "block":
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

    elif os_name == "darwin":
        # Uses macOS Packet Filter (pfctl) table named 'aegis_blocked'
        if action == "block":
            cmd = ["pfctl", "-t", "aegis_blocked", "-T", "add", ip]
        else:
            cmd = ["pfctl", "-t", "aegis_blocked", "-T", "delete", ip]

    else:
        return f"Unsupported OS: {os_name}"

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = (result.stdout + "\n" + result.stderr).strip()
        print(f"[FIREWALL - {os_name.upper()}] {action.upper()} {ip} -> {output}", flush=True)
        return output
    except Exception as e:
        error_msg = f"Firewall execution failed on {os_name}: {e}"
        print(f"[FIREWALL ERROR] {error_msg}", flush=True)
        return error_msg