import subprocess
import socket
import time
from datetime import datetime
import threading
import sys

log_entries = []
spinner_active = True
layer_results = {}


def spinner():
    symbols = ['|', '/', '-', '\\']
    idx = 0
    while spinner_active:
        sys.stdout.write(f"\rRunning diagnostics... {symbols[idx % len(symbols)]}")
        sys.stdout.flush()
        time.sleep(0.2)
        idx += 1


def log(message):
    timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
    entry = f"{timestamp} - {message}"
    log_entries.append(entry)
    print("\r" + message)


def ping_host(host):
    try:
        output = subprocess.run(["ping", "-n", "1", host], capture_output=True, text=True, timeout=5)
        if output.returncode == 0:
            return True, None
        else:
            return False, output.stderr.strip()
    except Exception as e:
        return False, str(e)


def tcp_connect(host, port):
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=5):
            end = time.time()
            return True, round((end - start) * 1000), None
    except Exception as e:
        return False, None, str(e)


def get_default_gateway():
    try:
        import psutil
        interfaces = psutil.net_if_addrs()
        for iface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip_parts = addr.address.split('.')
                    if len(ip_parts) == 4:
                        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
    except:
        pass
    return "192.168.50.1"  # fallback


def detect_environment():
    try:
        hostname = socket.getfqdn()
        if any(keyword in hostname.lower() for keyword in ["corp", "company", "enterprise"]):
            return "enterprise"

        import psutil
        interfaces = psutil.net_if_addrs()
        vpn_keywords = ["tun", "tap", "pptp", "ppp", "ipsec", "openvpn", "vpn"]
        for name in interfaces:
            if any(keyword in name.lower() for keyword in vpn_keywords):
                return "enterprise"

        gateways = psutil.net_if_stats()
        for iface, stats in gateways.items():
            if iface.lower().startswith("eth") or iface.lower().startswith("en"):
                if stats.isup:
                    return "home"

        for iface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.31."):
                        return "enterprise"

        import os
        user_domain = os.environ.get("USERDOMAIN", "").lower()
        if user_domain and user_domain not in ["", os.environ.get("COMPUTERNAME", "").lower()]:
            return "enterprise"

        return "home"
    except:
        return "unknown"


def final_root_cause_analysis():
    print("\n===== ROOT CAUSE INFERENCE =====")
    failed = [k for k, v in layer_results.items() if not v]
    if not failed:
        print("✅ All layers passed. No root cause needed.")
        return

    if failed == ["1 - Physical"]:
        print("🔧 Likely issue: NIC disabled, unplugged cable, or Wi-Fi turned off.")
    elif failed == ["2 - Data Link"]:
        print("🔧 Likely issue: No response from router. Check Wi-Fi or LAN cable.")
    elif failed == ["3 - Network"]:
        print("🔧 Likely issue: Router/modem can't reach the internet. Check ISP.")
    elif failed == ["4 - Transport"]:
        print("🔧 Likely issue: TCP blocked by firewall, proxy, or ISP.")
    elif failed == ["5 - Session"]:
        print("🔧 Session depends on TCP. Check Layer 4 causes.")
    elif failed == ["6 - Presentation"]:
        print("🔧 TLS failure. Possible SSL interception or misconfigured certificate.")
    elif failed == ["7 - Application"]:
        print("🔧 DNS issue. Try changing DNS server settings.")
    elif set(failed) >= {"4 - Transport", "7 - Application"}:
        print("🔧 Both TCP and DNS failing. Enterprise firewall or VPN likely.")
    elif set(failed) >= {"1 - Physical", "2 - Data Link", "3 - Network"}:
        print("🔧 End-to-end connectivity failure. Likely unplugged or disabled interface.")
    elif set(failed) >= {"3 - Network", "4 - Transport", "5 - Session", "6 - Presentation"} and "1 - Physical" not in failed and "2 - Data Link" not in failed:
        print("🔧 Enterprise-level filtering or firewall likely blocking traffic after connection. Deep Packet Inspection or policy enforcement suspected.")
    elif "6 - Presentation" in failed and "4 - Transport" not in failed:
        print("🔧 TLS blocked or interfered, but TCP open. Likely SSL inspection.")
    else:
        print("⚠️ Uncommon issue pattern. Try rebooting or contacting network support.")


def text_osi_results():
    print("\n===== OSI LAYER STATUS OVERVIEW =====")
    layers = [
        ("1 - Physical", "Wi-Fi card, Ethernet port, OS network driver"),
        ("2 - Data Link", "Router or access point, Wi-Fi/Ethernet adapter"),
        ("3 - Network", "Router, modem, Internet Service Provider"),
        ("4 - Transport", "Firewall, proxy, or ISP filtering"),
        ("5 - Session", "VPN apps, chat services, application-specific protocols"),
        ("6 - Presentation", "Operating system, SSL libraries, browser settings"),
        ("7 - Application", "DNS server, OS configuration, browser settings")
    ]
    for layer, responsible in layers:
        status = layer_results.get(layer, False)
        symbol = "✅" if status else "❌"
        print(f"{symbol} {layer} — Responsible: {responsible}")


def run_diagnostics():
    spinner_thread = threading.Thread(target=spinner)
    spinner_thread.start()

    env = detect_environment()
    print("===== NETWORK DEBUG TOOL =====")
    print(f"Detected Environment: {env.upper()}")

    # Layer 1 - Physical
    print("[Layer 1 - Physical] Assuming interface connected")
    layer_results["1 - Physical"] = True

    # Layer 2 - Data Link
    gateway_ip = get_default_gateway()
    print(f"[Layer 2 - Data Link] Pinging local gateway {gateway_ip}...")
    success, _ = ping_host(gateway_ip)
    layer_results["2 - Data Link"] = success

    # Layer 3 - Network
    print("[Layer 3 - Network] Pinging public IP 8.8.8.8...")
    success, _ = ping_host("8.8.8.8")
    layer_results["3 - Network"] = success

    # Layer 4 - Transport
    print("[Layer 4 - Transport] TCP connect to example.com:443...")
    success, _, _ = tcp_connect("example.com", 443)
    layer_results["4 - Transport"] = success

    # Layer 5 - Session
    layer_results["5 - Session"] = layer_results["4 - Transport"]

    # Layer 6 - Presentation
    try:
        import ssl
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname="example.com") as s:
            s.settimeout(5)
            s.connect(("example.com", 443))
        layer_results["6 - Presentation"] = True
    except:
        layer_results["6 - Presentation"] = False

    # Layer 7 - Application
    try:
        socket.gethostbyname("example.com")
        layer_results["7 - Application"] = True
    except:
        layer_results["7 - Application"] = False

    global spinner_active
    spinner_active = False
    spinner_thread.join()

    text_osi_results()
    final_root_cause_analysis()


if __name__ == "__main__":
    run_diagnostics()
