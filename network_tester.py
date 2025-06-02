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

def text_osi_results():
    log("\n===== OSI LAYER STATUS OVERVIEW =====")
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
    global spinner_active
    spin_thread = threading.Thread(target=spinner)
    spin_thread.start()

    issues = []
    env = detect_environment()
    log(f"===== NETWORK DEBUG TOOL (CLI Version) =====")
    log(f"Detected Environment: {env.upper()}")

    log("[Layer 1 - Physical] Checking interface status (assumed OK in CLI)...")
    try:
        import psutil
        stats = psutil.net_if_stats()
        up = any(info.isup for info in stats.values())
        if up:
            log("✅ OK - Network interface is connected")
            layer_results["1 - Physical"] = True
        else:
            log("❌ FAIL - No active network interface found")
            log("Explanation: Your device has no physical or virtual interface currently connected.")
            log("Plain Language: Your computer isn’t connected to any network.")
            log("Responsible: Wi-Fi card, Ethernet port, or OS network driver")
            issues.append("Layer 1 - Physical")
            layer_results["1 - Physical"] = False
    except Exception as e:
        log(f"❌ FAIL - Could not verify interface status: {e}")
        log("Responsible: Operating system or network stack")
        issues.append("Layer 1 - Physical")
        layer_results["1 - Physical"] = False

    log("[Layer 2 - Data Link] Pinging local gateway...")
    success, error = ping_host("192.168.50.1")
    if success:
        log("✅ OK - Gateway responded")
        layer_results["2 - Data Link"] = True
    else:
        log(f"❌ FAIL - Gateway not reachable: {error}")
        log("Explanation: Your device couldn't reach the local router, which usually indicates a disconnected Wi-Fi or bad Ethernet cable.")
        log("Plain Language: Your computer can't talk to your home router.")
        log("Responsible: Router or access point, Wi-Fi/Ethernet adapter")
        issues.append("Layer 2 - Data Link")
        layer_results["2 - Data Link"] = False

    log("[Layer 3 - Network] Pinging public IP 8.8.8.8...")
    success, error = ping_host("8.8.8.8")
    if success:
        log("✅ OK - Internet reachable via IP")
        layer_results["3 - Network"] = True
    else:
        log(f"❌ FAIL - No response from 8.8.8.8: {error}")
        log("Explanation: Your router couldn't reach the public internet. This is often due to a disconnected modem or ISP outage.")
        log("Plain Language: Your router may not be connected to the internet.")
        log("Responsible: Router, modem, or Internet Service Provider")
        issues.append("Layer 3 - Network")
        layer_results["3 - Network"] = False

    log("[Layer 4 - Transport] TCP connection to example.com:443...")
    success, latency, error = tcp_connect("example.com", 443)
    if success:
        log(f"✅ OK - TCP connected in {latency:.2f} ms")
        layer_results["4 - Transport"] = True
    else:
        log(f"❌ FAIL - TCP connect failed: {error}")
        log("Explanation: The system tried to reach example.com via TCP but the connection was blocked or timed out.")
        log("Plain Language: Your computer couldn't open a path to a website.")
        log("Responsible: Firewall, proxy, or ISP filtering")
        issues.append("Layer 4 - Transport")
        layer_results["4 - Transport"] = False

    log("[Layer 5 - Session] Assuming OK if TCP succeeded")
    if "Layer 4 - Transport" not in issues:
        log("✅ OK - Session layer assumed healthy")
        layer_results["5 - Session"] = True
    else:
        log("❌ FAIL - Session layer assumed failed due to TCP issue")
        log("Responsible: Typically relies on successful transport layer setup. Apps like VPNs, chat clients affected.")
        issues.append("Layer 5 - Session")
        layer_results["5 - Session"] = False

    log("[Layer 6 - Presentation] TLS/SSL handled by OS/libraries")
    try:
        import ssl
        ssl.create_default_context()
        log("✅ OK - Presentation layer assumed healthy")
        layer_results["6 - Presentation"] = True
    except Exception as e:
        log(f"❌ FAIL - Presentation layer issue: {e}")
        log("Explanation: TLS/SSL libraries failed to initialize. Secure websites may not work correctly.")
        log("Plain Language: Your device might have trouble opening secure sites.")
        log("Responsible: Operating system, SSL libraries, browser settings")
        issues.append("Layer 6 - Presentation")
        layer_results["6 - Presentation"] = False

    log("[Layer 7 - Application] Resolving DNS for example.com...")
    try:
        ip = socket.gethostbyname("example.com")
        log(f"✅ OK - DNS resolved to {ip}")
        layer_results["7 - Application"] = True
    except Exception as e:
        log(f"❌ FAIL - DNS resolution failed: {e}")
        log("Explanation: DNS queries translate web names to IPs. If this fails, the system can’t find sites by name.")
        log("Plain Language: Your computer can’t look up websites.")
        log("Responsible: DNS server, OS configuration, browser DNS settings")
        issues.append("Layer 7 - Application")
        layer_results["7 - Application"] = False

    log("===== ANALYSIS & SUGGESTIONS =====")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"network_diagnostics_log_{timestamp}.txt"
    if env == "enterprise":
        log("- You appear to be on a corporate network. Some issues may be caused by VPNs, proxies, or internal firewall policies. Contact IT if needed.")
    elif env == "home":
        log("- You appear to be on a home network. Restart your router or check with your ISP if problems persist.")
    else:
        log("- Environment unknown. Apply general networking diagnostics.")
    if not issues:
        log("✅ All network layers passed. No immediate issues detected.")
    else:
        for layer in issues:
            if layer == "Layer 1 - Physical":
                log("- Check your physical network adapter, ensure airplane mode is off and cables are connected.")
            elif layer == "Layer 2 - Data Link":
                log("- Check your local network connection (Wi-Fi/cable, router power).")
            elif layer == "Layer 3 - Network":
                log("- Your network may be blocked from reaching public IPs. Check firewall or routing policies.")
            elif layer == "Layer 4 - Transport":
                log("- TCP connections to the internet are failing. Possible proxy or enterprise firewall blocking.")
            elif layer == "Layer 5 - Session":
                log("- Session layer issue: This layer manages sessions between applications, and typically depends on successful TCP connections. Check if your organization blocks specific sessions or protocols.")
            elif layer == "Layer 6 - Presentation":
                log("- TLS/SSL errors may indicate outdated libraries or incorrect system time.")
            elif layer == "Layer 7 - Application":
                log("- DNS resolution failed. Check DNS settings or try another DNS server like 8.8.8.8.")

    with open(report_filename, "w", encoding="utf-8") as f:
        f.write("\n".join(log_entries))
        f.write("\n")

    text_osi_results()

    spinner_active = False
    spin_thread.join()

    print(f"Detailed report saved to: {report_filename}")
    input("\nDiagnostics complete. Press Enter to exit...")

if __name__ == "__main__":
    run_diagnostics()
