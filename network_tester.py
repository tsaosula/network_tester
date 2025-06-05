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
    print(f"\n{message}")

# Expose TCP connectivity test so unit tests can mock it directly
def tcp_test(host, port):
    """Attempt a TCP connection to ``host:port`` with a short timeout."""
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except Exception:
        return False

# ... [other unchanged functions remain above] ...

def final_root_cause_analysis():
    print("\n===== ROOT CAUSE INFERENCE =====")
    failed = [k for k, v in layer_results.items() if not v]
    passed = [k for k, v in layer_results.items() if v]

    summary_msg = f"Passed: {', '.join(passed) if passed else 'None'} | Failed: {', '.join(failed) if failed else 'None'}"
    log(f"Layer Summary: {summary_msg}")

    if not failed:
        print("✅ All layers passed. No root cause needed.")
        return

    explanation = None
    recovery = None
    advice = None

    if failed == ["1 - Physical"]:
        explanation = "NIC disabled, unplugged cable, or Wi-Fi turned off."
        recovery = "Check your network adapter settings, re-enable the NIC, or plug in the Ethernet cable."
        advice = "If the cable looks fine but the interface stays down, try another port or replace the cable."
    elif failed == ["2 - Data Link"]:
        explanation = "No response from router. Check Wi-Fi or LAN cable."
        recovery = "Reconnect to Wi-Fi or reseat the LAN cable. Restart your router if needed."
        advice = "Verify that other devices can reach the router to rule out router failure."
    elif failed == ["3 - Network"]:
        explanation = "Router/modem can't reach the internet. Check ISP."
        recovery = "Power cycle your modem/router, or contact your internet provider."
        advice = "Check the modem's status lights for errors indicating loss of service."
    elif failed == ["4 - Transport"]:
        explanation = "TCP blocked by firewall, proxy, or ISP."
        recovery = "Check firewall settings, disable VPN, or contact IT/admin for access."
        advice = "Temporarily disable any firewall or VPN to see if connectivity improves."
    elif failed == ["5 - Session"]:
        explanation = "Session init failed. VPN, tunneling, or remote app rejection."
        recovery = "Check VPN connection, restart session-based applications, or reauthenticate."
        advice = "Make sure your credentials are valid and that any VPN software is up to date."
    elif failed == ["6 - Presentation"]:
        explanation = "TLS failure. Possible SSL interception or certificate issues."
        recovery = "Try a different network, check date/time settings, or update CA certificates."
        advice = "Inspect certificate details in your browser to look for anomalies."
    elif failed == ["7 - Application"]:
        explanation = "DNS resolution failed. Misconfigured or blocked DNS."
        recovery = "Change DNS to 8.8.8.8 or 1.1.1.1, or troubleshoot DNS settings."
        advice = "Flush the DNS cache after changing settings to ensure fresh lookups."
    elif set(failed) >= {"1 - Physical", "2 - Data Link", "3 - Network"}:
        explanation = "Complete local connection failure. Interface disabled or cable unplugged."
        recovery = "Ensure NIC is enabled and cables are securely connected. Restart your device."
        advice = "Test with a known good cable or network card if available."
    elif set(failed) >= {"3 - Network", "4 - Transport", "5 - Session", "6 - Presentation"} and "1 - Physical" in passed and "2 - Data Link" in passed:
        explanation = "Enterprise firewall or DPI blocking internet services after gateway."
        recovery = "Check corporate security software, proxy configs, or try a trusted network."
        advice = "Consult your network administrator to confirm if any policies recently changed."
    elif set(failed) == {"4 - Transport", "7 - Application"}:
        explanation = "Firewall or VPN likely blocking both TCP and DNS traffic."
        recovery = "Disable or reconfigure VPN, inspect firewall/proxy rules."
        advice = "Try connecting without the VPN or firewall to verify the restriction."
    elif set(failed) == {"6 - Presentation"} and "4 - Transport" in passed:
        explanation = "TLS blocked or inspected, but TCP is open. SSL inspection suspected."
        recovery = "Use trusted network, or contact IT to bypass SSL inspection temporarily."
        advice = "Check if a corporate proxy is intercepting HTTPS traffic." 
    elif set(failed) == {"7 - Application"} and all(x in passed for x in ["1 - Physical", "2 - Data Link", "3 - Network", "4 - Transport", "5 - Session", "6 - Presentation"]):
        explanation = "Only DNS failing. Likely DNS misconfiguration, hijack, or captive portal."
        recovery = "Switch to public DNS or log into captive portal (if applicable)."
        advice = "Attempt accessing a site directly via IP to confirm DNS is the only issue."
    elif set(failed) == {"5 - Session", "6 - Presentation"} and all(x in passed for x in ["1 - Physical", "2 - Data Link", "3 - Network", "4 - Transport"]):
        explanation = "Session and TLS disrupted—likely service-level or protocol-specific filtering."
        recovery = "Try alternative services or networks, or contact service provider."
        advice = "Testing with another application can confirm if the block is app-specific."
    elif set(failed) == {"6 - Presentation", "7 - Application"} and all(x in passed for x in ["1 - Physical", "2 - Data Link", "3 - Network", "4 - Transport", "5 - Session"]):
        explanation = "TLS + DNS failing. SSL inspection and DNS filtering together suspected."
        recovery = "Try a different network or consult IT to bypass network filtering."
        advice = "Corporate filtering may require contacting IT for an exemption." 
    else:
        explanation = "Uncommon issue pattern. Try rebooting or contacting IT/network support."
        recovery = "Restart your device and network gear, then rerun diagnostics."
        advice = "Collect diagnostic logs to assist support staff in troubleshooting." 

    
    log(f"Root Cause Inference: {explanation}")
    log(f"Recovery Suggestion: {recovery}")
    if advice:
        log(f"Actionable Advice: {advice}")


def run_diagnostics():
    spinner_thread = threading.Thread(target=spinner)
    try:
        spinner_thread.start()

        import netifaces
        import http.client
        import ssl

        log("Starting OSI layer diagnostics...")

        # Layer 1 - Physical
        import psutil
        stats = psutil.net_if_stats()
        layer_results["1 - Physical"] = any(i.isup for i in stats.values())
        log("[Layer 1 - Physical] Interface status: " + ("UP" if layer_results["1 - Physical"] else "DOWN"))

        # Layer 2 - Data Link
        gws = netifaces.gateways()
        gateway_ip = gws.get('default', {}).get(netifaces.AF_INET, ["192.168.50.1"])[0]
        success, _ = subprocess.run(["ping", "-n", "1", gateway_ip], capture_output=True).returncode == 0, None
        layer_results["2 - Data Link"] = success
        log(f"[Layer 2 - Data Link] Pinging gateway {gateway_ip}: {'Success' if success else 'Fail'}")

        # Layer 3 - Network
        success, _ = subprocess.run(["ping", "-n", "1", "8.8.8.8"], capture_output=True).returncode == 0, None
        layer_results["3 - Network"] = success
        log(f"[Layer 3 - Network] Pinging 8.8.8.8: {'Success' if success else 'Fail'}")

        # Layer 4 - Transport
        s443 = tcp_test("example.com", 443)
        s80 = tcp_test("example.com", 80)
        layer_results["4 - Transport"] = s443 or s80
        log(f"[Layer 4 - Transport] TCP 443: {'OK' if s443 else 'FAIL'}, TCP 80: {'OK' if s80 else 'FAIL'}")

        # Layer 5 - Session
        try:
            conn = http.client.HTTPSConnection("example.com", timeout=5)
            conn.request("HEAD", "/")
            r = conn.getresponse()
            layer_results["5 - Session"] = r.status < 400
            conn.close()
        except:
            layer_results["5 - Session"] = False
        log(f"[Layer 5 - Session] HTTP session: {'Success' if layer_results['5 - Session'] else 'Fail'}")

        # Layer 6 - Presentation
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname="example.com") as s:
                s.settimeout(5)
                s.connect(("example.com", 443))
            layer_results["6 - Presentation"] = True
        except:
            layer_results["6 - Presentation"] = False
        log(f"[Layer 6 - Presentation] TLS handshake: {'Success' if layer_results['6 - Presentation'] else 'Fail'}")

        # Layer 7 - Application
        try:
            socket.gethostbyname("example.com")
            layer_results["7 - Application"] = True
        except:
            layer_results["7 - Application"] = False
        log(f"[Layer 7 - Application] DNS resolution: {'Success' if layer_results['7 - Application'] else 'Fail'}")

    finally:
        global spinner_active
        spinner_active = False
        spinner_thread.join()

    log("Diagnostics completed.")
    final_root_cause_analysis()

    with open("network_diagnostic_log.txt", "w") as f:
        f.write("\n".join(log_entries))


if __name__ == "__main__":
    run_diagnostics()
