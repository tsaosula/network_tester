import socket
import time
import subprocess
import requests
import psutil
import netifaces
from datetime import datetime
import os

LATENCY_THRESHOLD_MS = 150

# Generate unique log file name per run
timestamp_str = datetime.now().strftime("%Y%m%d_%H%M")
LOG_FILE = os.path.join(os.path.dirname(__file__), f"network_debug_{timestamp_str}.txt")

LAYER_DESCRIPTIONS = {
    1: "Physical layer: Checks if your network hardware (Wi-Fi or Ethernet) is working. Handled by your device drivers and hardware.",
    2: "Data Link layer: Ensures your device can communicate with the router/modem over your local network. Handled by your network adapter and OS.",
    3: "Network layer: Tests if you can reach the wider internet (like Google DNS). Controlled by your router and IP settings.",
    4: "Transport layer: Tries to start a secure connection to a server. Managed by the OS and firewall.",
    5: "Session layer: Manages how applications start and maintain connections. Often abstracted by the OS.",
    6: "Presentation layer: Handles data encryption/decryption (like HTTPS). Managed by the browser or apps.",
    7: "Application layer: Tests if web services work (DNS and HTTP). Handled by your browser or apps."
}

def log_line(text):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} - {text}\n")
    except Exception as e:
        print("⚠️ Failed to write to log file:", e)

def explain_layer(layer_num):
    if layer_num in LAYER_DESCRIPTIONS:
        description = f"\n▶ {LAYER_DESCRIPTIONS[layer_num]}"
        print(description)
        log_line(description)

def print_status(layer_num, layer_name, test_desc, success, latency=None, error_msg=None, threshold_ms=LATENCY_THRESHOLD_MS):
    explain_layer(layer_num)
    if not success:
        msg = f"[Layer {layer_num} - {layer_name}] ❌ {test_desc} - FAIL ({error_msg})"
    else:
        note = ""
        if latency is not None:
            note = f" (high latency: {latency:.2f} ms)" if latency >= threshold_ms else f" ({latency:.2f} ms)"
        msg = f"[Layer {layer_num} - {layer_name}] ✅ OK - {test_desc}{note}"
    print(msg)
    log_line(msg)

def get_default_gateway_ip():
    try:
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][0]
    except:
        return None

def check_interface_status():
    try:
        interfaces = psutil.net_if_stats()
        for iface, stats in interfaces.items():
            if stats.isup:
                return True, iface
        return False, "No active interfaces"
    except Exception as e:
        return False, str(e)

def ping_host(host, count=1):
    try:
        cmd = ['ping', '-n' if socket.getdefaulttimeout() is None else '-c', str(count), host]
        start = time.time()
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return (time.time() - start) * 1000, None
    except subprocess.CalledProcessError as e:
        return None, str(e)

def measure_dns_resolution(hostname):
    start = time.time()
    try:
        ip = socket.gethostbyname(hostname)
        return ip, (time.time() - start) * 1000, None
    except Exception as e:
        return None, None, str(e)

def measure_tcp_latency(host, port):
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=5):
            return (time.time() - start) * 1000, None
    except Exception as e:
        return None, str(e)

def measure_http_latency(url):
    start = time.time()
    try:
        response = requests.get(url, timeout=5)
        return (time.time() - start) * 1000, response.status_code, None
    except Exception as e:
        return None, None, str(e)

def main():
    print("===== NETWORK DEBUG TOOL (Bottom-Up OSI View) =====")
    log_line("===== New network diagnostic run =====")

    target_host = 'example.com'
    test_url = f"https://{target_host}"
    public_dns_ip = '8.8.8.8'
    router_ip = get_default_gateway_ip()

    if not router_ip:
        print_status(2, "Data Link", "Could not detect default gateway", False, None, "Unknown gateway IP")
        return

    # Layer 1 - Physical
    success, iface = check_interface_status()
    print_status(1, "Physical", "Network interface is up", success, None, iface if not success else None)

    # Layer 2 - Data Link
    ping_router_latency, ping_router_error = ping_host(router_ip)
    print_status(2, "Data Link", f"Ping local gateway {router_ip}", ping_router_latency is not None, ping_router_latency, ping_router_error)

    # Layer 3 - Network
    ping_dns_latency, ping_dns_error = ping_host(public_dns_ip)
    print_status(3, "Network", f"Ping public IP {public_dns_ip}", ping_dns_latency is not None, ping_dns_latency, ping_dns_error)

    # Layer 4 - Transport
    tcp_latency, tcp_error = measure_tcp_latency(target_host, 443)
    print_status(4, "Transport", f"TCP connect to {target_host}:443", tcp_latency is not None, tcp_latency, tcp_error)

    # Layer 5 - Session
    print_status(5, "Session", "Session assumed OK if TCP connection succeeds", tcp_latency is not None)

    # Layer 6 - Presentation
    print_status(6, "Presentation", "TLS/SSL handled by requests/OS — assumed OK", True)

    # Layer 7 - Application (DNS + HTTP)
    ip, dns_latency, dns_error = measure_dns_resolution(target_host)
    print_status(7, "Application", f"DNS resolve {target_host}", ip is not None, dns_latency, dns_error)

    http_latency, status_code, http_error = measure_http_latency(test_url)
    desc = f"HTTP GET {test_url} (status {status_code})" if http_latency else f"HTTP GET {test_url}"
    print_status(7, "Application", desc, http_latency is not None, http_latency, http_error)

    print(f"\n📝 Log saved to: {LOG_FILE}")

if __name__ == "__main__":
    main()
