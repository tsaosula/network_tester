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
        symbol = symbols[idx % len(symbols)]
        sys.stdout.write(f"\rRunning diagnostics... {symbol}")
        sys.stdout.flush()
        time.sleep(0.2)
        idx += 1


def log(message):
    timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
    entry = f"{timestamp} - {message}"
    log_entries.append(entry)
    print(f"\n{message}")


def tcp_test(host, port):
    """Attempt to establish a TCP connection to the specified host and port."""
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

    if not failed:
        print("✅ All layers passed. No root cause needed.")
        return

    rules = [
        (
            lambda f, p: f == ["1 - Physical"],
            "NIC disabled, unplugged cable, or Wi-Fi turned off.",
            (
                "Check your network adapter settings, re-enable the NIC, "
                "or plug in the Ethernet cable."
            ),
        ),
        (
            lambda f, p: f == ["2 - Data Link"],
            "No response from router. Check Wi-Fi or LAN cable.",
            (
                "Reconnect to Wi-Fi or reseat the LAN cable. "
                "Restart your router if needed."
            ),
        ),
        (
            lambda f, p: f == ["3 - Network"],
            "Router/modem can't reach the internet. Check ISP.",
            "Power cycle your modem/router, or contact your internet "
            "provider.",
        ),
        (
            lambda f, p: f == ["4 - Transport"],
            "TCP blocked by firewall, proxy, or ISP.",
            "Check firewall settings, disable VPN, or contact IT/admin "
            "for access.",
        ),
        (
            lambda f, p: f == ["5 - Session"],
            "Session init failed. VPN, tunneling, or remote app rejection.",
            (
                "Check VPN connection, restart session-based applications, "
                "or reauthenticate."
            ),
        ),
        (
            lambda f, p: f == ["6 - Presentation"],
            "TLS failure. Possible SSL interception or certificate issues.",
            (
                "Try a different network, check date/time settings, "
                "or update CA certificates."
            ),
        ),
        (
            lambda f, p: f == ["7 - Application"],
            "DNS resolution failed. Misconfigured or blocked DNS.",
            "Change DNS to 8.8.8.8 or 1.1.1.1, or troubleshoot DNS settings.",
        ),
        (
            lambda f, p: set(f) >= {
                "1 - Physical",
                "2 - Data Link",
                "3 - Network",
            },
            "Complete local connection failure. Interface disabled or "
            "cable unplugged.",
            (
                "Ensure NIC is enabled and cables are securely connected. "
                "Restart your device."
            ),
        ),
        (
            lambda f, p: (
                set(f)
                >= {
                    "3 - Network",
                    "4 - Transport",
                    "5 - Session",
                    "6 - Presentation",
                }
                and "1 - Physical" in p
                and "2 - Data Link" in p
            ),
            "Enterprise firewall or DPI blocking internet services after "
            "gateway.",
            (
                "Check corporate security software, proxy configs, "
                "or try a trusted network."
            ),
        ),
        (
            lambda f, p: set(f) == {"4 - Transport", "7 - Application"},
            "Firewall or VPN likely blocking both TCP and DNS traffic.",
            "Disable or reconfigure VPN, inspect firewall/proxy rules.",
        ),
        (
            lambda f, p: (
                set(f) == {"6 - Presentation"} and "4 - Transport" in p
            ),
            "TLS blocked or inspected, but TCP is open. SSL inspection "
            "suspected.",
            (
                "Use trusted network, or contact IT to bypass SSL inspection "
                "temporarily."
            ),
        ),
        (
            lambda f, p: (
                set(f) == {"7 - Application"}
                and all(
                    x in p
                    for x in [
                        "1 - Physical",
                        "2 - Data Link",
                        "3 - Network",
                        "4 - Transport",
                        "5 - Session",
                        "6 - Presentation",
                    ]
                )
            ),
            "Only DNS failing. Likely DNS misconfiguration, hijack, or "
            "captive portal.",
            (
                "Switch to public DNS or log into captive portal "
                "(if applicable)."
            ),
        ),
        (
            lambda f, p: (
                set(f) == {"5 - Session", "6 - Presentation"}
                and all(
                    x in p
                    for x in [
                        "1 - Physical",
                        "2 - Data Link",
                        "3 - Network",
                        "4 - Transport",
                    ]
                )
            ),
            "Session and TLS disrupted—likely service-level or "
            "protocol-specific filtering.",
            (
                "Try alternative services or networks, "
                "or contact service provider."
            ),
        ),
        (
            lambda f, p: (
                set(f) == {"6 - Presentation", "7 - Application"}
                and all(
                    x in p
                    for x in [
                        "1 - Physical",
                        "2 - Data Link",
                        "3 - Network",
                        "4 - Transport",
                        "5 - Session",
                    ]
                )
            ),
            "TLS + DNS failing. SSL inspection and DNS filtering "
            "together suspected.",
            (
                "Try a different network or consult IT to bypass "
                "network filtering."
            ),
        ),
    ]

    explanation = (
        "Uncommon issue pattern. Try rebooting or contacting "
        "IT/network support."
    )
    recovery = "Restart your device and network gear, then rerun diagnostics."

    for condition, exp, rec in rules:
        if condition(failed, passed):
            explanation, recovery = exp, rec
            break

    log(f"Root Cause Inference: {explanation}")
    log(f"Recovery Suggestion: {recovery}")


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
        status = "UP" if layer_results["1 - Physical"] else "DOWN"
        log(f"[Layer 1 - Physical] Interface status: {status}")

        # Layer 2 - Data Link
        gws = netifaces.gateways()
        gateway_ip = gws.get("default", {}).get(
            netifaces.AF_INET, ["192.168.50.1"]
        )[0]
        result = subprocess.run(
            ["ping", "-n", "1", gateway_ip], capture_output=True
        )
        success = result.returncode == 0
        layer_results["2 - Data Link"] = success
        log(
            f"[Layer 2 - Data Link] Pinging gateway {gateway_ip}: "
            f"{'Success' if success else 'Fail'}"
        )

        # Layer 3 - Network
        result = subprocess.run(
            ["ping", "-n", "1", "8.8.8.8"], capture_output=True
        )
        success = result.returncode == 0
        layer_results["3 - Network"] = success
        log(
            f"[Layer 3 - Network] Pinging 8.8.8.8: "
            f"{'Success' if success else 'Fail'}"
        )

        # Layer 4 - Transport
        s443 = tcp_test("example.com", 443)
        s80 = tcp_test("example.com", 80)
        layer_results["4 - Transport"] = s443 or s80
        log(
            f"[Layer 4 - Transport] TCP 443: {'OK' if s443 else 'FAIL'}, "
            f"TCP 80: {'OK' if s80 else 'FAIL'}"
        )

        # Layer 5 - Session
        try:
            conn = http.client.HTTPSConnection("example.com", timeout=5)
            conn.request("HEAD", "/")
            r = conn.getresponse()
            layer_results["5 - Session"] = r.status < 400
            conn.close()
        except Exception:
            layer_results["5 - Session"] = False
        log(
            f"[Layer 5 - Session] HTTP session: "
            f"{'Success' if layer_results['5 - Session'] else 'Fail'}"
        )

        # Layer 6 - Presentation
        try:
            ctx = ssl.create_default_context()
            wrapped = ctx.wrap_socket(
                socket.socket(), server_hostname="example.com"
            )
            with wrapped as s:
                s.settimeout(5)
                s.connect(("example.com", 443))
            layer_results["6 - Presentation"] = True
        except Exception:
            layer_results["6 - Presentation"] = False
        log(
            f"[Layer 6 - Presentation] TLS handshake: "
            f"{'Success' if layer_results['6 - Presentation'] else 'Fail'}"
        )

        # Layer 7 - Application
        try:
            socket.gethostbyname("example.com")
            layer_results["7 - Application"] = True
        except Exception:
            layer_results["7 - Application"] = False
        log(
            f"[Layer 7 - Application] DNS resolution: "
            f"{'Success' if layer_results['7 - Application'] else 'Fail'}"
        )

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
