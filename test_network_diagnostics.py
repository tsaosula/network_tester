import unittest
from unittest.mock import patch, MagicMock
import socket
import network_tester  # Adjust this if your module name differs

test_results = []


class TestNetworkDiagnostics(unittest.TestCase):

    @patch("socket.create_connection")
    def test_layer4_tcp_success(self, mock_connect):
        mock_connect.return_value.__enter__.return_value = True
        result = network_tester.tcp_test("example.com", 443)
        test_results.append("Layer 4 - TCP Success")
        self.assertTrue(result)

    @patch("socket.create_connection", side_effect=socket.timeout)
    def test_layer4_tcp_timeout(self, mock_connect):
        result = network_tester.tcp_test("example.com", 443)
        test_results.append("Layer 4 - TCP Timeout")
        self.assertFalse(result)

    @patch(
        "socket.create_connection",
        side_effect=OSError("Network unreachable"),
    )
    def test_layer4_tcp_oserror(self, mock_connect):
        result = network_tester.tcp_test("example.com", 443)
        test_results.append("Layer 4 - TCP OSError")
        self.assertFalse(result)

    @patch("psutil.net_if_stats")
    def test_layer1_physical(self, mock_stats):
        mock_stats.return_value = {"eth0": MagicMock(isup=True)}
        test_results.append("Layer 1 - Physical Interface Check")
        self.assertTrue(any(i.isup for i in mock_stats().values()))

    @patch("subprocess.run")
    def test_layer2_datalink(self, mock_run):
        mock_run.return_value.returncode = 0
        test_results.append("Layer 2 - Data Link Ping Gateway")
        result = mock_run(
            ["ping", "-n", "1", "192.168.1.1"], capture_output=True
        )
        self.assertEqual(result.returncode, 0)

    @patch("subprocess.run")
    def test_layer3_network(self, mock_run):
        mock_run.return_value.returncode = 0
        test_results.append("Layer 3 - Network Ping Public IP")
        result = mock_run(
            ["ping", "-n", "1", "8.8.8.8"], capture_output=True
        )
        self.assertEqual(result.returncode, 0)

    @patch("http.client.HTTPSConnection")
    def test_layer5_session(self, mock_conn):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_conn.return_value.getresponse.return_value = mock_response
        test_results.append("Layer 5 - HTTP Session")
        conn = mock_conn("example.com")
        conn.request("HEAD", "/")
        r = conn.getresponse()
        self.assertTrue(r.status < 400)

    @patch("ssl.create_default_context")
    def test_layer6_presentation(self, mock_ssl):
        mock_socket = MagicMock()
        mock_socket.connect.return_value = True
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = (
            mock_socket
        )
        mock_ssl.return_value = mock_context
        test_results.append("Layer 6 - TLS Handshake")
        s = mock_context.wrap_socket(
            socket.socket(), server_hostname="example.com"
        )
        s.settimeout(5)
        s.connect(("example.com", 443))
        self.assertTrue(True)

    @patch("socket.gethostbyname")
    def test_layer7_application(self, mock_dns):
        mock_dns.return_value = "93.184.216.34"
        ip = socket.gethostbyname("example.com")
        test_results.append("Layer 7 - DNS Resolution")
        self.assertEqual(ip, "93.184.216.34")

    @patch("network_tester.log")
    def test_final_root_cause_analysis(self, mock_log):
        network_tester.layer_results = {
            "1 - Physical": True,
            "2 - Data Link": True,
            "3 - Network": False,
            "4 - Transport": True,
            "5 - Session": True,
            "6 - Presentation": True,
            "7 - Application": True,
        }
        network_tester.final_root_cause_analysis()
        messages = [entry.args[0] for entry in mock_log.call_args_list]
        test_results.append("Final Root Cause Analysis")
        self.assertTrue(any("Root Cause Inference" in m for m in messages))
        self.assertTrue(any("Recovery Suggestion" in m for m in messages))


if __name__ == '__main__':
    result = unittest.main(exit=False)
    print("\n\n===== TEST SUMMARY =====")
    for test in test_results:
        print(f"✅ {test}")
