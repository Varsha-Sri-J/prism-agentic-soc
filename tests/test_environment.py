"""
Automated Test Suite for PRISM Synthetic SOC Environment (Phase 1).

Proves the 11 key requirements:
1. ALT-1042 can be retrieved.
2. web-server-03 can be retrieved.
3. Vulnerability evidence can be retrieved.
4. Server log evidence can be retrieved.
5. Network evidence can be retrieved.
6. Network topology can be retrieved.
7. block_ip executes.
8. Verification after block_ip fails.
9. Proxy-LB01 can be discovered.
10. block_upstream_route executes.
11. Final verification succeeds.
"""

import unittest
from backend.tools import (
    block_ip,
    block_upstream_route,
    get_alert,
    get_asset,
    get_environment_state,
    get_network_evidence,
    get_network_topology,
    reset_environment,
    search_server_logs,
    search_vulnerabilities,
    verify_block,
)


class TestPrismSyntheticEnvironment(unittest.TestCase):

    def setUp(self) -> None:
        """Reset the environment before each test for test isolation."""
        reset_environment()

    def test_01_alt_1042_can_be_retrieved(self) -> None:
        """1. Prove that ALT-1042 can be retrieved."""
        alert = get_alert("ALT-1042")
        self.assertIsNotNone(alert, "Alert ALT-1042 should exist in synthetic data")
        self.assertEqual(alert["alert_id"], "ALT-1042")
        self.assertEqual(alert["name"], "Possible SQL Injection")
        self.assertEqual(alert["source_ip"], "10.20.14.52")
        self.assertEqual(alert["target_asset"], "web-server-03")

    def test_02_web_server_03_can_be_retrieved(self) -> None:
        """2. Prove that web-server-03 asset can be retrieved."""
        asset = get_asset("web-server-03")
        self.assertIsNotNone(asset, "Asset web-server-03 should exist in inventory")
        self.assertEqual(asset["asset_id"], "web-server-03")
        self.assertEqual(asset["ip_address"], "192.168.10.15")
        self.assertEqual(asset["role"], "Production Web Application Server")

    def test_03_vulnerability_evidence_can_be_retrieved(self) -> None:
        """3. Prove that vulnerability evidence can be retrieved for target asset."""
        vulns = search_vulnerabilities("web-server-03")
        self.assertIsInstance(vulns, list)
        self.assertGreater(len(vulns), 0, "web-server-03 should have simulated vulnerabilities")
        
        # Check for SQL injection vulnerability
        sqli_vuln = next((v for v in vulns if "SQL" in v.get("title", "") or "CWE-89" in v.get("vulnerability_type", "")), None)
        self.assertIsNotNone(sqli_vuln, "Vulnerability list should contain SQL Injection")
        self.assertEqual(sqli_vuln["cve_id"], "CVE-2023-42819")
        self.assertEqual(sqli_vuln["status"], "UNPATCHED")

    def test_04_server_log_evidence_can_be_retrieved(self) -> None:
        """4. Prove that server log evidence with malicious SQL payload and success can be retrieved."""
        logs = search_server_logs(host="web-server-03", source_ip="10.20.14.52")
        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0, "Server logs should exist for web-server-03 and source 10.20.14.52")

        # Check for SQL payload reaching the application and succeeding (status 200)
        exploit_log = next(
            (
                log for log in logs
                if log.get("status_code") == 200 and (
                    "UNION SELECT" in log.get("payload", "")
                    or "UNION" in log.get("raw_request", "")
                )
            ),
            None
        )
        self.assertIsNotNone(exploit_log, "Server logs should contain the successful SQL injection request")
        self.assertIn("UNION SELECT", exploit_log.get("payload", ""))
        self.assertGreater(exploit_log.get("records_returned", 0), 0, "SQL payload execution extracted data records")

    def test_05_network_evidence_can_be_retrieved(self) -> None:
        """5. Prove that network evidence confirms request reached the target."""
        evidence = get_network_evidence("ALT-1042")
        self.assertIsNotNone(evidence, "Network evidence should exist for ALT-1042")
        self.assertEqual(evidence["alert_id"], "ALT-1042")
        self.assertEqual(evidence["source_ip"], "10.20.14.52")
        self.assertEqual(evidence["target_asset"], "web-server-03")
        self.assertTrue(evidence["request_reached_target"], "Network evidence must confirm traffic reached target")
        self.assertEqual(evidence["proxy_node"], "Proxy-LB01")

    def test_06_network_topology_can_be_retrieved(self) -> None:
        """6. Prove that network topology can be retrieved showing 10.20.14.52 -> Proxy-LB01 -> web-server-03."""
        topology = get_network_topology()
        self.assertIn("nodes", topology)
        self.assertIn("routes", topology)

        node_ids = [n["id"] for n in topology["nodes"]]
        self.assertIn("10.20.14.52", node_ids)
        self.assertIn("Proxy-LB01", node_ids)
        self.assertIn("web-server-03", node_ids)

        # Confirm path connections
        paths = topology.get("active_paths", [])
        self.assertTrue(any(p.get("hops") == ["10.20.14.52", "Proxy-LB01", "web-server-03"] for p in paths),
                        "Topology must reflect the path 10.20.14.52 -> Proxy-LB01 -> web-server-03")

    def test_07_block_ip_executes(self) -> None:
        """7. Prove that block_ip executes and records rule."""
        result = block_ip("10.20.14.52")
        self.assertEqual(result["status"], "EXECUTED")
        self.assertEqual(result["action"], "block_ip")

        state = get_environment_state()
        self.assertIn("10.20.14.52", state["blocked_ips"])

    def test_08_verification_after_block_ip_fails(self) -> None:
        """8. Prove that verification after block_ip fails because traffic passes through Proxy-LB01."""
        # Action: block the external IP
        block_ip("10.20.14.52")

        # Verification must FAIL
        verification = verify_block("web-server-03")
        self.assertFalse(verification["verified"], "Verification must fail after only block_ip")
        self.assertEqual(verification["status"], "FAILED")
        self.assertTrue(verification["ip_blocked"])
        self.assertFalse(verification["upstream_route_blocked"])
        self.assertIn("Traffic bypass detected", verification["reason"])

    def test_09_proxy_lb01_can_be_discovered(self) -> None:
        """9. Prove that Proxy-LB01 can be discovered from network topology / asset metadata."""
        topology = get_network_topology()
        proxy_node = next((n for n in topology["nodes"] if n["id"] == "Proxy-LB01"), None)
        self.assertIsNotNone(proxy_node, "Proxy-LB01 must be identifiable in topology")
        self.assertEqual(proxy_node["type"], "reverse_proxy")

        # Also discoverable via web-server-03 asset profile
        asset = get_asset("web-server-03")
        self.assertEqual(asset.get("upstream_proxy"), "Proxy-LB01")

        # And discoverable via network evidence
        evidence = get_network_evidence("ALT-1042")
        self.assertEqual(evidence.get("proxy_node"), "Proxy-LB01")

    def test_10_block_upstream_route_executes(self) -> None:
        """10. Prove that block_upstream_route executes."""
        result = block_upstream_route("Proxy-LB01")
        self.assertEqual(result["status"], "EXECUTED")
        self.assertEqual(result["action"], "block_upstream_route")

        state = get_environment_state()
        self.assertIn("Proxy-LB01", state["blocked_upstream_routes"])

    def test_11_final_verification_succeeds(self) -> None:
        """11. Prove that final verification succeeds after block_upstream_route."""
        # First action (blocked external IP)
        block_ip("10.20.14.52")
        self.assertFalse(verify_block("web-server-03")["verified"])

        # Second action (block upstream route Proxy-LB01)
        block_result = block_upstream_route("Proxy-LB01")
        self.assertEqual(block_result["status"], "EXECUTED")

        # Final verification MUST succeed
        verification = verify_block("web-server-03")
        self.assertTrue(verification["verified"], "Verification must succeed after blocking upstream route")
        self.assertEqual(verification["status"], "SUCCESS")
        self.assertTrue(verification["upstream_route_blocked"])
        self.assertTrue(verification["active_path_severed"])

        # Environment state confirms containment
        state = get_environment_state()
        self.assertEqual(state["containment_status"], "CONTAINED")


if __name__ == "__main__":
    unittest.main()
