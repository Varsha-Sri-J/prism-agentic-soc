"""
PRISM SOC Environment
Simulates a Security Operations Center local environment with synthetic datasets,
network topology, and stateful firewall containment verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class SOCEnvironment:
    """
    Simulated SOC runtime environment.
    Loads synthetic JSON datasets from the data directory and maintains
    in-memory firewall and containment states.
    """

    def __init__(self, data_dir: Optional[Path | str] = None) -> None:
        if data_dir is None:
            # Default to <repo_root>/data
            self.data_dir = Path(__file__).resolve().parent.parent / "data"
        else:
            self.data_dir = Path(data_dir)

        self.alerts: List[Dict[str, Any]] = []
        self.assets: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.server_logs: List[Dict[str, Any]] = []
        self.network_evidence: List[Dict[str, Any]] = []
        self.topology: Dict[str, Any] = {}
        self.firewall_state: Dict[str, Any] = {}

        self.load_data()

    def load_data(self) -> None:
        """Loads or reloads synthetic data from JSON files."""
        self.alerts = self._read_json_file("alerts.json").get("alerts", [])
        self.assets = self._read_json_file("assets.json").get("assets", [])
        self.vulnerabilities = self._read_json_file("vulnerabilities.json").get("vulnerabilities", [])
        self.server_logs = self._read_json_file("server_logs.json").get("logs", [])
        self.network_evidence = self._read_json_file("network_evidence.json").get("evidence", [])
        self.topology = self._read_json_file("topology.json")
        self.firewall_state = self._read_json_file("firewall_state.json")

        # Runtime dynamic state sets
        self.blocked_ips: List[str] = list(self.firewall_state.get("blocked_ips", []))
        self.blocked_upstream_routes: List[str] = list(self.firewall_state.get("blocked_upstream_routes", []))
        self.action_history: List[Dict[str, Any]] = []

    def _read_json_file(self, filename: str) -> Dict[str, Any]:
        file_path = self.data_dir / filename
        if not file_path.exists():
            return {}
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def reset(self) -> None:
        """Resets the environment back to initial clean state."""
        self.load_data()

    # --- Inspection Tools ---

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve security alert details by alert ID."""
        for alert in self.alerts:
            if alert.get("alert_id") == alert_id:
                return dict(alert)
        return None

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve asset inventory record by asset_id or hostname."""
        for asset in self.assets:
            if asset.get("asset_id") == asset_id or asset.get("hostname") == asset_id:
                return dict(asset)
        return None

    def search_vulnerabilities(self, asset_id: str) -> List[Dict[str, Any]]:
        """Search vulnerabilities affecting a specified asset."""
        results = [
            dict(v) for v in self.vulnerabilities
            if v.get("asset_id") == asset_id
        ]
        return results

    def search_server_logs(
        self, host: Optional[str] = None, source_ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search server logs by host and/or source_ip (supports client_ip / forwarded IP).
        """
        matched: List[Dict[str, Any]] = []
        for log in self.server_logs:
            if host and log.get("host") != host:
                continue
            if source_ip:
                log_source = log.get("source_ip")
                log_proxy = log.get("proxy_ip")
                if source_ip not in (log_source, log_proxy):
                    continue
            matched.append(dict(log))
        return matched

    def get_network_evidence(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve network traffic evidence associated with an alert."""
        for ev in self.network_evidence:
            if ev.get("alert_id") == alert_id:
                return dict(ev)
        return None

    def get_network_topology(self) -> Dict[str, Any]:
        """Return the current network topology map."""
        return dict(self.topology)

    # --- Response & Containment Tools ---

    def block_ip(self, ip: str) -> Dict[str, Any]:
        """
        Applies a firewall block rule for a source IP.
        """
        if ip not in self.blocked_ips:
            self.blocked_ips.append(ip)

        action_result = {
            "status": "EXECUTED",
            "action": "block_ip",
            "target": ip,
            "rule_id": f"RULE-BLOCK-IP-{len(self.blocked_ips):03d}",
            "message": f"Successfully applied perimeter firewall block rule for IP: {ip}",
        }
        self.action_history.append(action_result)
        return action_result

    def block_upstream_route(self, route: str) -> Dict[str, Any]:
        """
        Blocks or isolates an upstream routing node (e.g. reverse proxy or route path).
        """
        if route not in self.blocked_upstream_routes:
            self.blocked_upstream_routes.append(route)

        action_result = {
            "status": "EXECUTED",
            "action": "block_upstream_route",
            "target": route,
            "rule_id": f"RULE-BLOCK-ROUTE-{len(self.blocked_upstream_routes):03d}",
            "message": f"Successfully severed upstream forwarding route through: {route}",
        }
        self.action_history.append(action_result)
        return action_result

    def verify_block(self, target: str) -> Dict[str, Any]:
        """
        Verifies whether containment was successful for traffic reaching the target.

        In the demo topology:
            10.20.14.52 -> Proxy-LB01 -> web-server-03

        If only 10.20.14.52 is blocked, verification FAILS because the attack traffic
        is channeled through Proxy-LB01 and backend web-server-03 continues to accept
        the proxy connection.

        If Proxy-LB01 upstream route is blocked, verification SUCCEEDS.
        """
        # Identify whether the target refers to web-server-03
        is_web_server_03 = target in ("web-server-03", "192.168.10.15", "web-server-03.corp.internal")

        if not is_web_server_03:
            return {
                "verified": False,
                "status": "FAILED",
                "target": target,
                "reason": f"Unknown or unmonitored target: {target}",
            }

        # Check if upstream route (Proxy-LB01) is blocked
        proxy_blocked = "Proxy-LB01" in self.blocked_upstream_routes

        # Check if external IP is blocked
        ip_blocked = "10.20.14.52" in self.blocked_ips

        if proxy_blocked:
            return {
                "verified": True,
                "status": "SUCCESS",
                "target": target,
                "upstream_route_blocked": True,
                "ip_blocked": ip_blocked,
                "active_path_severed": True,
                "message": (
                    "Verification passed: Upstream route via Proxy-LB01 has been severed. "
                    "Synthetic probe packets from attacker cannot reach web-server-03."
                ),
            }

        if ip_blocked:
            return {
                "verified": False,
                "status": "FAILED",
                "target": target,
                "upstream_route_blocked": False,
                "ip_blocked": True,
                "active_path_severed": False,
                "reason": (
                    "Verification failed: Traffic bypass detected. While 10.20.14.52 is blocked at the perimeter, "
                    "traffic forwarded via intermediate reverse-proxy Proxy-LB01 continues to reach web-server-03. "
                    "Upstream route isolation is required."
                ),
            }

        return {
            "verified": False,
            "status": "FAILED",
            "target": target,
            "upstream_route_blocked": False,
            "ip_blocked": False,
            "active_path_severed": False,
            "reason": "Verification failed: No containment rules active. Malicious traffic reaches target uninterrupted.",
        }

    def get_environment_state(self) -> Dict[str, Any]:
        """Returns the full runtime state of the synthetic environment."""
        is_contained = "Proxy-LB01" in self.blocked_upstream_routes
        return {
            "environment_mode": "SYNTHETIC_SOC",
            "containment_status": "CONTAINED" if is_contained else "UNCONTAINED",
            "blocked_ips": list(self.blocked_ips),
            "blocked_upstream_routes": list(self.blocked_upstream_routes),
            "total_actions_executed": len(self.action_history),
            "action_history": list(self.action_history),
            "open_alerts": [a["alert_id"] for a in self.alerts if a.get("status") == "OPEN"],
            "assets_monitored": [a["asset_id"] for a in self.assets],
        }
