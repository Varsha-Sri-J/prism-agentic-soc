"""
PRISM Deterministic SOC Tools
Exposes the required deterministic interfaces operating on the local synthetic environment.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from backend.environment import SOCEnvironment

# Default singleton instance
_default_env = SOCEnvironment()


def get_environment() -> SOCEnvironment:
    """Get the active singleton SOCEnvironment."""
    return _default_env


def reset_environment() -> None:
    """Reset the default SOCEnvironment back to initial state."""
    _default_env.reset()


def get_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve security alert by alert_id."""
    return _default_env.get_alert(alert_id)


def get_asset(asset_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve asset details by asset_id or hostname."""
    return _default_env.get_asset(asset_id)


def search_vulnerabilities(asset_id: str) -> List[Dict[str, Any]]:
    """Search vulnerabilities associated with a target asset."""
    return _default_env.search_vulnerabilities(asset_id)


def search_server_logs(host: Optional[str] = None, source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """Search server logs for a given host and/or source_ip."""
    return _default_env.search_server_logs(host=host, source_ip=source_ip)


def get_network_evidence(alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve network traffic evidence associated with an alert."""
    return _default_env.get_network_evidence(alert_id)


def get_network_topology() -> Dict[str, Any]:
    """Retrieve the current network topology mapping."""
    return _default_env.get_network_topology()


def block_ip(ip: str) -> Dict[str, Any]:
    """Block an IP address at the firewall perimeter."""
    return _default_env.block_ip(ip)


def block_upstream_route(route: str) -> Dict[str, Any]:
    """Block an upstream forwarding route (e.g. reverse proxy node)."""
    return _default_env.block_upstream_route(route)


def verify_block(target: str) -> Dict[str, Any]:
    """Verify whether containment blocked traffic reaching target host."""
    return _default_env.verify_block(target)


def get_environment_state() -> Dict[str, Any]:
    """Return the current state of the synthetic environment."""
    return _default_env.get_environment_state()
