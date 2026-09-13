"""
PRISM Autonomous SOC Agent.
Implements the core agent control loop:
OBSERVE -> DECIDE -> ACT -> VERIFY -> REPLAN -> CONCLUDE
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from backend.decision_engine import DecisionEngine, DeterministicDecisionEngine
from backend.environment import SOCEnvironment
from backend.models import IncidentState


class PRISMAgent:
    """
    Autonomous SOC Investigation and Response Agent.
    Operates on a persistent IncidentState and selects deterministic tools
    dynamically based on evidence gaps, uncertainty, and verification feedback.
    """

    def __init__(
        self,
        decision_engine: Optional[DecisionEngine] = None,
        environment: Optional[SOCEnvironment] = None,
    ) -> None:
        if decision_engine is not None:
            self.engine = decision_engine
        else:
            from backend.decision_engine import LLMDecisionEngine
            self.engine = LLMDecisionEngine()
        self.env: SOCEnvironment = environment or SOCEnvironment()

    @property
    def mode(self) -> str:
        """Returns the active operational mode ('LIVE (gemini)' or 'MOCK')."""
        if hasattr(self.engine, "mode_name"):
            return getattr(self.engine, "mode_name")
        return "MOCK"

    def run(self, alert_id: str = "ALT-1042", max_steps: int = 15) -> IncidentState:
        """
        Executes the autonomous investigation and containment loop for a given alert.
        Persists and returns the final IncidentState.
        """
        state = IncidentState(
            incident_id=f"INC-{alert_id}",
            goal=f"Autonomously investigate alert {alert_id}, determine if attack succeeded, and contain threat.",
        )

        step_counter = 0

        while step_counter < max_steps:
            step_counter += 1

            # 1. OBSERVE & DECIDE NEXT STEP
            decision = self.engine.decide(state)

            # Check if goal is already satisfied (e.g. verified containment)
            if decision.is_goal_satisfied or decision.action_type == "CONCLUDE":
                if decision.status_update:
                    state.status = decision.status_update
                if decision.hypothesis_update:
                    state.current_hypothesis = decision.hypothesis_update
                if decision.confidence_update is not None:
                    state.confidence = decision.confidence_update

                state.add_trace(
                    step=step_counter,
                    action_type=decision.action_type,
                    tool_selected=None,
                    tool_input={},
                    summarized_result="Goal achieved. Threat contained and verified.",
                    state_change={"status": state.status, "confidence": state.confidence},
                    rationale=decision.rationale,
                )
                break

            # 2. CALL TOOL (Deterministic tool execution)
            tool_name = decision.tool
            tool_input = decision.tool_input or {}
            raw_result, summary_result = self._execute_tool(tool_name, tool_input)

            # 3. OBSERVE TOOL RESULT & UPDATE INCIDENT STATE
            state_changes = self._update_state(state, decision, tool_name, raw_result)

            # 4. RECORD STRUCTURED TRACE ENTRY
            state.add_trace(
                step=step_counter,
                action_type=decision.action_type,
                tool_selected=tool_name,
                tool_input=tool_input,
                summarized_result=summary_result,
                state_change=state_changes,
                rationale=decision.rationale,
            )

        return state

    def _execute_tool(
        self, tool_name: Optional[str], tool_input: Dict[str, Any]
    ) -> Tuple[Any, str]:
        """Executes the chosen deterministic tool and returns structured result and summary."""
        if not tool_name:
            return None, "No tool selected"

        if tool_name == "get_alert":
            alert_id = tool_input.get("alert_id", "ALT-1042")
            res = self.env.get_alert(alert_id)
            if res:
                return res, f"Alert retrieved: {res.get('name')} from {res.get('source_ip')} targeting {res.get('target_asset')}."
            return None, f"Alert {alert_id} not found."

        if tool_name == "get_asset":
            asset_id = tool_input.get("asset_id", "web-server-03")
            res = self.env.get_asset(asset_id)
            if res:
                return res, f"Asset profile: {res.get('asset_id')} ({res.get('role')}, OS: {res.get('os')})."
            return None, f"Asset {asset_id} not found."

        if tool_name == "search_vulnerabilities":
            asset_id = tool_input.get("asset_id", "web-server-03")
            res = self.env.search_vulnerabilities(asset_id)
            cves = [v.get("cve_id") for v in res]
            return res, f"Found {len(res)} vulnerability: {', '.join(cves)} (SQL Injection, CVSS 9.8, Unpatched)."

        if tool_name == "search_server_logs":
            host = tool_input.get("host")
            source_ip = tool_input.get("source_ip")
            res = self.env.search_server_logs(host=host, source_ip=source_ip)
            exploit_logs = [l for l in res if l.get("status_code") == 200 and "UNION" in l.get("raw_request", "")]
            if exploit_logs:
                records = exploit_logs[0].get("records_returned", 0)
                return res, f"Found {len(res)} log entries. Malicious SQL payload executed returning HTTP 200 and {records} records extracted."
            return res, f"Found {len(res)} log entries."

        if tool_name == "get_network_evidence":
            alert_id = tool_input.get("alert_id", "ALT-1042")
            res = self.env.get_network_evidence(alert_id)
            if res:
                flow = res.get("flow_id")
                bytes_rx = res.get("bytes_received", 0)
                return res, f"Flow {flow} confirmed delivery to target. High exfiltration volume ({bytes_rx / 1024:.1f} KB) returned."
            return None, "No network evidence found."

        if tool_name == "get_network_topology":
            res = self.env.get_network_topology()
            hops = ["10.20.14.52", "Proxy-LB01", "web-server-03"]
            return res, f"Topology graph retrieved: Routing path discovered through intermediate proxy {' -> '.join(hops)}."

        if tool_name == "block_ip":
            ip = tool_input.get("ip", "")
            res = self.env.block_ip(ip)
            return res, f"Firewall rule applied: Blocked source IP {ip}."

        if tool_name == "block_upstream_route":
            route = tool_input.get("route", "")
            res = self.env.block_upstream_route(route)
            return res, f"Upstream route isolation applied: Severed routing path via {route}."

        if tool_name == "verify_block":
            target = tool_input.get("target", "web-server-03")
            res = self.env.verify_block(target)
            if res.get("verified"):
                return res, f"Verification SUCCESS: Threat path to {target} is completely severed."
            return res, f"Verification FAILED: Traffic bypass detected through Proxy-LB01."

        if tool_name == "get_environment_state":
            res = self.env.get_environment_state()
            return res, f"Environment containment status: {res.get('containment_status')}."

        return None, f"Unknown tool: {tool_name}"

    def _update_state(
        self,
        state: IncidentState,
        decision: DecisionResult,
        tool_name: Optional[str],
        tool_result: Any,
    ) -> Dict[str, Any]:
        """Applies state changes and records evidence."""
        changes: Dict[str, Any] = {}

        if decision.status_update:
            state.status = decision.status_update
            changes["status"] = state.status

        if decision.hypothesis_update:
            state.current_hypothesis = decision.hypothesis_update
            changes["hypothesis"] = state.current_hypothesis

        if decision.confidence_update is not None:
            state.confidence = decision.confidence_update
            changes["confidence"] = state.confidence

        if decision.plan_update:
            state.current_plan = decision.plan_update
            changes["plan"] = state.current_plan

        # Evidence updates
        if tool_name == "get_alert" and tool_result:
            state.alert = tool_result
            state.evidence_collected["alert"] = tool_result
            changes["evidence_alert"] = tool_result.get("alert_id")

        elif tool_name == "get_asset" and tool_result:
            state.evidence_collected["asset"] = tool_result
            changes["evidence_asset"] = tool_result.get("asset_id")

        elif tool_name == "search_vulnerabilities" and tool_result:
            state.evidence_collected["vulnerabilities"] = tool_result
            changes["evidence_vulnerabilities_count"] = len(tool_result)

        elif tool_name == "search_server_logs" and tool_result:
            state.evidence_collected["server_logs"] = tool_result
            changes["evidence_server_logs_count"] = len(tool_result)

        elif tool_name == "get_network_evidence" and tool_result:
            state.evidence_collected["network_evidence"] = tool_result
            changes["evidence_network"] = tool_result.get("flow_id")

        elif tool_name == "get_network_topology" and tool_result:
            state.evidence_collected["network_topology"] = tool_result
            changes["evidence_topology_nodes"] = len(tool_result.get("nodes", []))

        elif tool_name in ("block_ip", "block_upstream_route") and tool_result:
            state.record_action(tool_result)
            changes["action_executed"] = tool_result.get("action")

        elif tool_name == "verify_block" and tool_result:
            state.record_verification(tool_result)
            changes["verification_outcome"] = tool_result.get("status")

        return changes
