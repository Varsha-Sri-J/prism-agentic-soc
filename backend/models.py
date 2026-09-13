"""
PRISM Incident Models and State Management.
Defines persistent IncidentState, AgentTraceEntry, and DecisionRationale.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class DecisionRationale:
    """
    Structured, concise decision rationale without hidden chain-of-thought.
    """
    decision: str
    reason: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "decision": self.decision,
            "reason": self.reason,
        }


@dataclass
class AgentTraceEntry:
    """
    Structured trace entry for every step in the agent investigation.
    """
    step: int
    timestamp: str
    action_type: str  # e.g., "INVESTIGATE", "ACT", "VERIFY", "REPLAN", "CONCLUDE"
    tool_selected: Optional[str]
    tool_input: Dict[str, Any]
    summarized_result: str
    state_change: Dict[str, Any]
    rationale: DecisionRationale

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "timestamp": self.timestamp,
            "action_type": self.action_type,
            "tool_selected": self.tool_selected,
            "tool_input": self.tool_input,
            "summarized_result": self.summarized_result,
            "state_change": self.state_change,
            "rationale": self.rationale.to_dict(),
        }

    def format_display(self) -> str:
        """User-facing clean text representation of the trace step."""
        lines = [
            f"STEP {self.step} [{self.action_type}]",
            f"Decision: {self.rationale.decision}",
            f"Reason:   {self.rationale.reason}",
        ]
        if self.tool_selected:
            lines.append(f"Tool:     {self.tool_selected}({self.tool_input})")
            lines.append(f"Result:   {self.summarized_result}")
        return "\n".join(lines)


@dataclass
class IncidentState:
    """
    Persistent state of a SOC incident investigation.
    Maintains all collected evidence, hypothesis, actions, and verification history.
    """
    incident_id: str
    goal: str
    alert: Optional[Dict[str, Any]] = None
    evidence_collected: Dict[str, Any] = field(default_factory=lambda: {
        "alert": None,
        "asset": None,
        "vulnerabilities": [],
        "server_logs": [],
        "network_evidence": None,
        "network_topology": None,
    })
    current_hypothesis: str = "Triage in progress: Alert received, evidence uncollected."
    confidence: float = 0.0  # 0.0 (unconfirmed) to 1.0 (proven)
    investigation_history: List[Dict[str, Any]] = field(default_factory=list)
    actions_taken: List[Dict[str, Any]] = field(default_factory=list)
    verification_results: List[Dict[str, Any]] = field(default_factory=list)
    failed_actions: List[Dict[str, Any]] = field(default_factory=list)
    current_plan: List[str] = field(default_factory=lambda: [
        "1. Retrieve alert and determine target asset",
        "2. Gather asset context and check known vulnerabilities",
        "3. Inspect server logs for exploit execution",
        "4. Correlate network evidence for data transfer",
        "5. Contain threat if attack success is confirmed",
        "6. Verify containment and replan if bypassed",
    ])
    status: str = "TRIAGING"  # "TRIAGING", "INVESTIGATING", "CONTAINING", "VERIFYING", "REPLANNING", "CONTAINED", "CLOSED"
    trace: List[AgentTraceEntry] = field(default_factory=list)

    def add_trace(
        self,
        step: int,
        action_type: str,
        tool_selected: Optional[str],
        tool_input: Dict[str, Any],
        summarized_result: str,
        state_change: Dict[str, Any],
        rationale: DecisionRationale,
    ) -> AgentTraceEntry:
        """Appends a new structured trace entry and history record."""
        now_iso = datetime.now(timezone.utc).isoformat()
        entry = AgentTraceEntry(
            step=step,
            timestamp=now_iso,
            action_type=action_type,
            tool_selected=tool_selected,
            tool_input=tool_input,
            summarized_result=summarized_result,
            state_change=state_change,
            rationale=rationale,
        )
        self.trace.append(entry)
        self.investigation_history.append(entry.to_dict())
        return entry

    def record_action(self, action: Dict[str, Any]) -> None:
        """Records an executed response action."""
        self.actions_taken.append(action)

    def record_verification(self, verification: Dict[str, Any]) -> None:
        """Records a verification attempt, updating failed_actions if not verified."""
        self.verification_results.append(verification)
        if not verification.get("verified", False):
            failed_entry = {
                "action": self.actions_taken[-1] if self.actions_taken else None,
                "verification": verification,
                "reason": verification.get("reason", "Verification failed"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.failed_actions.append(failed_entry)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the entire incident state to a JSON-compatible dictionary."""
        return {
            "incident_id": self.incident_id,
            "goal": self.goal,
            "alert": self.alert,
            "evidence_collected": self.evidence_collected,
            "current_hypothesis": self.current_hypothesis,
            "confidence": round(self.confidence, 2),
            "investigation_history": self.investigation_history,
            "actions_taken": self.actions_taken,
            "verification_results": self.verification_results,
            "failed_actions": self.failed_actions,
            "current_plan": self.current_plan,
            "status": self.status,
            "trace": [t.to_dict() for t in self.trace],
        }

    def summary(self) -> str:
        """Concise summary of current incident state."""
        return (
            f"Incident {self.incident_id} [{self.status}]: "
            f"Confidence: {int(self.confidence * 100)}% | "
            f"Hypothesis: {self.current_hypothesis} | "
            f"Actions Taken: {len(self.actions_taken)} | "
            f"Failed Actions: {len(self.failed_actions)} | "
            f"Verifications: {len(self.verification_results)}"
        )

    def to_compact_state(self) -> Dict[str, Any]:
        """Returns a compact, token-efficient representation of incident state for LLM context."""
        alert_summary = None
        if self.alert:
            alert_summary = {
                "alert_id": self.alert.get("alert_id"),
                "name": self.alert.get("name"),
                "source_ip": self.alert.get("source_ip"),
                "target_asset": self.alert.get("target_asset"),
                "severity": self.alert.get("severity"),
            }

        asset_summary = None
        raw_asset = self.evidence_collected.get("asset")
        if raw_asset:
            asset_summary = {
                "asset_id": raw_asset.get("asset_id"),
                "role": raw_asset.get("role"),
                "os": raw_asset.get("os"),
                "criticality": raw_asset.get("criticality"),
            }

        vulns_summary = [
            {"cve": v.get("cve_id"), "title": v.get("title"), "status": v.get("status")}
            for v in self.evidence_collected.get("vulnerabilities", [])
        ]

        server_logs_summary = None
        raw_logs = self.evidence_collected.get("server_logs", [])
        if raw_logs:
            server_logs_summary = {
                "total_logs": len(raw_logs),
                "exploit_found": any("UNION" in l.get("raw_request", "") or "UNION" in l.get("payload", "") for l in raw_logs),
                "status_codes": [l.get("status_code") for l in raw_logs],
            }

        net_ev = self.evidence_collected.get("network_evidence")
        net_summary = None
        if net_ev:
            net_summary = {
                "flow_id": net_ev.get("flow_id"),
                "reached_target": net_ev.get("request_reached_target"),
                "proxy_node": net_ev.get("proxy_node"),
                "bytes_received": net_ev.get("bytes_received"),
            }

        topology_summary = None
        raw_topo = self.evidence_collected.get("network_topology")
        if raw_topo:
            topology_summary = {
                "nodes": [n.get("id") for n in raw_topo.get("nodes", [])],
                "active_paths": [p.get("hops") for p in raw_topo.get("active_paths", [])],
            }

        return {
            "incident_id": self.incident_id,
            "goal": self.goal,
            "status": self.status,
            "confidence": round(self.confidence, 2),
            "current_hypothesis": self.current_hypothesis,
            "alert": alert_summary,
            "evidence": {
                "asset": asset_summary,
                "vulnerabilities": vulns_summary if vulns_summary else None,
                "server_logs": server_logs_summary,
                "network_evidence": net_summary,
                "network_topology": topology_summary,
            },
            "actions_taken": [f"{a.get('action')}:{a.get('target')}" for a in self.actions_taken],
            "actions_count": len(self.actions_taken),
            "verifications_count": len(self.verification_results),
            "last_verification": self.verification_results[-1] if self.verification_results else None,
            "failed_actions": [
                {"action": f.get("action", {}).get("action"), "reason": f.get("reason")}
                for f in self.failed_actions
            ],
        }
