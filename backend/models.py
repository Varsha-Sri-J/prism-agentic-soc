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
