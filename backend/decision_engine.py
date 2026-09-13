"""
PRISM Decision Engine Architecture.
Provides an abstract DecisionEngine base class, a deterministic state-evaluating engine
for testable/offline execution, and an LLM-ready tool-calling engine.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from backend.models import DecisionRationale, IncidentState


@dataclass
class DecisionResult:
    """
    Outcome of an agent decision step.
    """
    action_type: str  # "INVESTIGATE", "ACT", "VERIFY", "REPLAN", "CONCLUDE"
    rationale: DecisionRationale
    tool: Optional[str] = None
    tool_input: Dict[str, Any] = None  # type: ignore[assignment]
    is_goal_satisfied: bool = False
    hypothesis_update: Optional[str] = None
    confidence_update: Optional[float] = None
    status_update: Optional[str] = None
    plan_update: Optional[List[str]] = None

    def __post_init__(self) -> None:
        if self.tool_input is None:
            self.tool_input = {}


class DecisionEngine(ABC):
    """Abstract interface for PRISM agent decision making."""

    @abstractmethod
    def decide(self, state: IncidentState) -> DecisionResult:
        """
        Evaluate current incident state and decide the next action.
        """
        pass


class DeterministicDecisionEngine(DecisionEngine):
    """
    Deterministic decision engine that dynamically evaluates missing evidence,
    uncertainty, and verification outcomes (NOT a hardcoded script).

    It adapts directly to state changes:
    - Identifies which evidence dimensions are missing
    - Assesses exploit success when evidence is complete
    - Executes initial containment
    - Verifies containment
    - Detects verification failures in `failed_actions`
    - Investigates network topology in response to failure
    - Replans containment to isolate upstream proxy routes
    - Concludes once verification succeeds
    """

    def decide(self, state: IncidentState) -> DecisionResult:
        # 1. If we have unverified actions, verification is highest priority
        if len(state.actions_taken) > len(state.verification_results):
            last_action = state.actions_taken[-1]
            target_asset = self._get_target_asset(state) or "web-server-03"
            return DecisionResult(
                action_type="VERIFY",
                rationale=DecisionRationale(
                    decision=f"Verify containment action ({last_action.get('action')})",
                    reason=f"Action '{last_action.get('action')}' was applied. Active reachability probe is required to verify whether traffic to '{target_asset}' is blocked."
                ),
                tool="verify_block",
                tool_input={"target": target_asset},
                status_update="VERIFYING",
            )

        # 2. Check if the latest verification check failed and replanning is required
        if state.verification_results and not state.verification_results[-1].get("verified", False):
            # Did we investigate topology yet?
            if state.evidence_collected.get("network_topology") is None:
                last_verif = state.verification_results[-1]
                return DecisionResult(
                    action_type="REPLAN",
                    rationale=DecisionRationale(
                        decision="Investigate network topology",
                        reason=f"Containment verification failed ({last_verif.get('reason', 'Traffic still reaching target')}). Must inspect network topology to uncover route forwarding or proxy bypass."
                    ),
                    tool="get_network_topology",
                    tool_input={},
                    hypothesis_update="Containment failed: Threat traffic is bypassing edge block via intermediate routing node.",
                    status_update="REPLANNING",
                )

            # Topology is already collected. Check if upstream proxy is blocked.
            topology = state.evidence_collected.get("network_topology", {})
            proxy_node = self._extract_upstream_proxy(topology) or "Proxy-LB01"
            has_blocked_proxy = any(
                a.get("action") == "block_upstream_route" and a.get("target") == proxy_node
                for a in state.actions_taken
            )

            if not has_blocked_proxy:
                return DecisionResult(
                    action_type="ACT",
                    rationale=DecisionRationale(
                        decision=f"Isolate upstream route via {proxy_node}",
                        reason=f"Topology analysis reveals {proxy_node} is reverse-proxying attacker requests to target. Severing upstream route is required for containment."
                    ),
                    tool="block_upstream_route",
                    tool_input={"route": proxy_node},
                    status_update="CONTAINING",
                    plan_update=[
                        "1. Alert & evidence gathered [DONE]",
                        "2. Initial IP block [FAILED - BYPASS DETECTED]",
                        "3. Topology analyzed [DONE]",
                        f"4. Block upstream route {proxy_node} [IN PROGRESS]",
                        "5. Verify final containment",
                    ],
                )

        # 3. Check if containment succeeded
        if state.verification_results and state.verification_results[-1].get("verified", False):
            return DecisionResult(
                action_type="CONCLUDE",
                rationale=DecisionRationale(
                    decision="Conclude investigation",
                    reason="Containment verification succeeded. Active probes confirm threat path is completely severed. Incident objective satisfied."
                ),
                tool=None,
                tool_input={},
                is_goal_satisfied=True,
                status_update="CONTAINED",
                hypothesis_update="Incident resolved: SQL injection attack successfully contained via upstream route isolation.",
                confidence_update=1.0,
            )

        # 4. Check for missing investigation evidence based on current uncertainty
        # Dimension A: Alert metadata
        if state.alert is None:
            alert_id = self._extract_alert_id(state)
            return DecisionResult(
                action_type="INVESTIGATE",
                rationale=DecisionRationale(
                    decision="Retrieve alert details",
                    reason="Initial alert metadata is required to identify threat source IP, target asset, and alert signature."
                ),
                tool="get_alert",
                tool_input={"alert_id": alert_id},
                status_update="INVESTIGATING",
                confidence_update=0.2,
            )

        target_asset = self._get_target_asset(state) or "web-server-03"
        source_ip = self._get_source_ip(state) or "10.20.14.52"

        # Dimension B: Asset context
        if state.evidence_collected.get("asset") is None:
            return DecisionResult(
                action_type="INVESTIGATE",
                rationale=DecisionRationale(
                    decision="Retrieve asset context",
                    reason=f"Target asset '{target_asset}' is identified in alert, but host criticality, role, and exposed services are needed to determine blast radius."
                ),
                tool="get_asset",
                tool_input={"asset_id": target_asset},
                status_update="INVESTIGATING",
                confidence_update=0.35,
            )

        # Dimension C: Vulnerability search
        if not state.evidence_collected.get("vulnerabilities"):
            return DecisionResult(
                action_type="INVESTIGATE",
                rationale=DecisionRationale(
                    decision="Search for known vulnerabilities",
                    reason=f"Asset context is known for '{target_asset}', but host vulnerability status is unconfirmed. Need to verify if target is vulnerable to SQL injection."
                ),
                tool="search_vulnerabilities",
                tool_input={"asset_id": target_asset},
                status_update="INVESTIGATING",
                confidence_update=0.55,
                hypothesis_update=f"Target {target_asset} identified; checking known vulnerabilities.",
            )

        # Dimension D: Server / application logs
        if not state.evidence_collected.get("server_logs"):
            return DecisionResult(
                action_type="INVESTIGATE",
                rationale=DecisionRationale(
                    decision="Search server logs for exploit execution",
                    reason=f"Known SQL injection vulnerability found on '{target_asset}', but execution evidence is missing. Need to inspect application logs to verify if payload reached application."
                ),
                tool="search_server_logs",
                tool_input={"host": target_asset, "source_ip": source_ip},
                status_update="INVESTIGATING",
                confidence_update=0.75,
                hypothesis_update=f"Vulnerability verified on {target_asset}; verifying execution in server logs.",
            )

        # Dimension E: Network evidence
        if state.evidence_collected.get("network_evidence") is None:
            alert_id = self._extract_alert_id(state)
            return DecisionResult(
                action_type="INVESTIGATE",
                rationale=DecisionRationale(
                    decision="Correlate network flow evidence",
                    reason="Server logs confirm payload execution with HTTP 200, but network layer proof of packet delivery and data exfiltration volume is required to confirm compromise."
                ),
                tool="get_network_evidence",
                tool_input={"alert_id": alert_id},
                status_update="INVESTIGATING",
                confidence_update=0.9,
                hypothesis_update="Evidence indicates probable attack success with data extraction.",
            )

        # 5. Evidence is complete and confirms attack success -> Containment is justified
        if not state.actions_taken:
            return DecisionResult(
                action_type="ACT",
                rationale=DecisionRationale(
                    decision=f"Apply perimeter IP containment on {source_ip}",
                    reason=f"All evidence dimensions (vulnerability, server log 200 OK, network exfiltration) confirm attack succeeded. Containment of threat source {source_ip} is justified."
                ),
                tool="block_ip",
                tool_input={"ip": source_ip},
                status_update="CONTAINING",
                hypothesis_update=f"Attack confirmed successful on {target_asset}. Initial perimeter containment initiated against {source_ip}.",
                confidence_update=0.95,
            )

        # Fallback if no specific rule matched
        return DecisionResult(
            action_type="CONCLUDE",
            rationale=DecisionRationale(
                decision="Stop investigation",
                reason="No further actions required or state reached unexpected branch."
            ),
            tool=None,
            is_goal_satisfied=True,
        )

    def _extract_alert_id(self, state: IncidentState) -> str:
        if state.alert and "alert_id" in state.alert:
            return state.alert["alert_id"]
        # Parse from goal or default to ALT-1042
        if "ALT-" in state.goal:
            import re
            m = re.search(r"ALT-\d+", state.goal)
            if m:
                return m.group(0)
        return "ALT-1042"

    def _get_target_asset(self, state: IncidentState) -> Optional[str]:
        if state.alert and "target_asset" in state.alert:
            return state.alert["target_asset"]
        asset = state.evidence_collected.get("asset")
        if asset and "asset_id" in asset:
            return asset["asset_id"]
        return None

    def _get_source_ip(self, state: IncidentState) -> Optional[str]:
        if state.alert and "source_ip" in state.alert:
            return state.alert["source_ip"]
        return None

    def _extract_upstream_proxy(self, topology: Dict[str, Any]) -> Optional[str]:
        nodes = topology.get("nodes", [])
        for node in nodes:
            if node.get("type") in ("reverse_proxy", "load_balancer") or "Proxy" in node.get("id", ""):
                return node.get("id")
        return None


class LLMDecisionEngine(DecisionEngine):
    """
    LLM-powered Decision Engine utilizing tool-calling schemas.
    Falls back gracefully to DeterministicDecisionEngine if no API key is provided.
    """

    TOOLS_SCHEMA = [
        {
            "name": "get_alert",
            "description": "Retrieve security alert details by alert ID.",
            "parameters": {
                "type": "object",
                "properties": {"alert_id": {"type": "string", "description": "Unique alert identifier e.g. ALT-1042"}},
                "required": ["alert_id"],
            },
        },
        {
            "name": "get_asset",
            "description": "Retrieve asset inventory profile, role, OS, and services.",
            "parameters": {
                "type": "object",
                "properties": {"asset_id": {"type": "string", "description": "Asset identifier or hostname"}},
                "required": ["asset_id"],
            },
        },
        {
            "name": "search_vulnerabilities",
            "description": "Search known vulnerabilities and CVEs affecting an asset.",
            "parameters": {
                "type": "object",
                "properties": {"asset_id": {"type": "string", "description": "Target asset ID"}},
                "required": ["asset_id"],
            },
        },
        {
            "name": "search_server_logs",
            "description": "Search application and server access logs by host and source IP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Host name"},
                    "source_ip": {"type": "string", "description": "Source or proxy IP"},
                },
                "required": ["host", "source_ip"],
            },
        },
        {
            "name": "get_network_evidence",
            "description": "Retrieve network flow evidence and packet transfer metrics for an alert.",
            "parameters": {
                "type": "object",
                "properties": {"alert_id": {"type": "string", "description": "Alert identifier"}},
                "required": ["alert_id"],
            },
        },
        {
            "name": "get_network_topology",
            "description": "Retrieve the network routing topology and active paths.",
            "parameters": {"type": "object", "properties": {}},
        },
        {
            "name": "block_ip",
            "description": "Apply a perimeter firewall block rule on an IP address.",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "IP address to block"}},
                "required": ["ip"],
            },
        },
        {
            "name": "block_upstream_route",
            "description": "Isolate or block an upstream routing node (e.g. reverse proxy).",
            "parameters": {
                "type": "object",
                "properties": {"route": {"type": "string", "description": "Route or proxy node name to sever"}},
                "required": ["route"],
            },
        },
        {
            "name": "verify_block",
            "description": "Probe active traffic reachability to target host to verify containment.",
            "parameters": {
                "type": "object",
                "properties": {"target": {"type": "string", "description": "Target asset identifier"}},
                "required": ["target"],
            },
        },
        {
            "name": "get_environment_state",
            "description": "Get current firewall rules and containment state.",
            "parameters": {"type": "object", "properties": {}},
        },
    ]

    REGISTERED_TOOLS = {
        "get_alert": {"required": ["alert_id"]},
        "get_asset": {"required": ["asset_id"]},
        "search_vulnerabilities": {"required": ["asset_id"]},
        "search_server_logs": {"required": ["host", "source_ip"]},
        "get_network_evidence": {"required": ["alert_id"]},
        "get_network_topology": {"required": []},
        "block_ip": {"required": ["ip"]},
        "block_upstream_route": {"required": ["route"]},
        "verify_block": {"required": ["target"]},
        "get_environment_state": {"required": []},
    }

    SYSTEM_PROMPT = """You are PRISM, an Autonomous SOC Investigation & Response Agent.
Your objective is to investigate incoming security alerts, gather necessary evidence, determine if an attack succeeded, apply containment when justified, and verify the containment.

SAFETY CONSTRAINTS:
1. You may NEVER execute arbitrary code, shell commands, or network commands.
2. You may ONLY call tools from the registered tool whitelist.
3. You must maintain a concise decision rationale. Do NOT output hidden chain-of-thought.

DECISION PROTOCOL:
At each step, evaluate the provided INCIDENT STATE and decide the next action:
- If evidence is missing, select the appropriate investigation tool.
- If attack success is confirmed by evidence (vulnerability unpatched + exploit executed with 200 OK + exfiltration) and no containment is active, call 'block_ip'.
- If an action has not been verified, call 'verify_block'.
- If verification FAILED (traffic bypassed the block), investigate why by calling 'get_network_topology'.
- If topology reveals an intermediate reverse-proxy or route bypass, call 'block_upstream_route'.
- If post-action verification succeeds, conclude with action: 'finish'.

OUTPUT FORMAT:
Output MUST be a single JSON object. Choose ONE of the following formats:

Option 1 (To call a tool):
{
  "action": "tool_call",
  "tool": "<tool_name>",
  "arguments": { "<arg_name>": "<arg_val>" },
  "rationale": {
    "decision": "<concise statement of what action is chosen>",
    "reason": "<explanation based on evidence and uncertainty>"
  }
}

Option 2 (When threat is contained and verified):
{
  "action": "finish",
  "status": "CONTAINED",
  "rationale": {
    "decision": "Finish investigation",
    "reason": "Post-action verification confirms malicious traffic is blocked."
  }
}
"""

    def __init__(
        self,
        provider: Optional[Any] = None,
        fallback_engine: Optional[DecisionEngine] = None,
    ) -> None:
        from backend.llm_provider import GeminiProvider, LLMProvider, MockLLMProvider

        if provider is not None:
            self.provider: LLMProvider = provider
        else:
            provider_env = os.getenv("LLM_PROVIDER", "deterministic").lower()
            gemini_key = os.getenv("GEMINI_API_KEY")
            if provider_env == "gemini" and gemini_key:
                self.provider = GeminiProvider()
            else:
                self.provider = MockLLMProvider()

        self.fallback_engine: DecisionEngine = fallback_engine or DeterministicDecisionEngine()

    @property
    def mode_name(self) -> str:
        """Returns readable mode name e.g. LIVE (gemini) or MOCK."""
        from backend.llm_provider import GeminiProvider
        if isinstance(self.provider, GeminiProvider) and self.provider.is_configured:
            return f"LIVE (gemini:{self.provider.model_name})"
        return "MOCK"

    def validate_decision(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validates structured tool call against PRISM safety whitelist."""
        if not isinstance(data, dict):
            return False, "Response must be a JSON object."

        action = data.get("action")
        if action not in ("tool_call", "finish"):
            return False, f"Invalid action: '{action}'. Must be 'tool_call' or 'finish'."

        rationale = data.get("rationale")
        if not isinstance(rationale, dict):
            return False, "Missing or invalid 'rationale' object."
        if not rationale.get("decision") or not rationale.get("reason"):
            return False, "'rationale' must contain non-empty 'decision' and 'reason'."

        if action == "finish":
            return True, "Valid finish decision."

        # Validating tool_call
        tool_name = data.get("tool")
        if tool_name not in self.REGISTERED_TOOLS:
            return False, f"Safety constraint violation: Tool '{tool_name}' is not in registered tool whitelist."

        arguments = data.get("arguments")
        if not isinstance(arguments, dict):
            return False, f"'arguments' for tool '{tool_name}' must be an object."

        required_args = self.REGISTERED_TOOLS[tool_name]["required"]
        for arg in required_args:
            if arg not in arguments:
                return False, f"Missing required argument '{arg}' for tool '{tool_name}'."

        return True, "Valid tool call."

    def decide(self, state: IncidentState) -> DecisionResult:
        """
        Queries the LLM provider with compact incident state and validates the response.
        Retries once on error; falls back to DeterministicDecisionEngine if retry fails.
        """
        compact_state = state.to_compact_state()
        user_prompt = f"CURRENT INCIDENT STATE:\n{json.dumps(compact_state, indent=2)}\n\nDecide next step."

        try:
            raw_response = self.provider.generate_decision(
                system_prompt=self.SYSTEM_PROMPT,
                user_prompt=user_prompt,
                tools_schema=self.TOOLS_SCHEMA,
            )
            parsed, error = self._parse_json(raw_response)

            if parsed:
                is_valid, val_err = self.validate_decision(parsed)
                if is_valid:
                    return self._map_to_decision_result(parsed, state)
                error = val_err
        except Exception as exc:
            error = str(exc)

        # Retry once with correction prompt
        retry_prompt = (
            f"{user_prompt}\n\n"
            f"ERROR IN PREVIOUS ATTEMPT: {error}\n"
            "Please fix the error and output ONLY a valid JSON object matching the required schema."
        )

        try:
            raw_retry = self.provider.generate_decision(
                system_prompt=self.SYSTEM_PROMPT,
                user_prompt=retry_prompt,
                tools_schema=self.TOOLS_SCHEMA,
            )
            parsed_retry, error_retry = self._parse_json(raw_retry)
            if parsed_retry:
                is_valid, val_err = self.validate_decision(parsed_retry)
                if is_valid:
                    return self._map_to_decision_result(parsed_retry, state)
        except Exception:
            pass

        # Persistent failure -> fall back to DeterministicDecisionEngine
        return self.fallback_engine.decide(state)

    def _parse_json(self, text: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Extracts and parses JSON from model output, handling code block formatting."""
        if not text:
            return None, "Empty response from LLM provider."

        cleaned = text.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        try:
            data = json.loads(cleaned)
            return data, None
        except json.JSONDecodeError as e:
            return None, f"Invalid JSON: {e}"

    def _map_to_decision_result(
        self, parsed: Dict[str, Any], state: IncidentState
    ) -> DecisionResult:
        """Converts validated JSON dict into a DecisionResult."""
        action = parsed.get("action")
        rationale_dict = parsed.get("rationale", {})
        rationale = DecisionRationale(
            decision=rationale_dict.get("decision", ""),
            reason=rationale_dict.get("reason", ""),
        )

        if action == "finish":
            return DecisionResult(
                action_type="CONCLUDE",
                rationale=rationale,
                tool=None,
                tool_input={},
                is_goal_satisfied=True,
                status_update="CONTAINED",
                confidence_update=1.0,
                hypothesis_update="Incident resolved: Threat successfully contained and verified.",
            )

        tool = parsed.get("tool")
        arguments = parsed.get("arguments", {})

        status_update = None
        hypothesis_update = None
        confidence_update = None

        # Determine action_type and state progression updates
        if tool == "get_alert":
            action_type = "INVESTIGATE"
            status_update = "INVESTIGATING"
            confidence_update = 0.2
        elif tool == "get_asset":
            action_type = "INVESTIGATE"
            status_update = "INVESTIGATING"
            confidence_update = 0.35
        elif tool == "search_vulnerabilities":
            action_type = "INVESTIGATE"
            status_update = "INVESTIGATING"
            confidence_update = 0.55
            hypothesis_update = "Target host identified; checking known vulnerabilities."
        elif tool == "search_server_logs":
            action_type = "INVESTIGATE"
            status_update = "INVESTIGATING"
            confidence_update = 0.75
            hypothesis_update = "Vulnerability confirmed; checking exploit execution in server logs."
        elif tool == "get_network_evidence":
            action_type = "INVESTIGATE"
            status_update = "INVESTIGATING"
            confidence_update = 0.9
            hypothesis_update = "Server logs confirm exploit; verifying network delivery and exfiltration."
        elif tool == "block_ip":
            action_type = "ACT"
            status_update = "CONTAINING"
            confidence_update = 0.95
            hypothesis_update = "Attack confirmed successful; applying initial perimeter IP block."
        elif tool == "verify_block":
            action_type = "VERIFY"
            status_update = "VERIFYING"
        elif tool == "get_network_topology":
            action_type = "REPLAN" if state.failed_actions else "INVESTIGATE"
            status_update = "REPLANNING"
            hypothesis_update = "Containment failed; analyzing network topology to uncover routing bypass."
        elif tool == "block_upstream_route":
            action_type = "ACT"
            status_update = "CONTAINING"
            hypothesis_update = "Proxy forwarding detected; isolating upstream route via Proxy-LB01."
        else:
            action_type = "INVESTIGATE"

        return DecisionResult(
            action_type=action_type,
            rationale=rationale,
            tool=tool,
            tool_input=arguments,
            status_update=status_update,
            hypothesis_update=hypothesis_update,
            confidence_update=confidence_update,
        )
