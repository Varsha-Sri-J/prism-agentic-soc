"""
PRISM LLM Provider Layer.
Implements modular LLM provider abstraction:
- LLMProvider (base class)
- GeminiProvider (direct Google Gemini REST API integration using urllib)
- MockLLMProvider (for testing and offline deterministic mock mode)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class LLMProvider(ABC):
    """Abstract interface for LLM providers generating structured decisions."""

    @abstractmethod
    def generate_decision(
        self,
        system_prompt: str,
        user_prompt: str,
        tools_schema: List[Dict[str, Any]],
    ) -> str:
        """
        Sends the system instructions, compact incident state, and available tools
        to the model and returns the raw response text (expected to be JSON).
        """
        pass


class GeminiProvider(LLMProvider):
    """
    Google Gemini API provider using Python's standard library urllib.
    Requires GEMINI_API_KEY set in the environment or passed explicitly.
    """

    DEFAULT_MODEL = "gemini-1.5-flash"
    API_URL_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: int = 20,
    ) -> None:
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name or os.getenv("LLM_MODEL", self.DEFAULT_MODEL)
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        """Returns True if an API key is present."""
        return bool(self.api_key and self.api_key.strip())

    def generate_decision(
        self,
        system_prompt: str,
        user_prompt: str,
        tools_schema: List[Dict[str, Any]],
    ) -> str:
        if not self.is_configured:
            raise ValueError("GEMINI_API_KEY is not configured in the environment.")

        url = self.API_URL_TEMPLATE.format(model=self.model_name, api_key=self.api_key)

        # Build request payload enforcing JSON response
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": f"{system_prompt}\n\nTOOLS AVAILABLE:\n{json.dumps(tools_schema, indent=2)}\n\n{user_prompt}"}
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        req_data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                res_json = json.loads(body)

                # Extract generated text from candidates
                candidates = res_json.get("candidates", [])
                if not candidates:
                    raise RuntimeError("Gemini returned no candidates.")

                parts = candidates[0].get("content", {}).get("parts", [])
                if not parts:
                    raise RuntimeError("Gemini returned empty parts.")

                return parts[0].get("text", "").strip()

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gemini API HTTP {e.code}: {error_body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Gemini API network error: {e.reason}") from e


class MockLLMProvider(LLMProvider):
    """
    Mock LLM provider for deterministic offline testing and scenario validation.
    Allows pre-loading canned responses or dynamically synthesizing valid responses
    based on the incident state in the prompt.
    """

    def __init__(self, responses: Optional[List[str]] = None) -> None:
        self.responses: List[str] = list(responses) if responses else []
        self.call_history: List[Dict[str, Any]] = []

    def add_response(self, response_json_str: str) -> None:
        """Queue a mock response string."""
        self.responses.append(response_json_str)

    def generate_decision(
        self,
        system_prompt: str,
        user_prompt: str,
        tools_schema: List[Dict[str, Any]],
    ) -> str:
        self.call_history.append({
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "tools_schema_count": len(tools_schema),
        })

        if self.responses:
            return self.responses.pop(0)

        # Dynamic fallback simulation based on prompt content
        return self._synthesize_response(user_prompt)

    def _synthesize_response(self, user_prompt: str) -> str:
        """Synthesizes realistic tool calls matching the agent investigation flow."""
        try:
            state_data = {}
            if "INCIDENT STATE:" in user_prompt:
                json_part = user_prompt.split("INCIDENT STATE:")[1]
                start = json_part.find("{")
                end = json_part.rfind("}")
                if start != -1 and end != -1:
                    state_data = json.loads(json_part[start : end + 1])
        except Exception:
            state_data = {}

        evidence = state_data.get("evidence", {})
        failed_actions = state_data.get("failed_actions", [])
        last_verification = state_data.get("last_verification")
        actions_taken = state_data.get("actions_taken", [])
        actions_count = state_data.get("actions_count", len(actions_taken))
        verifs_count = state_data.get("verifications_count", 1 if last_verification else 0)

        # 1. If last verification was successful, conclude
        if last_verification and last_verification.get("verified"):
            return json.dumps({
                "action": "finish",
                "status": "CONTAINED",
                "rationale": {
                    "decision": "Conclude investigation",
                    "reason": "Post-action verification confirms malicious traffic is completely blocked.",
                },
            })

        # 2. If unverified action exists (actions_count > verifs_count), verify it
        if actions_count > verifs_count:
            return json.dumps({
                "action": "tool_call",
                "tool": "verify_block",
                "arguments": {"target": "web-server-03"},
                "rationale": {
                    "decision": "Verify containment action",
                    "reason": "Containment rule applied. Active reachability probe is required to verify whether traffic is blocked.",
                },
            })

        # 3. If verification failed (failed_actions present)
        if failed_actions:
            if not evidence.get("network_topology"):
                return json.dumps({
                    "action": "tool_call",
                    "tool": "get_network_topology",
                    "arguments": {},
                    "rationale": {
                        "decision": "Investigate network topology",
                        "reason": "Perimeter block failed. Inspecting routing topology to uncover proxy bypass.",
                    },
                })
            if not any("block_upstream_route" in a for a in actions_taken):
                return json.dumps({
                    "action": "tool_call",
                    "tool": "block_upstream_route",
                    "arguments": {"route": "Proxy-LB01"},
                    "rationale": {
                        "decision": "Block upstream route Proxy-LB01",
                        "reason": "Traffic is forwarded via reverse proxy Proxy-LB01; upstream route isolation is required.",
                    },
                })

        # Investigation evidence gathering
        if not state_data.get("alert"):
            return json.dumps({
                "action": "tool_call",
                "tool": "get_alert",
                "arguments": {"alert_id": "ALT-1042"},
                "rationale": {
                    "decision": "Retrieve alert details",
                    "reason": "Alert metadata is required to identify source and target.",
                },
            })

        if not evidence.get("asset"):
            return json.dumps({
                "action": "tool_call",
                "tool": "get_asset",
                "arguments": {"asset_id": "web-server-03"},
                "rationale": {
                    "decision": "Retrieve asset profile",
                    "reason": "Asset context is needed to evaluate target host role and exposed services.",
                },
            })

        if not evidence.get("vulnerabilities"):
            return json.dumps({
                "action": "tool_call",
                "tool": "search_vulnerabilities",
                "arguments": {"asset_id": "web-server-03"},
                "rationale": {
                    "decision": "Search known vulnerabilities",
                    "reason": "Need to determine if target has an unpatched SQL injection vulnerability.",
                },
            })

        if not evidence.get("server_logs"):
            return json.dumps({
                "action": "tool_call",
                "tool": "search_server_logs",
                "arguments": {"host": "web-server-03", "source_ip": "10.20.14.52"},
                "rationale": {
                    "decision": "Search server logs for exploit attempt",
                    "reason": "Target vulnerability is confirmed; inspecting application logs for payload execution.",
                },
            })

        if not evidence.get("network_evidence"):
            return json.dumps({
                "action": "tool_call",
                "tool": "get_network_evidence",
                "arguments": {"alert_id": "ALT-1042"},
                "rationale": {
                    "decision": "Correlate network flow evidence",
                    "reason": "Confirm packet delivery and data exfiltration volume.",
                },
            })

        # Containment trigger
        if not actions_taken:
            return json.dumps({
                "action": "tool_call",
                "tool": "block_ip",
                "arguments": {"ip": "10.20.14.52"},
                "rationale": {
                    "decision": "Apply perimeter block on 10.20.14.52",
                    "reason": "Correlated evidence confirms attack succeeded; containment of threat source is justified.",
                },
            })

        # Default fallback
        return json.dumps({
            "action": "finish",
            "status": "CONTAINED",
            "rationale": {
                "decision": "Finish investigation",
                "reason": "Investigation completed.",
            },
        })
