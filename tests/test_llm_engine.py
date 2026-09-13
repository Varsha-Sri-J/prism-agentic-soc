"""
PRISM Phase 3 Test Suite: Real LLM-Driven Tool Selection.
Tests:
- LLM decision parsing
- Tool-call validation
- Invalid tool handling (safety constraint)
- Malformed LLM response fallback & retry
- LLM-driven investigation in mocked mode
- Failed verification causing a new decision
- Successful replan
- Final CONTAINED state
- Mode reporting (MOCK vs LIVE)
"""

import json
import unittest
from backend.agent import PRISMAgent
from backend.decision_engine import LLMDecisionEngine
from backend.environment import SOCEnvironment
from backend.llm_provider import GeminiProvider, MockLLMProvider
from backend.models import IncidentState


class TestLLMDecisionEngine(unittest.TestCase):

    def setUp(self) -> None:
        self.env = SOCEnvironment()
        self.env.reset()

    def test_01_llm_decision_parsing_tool_call(self) -> None:
        """1. Prove LLM decision JSON parsing for tool_call action."""
        valid_json = json.dumps({
            "action": "tool_call",
            "tool": "search_server_logs",
            "arguments": {"host": "web-server-03", "source_ip": "10.20.14.52"},
            "rationale": {
                "decision": "Retrieve server logs",
                "reason": "Vulnerability is confirmed, checking for execution evidence."
            }
        })
        mock_provider = MockLLMProvider(responses=[valid_json])
        engine = LLMDecisionEngine(provider=mock_provider)

        state = IncidentState(incident_id="INC-TEST", goal="Test goal")
        decision = engine.decide(state)

        self.assertEqual(decision.tool, "search_server_logs")
        self.assertEqual(decision.tool_input, {"host": "web-server-03", "source_ip": "10.20.14.52"})
        self.assertEqual(decision.rationale.decision, "Retrieve server logs")
        self.assertEqual(decision.action_type, "INVESTIGATE")

    def test_02_llm_decision_parsing_finish(self) -> None:
        """2. Prove LLM decision JSON parsing for finish action."""
        finish_json = json.dumps({
            "action": "finish",
            "status": "CONTAINED",
            "rationale": {
                "decision": "Finish investigation",
                "reason": "Post-action verification confirms malicious traffic is blocked."
            }
        })
        mock_provider = MockLLMProvider(responses=[finish_json])
        engine = LLMDecisionEngine(provider=mock_provider)

        state = IncidentState(incident_id="INC-TEST", goal="Test goal")
        decision = engine.decide(state)

        self.assertTrue(decision.is_goal_satisfied)
        self.assertEqual(decision.action_type, "CONCLUDE")
        self.assertEqual(decision.status_update, "CONTAINED")
        self.assertEqual(decision.rationale.decision, "Finish investigation")

    def test_03_tool_call_validation_success(self) -> None:
        """3. Prove validation succeeds for legitimate registered tools and arguments."""
        engine = LLMDecisionEngine(provider=MockLLMProvider())

        valid_data = {
            "action": "tool_call",
            "tool": "block_ip",
            "arguments": {"ip": "10.20.14.52"},
            "rationale": {"decision": "Block threat IP", "reason": "Attack verified."}
        }
        is_valid, msg = engine.validate_decision(valid_data)
        self.assertTrue(is_valid)
        self.assertEqual(msg, "Valid tool call.")

    def test_04_invalid_tool_handling(self) -> None:
        """4. Prove safety constraints reject unwhitelisted or dangerous tools."""
        engine = LLMDecisionEngine(provider=MockLLMProvider())

        malicious_data = {
            "action": "tool_call",
            "tool": "execute_shell_command",
            "arguments": {"cmd": "rm -rf /"},
            "rationale": {"decision": "Run shell", "reason": "Testing safety"}
        }
        is_valid, msg = engine.validate_decision(malicious_data)
        self.assertFalse(is_valid)
        self.assertIn("Safety constraint violation", msg)
        self.assertIn("execute_shell_command", msg)

    def test_05_missing_arguments_validation(self) -> None:
        """5. Prove validation fails when required tool arguments are missing."""
        engine = LLMDecisionEngine(provider=MockLLMProvider())

        missing_arg_data = {
            "action": "tool_call",
            "tool": "block_upstream_route",
            "arguments": {},  # Missing required 'route'
            "rationale": {"decision": "Block route", "reason": "Testing missing arg"}
        }
        is_valid, msg = engine.validate_decision(missing_arg_data)
        self.assertFalse(is_valid)
        self.assertIn("Missing required argument 'route'", msg)

    def test_06_malformed_llm_response_retry_success(self) -> None:
        """6. Prove engine retries once with correction prompt when LLM output is malformed."""
        bad_json = "This is not valid json text from model"
        good_json = json.dumps({
            "action": "tool_call",
            "tool": "get_alert",
            "arguments": {"alert_id": "ALT-1042"},
            "rationale": {"decision": "Retrieve alert", "reason": "Need initial metadata."}
        })

        mock_provider = MockLLMProvider(responses=[bad_json, good_json])
        engine = LLMDecisionEngine(provider=mock_provider)

        state = IncidentState(incident_id="INC-TEST", goal="Test goal")
        decision = engine.decide(state)

        # Confirm retry was made (2 calls in history) and recovered successfully
        self.assertEqual(len(mock_provider.call_history), 2)
        self.assertIn("ERROR IN PREVIOUS ATTEMPT", mock_provider.call_history[1]["user_prompt"])
        self.assertEqual(decision.tool, "get_alert")
        self.assertEqual(decision.rationale.decision, "Retrieve alert")

    def test_07_malformed_llm_response_fallback_to_deterministic(self) -> None:
        """7. Prove engine falls back to DeterministicDecisionEngine if retry still fails."""
        bad_json_1 = "Bad output 1"
        bad_json_2 = "Bad output 2"

        mock_provider = MockLLMProvider(responses=[bad_json_1, bad_json_2])
        engine = LLMDecisionEngine(provider=mock_provider)

        state = IncidentState(incident_id="INC-TEST", goal="Test goal")
        decision = engine.decide(state)

        # Confirm 2 attempts were made before falling back to deterministic decision
        self.assertEqual(len(mock_provider.call_history), 2)
        # Fallback should provide a valid deterministic decision (get_alert for initial state)
        self.assertEqual(decision.tool, "get_alert")
        self.assertIsNotNone(decision.rationale)

    def test_08_llm_driven_investigation_in_mocked_mode(self) -> None:
        """8. Prove full autonomous investigation executes in MOCK mode."""
        mock_provider = MockLLMProvider()
        engine = LLMDecisionEngine(provider=mock_provider)
        agent = PRISMAgent(decision_engine=engine, environment=self.env)

        self.assertEqual(agent.mode, "MOCK")
        final_state = agent.run("ALT-1042")

        self.assertEqual(final_state.status, "CONTAINED")
        self.assertTrue(len(final_state.trace) >= 8)

    def test_09_failed_verification_causes_new_decision(self) -> None:
        """9. Prove failed verification causes the LLM engine to select topology investigation."""
        # Set up an incident state where block_ip was executed and verify_block failed
        state = IncidentState(
            incident_id="INC-ALT-1042",
            goal="Investigate and contain threat"
        )
        state.alert = {"alert_id": "ALT-1042", "source_ip": "10.20.14.52", "target_asset": "web-server-03"}
        state.evidence_collected["alert"] = state.alert
        state.evidence_collected["asset"] = {"asset_id": "web-server-03"}
        state.evidence_collected["vulnerabilities"] = [{"cve_id": "CVE-2023-42819"}]
        state.evidence_collected["server_logs"] = [{"status_code": 200}]
        state.evidence_collected["network_evidence"] = {"flow_id": "FL-1"}

        # First action executed
        state.record_action({"action": "block_ip", "target": "10.20.14.52"})
        # First verification failed
        state.record_verification({
            "verified": False,
            "status": "FAILED",
            "reason": "Traffic bypass detected through Proxy-LB01."
        })

        mock_provider = MockLLMProvider()
        engine = LLMDecisionEngine(provider=mock_provider)
        decision = engine.decide(state)

        # The LLM engine must recognize failed verification and choose get_network_topology
        self.assertEqual(decision.tool, "get_network_topology")
        self.assertIn("network topology", decision.rationale.decision.lower())

    def test_10_successful_replan_after_topology_discovery(self) -> None:
        """10. Prove successful replan: after topology reveals proxy, upstream route is blocked."""
        state = IncidentState(incident_id="INC-ALT-1042", goal="Investigate and contain threat")
        state.alert = {"alert_id": "ALT-1042", "source_ip": "10.20.14.52", "target_asset": "web-server-03"}
        state.record_action({"action": "block_ip", "target": "10.20.14.52"})
        state.record_verification({
            "verified": False,
            "status": "FAILED",
            "reason": "Traffic bypass detected through Proxy-LB01."
        })
        state.evidence_collected["network_topology"] = {
            "nodes": [{"id": "10.20.14.52"}, {"id": "Proxy-LB01", "type": "reverse_proxy"}, {"id": "web-server-03"}]
        }

        mock_provider = MockLLMProvider()
        engine = LLMDecisionEngine(provider=mock_provider)
        decision = engine.decide(state)

        # Must replan and select block_upstream_route on Proxy-LB01
        self.assertEqual(decision.tool, "block_upstream_route")
        self.assertEqual(decision.tool_input, {"route": "Proxy-LB01"})

    def test_11_final_verification_succeeds_and_concludes(self) -> None:
        """11. Prove final verification success leads to finish/conclude decision."""
        state = IncidentState(incident_id="INC-ALT-1042", goal="Investigate and contain threat")
        state.record_action({"action": "block_ip", "target": "10.20.14.52"})
        state.record_action({"action": "block_upstream_route", "target": "Proxy-LB01"})
        state.record_verification({"verified": False, "status": "FAILED"})
        state.record_verification({"verified": True, "status": "SUCCESS"})

        mock_provider = MockLLMProvider()
        engine = LLMDecisionEngine(provider=mock_provider)
        decision = engine.decide(state)

        self.assertTrue(decision.is_goal_satisfied)
        self.assertEqual(decision.action_type, "CONCLUDE")
        self.assertEqual(decision.status_update, "CONTAINED")

    def test_12_mode_reporting(self) -> None:
        """12. Prove mode reporting distinguishes LIVE and MOCK configurations."""
        # Mock mode
        mock_engine = LLMDecisionEngine(provider=MockLLMProvider())
        agent_mock = PRISMAgent(decision_engine=mock_engine)
        self.assertEqual(agent_mock.mode, "MOCK")

        # Live Gemini mode (when configured)
        gemini_provider = GeminiProvider(api_key="mock_key_for_test", model_name="gemini-1.5-flash")
        gemini_engine = LLMDecisionEngine(provider=gemini_provider)
        agent_live = PRISMAgent(decision_engine=gemini_engine)
        self.assertEqual(agent_live.mode, "LIVE (gemini:gemini-1.5-flash)")


if __name__ == "__main__":
    unittest.main()
