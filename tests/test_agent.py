"""
PRISM Autonomous Agent Test Suite (Phase 2).
Verifies all 12 key agent requirements plus dynamic state-driven responsiveness.

Tests:
1. Agent receives ALT-1042.
2. Agent maintains IncidentState.
3. Agent retrieves evidence.
4. Agent determines likely attack success.
5. Agent performs first containment.
6. Verification fails.
7. Agent recognizes failed containment.
8. Agent investigates network topology.
9. Agent replans.
10. Agent performs upstream containment.
11. Agent verifies final containment.
12. Agent reaches CONTAINED state.
13. Agent responds dynamically to verification outcomes rather than a fixed script.
14. Agent generates valid structured trace entries without hidden chain-of-thought.
"""

import unittest
from backend.agent import PRISMAgent
from backend.decision_engine import DeterministicDecisionEngine
from backend.environment import SOCEnvironment
from backend.models import IncidentState


class TestPRISMAgent(unittest.TestCase):

    def setUp(self) -> None:
        self.env = SOCEnvironment()
        self.env.reset()
        self.agent = PRISMAgent(environment=self.env)
        # Execute the agent on ALT-1042
        self.state: IncidentState = self.agent.run(alert_id="ALT-1042", max_steps=15)

    def test_01_agent_receives_alt_1042(self) -> None:
        """1. Agent receives ALT-1042 and associates it with the incident."""
        self.assertIn("ALT-1042", self.state.incident_id)
        self.assertIsNotNone(self.state.alert)
        self.assertEqual(self.state.alert["alert_id"], "ALT-1042")
        self.assertEqual(self.state.alert["target_asset"], "web-server-03")

    def test_02_agent_maintains_incident_state(self) -> None:
        """2. Agent maintains persistent IncidentState throughout investigation."""
        self.assertIsInstance(self.state, IncidentState)
        self.assertEqual(self.state.incident_id, "INC-ALT-1042")
        self.assertTrue(len(self.state.investigation_history) > 0)
        self.assertTrue(len(self.state.actions_taken) > 0)
        self.assertTrue(len(self.state.verification_results) > 0)

        # Test dictionary serialization
        state_dict = self.state.to_dict()
        self.assertIn("incident_id", state_dict)
        self.assertIn("evidence_collected", state_dict)
        self.assertIn("failed_actions", state_dict)
        self.assertIn("current_plan", state_dict)

    def test_03_agent_retrieves_evidence(self) -> None:
        """3. Agent retrieves evidence across all key dimensions."""
        evidence = self.state.evidence_collected
        self.assertIsNotNone(evidence.get("alert"), "Alert evidence should be present")
        self.assertIsNotNone(evidence.get("asset"), "Asset evidence should be present")
        self.assertTrue(len(evidence.get("vulnerabilities", [])) > 0, "Vulnerability evidence should be present")
        self.assertTrue(len(evidence.get("server_logs", [])) > 0, "Server logs should be present")
        self.assertIsNotNone(evidence.get("network_evidence"), "Network evidence should be present")

    def test_04_agent_determines_likely_attack_success(self) -> None:
        """4. Agent determines likely attack success based on correlated evidence."""
        # High confidence in compromise
        self.assertGreaterEqual(self.state.confidence, 0.85)
        # Hypothesis reflects exploit success
        hypothesis_lower = self.state.current_hypothesis.lower()
        self.assertTrue(
            "sql injection" in hypothesis_lower or "attack" in hypothesis_lower or "contained" in hypothesis_lower,
            f"Hypothesis should reflect attack status: {self.state.current_hypothesis}"
        )

    def test_05_agent_performs_first_containment(self) -> None:
        """5. Agent performs first containment via block_ip on threat source."""
        self.assertTrue(len(self.state.actions_taken) >= 1)
        first_action = self.state.actions_taken[0]
        self.assertEqual(first_action.get("action"), "block_ip")
        self.assertEqual(first_action.get("target"), "10.20.14.52")

    def test_06_verification_fails(self) -> None:
        """6. Initial containment verification fails due to proxy forwarding."""
        self.assertTrue(len(self.state.verification_results) >= 1)
        first_verification = self.state.verification_results[0]
        self.assertFalse(first_verification.get("verified"))
        self.assertEqual(first_verification.get("status"), "FAILED")
        self.assertIn("Traffic bypass detected", first_verification.get("reason", ""))

    def test_07_agent_recognizes_failed_containment(self) -> None:
        """7. Agent records and recognizes failed containment in failed_actions."""
        self.assertEqual(len(self.state.failed_actions), 1)
        failed_entry = self.state.failed_actions[0]
        self.assertEqual(failed_entry["action"]["action"], "block_ip")
        self.assertIn("Proxy-LB01", failed_entry["reason"])

    def test_08_agent_investigates_network_topology(self) -> None:
        """8. Agent investigates network topology in response to containment failure."""
        topology_evidence = self.state.evidence_collected.get("network_topology")
        self.assertIsNotNone(topology_evidence, "Network topology should be retrieved after failure")
        nodes = [n["id"] for n in topology_evidence.get("nodes", [])]
        self.assertIn("Proxy-LB01", nodes)

        # Confirm in trace that topology lookup occurred after the failed verification
        trace = self.state.trace
        fail_step_index = next(
            i for i, t in enumerate(trace)
            if t.tool_selected == "verify_block" and not t.summarized_result.startswith("Verification SUCCESS")
        )
        topology_step_index = next(
            i for i, t in enumerate(trace)
            if t.tool_selected == "get_network_topology"
        )
        self.assertGreater(
            topology_step_index,
            fail_step_index,
            "Topology lookup must be triggered after verification failure"
        )

    def test_09_agent_replans(self) -> None:
        """9. Agent replans and adapts its strategy upon discovering proxy bypass."""
        trace = self.state.trace
        replan_steps = [t for t in trace if t.action_type in ("REPLAN", "ACT") and "upstream" in t.rationale.decision.lower()]
        self.assertTrue(len(replan_steps) > 0, "Agent trace must document replanning for upstream route")
        self.assertIn("upstream route", replan_steps[0].rationale.reason.lower())

    def test_10_agent_performs_upstream_containment(self) -> None:
        """10. Agent performs upstream containment by blocking Proxy-LB01 route."""
        upstream_actions = [
            a for a in self.state.actions_taken
            if a.get("action") == "block_upstream_route" and a.get("target") == "Proxy-LB01"
        ]
        self.assertEqual(len(upstream_actions), 1)

    def test_11_agent_verifies_final_containment(self) -> None:
        """11. Agent verifies final containment with reachability probe."""
        self.assertTrue(len(self.state.verification_results) >= 2)
        final_verification = self.state.verification_results[-1]
        self.assertTrue(final_verification.get("verified"))
        self.assertEqual(final_verification.get("status"), "SUCCESS")

    def test_12_agent_reaches_contained_state(self) -> None:
        """12. Agent transitions incident status to CONTAINED and completes goal."""
        self.assertEqual(self.state.status, "CONTAINED")
        self.assertEqual(self.state.confidence, 1.0)
        final_trace = self.state.trace[-1]
        self.assertEqual(final_trace.action_type, "CONCLUDE")
        self.assertEqual(self.state.goal, "Autonomously investigate alert ALT-1042, determine if attack succeeded, and contain threat.")

    def test_13_agent_responds_dynamically_not_predetermined_sequence(self) -> None:
        """
        PROVE that the agent responds dynamically to verification feedback:
        If an environment verifies containment successfully on the first attempt
        (i.e. no proxy bypass occurs), the agent immediately concludes without
        fetching topology or blocking upstream routes.
        """
        # Create a mock environment where verify_block always succeeds
        class NoBypassEnvironment(SOCEnvironment):
            def verify_block(self, target: str):
                return {
                    "verified": True,
                    "status": "SUCCESS",
                    "target": target,
                    "upstream_route_blocked": False,
                    "ip_blocked": True,
                    "message": "Direct perimeter block succeeded without proxy bypass."
                }

        mock_env = NoBypassEnvironment()
        dynamic_agent = PRISMAgent(environment=mock_env)
        dynamic_state = dynamic_agent.run(alert_id="ALT-1042")

        # Must contain in status CONTAINED
        self.assertEqual(dynamic_state.status, "CONTAINED")

        # Because verify_block succeeded immediately, agent MUST NOT have:
        # 1. Investigate topology
        self.assertIsNone(dynamic_state.evidence_collected.get("network_topology"))
        # 2. Called block_upstream_route
        actions = [a.get("action") for a in dynamic_state.actions_taken]
        self.assertNotIn("block_upstream_route", actions)
        self.assertEqual(actions, ["block_ip"])
        self.assertEqual(len(dynamic_state.failed_actions), 0)

    def test_14_agent_trace_structure_and_concise_rationale(self) -> None:
        """14. Verify that each trace entry has valid structure and concise rationale."""
        self.assertTrue(len(self.state.trace) >= 8)
        for entry in self.state.trace:
            self.assertIsInstance(entry.step, int)
            self.assertTrue(len(entry.timestamp) > 0)
            self.assertIn(entry.action_type, ("INVESTIGATE", "ACT", "VERIFY", "REPLAN", "CONCLUDE"))
            self.assertIsInstance(entry.rationale.decision, str)
            self.assertIsInstance(entry.rationale.reason, str)
            self.assertTrue(len(entry.rationale.decision) > 0)
            self.assertTrue(len(entry.rationale.reason) > 0)
            # Ensure no private/hidden chain of thought
            self.assertNotIn("thought", entry.to_dict())
            self.assertNotIn("chain_of_thought", entry.to_dict())


if __name__ == "__main__":
    unittest.main()
