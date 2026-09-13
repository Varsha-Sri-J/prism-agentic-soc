"""
PRISM Phase 4 Frontend Integration Tests.
Verifies that styles, visual components, and dashboard entrypoint execute cleanly
with both standby states and live PRISMAgent IncidentState data.
"""

import unittest
from backend.agent import PRISMAgent
from backend.environment import SOCEnvironment
from frontend.components import (
    render_agent_trace,
    render_attack_path_topology,
    render_evidence_panel,
    render_header,
    render_incident_summary,
    render_response_panel,
)
from frontend.styles import CUSTOM_CSS


class TestFrontendComponents(unittest.TestCase):

    def setUp(self) -> None:
        self.env = SOCEnvironment()
        self.env.reset()
        self.agent = PRISMAgent(environment=self.env)
        self.state = self.agent.run("ALT-1042")

    def test_01_styles_css_defined(self) -> None:
        """1. Verify custom cyber SOC styling tokens exist."""
        self.assertIsInstance(CUSTOM_CSS, str)
        self.assertIn(".prism-header", CUSTOM_CSS)
        self.assertIn(".badge-contained", CUSTOM_CSS)
        self.assertIn(".kpi-card", CUSTOM_CSS)
        self.assertIn(".trace-step-failed", CUSTOM_CSS)

    def test_02_components_render_standby_state(self) -> None:
        """2. Verify visual components render safely with None / initial state."""
        try:
            render_header(mode="MOCK", incident_id="ALT-1042", status="STANDBY")
            render_incident_summary(None)
            render_attack_path_topology(None)
            render_response_panel(None)
            render_evidence_panel(None)
            render_agent_trace(None)
        except Exception as exc:
            self.fail(f"Component rendering failed on standby state: {exc}")

    def test_03_components_render_active_incident_state(self) -> None:
        """3. Verify visual components render safely with real IncidentState."""
        try:
            render_header(mode="MOCK", incident_id=self.state.incident_id, status=self.state.status)
            render_incident_summary(self.state)
            render_attack_path_topology(self.state)
            render_response_panel(self.state)
            render_evidence_panel(self.state)
            render_agent_trace(self.state)
        except Exception as exc:
            self.fail(f"Component rendering failed on active IncidentState: {exc}")

    def test_04_app_entrypoint_importable(self) -> None:
        """4. Verify frontend app entrypoint is cleanly importable."""
        import frontend.app
        self.assertTrue(callable(frontend.app.main))

    def test_05_app_test_investigation_interaction(self) -> None:
        """5. Prove end-to-end user interaction in Streamlit using AppTest."""
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file("frontend/app.py").run()
        self.assertFalse(at.exception)

        # Locate and click 'Run Investigation' button
        run_btn = next((b for b in at.button if "Run Investigation" in b.label), None)
        self.assertIsNotNone(run_btn, "Run Investigation button must exist")

        # Click and re-run Streamlit execution
        at_after = run_btn.click().run()
        self.assertFalse(at_after.exception)

        # Check that session state now holds CONTAINED state
        self.assertIn("state", at_after.session_state)
        resulting_state = at_after.session_state.state
        self.assertIsNotNone(resulting_state)
        self.assertEqual(resulting_state.status, "CONTAINED")


if __name__ == "__main__":
    unittest.main()
