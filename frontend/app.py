"""
PRISM Streamlit SOC Dashboard Entrypoint.
Connects directly to PRISMAgent and visualizes the autonomous investigation,
failure verification, replanning, and final containment.
"""

from __future__ import annotations

import os
import streamlit as st

from backend.agent import PRISMAgent
from backend.decision_engine import LLMDecisionEngine
from backend.environment import SOCEnvironment
from backend.llm_provider import GeminiProvider, MockLLMProvider
from backend.tools import reset_environment
from frontend.components import (
    render_agent_trace,
    render_attack_path_topology,
    render_evidence_panel,
    render_header,
    render_incident_summary,
    render_response_panel,
)
from frontend.styles import CUSTOM_CSS


def main() -> None:
    st.set_page_config(
        page_title="PRISM — Autonomous SOC Agent",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Inject Cyber SOC CSS
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    # Initialize session state
    if "state" not in st.session_state:
        st.session_state.state = None
    if "has_run" not in st.session_state:
        st.session_state.has_run = False

    # --- SIDEBAR CONTROLS ---
    with st.sidebar:
        st.markdown("## 🛡️ PRISM Controls")
        st.markdown("Autonomous SOC Investigation & Containment Agent")
        st.markdown("---")

        mode_choice = st.radio(
            "Operational Mode",
            ["MOCK", "LIVE (gemini)"],
            index=0,
            help="MOCK mode uses deterministic LLM simulation without an API key. LIVE mode calls Google Gemini API.",
        )

        gemini_key_input = ""
        active_mode_str = "MOCK"

        if mode_choice == "LIVE (gemini)":
            env_key = os.getenv("GEMINI_API_KEY", "")
            if env_key:
                st.success("✅ GEMINI_API_KEY detected in environment")
                gemini_key_input = env_key
                active_mode_str = "LIVE (gemini)"
            else:
                st.warning("⚠️ No GEMINI_API_KEY found in environment.")
                gemini_key_input = st.text_input(
                    "Enter Gemini API Key",
                    type="password",
                    placeholder="AIzaSy...",
                    help="Provide a valid Gemini API key to enable live LLM tool calling.",
                )
                if gemini_key_input:
                    active_mode_str = "LIVE (gemini)"
                else:
                    st.info("ℹ️ Running in MOCK fallback mode until an API key is provided.")
                    active_mode_str = "MOCK (Fallback)"

        st.markdown("---")
        st.markdown("### 🎯 Target Scenario")
        alert_selected = st.selectbox(
            "Select Alert",
            ["ALT-1042 (Possible SQL Injection)"],
            index=0,
        )
        st.caption("Target: `web-server-03` | Source: `10.20.14.52` | Proxy: `Proxy-LB01`")

        st.markdown("---")
        run_clicked = st.button("🚀 Run Investigation", type="primary", use_container_width=True)
        reset_clicked = st.button("🔄 Reset Environment", use_container_width=True)

        st.markdown("---")
        st.markdown(
            "<small style='color:#64748b;'>"
            "PRISM SOC Agent v1.0<br>"
            "Tech Zephyr 4.0 Hackathon"
            "</small>",
            unsafe_allow_html=True,
        )

    # Handle Reset Action
    if reset_clicked:
        reset_environment()
        st.session_state.state = None
        st.session_state.has_run = False
        st.rerun()

    # Handle Run Action
    if run_clicked:
        reset_environment()
        env = SOCEnvironment()
        env.reset()

        # Configure Decision Engine according to selected mode
        if mode_choice == "LIVE (gemini)" and gemini_key_input:
            provider = GeminiProvider(api_key=gemini_key_input)
            engine = LLMDecisionEngine(provider=provider)
        else:
            provider = MockLLMProvider()
            engine = LLMDecisionEngine(provider=provider)

        agent = PRISMAgent(decision_engine=engine, environment=env)

        with st.spinner("PRISM Agent observing, investigating, and responding to ALT-1042..."):
            resulting_state = agent.run(alert_id="ALT-1042", max_steps=15)
            st.session_state.state = resulting_state
            st.session_state.has_run = True

        st.rerun()

    # Current state
    current_state = st.session_state.state
    current_status = current_state.status if current_state else "STANDBY"

    # --- TOP HEADER ---
    render_header(
        mode=active_mode_str,
        incident_id="ALT-1042",
        status=current_status,
    )

    # --- INCIDENT KPI SUMMARY ---
    render_incident_summary(current_state)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- MAIN SPLIT LAYOUT ---
    left_col, right_col = st.columns([5, 7])

    with left_col:
        render_attack_path_topology(current_state)
        render_response_panel(current_state)
        render_evidence_panel(current_state)

    with right_col:
        render_agent_trace(current_state)


if __name__ == "__main__":
    main()
