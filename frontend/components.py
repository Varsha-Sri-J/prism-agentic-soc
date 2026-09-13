"""
PRISM Dashboard Visual Components.
Renders Header, Incident Summary, Topology Graph, Evidence Cards,
Agent Trace, and Response Timeline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import streamlit as st

from backend.models import IncidentState


def render_header(mode: str, incident_id: str, status: str) -> None:
    """Renders the top branding header with mode and status badges."""
    badge_class = "badge-contained" if status == "CONTAINED" else "badge-investigating"
    status_icon = "🛡️" if status == "CONTAINED" else "⚡"

    html = f"""
    <div class="prism-header">
        <div>
            <h1 class="prism-title">PRISM</h1>
            <div class="prism-subtitle">Autonomous Security Investigation & Response Agent</div>
        </div>
        <div style="display: flex; gap: 1rem; align-items: center;">
            <span class="badge-mode">MODE: {mode}</span>
            <span class="badge-mode">INCIDENT: {incident_id}</span>
            <span class="{badge_class}">{status_icon} {status}</span>
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def render_incident_summary(state: Optional[IncidentState]) -> None:
    """Renders high-level incident KPI metric cards."""
    if not state or not state.alert:
        # Placeholder summary before execution
        cols = st.columns(4)
        with cols[0]:
            _kpi_card("Target Host", "web-server-03")
        with cols[1]:
            _kpi_card("Threat Source", "10.20.14.52")
        with cols[2]:
            _kpi_card("Severity", "CRITICAL")
        with cols[3]:
            _kpi_card("Status", "STANDBY")
        return

    alert = state.alert
    confidence_pct = f"{int(state.confidence * 100)}%"
    assessment = "Compromised (Exploit Succeeded)" if state.confidence >= 0.8 else "Analyzing"

    cols = st.columns(4)
    with cols[0]:
        _kpi_card("Incident ID", state.incident_id)
        _kpi_card("Target Host", alert.get("target_asset", "web-server-03"))
    with cols[1]:
        _kpi_card("Threat Type", alert.get("name", "SQL Injection"))
        _kpi_card("Source IP", alert.get("source_ip", "10.20.14.52"))
    with cols[2]:
        _kpi_card("Severity", alert.get("severity", "CRITICAL"))
        _kpi_card("Confidence", confidence_pct)
    with cols[3]:
        _kpi_card("Attack Assessment", assessment)
        _kpi_card("Containment Status", state.status)


def _kpi_card(title: str, value: str) -> None:
    html = f"""
    <div class="kpi-card">
        <div class="kpi-title">{title}</div>
        <div class="kpi-value">{value}</div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def render_attack_path_topology(state: Optional[IncidentState]) -> None:
    """Visualizes the 10.20.14.52 -> Proxy-LB01 -> web-server-03 routing path and containment state."""
    st.markdown("### 🌐 Attack Path & Routing Topology")

    # Determine state flags
    is_contained = state and state.status == "CONTAINED"
    has_failed = state and len(state.failed_actions) > 0
    upstream_blocked = state and any(a.get("action") == "block_upstream_route" for a in state.actions_taken)
    ip_blocked = state and any(a.get("action") == "block_ip" for a in state.actions_taken)

    # Styling and label based on investigation progression
    if is_contained or upstream_blocked:
        arrow_1 = "<div class='arrow-path'>↓ (Route to Proxy Active)</div>"
        arrow_2 = "<div class='arrow-severed'>⛔ ROUTE SEVERED BY AGENT [block_upstream_route] ⛔</div>"
        target_class = "node-contained"
        target_label = "web-server-03<br><small style='color:#10b981;'>Protected / Isolated</small>"
        proxy_desc = "Proxy-LB01<br><small style='color:#ef4444;'>Forwarding Dropped</small>"
    elif has_failed or ip_blocked:
        arrow_1 = "<div class='arrow-severed'>⚠️ IP BLOCKED AT PERIMETER (10.20.14.52)</div>"
        arrow_2 = "<div class='arrow-severed'>⚠️ TRAFFIC BYPASS: Proxy forwards to Target!</div>"
        target_class = "node-attacker"
        target_label = "web-server-03<br><small style='color:#ef4444;'>Vulnerable / Still Reachable</small>"
        proxy_desc = "Proxy-LB01<br><small style='color:#f59e0b;'>Reverse Proxy Forwarding</small>"
    else:
        arrow_1 = "<div class='arrow-path'>↓ Ingress Route</div>"
        arrow_2 = "<div class='arrow-path'>↓ Upstream Forwarding</div>"
        target_class = "node-target"
        target_label = "web-server-03<br><small style='color:#94a3b8;'>Production Web Server</small>"
        proxy_desc = "Proxy-LB01<br><small style='color:#94a3b8;'>DMZ Load Balancer</small>"

    html = f"""
    <div class="topology-container">
        <div class="topo-node node-attacker">
            10.20.14.52<br><small style='color:#ef4444;'>Attacker (Threat Source)</small>
        </div>
        {arrow_1}
        <div class="topo-node node-proxy">
            {proxy_desc}
        </div>
        {arrow_2}
        <div class="topo-node {target_class}">
            {target_label}
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def render_response_panel(state: Optional[IncidentState]) -> None:
    """Displays containment actions, failure replanning, and verification timeline."""
    st.markdown("### ⚡ Response & Verification Progression")

    if not state or not state.actions_taken:
        st.info("Awaiting investigation trigger. Run the investigation to view response actions.")
        return

    # 1. First Action
    st.markdown("""
    <div style="background:#151d2e; border-left:4px solid #3b82f6; padding:0.8rem; border-radius:6px; margin-bottom:0.6rem;">
        <strong>Action 1: Initial Perimeter Containment</strong><br>
        <code>block_ip("10.20.14.52")</code>
    </div>
    """, unsafe_allow_html=True)

    # 2. First Verification
    if state.verification_results:
        verif1 = state.verification_results[0]
        if not verif1.get("verified"):
            st.markdown("""
            <div style="background:#151d2e; border-left:4px solid #ef4444; padding:0.8rem; border-radius:6px; margin-bottom:0.6rem;">
                <span style="color:#ef4444; font-weight:bold;">Verification 1: FAILED ❌</span><br>
                <span style="color:#94a3b8; font-size:0.85rem;">Traffic bypass detected. Requests continue reaching target through reverse proxy <code>Proxy-LB01</code>.</span>
            </div>
            """, unsafe_allow_html=True)

    # 3. Replanning Step
    if len(state.failed_actions) > 0 and state.evidence_collected.get("network_topology"):
        st.markdown("""
        <div style="background:#151d2e; border-left:4px solid #f59e0b; padding:0.8rem; border-radius:6px; margin-bottom:0.6rem;">
            <span style="color:#f59e0b; font-weight:bold;">Replanning Triggered 🔄</span><br>
            <span style="color:#94a3b8; font-size:0.85rem;">Network topology analyzed. Identified upstream node <code>Proxy-LB01</code> as active bypass route. Strategy shifted to upstream route isolation.</span>
        </div>
        """, unsafe_allow_html=True)

    # 4. Second Action
    has_upstream_action = any(a.get("action") == "block_upstream_route" for a in state.actions_taken)
    if has_upstream_action:
        st.markdown("""
        <div style="background:#151d2e; border-left:4px solid #8b5cf6; padding:0.8rem; border-radius:6px; margin-bottom:0.6rem;">
            <strong>Action 2: Upstream Route Isolation</strong><br>
            <code>block_upstream_route("Proxy-LB01")</code>
        </div>
        """, unsafe_allow_html=True)

    # 5. Final Verification
    if len(state.verification_results) > 1:
        verif2 = state.verification_results[-1]
        if verif2.get("verified"):
            st.markdown("""
            <div style="background:#151d2e; border-left:4px solid #10b981; padding:0.8rem; border-radius:6px; margin-bottom:0.6rem;">
                <span style="color:#10b981; font-weight:bold;">Verification 2: SUCCESS ✅</span><br>
                <span style="color:#94a3b8; font-size:0.85rem;">Active reachability probe confirms upstream route is severed. Target web-server-03 is completely protected.</span>
            </div>
            """, unsafe_allow_html=True)

    if state.status == "CONTAINED":
        st.success("🛡️ Final Incident Outcome: **CONTAINED**")


def render_evidence_panel(state: Optional[IncidentState]) -> None:
    """Displays evidence collected across all five dimensions."""
    st.markdown("### 🔍 Collected Incident Evidence")

    if not state:
        st.info("No evidence collected yet.")
        return

    ev = state.evidence_collected

    # 1. NIDS Alert
    with st.expander("🚨 NIDS Alert Evidence", expanded=bool(ev.get("alert"))):
        if ev.get("alert"):
            a = ev["alert"]
            st.markdown(f"**Alert ID:** `{a.get('alert_id')}` | **Severity:** `{a.get('severity')}`")
            st.markdown(f"**Signature:** `{a.get('signature')}`")
            st.markdown(f"**Description:** {a.get('description')}")
        else:
            st.write("Not yet gathered.")

    # 2. Asset Profile
    with st.expander("🖥️ Target Asset Context", expanded=bool(ev.get("asset"))):
        if ev.get("asset"):
            ast_data = ev["asset"]
            st.markdown(f"**Hostname:** `{ast_data.get('hostname')}` | **IP:** `{ast_data.get('ip_address')}`")
            st.markdown(f"**Role:** {ast_data.get('role')} | **OS:** {ast_data.get('os')}")
            st.markdown(f"**Criticality:** `{ast_data.get('criticality')}` | **Upstream Proxy:** `{ast_data.get('upstream_proxy')}`")
        else:
            st.write("Not yet gathered.")

    # 3. Vulnerabilities
    with st.expander("🔓 Known Vulnerabilities", expanded=bool(ev.get("vulnerabilities"))):
        if ev.get("vulnerabilities"):
            for v in ev["vulnerabilities"]:
                st.markdown(f"**CVE:** `{v.get('cve_id')}` | **Severity:** `{v.get('severity')}` (CVSS {v.get('cvss_score')})")
                st.markdown(f"**Vulnerability:** {v.get('title')}")
                st.markdown(f"**Status:** `{v.get('status')}` | **Component:** `{v.get('affected_component')}`")
        else:
            st.write("Not yet gathered.")

    # 4. Server Logs
    with st.expander("📜 Application & Server Logs", expanded=bool(ev.get("server_logs"))):
        if ev.get("server_logs"):
            for log in ev["server_logs"]:
                status_color = "#10b981" if log.get("status_code") == 200 else "#ef4444"
                st.markdown(f"""
                <div style="background:#0f172a; padding:0.5rem; border-radius:4px; margin-bottom:0.3rem; font-size:0.8rem; font-family:monospace;">
                    <span style="color:{status_color}; font-weight:bold;">[{log.get('status_code')}]</span>
                    {log.get('method')} {log.get('endpoint')} | Source: {log.get('source_ip')} via Proxy: {log.get('proxy_ip')}<br>
                    <span style="color:#94a3b8;">{log.get('message')}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.write("Not yet gathered.")

    # 5. Network Evidence
    with st.expander("📡 Network NetFlow Evidence", expanded=bool(ev.get("network_evidence"))):
        if ev.get("network_evidence"):
            net = ev["network_evidence"]
            st.markdown(f"**Flow ID:** `{net.get('flow_id')}` | **Protocol:** `{net.get('protocol')}`")
            st.markdown(f"**Target Reached:** `{net.get('request_reached_target')}` | **Intermediate Node:** `{net.get('proxy_node')}`")
            st.markdown(f"**Bytes Rx (Exfiltrated):** `{net.get('bytes_received')} bytes` ({net.get('bytes_received', 0) / 1024:.1f} KB)")
            st.markdown(f"**Flow Summary:** {net.get('summary')}")
        else:
            st.write("Not yet gathered.")


def render_agent_trace(state: Optional[IncidentState]) -> None:
    """Renders the real step-by-step AgentTraceEntry records."""
    st.markdown("### 📋 Autonomous Agent Trace")

    if not state or not state.trace:
        st.info("No investigation trace available. Click 'Run Investigation' to start.")
        return

    for entry in state.trace:
        # Determine CSS class based on outcome
        if "FAILED" in entry.summarized_result:
            box_class = "trace-step trace-step-failed"
            badge = "<span style='color:#ef4444; font-weight:bold;'>VERIFY FAILED ❌</span>"
        elif entry.action_type == "REPLAN" or "topology" in entry.rationale.decision.lower():
            box_class = "trace-step trace-step-replan"
            badge = "<span style='color:#f59e0b; font-weight:bold;'>REPLAN ⚡</span>"
        elif "SUCCESS" in entry.summarized_result and entry.tool_selected == "verify_block":
            box_class = "trace-step trace-step-success"
            badge = "<span style='color:#10b981; font-weight:bold;'>VERIFY SUCCESS ✅</span>"
        elif entry.action_type == "CONCLUDE":
            box_class = "trace-step trace-step-success"
            badge = "<span style='color:#10b981; font-weight:bold;'>CONTAINED 🛡️</span>"
        else:
            box_class = "trace-step trace-step-normal"
            badge = f"<span style='color:#38bdf8;'>{entry.action_type}</span>"

        tool_markup = ""
        if entry.tool_selected:
            tool_markup = f"<div class='trace-tool'>{entry.tool_selected}({entry.tool_input})</div>"

        html = f"""
        <div class="{box_class}">
            <div class="trace-header">
                <span class="trace-number">STEP {entry.step}</span>
                {badge}
            </div>
            <div class="trace-decision">{entry.rationale.decision}</div>
            <div class="trace-reason"><strong>Reason:</strong> {entry.rationale.reason}</div>
            {tool_markup}
            <div class="trace-result"><strong>Result:</strong> {entry.summarized_result}</div>
        </div>
        """
        st.markdown(html, unsafe_allow_html=True)
