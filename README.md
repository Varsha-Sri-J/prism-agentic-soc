# PRISM — Autonomous SOC Investigation & Response Agent

**Autonomous SOC Agent & Synthetic Environment (Phase 1 & Phase 2)**  
*Built for the Tech Zephyr 4.0 Agentic AI Hackathon*

---

## 1. Project Overview

PRISM is an autonomous Security Operations Center (SOC) agent that investigates security alerts, evaluates exploit success across multiple evidence dimensions, executes containment actions, actively verifies containment reachability, and dynamically replans when containment actions are bypassed.

The operational agent control loop is:
```
OBSERVE → DECIDE NEXT STEP → CALL TOOL → OBSERVE TOOL RESULT → UPDATE INCIDENT STATE → DECIDE AGAIN → ACT WHEN JUSTIFIED → VERIFY → REPLAN IF VERIFICATION FAILS → FINAL VERIFICATION
```

- **Phase 1:** Deterministic synthetic SOC environment, data stores, and verification engine.
- **Phase 2:** Autonomous agent control loop, persistent `IncidentState`, dynamic tool selection, failure replanning, and dual-mode decision engine (deterministic + LLM tool calling).

---

## 2. Directory Structure

```
prism-agentic-soc/
├── data/
│   ├── alerts.json             # NIDS/SIEM alert catalog (ALT-1042)
│   ├── assets.json             # Asset inventory with host profiles, roles & services
│   ├── vulnerabilities.json    # Target asset CVEs and vulnerability details
│   ├── server_logs.json        # Application & access logs showing attack execution
│   ├── network_evidence.json   # NetFlow / packet evidence and payload confirmation
│   ├── topology.json           # Network topology graph (nodes, routes, paths)
│   └── firewall_state.json     # Initial firewall & routing state
├── backend/
│   ├── __init__.py             # Public package exports
│   ├── models.py               # IncidentState, DecisionRationale, AgentTraceEntry
│   ├── decision_engine.py      # Deterministic & LLM-ready tool calling Decision Engines
│   ├── agent.py                # Autonomous PRISMAgent control loop
│   ├── environment.py          # SOCEnvironment engine managing datasets and state
│   └── tools.py                # 10 deterministic SOC tools
├── tests/
│   ├── __init__.py
│   ├── test_environment.py     # Phase 1 synthetic environment test suite (11 tests)
│   └── test_agent.py           # Phase 2 autonomous agent test suite (14 tests)
├── requirements.txt            # Dependencies (pytest)
├── .env.example                # LLM API configuration template
├── .gitignore
└── README.md                   # Complete architectural and API documentation
```

---

## 3. Persistent Incident State (`IncidentState`)

The agent maintains an explicit, stateful model throughout the entire lifecycle:

```python
IncidentState(
    incident_id="INC-ALT-1042",
    goal="Autonomously investigate alert ALT-1042, determine if attack succeeded, and contain threat.",
    alert={...},
    evidence_collected={
        "alert": {...},
        "asset": {...},
        "vulnerabilities": [...],
        "server_logs": [...],
        "network_evidence": {...},
        "network_topology": {...}
    },
    current_hypothesis="Incident resolved: SQL injection attack successfully contained via upstream route isolation.",
    confidence=1.0,
    investigation_history=[...],
    actions_taken=[...],
    verification_results=[...],
    failed_actions=[...],
    current_plan=[...],
    status="CONTAINED",
    trace=[...]
)
```

---

## 4. Structured Agent Trace

Each step produces a concise trace entry without exposing private chain-of-thought:

```
STEP 1 [INVESTIGATE]
Decision: Retrieve alert details
Reason:   Initial alert metadata is required to identify threat source IP, target asset, and alert signature.
Tool:     get_alert({'alert_id': 'ALT-1042'})
Result:   Alert retrieved: Possible SQL Injection from 10.20.14.52 targeting web-server-03.
...
STEP 7 [VERIFY]
Decision: Verify containment action (block_ip)
Reason:   Action 'block_ip' was applied. Active reachability probe is required to verify whether traffic to 'web-server-03' is blocked.
Tool:     verify_block({'target': 'web-server-03'})
Result:   Verification FAILED: Traffic bypass detected through Proxy-LB01.

STEP 8 [REPLAN]
Decision: Investigate network topology
Reason:   Containment verification failed. Must inspect network topology to uncover route forwarding or proxy bypass.
Tool:     get_network_topology({})
Result:   Topology graph retrieved: Routing path discovered through intermediate proxy 10.20.14.52 -> Proxy-LB01 -> web-server-03.

STEP 9 [ACT]
Decision: Isolate upstream route via Proxy-LB01
Reason:   Topology analysis reveals Proxy-LB01 is reverse-proxying attacker requests to target. Severing upstream route is required for containment.
Tool:     block_upstream_route({'route': 'Proxy-LB01'})
Result:   Upstream route isolation applied: Severed routing path via Proxy-LB01.

STEP 10 [VERIFY]
Decision: Verify containment action (block_upstream_route)
Reason:   Action 'block_upstream_route' was applied. Active reachability probe is required to verify whether traffic to 'web-server-03' is blocked.
Tool:     verify_block({'target': 'web-server-03'})
Result:   Verification SUCCESS: Threat path to web-server-03 is completely severed.

STEP 11 [CONCLUDE]
Decision: Conclude investigation
Reason:   Containment verification succeeded. Active probes confirm threat path is completely severed. Incident objective satisfied.
```

---

## 5. Running the Complete Test Suite

Run all 25 automated tests across Phase 1 and Phase 2:

```bash
# Using pytest
.venv/bin/pytest -v tests/

# Or using Python's standard library
python3 -m unittest discover -s tests -p "test_*.py" -v
```

### Running the Live Agent Demonstration

```bash
python3 -c '
from backend.agent import PRISMAgent

agent = PRISMAgent()
state = agent.run("ALT-1042")
for t in state.trace:
    print(f"STEP {t.step} [{t.action_type}] - {t.rationale.decision}")
    if t.tool_selected:
        print(f"  Tool: {t.tool_selected} -> {t.summarized_result}")
print(f"\nFinal State: {state.status} | Confidence: {int(state.confidence*100)}%")
'
```
