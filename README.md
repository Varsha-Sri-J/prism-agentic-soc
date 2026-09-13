# PRISM — Autonomous SOC Investigation & Response Agent

**Autonomous SOC Agent, Synthetic Environment & Real LLM Tool Calling (Phases 1, 2 & 3)**  
*Built for the Tech Zephyr 4.0 Agentic AI Hackathon*

---

## 1. Project Overview

PRISM is an autonomous Security Operations Center (SOC) agent that investigates security alerts, evaluates exploit success across multiple evidence dimensions, executes containment actions, actively verifies containment reachability, and dynamically replans when containment actions are bypassed.

The operational agent control loop is:
```
OBSERVE → DECIDE NEXT STEP → CALL TOOL → OBSERVE TOOL RESULT → UPDATE INCIDENT STATE → DECIDE AGAIN → ACT WHEN JUSTIFIED → VERIFY → REPLAN IF VERIFICATION FAILS → FINAL VERIFICATION
```

- **Phase 1:** Deterministic synthetic SOC environment, data stores, and verification engine.
- **Phase 2:** Autonomous agent control loop, persistent `IncidentState`, dynamic tool selection, and failure replanning.
- **Phase 3:** Real LLM-driven structured tool calling (Google Gemini support via `GEMINI_API_KEY`), strict validation and safety constraints, single-retry error recovery, deterministic fallback, and `LIVE` vs `MOCK` demonstration modes.

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
│   ├── llm_provider.py         # LLMProvider base, GeminiProvider (REST), MockLLMProvider
│   ├── decision_engine.py      # LLMDecisionEngine (validation/retries/fallback) & DeterministicDecisionEngine
│   ├── agent.py                # Autonomous PRISMAgent control loop with mode reporting
│   ├── environment.py          # SOCEnvironment engine managing datasets and state
│   └── tools.py                # 10 deterministic SOC tools
├── tests/
│   ├── __init__.py
│   ├── test_environment.py     # Phase 1 synthetic environment test suite (11 tests)
│   ├── test_agent.py           # Phase 2 autonomous agent test suite (14 tests)
│   └── test_llm_engine.py      # Phase 3 LLM tool calling test suite (12 tests)
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

---

## 5. Demonstration Modes: LIVE vs MOCK

PRISM operates in two primary execution modes:

### MOCK Mode (Default / Offline)
- Uses `MockLLMProvider` or `DeterministicDecisionEngine`.
- Requires **no external API keys** or active internet connection.
- Ideal for automated CI/CD, local evaluation, and test suites.

```bash
python3 -c '
from backend.agent import PRISMAgent

agent = PRISMAgent()
print(f"Active Mode: {agent.mode}")
state = agent.run("ALT-1042")
print(f"Final Outcome: {state.status} | Confidence: {int(state.confidence*100)}%")
'
```

### LIVE Mode (Google Gemini)
- Uses real LLM-driven structured tool calling via `GeminiProvider`.
- Configure your Gemini API key in your environment or `.env` file:
```bash
export LLM_PROVIDER=gemini
export GEMINI_API_KEY="your_gemini_api_key_here"
export LLM_MODEL="gemini-1.5-flash"
```
- PRISM will automatically detect the configuration and operate in `LIVE (gemini:gemini-1.5-flash)` mode.
- If the API key is missing or the network fails, PRISM automatically retries once and safely falls back to deterministic decision making.

---

## 6. Safety & Tool Whitelist Constraints

The LLM decision engine enforces strict safety boundaries:
1. **No Code Execution:** The LLM is never given access to Python `eval`, shell interpreters, or arbitrary system commands.
2. **Strict Whitelist:** Tool calls are validated against the 10 registered PRISM tools:
   - `get_alert`, `get_asset`, `search_vulnerabilities`, `search_server_logs`, `get_network_evidence`, `get_network_topology`, `block_ip`, `block_upstream_route`, `verify_block`, `get_environment_state`.
3. **Parameter Verification:** All tool call arguments and types are strictly validated before execution.
4. **No Hidden Chain-of-Thought:** Decisions only persist concise rationale objects (`decision` and `reason`).

---

## 7. Running the Complete Test Suite

The test suite covers 37 automated tests across all 3 phases:

```bash
# Using pytest
.venv/bin/pytest -v tests/

# Or using Python standard library
python3 -m unittest discover -s tests -p "test_*.py" -v
```

### Test Suite Verification Matrix

- [x] **Phase 1: Synthetic SOC Environment** (11 tests in `tests/test_environment.py`)
  - Retrieval of alerts, assets, vulnerabilities, server logs, network evidence, and topology.
  - Verification failure after naive `block_ip`.
  - Discovery of `Proxy-LB01` and successful containment via `block_upstream_route`.
- [x] **Phase 2: Autonomous Agent Control Loop** (14 tests in `tests/test_agent.py`)
  - Persistent `IncidentState` management and lifecycle progression.
  - Multi-dimensional evidence correlation.
  - Dynamic replanning triggered by failed verification (not a predetermined sequence).
  - Clean trace generation and state updates.
- [x] **Phase 3: Real LLM Tool Calling & Safety** (12 tests in `tests/test_llm_engine.py`)
  - Structured decision parsing (`action="tool_call"` and `action="finish"`).
  - Safety validation rejecting unwhitelisted and dangerous tools.
  - Single-retry correction on malformed model responses.
  - Graceful fallback to deterministic decision making.
  - End-to-end investigation with dynamic replanning in `MOCK` mode.
  - `LIVE` vs `MOCK` mode reporting.
