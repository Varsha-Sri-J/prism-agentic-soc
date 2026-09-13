"""
PRISM Dashboard Styles and Cyber SOC Dark Theme.
Defines CSS tokens, status badges, glow borders, and layout styles.
"""

CUSTOM_CSS = """
<style>
/* Global Cyber Dark Theme */
.stApp {
    background-color: #0b0f19;
    color: #e2e8f0;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

/* Header Container */
.prism-header {
    background: linear-gradient(135deg, #111827 0%, #1e293b 100%);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 1.5rem 2rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.prism-title {
    font-size: 2.2rem;
    font-weight: 800;
    letter-spacing: 0.1em;
    background: linear-gradient(90deg, #00f2fe 0%, #4facfe 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0;
}

.prism-subtitle {
    color: #94a3b8;
    font-size: 0.95rem;
    margin-top: 0.2rem;
}

/* Status Badges */
.badge-contained {
    background-color: rgba(16, 185, 129, 0.15);
    color: #10b981;
    border: 1px solid #10b981;
    padding: 0.35rem 0.85rem;
    border-radius: 9999px;
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    box-shadow: 0 0 12px rgba(16, 185, 129, 0.3);
}

.badge-investigating {
    background-color: rgba(56, 189, 248, 0.15);
    color: #38bdf8;
    border: 1px solid #38bdf8;
    padding: 0.35rem 0.85rem;
    border-radius: 9999px;
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    box-shadow: 0 0 12px rgba(56, 189, 248, 0.3);
}

.badge-mode {
    background-color: rgba(139, 92, 246, 0.15);
    color: #a78bfa;
    border: 1px solid #8b5cf6;
    padding: 0.35rem 0.85rem;
    border-radius: 9999px;
    font-size: 0.85rem;
    font-weight: 600;
}

/* Metric KPI Cards */
.kpi-card {
    background: #151d2e;
    border: 1px solid #233047;
    border-radius: 10px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.75rem;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
    transition: transform 0.2s ease, border-color 0.2s ease;
}

.kpi-card:hover {
    border-color: #38bdf8;
    transform: translateY(-2px);
}

.kpi-title {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: #64748b;
    letter-spacing: 0.05em;
    font-weight: 700;
}

.kpi-value {
    font-size: 1.25rem;
    font-weight: 700;
    color: #f8fafc;
    margin-top: 0.25rem;
}

/* Evidence Cards */
.evidence-card {
    background: #111827;
    border-left: 4px solid #3b82f6;
    border-top: 1px solid #1f2937;
    border-right: 1px solid #1f2937;
    border-bottom: 1px solid #1f2937;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 0.8rem;
}

.evidence-title {
    font-weight: 700;
    font-size: 0.95rem;
    color: #e2e8f0;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

/* Trace Step Box */
.trace-step {
    background: #131b2e;
    border: 1px solid #1f2d47;
    border-radius: 8px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.85rem;
    position: relative;
}

.trace-step-failed {
    border-left: 5px solid #ef4444;
    background: linear-gradient(90deg, rgba(239, 68, 68, 0.08) 0%, #131b2e 100%);
}

.trace-step-replan {
    border-left: 5px solid #f59e0b;
    background: linear-gradient(90deg, rgba(245, 158, 11, 0.08) 0%, #131b2e 100%);
}

.trace-step-success {
    border-left: 5px solid #10b981;
    background: linear-gradient(90deg, rgba(16, 185, 129, 0.08) 0%, #131b2e 100%);
}

.trace-step-normal {
    border-left: 5px solid #3b82f6;
}

.trace-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.4rem;
}

.trace-number {
    font-weight: 800;
    font-size: 0.85rem;
    letter-spacing: 0.05em;
    color: #94a3b8;
}

.trace-decision {
    font-size: 1rem;
    font-weight: 700;
    color: #f1f5f9;
}

.trace-reason {
    font-size: 0.85rem;
    color: #94a3b8;
    margin-top: 0.2rem;
}

.trace-tool {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: #38bdf8;
    background: rgba(56, 189, 248, 0.1);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    display: inline-block;
    margin-top: 0.4rem;
}

.trace-result {
    font-size: 0.85rem;
    color: #cbd5e1;
    margin-top: 0.4rem;
}

/* Topology Diagram Styling */
.topology-container {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 1.5rem;
    text-align: center;
    margin-bottom: 1.2rem;
}

.topo-node {
    display: inline-block;
    padding: 0.75rem 1.25rem;
    border-radius: 8px;
    font-weight: 700;
    font-size: 0.9rem;
    margin: 0.5rem;
    min-width: 150px;
}

.node-attacker {
    background: rgba(239, 68, 68, 0.15);
    color: #f87171;
    border: 1px solid #ef4444;
}

.node-proxy {
    background: rgba(245, 158, 11, 0.15);
    color: #fbbf24;
    border: 1px solid #f59e0b;
}

.node-target {
    background: rgba(59, 130, 246, 0.15);
    color: #60a5fa;
    border: 1px solid #3b82f6;
}

.node-contained {
    background: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid #10b981;
}

.arrow-path {
    color: #64748b;
    font-size: 1.2rem;
    font-weight: bold;
    margin: 0.2rem 0;
}

.arrow-severed {
    color: #ef4444;
    font-weight: bold;
    font-size: 0.9rem;
}
</style>
"""
