import asyncio
import argparse
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any

from state.models import IncidentState
from agents.log_analyst import LogAnalystAgent
from agents.threat_hunter import ThreatHunterAgent
from agents.incident_responder import IncidentResponderAgent
from eval.simulator import AdversarialEvaluator

# Initialize FastAPI App
app = FastAPI(
    title="AegisHunt API Gateway",
    description="Automated Incident Response & Threat Hunting Agent Webhook Services",
    version="1.0.0"
)

# Webhook payload models
class LogPayload(BaseModel):
    logs: List[str]

# Global agent instances
analyst_agent = LogAnalystAgent()
hunter_agent = ThreatHunterAgent()
responder_agent = IncidentResponderAgent()

from fastapi.responses import HTMLResponse

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisHunt SOC Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(17, 24, 39, 0.85);
            --border-color: rgba(255, 255, 255, 0.08);
            --primary: #00ccff;
            --success: #00ff66;
            --warning: #ffaa00;
            --danger: #ff3366;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(0, 204, 255, 0.05) 0px, transparent 50%),
                radial-gradient(at 50% 0%, rgba(139, 92, 246, 0.05) 0px, transparent 50%),
                radial-gradient(at 100% 0%, rgba(0, 255, 102, 0.05) 0px, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border-color);
            background: rgba(11, 15, 25, 0.5);
            backdrop-filter: blur(10px);
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .logo-container {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            border-radius: 8px;
            box-shadow: 0 0 15px rgba(0, 204, 255, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            color: #000;
            font-size: 1.2rem;
        }

        .logo-text {
            font-weight: 800;
            font-size: 1.5rem;
            background: linear-gradient(to right, #ffffff, #a5b4fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }

        .system-status {
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.85rem;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            padding: 0.4rem 0.8rem;
            border-radius: 20px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }

        .status-dot.active {
            background-color: var(--success);
            box-shadow: 0 0 10px var(--success);
            animation: pulse-green 2s infinite;
        }

        @keyframes pulse-green {
            0% { box-shadow: 0 0 0 0 rgba(0, 255, 102, 0.7); }
            70% { box-shadow: 0 0 0 6px rgba(0, 255, 102, 0); }
            100% { box-shadow: 0 0 0 0 rgba(0, 255, 102, 0); }
        }

        .main-container {
            display: grid;
            grid-template-columns: 1fr 1.5fr;
            gap: 2rem;
            padding: 2rem;
            max-width: 1600px;
            margin: 0 auto;
            width: 100%;
            flex-grow: 1;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            backdrop-filter: blur(12px);
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
        }

        h2 {
            font-size: 1.25rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.75rem;
        }

        .attack-btn-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 0.75rem;
        }

        .btn {
            font-family: 'Outfit', sans-serif;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            text-align: center;
        }

        .btn:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: var(--primary);
            box-shadow: 0 0 10px rgba(0, 204, 255, 0.2);
            transform: translateY(-1px);
        }

        .btn.primary {
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            color: #000;
            border: none;
            width: 100%;
            padding: 1rem;
            font-size: 1.05rem;
            letter-spacing: 0.5px;
            box-shadow: 0 4px 15px rgba(0, 204, 255, 0.3);
        }

        .btn.primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 204, 255, 0.5);
            background: linear-gradient(135deg, #33d6ff, #9f7aea);
        }

        .textarea-container {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            flex-grow: 1;
        }

        textarea {
            width: 100%;
            min-height: 250px;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            color: #38bdf8;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            resize: vertical;
            outline: none;
            transition: border-color 0.2s ease;
        }

        textarea:focus {
            border-color: var(--primary);
        }

        .metrics-row {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
        }

        .metric-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            padding: 1rem;
            border-radius: 12px;
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .metric-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .metric-value {
            font-size: 1.1rem;
            font-weight: 800;
        }

        .agent-container {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .agent-card {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.3s ease;
        }

        .agent-card.active {
            border-color: var(--primary);
            box-shadow: 0 0 15px rgba(0, 204, 255, 0.15);
        }

        .agent-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 1rem;
            background: rgba(255, 255, 255, 0.04);
            border-bottom: 1px solid var(--border-color);
        }

        .agent-title {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 600;
            font-size: 0.95rem;
        }

        .agent-badge {
            width: 24px;
            height: 24px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 800;
            color: #000;
        }

        .agent-badge.a { background-color: #00ccff; }
        .agent-badge.b { background-color: #8b5cf6; }
        .agent-badge.c { background-color: #00ff66; }

        .agent-content {
            padding: 1rem;
            font-size: 0.9rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0, 0, 0, 0.2);
            color: #e5e7eb;
        }

        .remediation-line {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--success);
        }

        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 800;
        }

        .severity-badge.CRITICAL {
            background-color: rgba(255, 51, 102, 0.2);
            border: 1px solid var(--danger);
            color: var(--danger);
            animation: pulse-danger 1.5s infinite;
        }
        .severity-badge.HIGH {
            background-color: rgba(255, 170, 0, 0.2);
            border: 1px solid var(--warning);
            color: var(--warning);
        }
        .severity-badge.MEDIUM {
            background-color: rgba(234, 179, 8, 0.2);
            border: 1px solid #eab308;
            color: #facc15;
        }
        .severity-badge.LOW {
            background-color: rgba(0, 255, 102, 0.2);
            border: 1px solid var(--success);
            color: var(--success);
        }

        @keyframes pulse-danger {
            0% { box-shadow: 0 0 0 0 rgba(255, 51, 102, 0.4); }
            70% { box-shadow: 0 0 0 6px rgba(255, 51, 102, 0); }
            100% { box-shadow: 0 0 0 0 rgba(255, 51, 102, 0); }
        }

        .execution-status-val {
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }
        
        .status-text.MITIGATED { color: var(--success); }
        .status-text.ESCALATED { color: var(--danger); font-weight: 800; }
        .status-text.PENDING { color: var(--warning); }

        footer {
            padding: 1.5rem 2rem;
            border-top: 1px solid var(--border-color);
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            background: rgba(11, 15, 25, 0.5);
            margin-top: auto;
        }

        .empty-state {
            color: var(--text-muted);
            text-align: center;
            padding: 2rem;
            font-style: italic;
        }

        .highlight-text {
            color: var(--primary);
        }
        
        .code-block {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 0.5rem;
            border-radius: 6px;
            font-size: 0.8rem;
            margin-top: 0.25rem;
            color: #f3f4f6;
            overflow-x: auto;
        }
    </style>
</head>
<body>

    <header>
        <div class="logo-container">
            <div class="logo-icon">🛡️</div>
            <div class="logo-text">AegisHunt SOC</div>
        </div>
        <div class="system-status">
            <div class="status-badge">
                <span class="status-dot active"></span>
                <span>ENGINE: ONLINE</span>
            </div>
            <div class="status-badge">
                <span>AGENTS: 3 ACTIVE</span>
            </div>
        </div>
    </header>

    <div class="main-container">
        <!-- Attack Simulator Card -->
        <div class="card">
            <h2>🚨 Adversarial Injection Console</h2>
            
            <div class="attack-btn-grid">
                <button class="btn" onclick="loadLogs('sqli')">💉 Mutated SQLi</button>
                <button class="btn" onclick="loadLogs('revshell')">🐚 B64 RevShell</button>
                <button class="btn" onclick="loadLogs('ssh')">🔑 SSH Brute Force</button>
                <button class="btn" onclick="loadLogs('normal')">🟢 Normal Activity</button>
            </div>

            <div class="textarea-container">
                <label style="font-size: 0.85rem; color: var(--text-muted); font-weight: 600;">Ingested Server Logs Buffer</label>
                <textarea id="logBuffer" placeholder="Select an attack mutation above or type raw server logs here..."></textarea>
            </div>

            <button class="btn primary" id="pipelineBtn" onclick="runPipeline()">🚀 Run Multi-Agent Defense Loop</button>
        </div>

        <!-- SOC Dashboard Output -->
        <div class="card">
            <h2>📊 Real-Time Orchestration Output</h2>
            
            <!-- Global Metrics -->
            <div class="metrics-row">
                <div class="metric-card">
                    <span class="metric-label">Incident ID</span>
                    <span class="metric-value" id="incidentId" style="font-size: 0.85rem; font-family: 'JetBrains Mono'; font-weight: normal; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">N/A</span>
                </div>
                <div class="metric-card">
                    <span class="metric-label">Severity Assessment</span>
                    <span class="metric-value" id="severityVal">LOW</span>
                </div>
                <div class="metric-card">
                    <span class="metric-label">Remediation Status</span>
                    <span class="metric-value execution-status-val" id="statusVal">PENDING</span>
                </div>
            </div>

            <!-- Agents Outputs -->
            <div class="agent-container">
                <!-- Agent A -->
                <div class="agent-card" id="agentACard">
                    <div class="agent-header">
                        <div class="agent-title">
                            <span class="agent-badge a">A</span>
                            <span>Log Analyst & Triage Router</span>
                        </div>
                        <span style="font-size: 0.75rem; color: var(--text-muted);">agent_a_triage</span>
                    </div>
                    <div class="agent-content" id="agentAContent">
                        <div class="empty-state">Awaiting raw log stream ingestion...</div>
                    </div>
                </div>

                <!-- Agent B -->
                <div class="agent-card" id="agentBCard">
                    <div class="agent-header">
                        <div class="agent-title">
                            <span class="agent-badge b">B</span>
                            <span>Threat Hunter & CVE Investigator</span>
                        </div>
                        <span style="font-size: 0.75rem; color: var(--text-muted);">agent_b_threat_intel</span>
                    </div>
                    <div class="agent-content" id="agentBContent">
                        <div class="empty-state">Awaiting Triage data...</div>
                    </div>
                </div>

                <!-- Agent C -->
                <div class="agent-card" id="agentCCard">
                    <div class="agent-header">
                        <div class="agent-title">
                            <span class="agent-badge c">C</span>
                            <span>Incident Responder & Sandbox</span>
                        </div>
                        <span style="font-size: 0.75rem; color: var(--text-muted);">agent_c_responder</span>
                    </div>
                    <div class="agent-content" id="agentCContent">
                        <div class="empty-state">Awaiting remediation parameters...</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer>
        <p>AegisHunt Cybersecurity Capstone • Powered by Custom Multi-Agent Async Orchestrator</p>
    </footer>

    <script>
        async function loadLogs(type) {
            try {
                const res = await fetch(`/api/simulate/${type}`);
                if (!res.ok) throw new Error("Failed to load logs");
                const data = await res.json();
                document.getElementById('logBuffer').value = data.logs.join('\\n');
            } catch (err) {
                alert("Error loading mock log variant: " + err.message);
            }
        }

        async function runPipeline() {
            const rawLogsText = document.getElementById('logBuffer').value.trim();
            if (!rawLogsText) {
                alert("Please inject or type some logs first!");
                return;
            }

            const pipelineBtn = document.getElementById('pipelineBtn');
            pipelineBtn.disabled = true;
            pipelineBtn.textContent = "⚡ Running Multi-Agent Pipeline...";

            // Clear visual state
            document.getElementById('agentACard').classList.remove('active');
            document.getElementById('agentBCard').classList.remove('active');
            document.getElementById('agentCCard').classList.remove('active');

            try {
                const logs = rawLogsText.split('\\n').filter(l => l.trim() !== '');
                const res = await fetch('/webhook', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ logs })
                });

                if (!res.ok) throw new Error("Webhook server error");

                const result = await res.json();

                // Update Globals
                document.getElementById('incidentId').innerText = result.incident_id || "N/A";
                
                // Severity Badge
                const severity = result.severity_score || "LOW";
                document.getElementById('severityVal').innerHTML = `<span class="severity-badge ${severity}">${severity}</span>`;
                
                // Status Badge
                const status = result.execution_status || "PENDING";
                document.getElementById('statusVal').innerHTML = `<span class="status-text ${status}">${status}</span>`;

                // Render Agent A
                document.getElementById('agentACard').classList.add('active');
                const anomalies = result.detected_anomalies || [];
                if (anomalies.length === 0) {
                    document.getElementById('agentAContent').innerHTML = `<div>[Triage] No security anomalies detected in raw logs. Normal state.</div>`;
                } else {
                    let agentAHtml = `<div><strong>[Triage] Detected Anomalies (${anomalies.length}):</strong></div>`;
                    anomalies.forEach((a, idx) => {
                        agentAHtml += `
                            <div style="margin-top: 0.5rem; border-left: 2px solid var(--primary); padding-left: 0.5rem;">
                                <div>Anomaly #${idx+1}: <span class="highlight-text">${a.type}</span></div>
                                <div>Source IP: ${a.source_ip || 'N/A'}</div>
                                ${a.target_port ? `<div>Target Port: ${a.target_port}</div>` : ''}
                                ${a.process_id ? `<div>Process ID: ${a.process_id}</div>` : ''}
                                ${a.payload ? `<div>Extracted Payload: <code>${a.payload}</code></div>` : ''}
                            </div>
                        `;
                    });
                    document.getElementById('agentAContent').innerHTML = agentAHtml;
                }

                // Render Agent B (after 500ms delay for visual workflow transition)
                setTimeout(() => {
                    document.getElementById('agentBCard').classList.add('active');
                    const cves = result.associated_cves || [];
                    if (cves.length === 0) {
                        document.getElementById('agentBContent').innerHTML = `<div>[Threat Intel] No associated CVE registries. Risk rating minimal.</div>`;
                    } else {
                        let agentBHtml = `<div><strong>[Threat Intel] Correlated Intel:</strong></div>`;
                        anomalies.forEach(a => {
                            if (a.cve_id) {
                                agentBHtml += `
                                    <div style="margin-top: 0.5rem; border-left: 2px solid #8b5cf6; padding-left: 0.5rem;">
                                        <div>CVE Reference: <span style="color: #a78bfa; font-weight:600;">${a.cve_id}</span></div>
                                        <div>MITRE Techniques: ${a.mitre_techniques ? a.mitre_techniques.join(', ') : 'N/A'}</div>
                                        <div>Impact: <span style="color: #f43f5e;">${a.impact || 'N/A'}</span></div>
                                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">Remediation: ${a.remediation_summary || 'N/A'}</div>
                                    </div>
                                `;
                            }
                        });
                        document.getElementById('agentBContent').innerHTML = agentBHtml;
                    }
                }, 400);

                // Render Agent C
                setTimeout(() => {
                    document.getElementById('agentCCard').classList.add('active');
                    const mitigations = result.mitigation_plan || [];
                    if (mitigations.length === 0) {
                        document.getElementById('agentCContent').innerHTML = `<div>[Containment] Plan empty. No action taken.</div>`;
                    } else {
                        let agentCHtml = `<div><strong>[Remediation] Mapped Sandbox Operations:</strong></div>`;
                        mitigations.forEach(cmd => {
                            const isComment = cmd.startsWith('#');
                            if (isComment) {
                                agentCHtml += `<div style="color: var(--text-muted); font-size: 0.8rem; margin-top: 0.25rem;">${cmd}</div>`;
                            } else {
                                agentCHtml += `
                                    <div class="remediation-line" style="margin-top: 0.25rem;">
                                        <span>⚙️</span>
                                        <div>
                                            <div class="code-block">${cmd}</div>
                                        </div>
                                    </div>
                                `;
                            }
                        });
                        agentCHtml += `
                            <div style="margin-top: 0.75rem; font-size: 0.85rem; font-weight:600;">
                                Sandbox status: <span class="status-text ${status}">${status === 'ESCALATED' ? 'ESCALATED to SOC Human Handler' : 'SUCCESSFULLY DEPLOYED & CONTAINED'}</span>
                            </div>
                        `;
                        document.getElementById('agentCContent').innerHTML = agentCHtml;
                    }
                }, 800);

            } catch (err) {
                alert("Pipeline execution failed: " + err.message);
            } finally {
                pipelineBtn.disabled = false;
                pipelineBtn.textContent = "🚀 Run Multi-Agent Defense Loop";
            }
        }

        // Initialize normal logs on load
        loadLogs('normal');
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def read_root():
    return DASHBOARD_HTML

@app.get("/api/simulate/{attack_type}")
def get_simulated_logs(attack_type: str, ip: str = "192.168.1.188"):
    from eval.simulator import RedTeamSimulator
    from tools.log_stream import LogStreamTool
    if attack_type == "ssh":
        return {"logs": LogStreamTool.get_ssh_brute_force_logs(attacker_ip=ip)}
    elif attack_type == "sqli":
        return {"logs": RedTeamSimulator.mutate_sql_injection(attacker_ip=ip)}
    elif attack_type == "revshell":
        return {"logs": RedTeamSimulator.mutate_reverse_shell(attacker_ip=ip)}
    elif attack_type == "normal":
        return {"logs": [
            "2026-07-06T18:00:00Z systemd[1]: Started System Logging Service.",
            "2026-07-06T18:05:22Z CRON[1204]: (root) CMD (sysstat-collect)",
            '2026-07-06T18:10:01Z nginx[1022]: 127.0.0.1 - - [06/Jul/2026:18:10:01 +0000] "GET /health HTTP/1.1" 200 45'
        ]}
    else:
        raise HTTPException(status_code=400, detail="Invalid attack type")

@app.post("/webhook")
async def receive_logs(payload: LogPayload):
    """
    Ingests raw log streams via webhook, pushes them through the AegisHunt Agent Pipeline,
    and returns the orchestrated containment and threat details.
    """
    if not payload.logs:
        raise HTTPException(status_code=400, detail="Log list cannot be empty")
        
    try:
        # 1. Initialize State
        state = IncidentState(raw_logs=payload.logs)
        
        # 2. Run sequential agent loops
        state = await analyst_agent.process(state)
        state = await hunter_agent.process(state)
        state = await responder_agent.process(state)
        
        # 3. Return serialized Pydantic state model
        return state.model_dump()
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Agent internal workflow failed: {str(e)}")


async def run_simulation():
    """
    Runs automated Red Team logs through the AegisHunt agents and prints
    evaluation statistics.
    """
    print("=" * 70)
    print("       AegisHunt: Adversarial Evaluation & Red Team Simulation")
    print("=" * 70)
    
    evaluator = AdversarialEvaluator()
    
    scenarios = [
        {"type": "sql_injection", "ip": "203.0.113.88"},
        {"type": "reverse_shell", "ip": "198.51.100.77"}
    ]
    
    all_passed = True
    for scenario in scenarios:
        print(f"\n[+] Injecting Mutated Red Team Attack: {scenario['type'].upper()}")
        print(f"    Attacker Source IP: {scenario['ip']}")
        
        result = await evaluator.evaluate_run(scenario["type"], scenario["ip"])
        
        print("\n--- Agent Execution Output ---")
        print(f"Logs Analyzed: {result['logs_analyzed']}")
        print(f"Anomalies Found: {result['anomalies_detected']}")
        print(f"Assessed Severity: {result['severity_score']}")
        print(f"Execution Status: {result['execution_status']}")
        print("Remediation Plan:")
        for cmd in result['mitigation_plan']:
            print(f"  - {cmd}")
            
        print(f"Expected Blocking Rule: {result['expected_remediation_rule']}")
        
        if result['evaluation_passed']:
            print("\033[92m[PASS] Defensive agents mitigated the attack successfully!\033[0m")
        else:
            print("\033[91m[FAIL] Defense response missed targeting the attacker asset.\033[0m")
            all_passed = False
            
    print("\n" + "=" * 70)
    if all_passed:
        print("RESULT: ALL SIMULATION SCENARIOS PASSED")
    else:
        print("RESULT: SOME SCENARIOS FAILED")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="AegisHunt CLI Daemon")
    parser.add_argument(
        "--mode",
        choices=["simulate", "server"],
        default="simulate",
        help="Run simulation suite or start FastAPI production webhook receiver."
    )
    parser.add_argument("--host", default="0.0.0.0", help="Binding host for FastAPI server")
    parser.add_argument("--port", type=int, default=8000, help="Listening port for FastAPI server")
    
    args = parser.parse_args()
    
    if args.mode == "simulate":
        asyncio.run(run_simulation())
    elif args.mode == "server":
        uvicorn.run(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main()
