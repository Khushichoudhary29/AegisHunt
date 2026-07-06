import pytest
from uuid import uuid4
from state.models import IncidentState, SeverityEnum, StatusEnum
from agents.log_analyst import LogAnalystAgent
from agents.threat_hunter import ThreatHunterAgent
from agents.incident_responder import IncidentResponderAgent
from tools.log_stream import LogStreamTool
from tools.cve_lookup import CVELookupTool
from tools.mitigation_sandbox import SandboxMitigationTool
from eval.simulator import AdversarialEvaluator, RedTeamSimulator

@pytest.mark.asyncio
async def test_log_analyst_agent():
    agent = LogAnalystAgent()
    
    # Generate mock log stream
    logs = LogStreamTool.get_ssh_brute_force_logs(attacker_ip="10.0.0.5", target_user="victim")
    state = IncidentState(raw_logs=logs)
    
    # Process
    updated_state = await agent.process(state)
    
    assert len(updated_state.detected_anomalies) > 0
    anomaly = updated_state.detected_anomalies[0]
    assert anomaly["type"] == "ssh_brute_force"
    assert anomaly["source_ip"] == "10.0.0.5"
    assert anomaly["target_user"] == "victim"

@pytest.mark.asyncio
async def test_threat_hunter_agent():
    hunter = ThreatHunterAgent()
    
    # Prepare dummy incident state with a detected anomaly
    state = IncidentState(
        detected_anomalies=[{
            "type": "sql_injection",
            "source_ip": "172.16.2.20"
        }]
    )
    
    updated_state = await hunter.process(state)
    
    assert "CVE-MOCK-SQLI" in updated_state.associated_cves
    assert updated_state.severity_score == SeverityEnum.HIGH

@pytest.mark.asyncio
async def test_incident_responder_agent():
    responder = IncidentResponderAgent()
    
    # Prepare state with anomalies and severity score
    state = IncidentState(
        severity_score=SeverityEnum.HIGH,
        detected_anomalies=[
            {
                "type": "sql_injection",
                "source_ip": "172.16.2.20",
                "payload": "UNION SELECT"
            },
            {
                "type": "reverse_shell",
                "source_ip": "172.16.2.30",
                "process_id": "9021"
            }
        ]
    )
    
    updated_state = await responder.process(state)
    
    # Check mitigation plan
    plan = updated_state.mitigation_plan
    assert "iptables -A INPUT -s 172.16.2.20 -j DROP" in plan
    assert "kill -9 9021" in plan
    assert "iptables -A OUTPUT -d 172.16.2.30 -j DROP" in plan
    assert updated_state.execution_status == StatusEnum.MITIGATED

def test_sandbox_tool():
    res = SandboxMitigationTool.execute_command("iptables -A INPUT -s 1.1.1.1 -j DROP")
    assert res["status"] == "success"
    assert "1.1.1.1" in res["stdout"]
    
    res_kill = SandboxMitigationTool.execute_command("kill -9 1234")
    assert res_kill["status"] == "success"
    assert "1234" in res_kill["stdout"]

def test_cve_lookup_tool():
    res = CVELookupTool.resolve_anomaly("sql_injection")
    assert res is not None
    assert res["cve_id"] == "CVE-MOCK-SQLI"
    assert "HIGH" in res["severity"]

@pytest.mark.asyncio
async def test_adversarial_evaluator():
    evaluator = AdversarialEvaluator()
    
    # Evaluate SQL Injection attack
    res_sqli = await evaluator.evaluate_run("sql_injection", "203.0.113.111")
    assert res_sqli["evaluation_passed"] is True
    assert res_sqli["severity_score"] == "HIGH"
    
    # Evaluate Reverse Shell attack
    res_rev = await evaluator.evaluate_run("reverse_shell", "198.51.100.222")
    assert res_rev["evaluation_passed"] is True
    assert res_rev["severity_score"] == "CRITICAL"
    assert res_rev["execution_status"] == "ESCALATED" # Critical escalates!
