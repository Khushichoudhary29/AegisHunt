from state.models import IncidentState, StatusEnum, SeverityEnum
from agents.base import AegisAgent
from tools.mitigation_sandbox import SandboxMitigationTool

class IncidentResponderAgent(AegisAgent):
    """
    Agent C: Incident Responder & Remediation Agent.
    Formulates remediation scripts and firewall rules based on the severity and CVE analysis,
    and runs containment commands safely via the SandboxMitigationTool.
    """

    def __init__(self):
        super().__init__(name="IncidentResponderAgent")

    async def process(self, state: IncidentState) -> IncidentState:
        self.logger.info("Formulating Incident Containment & Remediation plan...")

        if not state.detected_anomalies:
            self.logger.info("No anomalies to mitigate. Setting status to MITIGATED.")
            state.execution_status = StatusEnum.MITIGATED
            return state

        mitigation_plan = []

        # Generate containment commands based on each structured anomaly
        for anomaly in state.detected_anomalies:
            anomaly_type = anomaly.get("type")
            source_ip = anomaly.get("source_ip", "0.0.0.0")
            pid = anomaly.get("process_id")

            if anomaly_type in ("ssh_brute_force", "ssh_brute_force_success"):
                if source_ip and source_ip != "0.0.0.0":
                    block_cmd = f"iptables -A INPUT -s {source_ip} -j DROP"
                    mitigation_plan.append(block_cmd)
                    self.logger.info(f"Drafted Network Containment: Block SSH Brute Force IP {source_ip}")

            elif anomaly_type == "sql_injection":
                if source_ip and source_ip != "0.0.0.0":
                    block_cmd = f"iptables -A INPUT -s {source_ip} -j DROP"
                    mitigation_plan.append(block_cmd)
                    self.logger.info(f"Drafted Network Containment: Block SQL Injection attacker IP {source_ip}")
                
                # Mock WAF Rule configuration step
                payload = anomaly.get("payload", "")
                mitigation_plan.append(f"# WAF rule block payload keyword: {payload}")

            elif anomaly_type == "reverse_shell":
                # Kill malicious process
                if pid and pid != "unknown":
                    kill_cmd = f"kill -9 {pid}"
                    mitigation_plan.append(kill_cmd)
                    self.logger.info(f"Drafted Host Containment: Kill malicious process PID {pid}")
                
                # Block command-and-control connection
                if source_ip and source_ip != "0.0.0.0":
                    block_cmd = f"iptables -A OUTPUT -d {source_ip} -j DROP"
                    mitigation_plan.append(block_cmd)
                    self.logger.info(f"Drafted Network Isolation: Block outgoing connections to C2 IP {source_ip}")

        state.mitigation_plan = mitigation_plan

        # Execute/Simulate commands via SandboxMitigationTool
        self.logger.info("Deploying drafted remediation steps to Sandbox Mitigation Environment...")
        all_success = True
        for cmd in mitigation_plan:
            if cmd.startswith("#"):
                continue  # skip comments in execution execution
            
            result = SandboxMitigationTool.execute_command(cmd)
            if result.get("code") == 0:
                self.logger.info(f"Executed: {cmd} -> {result.get('stdout')}")
            else:
                self.logger.error(f"Execution Failed: {cmd} -> {result.get('stderr')}")
                all_success = False

        # Set final execution status based on outcome and severity
        if all_success:
            if state.severity_score == SeverityEnum.CRITICAL:
                self.logger.warning("Vulnerability severity is CRITICAL. Escalating incident to human SOC Analysts for validation.")
                state.execution_status = StatusEnum.ESCALATED
            else:
                self.logger.info("Incident containment completed successfully. Setting status to MITIGATED.")
                state.execution_status = StatusEnum.MITIGATED
        else:
            self.logger.error("Remediation execution encountered failures. Escalating incident.")
            state.execution_status = StatusEnum.ESCALATED

        return state
