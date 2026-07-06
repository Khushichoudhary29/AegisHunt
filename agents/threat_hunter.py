from typing import List
from state.models import IncidentState, SeverityEnum
from agents.base import AegisAgent
from tools.cve_lookup import CVELookupTool

class ThreatHunterAgent(AegisAgent):
    """
    Agent B: Threat Hunter & CVE Investigator.
    Queries the local mock CVE registry based on Agent A's indicators, maps threat events
    to MITRE ATT&CK techniques, and dynamically calculates overall incident severity.
    """

    def __init__(self):
        super().__init__(name="ThreatHunterAgent")

    async def process(self, state: IncidentState) -> IncidentState:
        self.logger.info("Starting Threat Intelligence enrichment & CVE correlation...")

        if not state.detected_anomalies:
            self.logger.info("No anomalies detected in prior step. Skipping enrichment.")
            state.severity_score = SeverityEnum.LOW
            return state

        highest_severity = SeverityEnum.LOW
        associated_cves = []

        # Maps string representation to SeverityEnum for comparison
        severity_rank = {
            SeverityEnum.LOW: 1,
            SeverityEnum.MEDIUM: 2,
            SeverityEnum.HIGH: 3,
            SeverityEnum.CRITICAL: 4
        }

        for anomaly in state.detected_anomalies:
            anomaly_type = anomaly.get("type")
            if not anomaly_type:
                continue

            # Special case for brute force leading to success
            if anomaly_type == "ssh_brute_force_success":
                anomaly_type = "ssh_brute_force"
                cve_info = CVELookupTool.resolve_anomaly(anomaly_type)
                if cve_info:
                    # Upgrade severity because the attempt was successful
                    cve_info = dict(cve_info)  # copy it
                    cve_info["severity"] = "CRITICAL"
            else:
                cve_info = CVELookupTool.resolve_anomaly(anomaly_type)

            if cve_info:
                cve_id = cve_info["cve_id"]
                severity_str = cve_info["severity"].upper()
                
                # Convert string severity to SeverityEnum
                try:
                    cve_severity = SeverityEnum(severity_str)
                except ValueError:
                    cve_severity = SeverityEnum.MEDIUM

                self.logger.info(
                    f"Correlated anomaly '{anomaly_type}' to threat intel record: "
                    f"{cve_id} ({cve_info['title']}) | Severity: {severity_str} | MITRE: {cve_info['mitre_techniques']}"
                )

                if cve_id not in associated_cves:
                    associated_cves.append(cve_id)

                # Track highest severity
                if severity_rank[cve_severity] > severity_rank[highest_severity]:
                    highest_severity = cve_severity
                    
                # Update anomaly dictionary in state with CVE enrichment info
                anomaly["cve_id"] = cve_id
                anomaly["mitre_techniques"] = cve_info["mitre_techniques"]
                anomaly["impact"] = cve_info["impact"]
                anomaly["remediation_summary"] = cve_info["remediation"]
            else:
                self.logger.info(f"No direct CVE mapping found for anomaly category: {anomaly_type}")

        state.associated_cves = associated_cves
        state.severity_score = highest_severity
        self.logger.info(f"Enrichment completed. Associated CVEs: {associated_cves} | Evaluated Severity: {highest_severity.value}")
        return state
