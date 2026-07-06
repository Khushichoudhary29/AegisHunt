import re
import base64
from typing import List, Dict, Any
from state.models import IncidentState
from agents.base import AegisAgent

class LogAnalystAgent(AegisAgent):
    """
    Agent A: Log Analyst & Triage Router.
    Scans incoming server logs, identifies anomalies, parses malicious indicators
    (IPs, usernames, process IDs, attack patterns), and structures them into state anomalies.
    """
    
    def __init__(self):
        super().__init__(name="LogAnalystAgent")
        
        # Regex patterns for matching common indicators of compromise (IOCs)
        self.ssh_failed_pattern = re.compile(
            r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        )
        self.ssh_accepted_pattern = re.compile(
            r"Accepted password for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        )
        self.sqli_pattern = re.compile(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*(UNION%20SELECT|UNION\s+SELECT|'1'='1|DROP%20TABLE|DROP\s+TABLE)",
            re.IGNORECASE
        )
        self.revshell_pattern = re.compile(
            r"a\d=\"/dev/tcp/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)\"|spawn(?:ed|ing).*shell.*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)|/dev/tcp/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)",
            re.IGNORECASE
        )
        self.pid_pattern = re.compile(r"auditd\[(\d+)\]|Process\s+(\d+)")

    async def process(self, state: IncidentState) -> IncidentState:
        self.logger.info("Initializing Log Triage Loop across incoming raw logs...")
        
        ssh_failures = {}
        anomalies: List[Dict[str, Any]] = []

        for log in state.raw_logs:
            # Heuristic Base64 detection to decode nested malicious payloads
            b64_candidates = re.findall(r"([A-Za-z0-9+/]{16,}={0,2})", log)
            for candidate in b64_candidates:
                try:
                    # Pad correctly if length is not multiple of 4
                    missing_padding = len(candidate) % 4
                    padded_candidate = candidate
                    if missing_padding:
                        padded_candidate += '=' * (4 - missing_padding)
                    decoded = base64.b64decode(padded_candidate).decode("utf-8", errors="ignore")
                    if "/dev/tcp/" in decoded or "bash -i" in decoded:
                        self.logger.warning(f"CRITICAL IOC: Heuristics decoded base64 payload from log: {decoded.strip()}")
                        log = log + f" [Decoded: {decoded}]"
                        break
                except Exception:
                    pass

            # 1. Check Reverse Shell Indicators
            revshell_match = self.revshell_pattern.search(log)
            if revshell_match:
                # Extract destination IP & port depending on which regex group matched
                groups = [g for g in revshell_match.groups() if g is not None]
                dest_ip = groups[0] if len(groups) > 0 else "unknown"
                dest_port = groups[1] if len(groups) > 1 else "unknown"
                
                # Extract PID
                pid_match = self.pid_pattern.search(log)
                pid = pid_match.group(1) or pid_match.group(2) if pid_match else "unknown"
                
                self.logger.warning(f"CRITICAL IOC: Interactive Reverse Shell detected to {dest_ip}:{dest_port} (PID: {pid})")
                anomalies.append({
                    "type": "reverse_shell",
                    "source_ip": dest_ip,
                    "target_port": dest_port,
                    "process_id": pid,
                    "raw_evidence": log
                })
                continue

            # 2. Check SQL Injection Indicators
            sqli_match = self.sqli_pattern.search(log)
            if sqli_match:
                attacker_ip = sqli_match.group(1)
                payload = sqli_match.group(2)
                self.logger.warning(f"HIGH IOC: SQL Injection payload '{payload}' detected from {attacker_ip}")
                anomalies.append({
                    "type": "sql_injection",
                    "source_ip": attacker_ip,
                    "payload": payload,
                    "raw_evidence": log
                })
                continue

            # 3. Check SSH Auth Anomalies
            ssh_failed_match = self.ssh_failed_pattern.search(log)
            if ssh_failed_match:
                username = ssh_failed_match.group(1)
                ip = ssh_failed_match.group(2)
                ssh_failures[ip] = ssh_failures.get(ip, 0) + 1
                if ssh_failures[ip] >= 3:
                    self.logger.warning(f"MEDIUM IOC: Active SSH Brute-Force attempt from {ip} on user '{username}' (Failed count: {ssh_failures[ip]})")
                    # Check if already added to avoid duplicates
                    if not any(a["type"] == "ssh_brute_force" and a["source_ip"] == ip for a in anomalies):
                        anomalies.append({
                            "type": "ssh_brute_force",
                            "source_ip": ip,
                            "target_user": username,
                            "failed_attempts": ssh_failures[ip],
                            "raw_evidence": log
                        })
                continue

            ssh_accepted_match = self.ssh_accepted_pattern.search(log)
            if ssh_accepted_match:
                username = ssh_accepted_match.group(1)
                ip = ssh_accepted_match.group(2)
                # If we saw failures before, this is an escalation (Brute Force succeeded)
                is_compromised = ip in ssh_failures
                severity_flag = "CRITICAL" if is_compromised else "INFO"
                self.logger.info(f"[{severity_flag}] SSH password accepted for {username} from {ip}")
                
                if is_compromised:
                    anomalies.append({
                        "type": "ssh_brute_force_success",
                        "source_ip": ip,
                        "target_user": username,
                        "raw_evidence": log
                    })

        # Set anomalies on state
        state.detected_anomalies = anomalies
        self.logger.info(f"Log analysis completed. Structured anomalies found: {len(anomalies)}")
        return state
