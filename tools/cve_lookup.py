from typing import Dict, Any, Optional

class CVELookupTool:
    """
    A hardcoded local registry mimicking the NIST NVD API that resolves
    vulnerability indicators and IDs to specific system impacts and MITRE techniques.
    """

    # Mock CVE registry database
    _CVE_DATABASE = {
        "CVE-2024-6387": {
            "cve_id": "CVE-2024-6387",
            "title": "regreSSHion: Remote Code Execution in OpenSSH Server",
            "description": "A signal handler race condition vulnerability was found in OpenSSH's server (sshd). "
                          "If exploited, this vulnerability could lead to remote code execution as root.",
            "mitre_techniques": ["T1190", "T1068"],
            "severity": "CRITICAL",
            "impact": "Full system compromise, root execution",
            "remediation": "Upgrade OpenSSH Server to version 9.8p1 or newer, or set LoginGraceTime to 0 in sshd_config."
        },
        "CVE-2021-44228": {
            "cve_id": "CVE-2021-44228",
            "title": "Log4Shell: Apache Log4j2 Remote Code Execution Vulnerability",
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other "
                          "JNDI related endpoints, allowing an attacker to execute arbitrary code.",
            "mitre_techniques": ["T1190", "T1210"],
            "severity": "CRITICAL",
            "impact": "Remote code execution, lateral movement",
            "remediation": "Update Apache Log4j2 dependency to >= 2.15.0 or set system property log4j2.formatMsgNoLookups=true."
        },
        "CVE-2020-14386": {
            "cve_id": "CVE-2020-14386",
            "title": "Linux Kernel memory corruption in af_packet.c",
            "description": "A flaw was found in the Linux kernel where an out-of-bounds write vulnerability could allow "
                          "a local user with CAP_NET_RAW capability to crash the system or escalate privileges.",
            "mitre_techniques": ["T1068"],
            "severity": "HIGH",
            "impact": "Local Privilege Escalation, denial of service",
            "remediation": "Patch the kernel or disable unprivileged user namespaces by setting user.max_user_namespaces=0."
        },
        "CVE-MOCK-SQLI": {
            "cve_id": "CVE-MOCK-SQLI",
            "title": "SQL Injection in Main Authentication Endpoint",
            "description": "Improper input sanitization on HTTP request parameters allows remote attackers to bypass "
                          "authentication mechanisms and extract arbitrary database records.",
            "mitre_techniques": ["T1190", "T1592"],
            "severity": "HIGH",
            "impact": "Database extraction, authentication bypass, data loss",
            "remediation": "Use parameterized queries/prepared statements and sanitize user input with web application firewalls (WAF)."
        },
        "CVE-MOCK-BRUTE": {
            "cve_id": "CVE-MOCK-BRUTE",
            "title": "SSH Brute-Force Password Spraying",
            "description": "Vulnerability to persistent authentication attempts due to lack of rate limiting or account lockout policies.",
            "mitre_techniques": ["T1110.001", "T1110.003"],
            "severity": "MEDIUM",
            "impact": "Unauthorized system access, credential harvesting",
            "remediation": "Enable Fail2ban, enforce SSH key-based authentication, and block offending IPs via iptables."
        },
        "CVE-MOCK-REVSHELL": {
            "cve_id": "CVE-MOCK-REVSHELL",
            "title": "Interactive Reverse Shell Execution",
            "description": "Attacker initiates an outbound socket connection from a compromised container or host back to "
                          "their command-and-control server, providing interactive shell access.",
            "mitre_techniques": ["T1059.004", "T1071.001"],
            "severity": "CRITICAL",
            "impact": "Active interactive command-and-control access, data exfiltration",
            "remediation": "Kill malicious process by PID, terminate connection, isolate container network, and deploy egress firewall filtering."
        }
    }

    @classmethod
    def lookup(cls, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves threat intelligence information for a specific CVE or vulnerability tag.
        """
        return cls._CVE_DATABASE.get(cve_id.upper())

    @classmethod
    def resolve_anomaly(cls, anomaly_type: str) -> Optional[Dict[str, Any]]:
        """
        Maps a parsed anomaly type to the corresponding mock CVE.
        """
        mapping = {
            "ssh_brute_force": "CVE-MOCK-BRUTE",
            "sql_injection": "CVE-MOCK-SQLI",
            "reverse_shell": "CVE-MOCK-REVSHELL",
            "log4shell": "CVE-2021-44228",
            "kernel_exploit": "CVE-2020-14386"
        }
        cve_id = mapping.get(anomaly_type.lower())
        if cve_id:
            return cls.lookup(cve_id)
        return None
