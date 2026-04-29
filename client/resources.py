"""
client/resources.py
───────────────────
Register all @mcp.resource handlers on a FastMCP instance.

Resources are READ-ONLY — they have no side-effects and can be fetched
by the agent at any time to build context without triggering real commands.

URI scheme: kali://<category>/<item>

Import and call register_resources(mcp, kali_client) from client.py.
"""

import json

from mcp.server.fastmcp import FastMCP

from client.http_client import KaliToolsClient


def register_resources(mcp: FastMCP, kali_client: KaliToolsClient) -> None:

    @mcp.resource("kali://server/health")
    def resource_health() -> str:
        """
        Live health status of the Kali API server.

        The agent can read this before starting a workflow to know whether
        all tools are available, without being asked.
        """
        result = kali_client.check_health()
        return json.dumps(result, indent=2)

    @mcp.resource("kali://server/tools")
    def resource_tools() -> str:
        """
        Catalogue of all tools exposed by this MCP server and what they do.

        Gives the agent a reference to consult when deciding which tool to
        use for a given task, without trial-and-error.
        """
        tools = {
            "nmap_scan":       "Network port scanner and service fingerprinter",
            "gobuster_scan":   "Directory / DNS / vhost brute-forcer",
            "dirb_scan":       "Web content discovery scanner",
            "nikto_scan":      "Web server vulnerability scanner",
            "sqlmap_scan":     "Automated SQL injection tester",
            "metasploit_run":  "Exploitation framework module runner",
            "hydra_attack":    "Online password brute-forcer",
            "john_crack":      "Offline hash cracker",
            "wpscan_analyze":  "WordPress vulnerability scanner",
            "enum4linux_scan": "Windows / Samba enumeration",
            "execute_command": "Run any arbitrary shell command",
            "server_health":   "Check tool availability on the Kali server",
        }
        return json.dumps(tools, indent=2)

    @mcp.resource("kali://server/wordlists")
    def resource_wordlists() -> str:
        """
        Wordlists available on the Kali server.

        The agent can read this before launching Gobuster / Hydra / John
        and pick the right wordlist for the job (e.g. big.txt vs common.txt).
        """
        result = kali_client.execute_command(
            "find /usr/share/wordlists -name '*.txt' 2>/dev/null | sort | head -40"
        )
        wordlists = result.get("stdout", "No wordlists found")
        return f"Available wordlists on Kali server:\n\n{wordlists}"

    @mcp.resource("kali://server/network")
    def resource_network() -> str:
        """
        Current network interfaces and routing table on the Kali server.

        Useful at the start of a session to confirm which network the Kali
        box is on — important for choosing the right LHOST etc.
        """
        ifaces = kali_client.execute_command("ip -brief addr show")
        routes = kali_client.execute_command("ip route show")
        return (
            "=== Interfaces ===\n"
            + ifaces.get("stdout", "")
            + "\n=== Routes ===\n"
            + routes.get("stdout", "")
        )

    @mcp.resource("kali://methodology/pentest-phases")
    def resource_methodology() -> str:
        """
        Standard penetration testing methodology phases for reference.

        The agent can consult this to stay on track and not skip phases
        during an engagement.
        """
        methodology = {
            "1_reconnaissance": {
                "description": "Passive and active information gathering",
                "tools": ["nmap_scan (host discovery)", "execute_command (whois, dig, theHarvester)"],
            },
            "2_scanning": {
                "description": "Port scanning, service fingerprinting, OS detection",
                "tools": ["nmap_scan", "nikto_scan"],
            },
            "3_enumeration": {
                "description": "Extract detailed info from discovered services",
                "tools": ["enum4linux_scan", "gobuster_scan", "dirb_scan", "wpscan_analyze"],
            },
            "4_exploitation": {
                "description": "Gain access using discovered vulnerabilities",
                "tools": ["metasploit_run", "sqlmap_scan", "hydra_attack"],
            },
            "5_post_exploitation": {
                "description": "Privilege escalation, persistence, lateral movement",
                "tools": ["execute_command"],
            },
            "6_reporting": {
                "description": "Document findings, evidence, and remediation steps",
                "tools": ["(manual — summarise all tool outputs)"],
            },
        }
        return json.dumps(methodology, indent=2)

    @mcp.resource("kali://methodology/common-ports")
    def resource_common_ports() -> str:
        """
        Common ports and associated services / attack vectors.

        The agent can use this as a lookup table after an nmap scan to
        decide which tools to run next based on open ports.
        """
        ports = {
            "21":   {"service": "FTP",        "tools": ["hydra_attack", "execute_command (anonymous login)"]},
            "22":   {"service": "SSH",        "tools": ["hydra_attack"]},
            "23":   {"service": "Telnet",     "tools": ["hydra_attack"]},
            "25":   {"service": "SMTP",       "tools": ["execute_command (smtp-user-enum)"]},
            "53":   {"service": "DNS",        "tools": ["gobuster_scan (dns mode)", "execute_command (dig, dnsenum)"]},
            "80":   {"service": "HTTP",       "tools": ["nikto_scan", "gobuster_scan", "sqlmap_scan", "wpscan_analyze"]},
            "139":  {"service": "NetBIOS",    "tools": ["enum4linux_scan"]},
            "443":  {"service": "HTTPS",      "tools": ["nikto_scan", "gobuster_scan", "sqlmap_scan"]},
            "445":  {"service": "SMB",        "tools": ["enum4linux_scan", "execute_command (smbclient)"]},
            "1433": {"service": "MSSQL",      "tools": ["sqlmap_scan", "hydra_attack"]},
            "3306": {"service": "MySQL",      "tools": ["sqlmap_scan", "hydra_attack"]},
            "3389": {"service": "RDP",        "tools": ["hydra_attack"]},
            "5432": {"service": "PostgreSQL", "tools": ["hydra_attack"]},
            "8080": {"service": "HTTP-Alt",   "tools": ["nikto_scan", "gobuster_scan", "sqlmap_scan"]},
        }
        return json.dumps(ports, indent=2)
