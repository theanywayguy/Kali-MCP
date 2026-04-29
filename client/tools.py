"""
client/tools.py
───────────────
Register all @mcp.tool handlers on a FastMCP instance.

Each tool:
  1. Receives typed parameters from the AI agent
  2. Packages them into a dict
  3. POSTs to the Flask server → Flask runs the real binary → returns JSON
  4. Returns that JSON back to the agent

Import and call register_tools(mcp, kali_client) from client.py.
"""

from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

from client.http_client import KaliToolsClient


def register_tools(mcp: FastMCP, kali_client: KaliToolsClient) -> None:

    @mcp.tool(name="nmap_scan")
    def nmap_scan(
        target: str,
        scan_type: str = "-sV",
        ports: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Run an Nmap scan against a target.

        Args:
            target:          IP address or hostname to scan
            scan_type:       Nmap flags e.g. -sV, -sCV, -A
            ports:           Ports or ranges e.g. "80,443" or "1-1000"
            additional_args: Extra Nmap flags e.g. "-T4 -Pn"
        """
        return kali_client.safe_post("api/tools/nmap", {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args,
        })

    @mcp.tool(name="gobuster_scan")
    def gobuster_scan(
        url: str,
        mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Run Gobuster to brute-force directories, DNS subdomains, or vhosts.

        Args:
            url:             Target URL
            mode:            dir | dns | fuzz | vhost
            wordlist:        Full path to wordlist on the Kali server
            additional_args: Extra Gobuster flags
        """
        return kali_client.safe_post("api/tools/gobuster", {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args,
        })

    @mcp.tool(name="dirb_scan")
    def dirb_scan(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Run Dirb web content scanner.

        Args:
            url:             Target URL
            wordlist:        Full path to wordlist on the Kali server
            additional_args: Extra Dirb flags
        """
        return kali_client.safe_post("api/tools/dirb", {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args,
        })

    @mcp.tool(name="nikto_scan")
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Run Nikto web server vulnerability scanner.

        Args:
            target:          Target URL or IP
            additional_args: Extra Nikto flags
        """
        return kali_client.safe_post("api/tools/nikto", {
            "target": target,
            "additional_args": additional_args,
        })

    @mcp.tool(name="sqlmap_scan")
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Run SQLmap SQL injection scanner.

        Args:
            url:             Target URL
            data:            POST body string (for POST-based injection)
            additional_args: Extra SQLmap flags
        """
        return kali_client.safe_post("api/tools/sqlmap", {
            "url": url,
            "data": data,
            "additional_args": additional_args,
        })

    @mcp.tool(name="metasploit_run")
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.

        Args:
            module:  Module path e.g. exploit/multi/handler
            options: Dict of SET options e.g. {"LHOST": "10.0.0.1", "LPORT": 4444}
        """
        return kali_client.safe_post("api/tools/metasploit", {
            "module": module,
            "options": options,
        })

    @mcp.tool(name="hydra_attack")
    def hydra_attack(
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password: str = "",
        password_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Run Hydra password brute-force attack.

        Args:
            target:          Target IP or hostname
            service:         Service protocol e.g. ssh, ftp, http-post-form
            username:        Single username
            username_file:   Path to username wordlist
            password:        Single password
            password_file:   Path to password wordlist
            additional_args: Extra Hydra flags
        """
        return kali_client.safe_post("api/tools/hydra", {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args,
        })

    @mcp.tool(name="john_crack")
    def john_crack(
        hash_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        format_type: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Run John the Ripper hash cracker.

        Args:
            hash_file:       Path to file containing hashes on the Kali server
            wordlist:        Path to wordlist
            format_type:     Hash format e.g. md5crypt, sha512crypt, ntlm
            additional_args: Extra John flags
        """
        return kali_client.safe_post("api/tools/john", {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args,
        })

    @mcp.tool(name="wpscan_analyze")
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Run WPScan WordPress vulnerability scanner.

        Args:
            url:             Target WordPress URL
            additional_args: Extra WPScan flags e.g. --enumerate u
        """
        return kali_client.safe_post("api/tools/wpscan", {
            "url": url,
            "additional_args": additional_args,
        })

    @mcp.tool(name="enum4linux_scan")
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Run Enum4linux Windows/Samba enumeration.

        Args:
            target:          Target IP or hostname
            additional_args: Flags — default -a runs all checks
        """
        return kali_client.safe_post("api/tools/enum4linux", {
            "target": target,
            "additional_args": additional_args,
        })

    @mcp.tool(name="execute_command")
    def run_command(command: str) -> Dict[str, Any]:
        """
        Execute any arbitrary shell command on the Kali server.

        Use this for tools not covered by the dedicated endpoints above.

        Args:
            command: Full shell command string e.g. "whois 10.10.10.1"
        """
        return kali_client.execute_command(command)

    @mcp.tool(name="server_health")
    def server_health() -> Dict[str, Any]:
        """
        Check the health of the Kali API server and which tools are installed.

        Returns a dict with tool availability status — useful before starting
        a pentest workflow to confirm the required tools are present.
        """
        return kali_client.check_health()
