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
  • Port 21              → run execute_command("ftp -n {target}") to test anonymous login
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
  • If Joomla / Drupal → execute_command with appropriate scanner

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
    - additional_args = "-t 4 -W 3" (4 threads, 3s wait — avoids lockouts)

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
