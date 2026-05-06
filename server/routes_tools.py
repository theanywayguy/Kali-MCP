"""
server/routes_tools.py
──────────────────────
Flask Blueprint for all /api/tools/* endpoints.

Each route:
  1. Validates required parameters
  2. Builds the command list (never passes user input directly to shell)
  3. Calls execute_command() and returns JSON
"""

import logging
import os
import re
import shlex
import traceback

from flask import Blueprint, jsonify, request

from server.executor import execute_command

logger = logging.getLogger(__name__)

tools_bp = Blueprint("tools", __name__, url_prefix="/api/tools")


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------
@tools_bp.route("/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params          = request.json
        target          = params.get("target", "")
        scan_type       = params.get("scan_type", "-sCV")
        ports           = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["nmap"] + shlex.split(scan_type)
        if ports:
            command += ["-p", ports]
        if additional_args:
            command += shlex.split(additional_args)
        command.append(target)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Gobuster
# ---------------------------------------------------------------------------
@tools_bp.route("/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster directory/DNS/vhost brute-forcer."""
    try:
        params          = request.json
        url             = params.get("url", "")
        mode            = params.get("mode", "dir")
        wordlist        = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        if mode not in ("dir", "dns", "fuzz", "vhost"):
            return jsonify({"error": f"Invalid mode: {mode}. Must be dir | dns | fuzz | vhost"}), 400

        command = ["gobuster", mode, "-u", url, "-w", wordlist]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Dirb
# ---------------------------------------------------------------------------
@tools_bp.route("/dirb", methods=["POST"])
def dirb():
    """Execute dirb web content scanner."""
    try:
        params          = request.json
        url             = params.get("url", "")
        wordlist        = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["dirb", url, wordlist]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Nikto
# ---------------------------------------------------------------------------
@tools_bp.route("/nikto", methods=["POST"])
def nikto():
    """Execute Nikto web server vulnerability scanner."""
    try:
        params          = request.json
        target          = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["nikto", "-h", target]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# SQLmap
# ---------------------------------------------------------------------------
@tools_bp.route("/sqlmap", methods=["POST"])
def sqlmap():
    """Execute SQLmap SQL injection scanner."""
    try:
        params          = request.json
        url             = params.get("url", "")
        data            = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["sqlmap", "-u", url, "--batch"]
        if data:
            command += ["--data", data]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Metasploit
# ---------------------------------------------------------------------------
@tools_bp.route("/metasploit", methods=["POST"])
def metasploit():
    """Execute a Metasploit module via msfconsole resource script."""
    try:
        params  = request.json
        module  = params.get("module", "")
        options = params.get("options", {})

        if not module:
            return jsonify({"error": "Module parameter is required"}), 400

        if not re.match(r"^[a-zA-Z0-9/_-]+$", module):
            return jsonify({"error": "Invalid module name"}), 400

        resource_content = f"use {module}\n"
        for key, value in options.items():
            if not re.match(r"^[a-zA-Z0-9_]+$", str(key)):
                return jsonify({"error": f"Invalid option key: {key}"}), 400
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        resource_file = "/tmp/mks_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        result = execute_command(["msfconsole", "-q", "-r", resource_file])

        try:
            os.remove(resource_file)
        except Exception as cleanup_err:
            logger.warning(f"Could not remove temp resource file: {cleanup_err}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Hydra
# ---------------------------------------------------------------------------
@tools_bp.route("/hydra", methods=["POST"])
def hydra():
    """Execute Hydra password brute-force attack."""
    try:
        params          = request.json
        target          = params.get("target", "")
        service         = params.get("service", "")
        username        = params.get("username", "")
        username_file   = params.get("username_file", "")
        password        = params.get("password", "")
        password_file   = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        if not target or not service:
            return jsonify({"error": "Target and service parameters are required"}), 400

        if not (username or username_file) or not (password or password_file):
            return jsonify({"error": "username/username_file and password/password_file are required"}), 400

        command = ["hydra", "-t", "4"]
        command += ["-l", username] if username else ["-L", username_file]
        command += ["-p", password] if password else ["-P", password_file]
        command += [target, service]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# John the Ripper
# ---------------------------------------------------------------------------
@tools_bp.route("/john", methods=["POST"])
def john():
    """Execute John the Ripper hash cracker."""
    try:
        params          = request.json
        hash_file       = params.get("hash_file", "")
        wordlist        = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type     = params.get("format", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            return jsonify({"error": "Hash file parameter is required"}), 400

        command = ["john"]
        if format_type:
            command.append(f"--format={format_type}")
        if wordlist:
            command.append(f"--wordlist={wordlist}")
        if additional_args:
            command += shlex.split(additional_args)
        command.append(hash_file)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in john endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# WPScan
# ---------------------------------------------------------------------------
@tools_bp.route("/wpscan", methods=["POST"])
def wpscan():
    """Execute WPScan WordPress vulnerability scanner."""
    try:
        params          = request.json
        url             = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["wpscan", "--url", url]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Enum4linux
# ---------------------------------------------------------------------------
@tools_bp.route("/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux Windows/Samba enumeration."""
    try:
        params          = request.json
        target          = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["enum4linux"] + shlex.split(additional_args) + [target]

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Tshark — live capture
# ---------------------------------------------------------------------------
@tools_bp.route("/tshark", methods=["POST"])
def tshark():
    """Capture and analyse live network traffic with tshark."""
    try:
        params          = request.json
        interface       = params.get("interface", "eth0")
        capture_filter  = params.get("capture_filter", "")
        duration        = params.get("duration", "10")
        additional_args = params.get("additional_args", "")

        if not interface:
            return jsonify({"error": "Interface parameter is required"}), 400

        # -q suppresses the per-packet summary noise; only stats/results are printed
        command = ["tshark", "-q", "-i", interface, "-a", f"duration:{duration}"]
        if capture_filter:
            command += ["-f", capture_filter]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in tshark endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Tshark — read pcap file
# ---------------------------------------------------------------------------
@tools_bp.route("/tshark/pcap", methods=["POST"])
def tshark_pcap():
    """Read and analyse an existing pcap/pcapng file with tshark."""
    try:
        params          = request.json
        pcap_file       = params.get("pcap_file", "")
        display_filter  = params.get("display_filter", "")
        additional_args = params.get("additional_args", "")

        if not pcap_file:
            return jsonify({"error": "pcap_file parameter is required"}), 400

        command = ["tshark", "-r", pcap_file]
        if display_filter:
            command += ["-Y", display_filter]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in tshark_pcap endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Tcpdump
# ---------------------------------------------------------------------------
@tools_bp.route("/tcpdump", methods=["POST"])
def tcpdump():
    """Lightweight packet capture with tcpdump."""
    try:
        params          = request.json
        interface       = params.get("interface", "eth0")
        capture_filter  = params.get("capture_filter", "")
        packet_count    = params.get("packet_count", "50")
        additional_args = params.get("additional_args", "-nn")

        command = ["tcpdump", "-i", interface, "-c", str(packet_count)]
        if capture_filter:
            command.append(capture_filter)
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in tcpdump endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Netdiscover
# ---------------------------------------------------------------------------
@tools_bp.route("/netdiscover", methods=["POST"])
def netdiscover():
    """ARP host discovery with netdiscover."""
    try:
        params          = request.json
        target_range    = params.get("target_range", "")
        interface       = params.get("interface", "")
        additional_args = params.get("additional_args", "-P")

        command = ["netdiscover", "-r", target_range] if target_range else ["netdiscover"]
        if interface:
            command += ["-i", interface]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in netdiscover endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Masscan
# ---------------------------------------------------------------------------
@tools_bp.route("/masscan", methods=["POST"])
def masscan():
    """Fast full-port scanner with masscan."""
    try:
        params          = request.json
        target          = params.get("target", "")
        ports           = params.get("ports", "0-65535")
        rate            = params.get("rate", "1000")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        command = ["masscan", target, "-p", ports, "--rate", str(rate)]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in masscan endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# WhatWeb
# ---------------------------------------------------------------------------
@tools_bp.route("/whatweb", methods=["POST"])
def whatweb():
    """Web technology fingerprinter."""
    try:
        params          = request.json
        url             = params.get("url", "")
        aggression      = params.get("aggression", "1")
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["whatweb", url, f"--aggression={aggression}"]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in whatweb endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# SSH command execution
# ---------------------------------------------------------------------------
@tools_bp.route("/ssh", methods=["POST"])
def ssh_command():
    """Run a command on a remote host over SSH via paramiko."""
    try:
        import paramiko

        params    = request.json
        host      = params.get("host", "")
        username  = params.get("username", "")
        password  = params.get("password", "")
        command   = params.get("command", "")
        key_file  = params.get("key_file", "")
        port      = int(params.get("port", 22))
        timeout   = int(params.get("timeout", 30))

        if not host or not username or not command:
            return jsonify({"error": "host, username, and command are required"}), 400

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = dict(hostname=host, port=port, username=username, timeout=timeout)
        if key_file:
            connect_kwargs["key_filename"] = key_file
        elif password:
            connect_kwargs["password"] = password
        else:
            return jsonify({"error": "Either password or key_file is required"}), 400

        client.connect(**connect_kwargs)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        client.close()

        return jsonify({"stdout": out, "stderr": err, "returncode": exit_code})
    except ImportError:
        return jsonify({"error": "paramiko not installed — run: pip install paramiko"}), 500
    except Exception as e:
        logger.error(f"Error in ssh endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Searchsploit
# ---------------------------------------------------------------------------
@tools_bp.route("/searchsploit", methods=["POST"])
def searchsploit():
    """Search the Exploit-DB offline archive with searchsploit."""
    try:
        params          = request.json
        query           = params.get("query", "")
        additional_args = params.get("additional_args", "")

        if not query:
            return jsonify({"error": "Query parameter is required"}), 400

        command = ["searchsploit"] + shlex.split(query)
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in searchsploit endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# LinPEAS / WinPEAS
# ---------------------------------------------------------------------------
@tools_bp.route("/linpeas", methods=["POST"])
def linpeas():
    """
    Run LinPEAS or WinPEAS on a remote host via SSH.

    Downloads the latest PEAS script from the Kali server's local copy
    (or a specified path), uploads it to the target, executes it, and
    returns the full output.
    """
    try:
        import paramiko

        params       = request.json
        host         = params.get("host", "")
        username     = params.get("username", "")
        password     = params.get("password", "")
        key_file     = params.get("key_file", "")
        port         = int(params.get("port", 22))
        script_type  = params.get("script_type", "linpeas")   # linpeas | winpeas
        script_path  = params.get("script_path", "")          # override local path
        timeout      = int(params.get("timeout", 300))

        if not host or not username:
            return jsonify({"error": "host and username are required"}), 400

        # Resolve local PEAS script
        if not script_path:
            candidates = [
                f"/usr/share/peass/{script_type}.sh",
                f"/opt/PEASS-ng/{script_type}.sh",
                f"/root/{script_type}.sh",
                f"/home/kali/{script_type}.sh",
            ]
            script_path = next((p for p in candidates if os.path.isfile(p)), "")
            if not script_path:
                return jsonify({
                    "error": (
                        f"{script_type}.sh not found. "
                        "Provide script_path or install PEASS: "
                        "apt install peass  OR  "
                        "wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
                    )
                }), 400

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = dict(hostname=host, port=port, username=username, timeout=30)
        if key_file:
            connect_kwargs["key_filename"] = key_file
        elif password:
            connect_kwargs["password"] = password
        else:
            return jsonify({"error": "Either password or key_file is required"}), 400

        client.connect(**connect_kwargs)

        # Upload script to /tmp on target
        remote_path = f"/tmp/.{script_type}_{os.getpid()}.sh"
        sftp = client.open_sftp()
        sftp.put(script_path, remote_path)
        sftp.close()

        # Execute and capture output (ANSI stripped for readability)
        run_cmd = f"chmod +x {remote_path} && {remote_path} 2>/dev/null; rm -f {remote_path}"
        stdin, stdout, stderr = client.exec_command(run_cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")

        # Strip ANSI escape codes so the output is readable in MCP
        # Covers colour codes, cursor movement, erase sequences, and OSC strings
        ansi_escape = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-9;]*[ -/]*[@-~]|\][^\x07]*\x07)")
        out = ansi_escape.sub("", out)

        client.close()
        return jsonify({"stdout": out, "stderr": err, "returncode": 0})
    except ImportError:
        return jsonify({"error": "paramiko not installed — run: pip install paramiko"}), 500
    except Exception as e:
        logger.error(f"Error in linpeas endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# HTTP request (curl wrapper)
# ---------------------------------------------------------------------------
@tools_bp.route("/http_request", methods=["POST"])
def http_request():
    """Make an HTTP request with curl — supports GET, POST, custom headers, cookies."""
    try:
        params          = request.json
        url             = params.get("url", "")
        method          = params.get("method", "GET").upper()
        data            = params.get("data", "")
        headers         = params.get("headers", {})
        cookies         = params.get("cookies", "")
        follow_redirect = params.get("follow_redirect", True)
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        command = ["curl", "-s", "-i", "-X", method]

        for key, value in headers.items():
            command += ["-H", f"{key}: {value}"]
        if cookies:
            command += ["-b", cookies]
        if data:
            command += ["-d", data]
        if follow_redirect:
            command.append("-L")
        if additional_args:
            command += shlex.split(additional_args)

        command.append(url)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in http_request endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Msfvenom — payload generation
# ---------------------------------------------------------------------------
@tools_bp.route("/msfvenom", methods=["POST"])
def msfvenom():
    """Generate a payload with msfvenom."""
    try:
        params          = request.json
        payload         = params.get("payload", "")
        lhost           = params.get("lhost", "")
        lport           = params.get("lport", "4444")
        output_format   = params.get("format", "elf")
        output_file     = params.get("output_file", "")
        encoder         = params.get("encoder", "")
        iterations      = params.get("iterations", "")
        additional_args = params.get("additional_args", "")

        if not payload:
            return jsonify({"error": "Payload parameter is required"}), 400

        # Without -o msfvenom writes raw binary to stdout which corrupts JSON.
        # Require an output_file so the binary goes to disk; stdout carries only
        # the progress/status lines which are safe to return as text.
        if not output_file:
            return jsonify({
                "error": "output_file is required — msfvenom writes binary to stdout "
                         "which would corrupt the JSON response. "
                         "Provide a path e.g. \"/tmp/shell.elf\"."
            }), 400

        command = ["msfvenom", "-p", payload]
        if lhost:
            command.append(f"LHOST={lhost}")
        if lport:
            command.append(f"LPORT={lport}")
        command += ["-f", output_format]
        if encoder:
            command += ["-e", encoder]
        if iterations:
            command += ["-i", str(iterations)]
        command += ["-o", output_file]
        if additional_args:
            command += shlex.split(additional_args)

        result = execute_command(command)

        # Confirm the file actually landed on disk
        result["output_file"]   = output_file
        result["file_created"]  = os.path.isfile(output_file)
        if not result["file_created"]:
            result["success"] = False
            result["warning"] = f"Command completed but {output_file} was not found — check stderr."

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in msfvenom endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Hashcat
# ---------------------------------------------------------------------------
@tools_bp.route("/hashcat", methods=["POST"])
def hashcat():
    """GPU-accelerated hash cracking with hashcat."""
    try:
        params          = request.json
        hash_file       = params.get("hash_file", "")
        hash_type       = params.get("hash_type", "")
        wordlist        = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        attack_mode     = params.get("attack_mode", "0")   # 0=dict, 3=brute, 6=hybrid
        rules           = params.get("rules", "")
        # --force removed from default: it bypasses GPU safety checks and can
        # cause incorrect results or hardware issues on real machines.
        # Pass additional_args="--force" explicitly if running inside a VM.
        additional_args = params.get("additional_args", "")

        if not hash_file or not hash_type:
            return jsonify({"error": "hash_file and hash_type are required"}), 400

        command = ["hashcat", "-m", str(hash_type), "-a", str(attack_mode), hash_file, wordlist]
        if rules:
            command += ["-r", rules]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in hashcat endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500

# ---------------------------------------------------------------------------
# Smbclient
# ---------------------------------------------------------------------------
@tools_bp.route("/smbclient", methods=["POST"])
def smbclient():
    """Interact with SMB shares via smbclient."""
    try:
        params          = request.json
        target          = params.get("target", "")
        share           = params.get("share", "")
        username        = params.get("username", "")
        password        = params.get("password", "")
        smb_command     = params.get("smb_command", "ls")    # smbclient -c argument
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        # Build UNC path — list shares if none specified
        unc = f"//{target}/{share}" if share else f"//{target}"
        command = ["smbclient", unc]

        if username:
            # Pass credentials via environment variable instead of the command
            # line — prevents the password appearing in `ps aux` / /proc/cmdline
            command += ["-U", username]
            if password:
                import subprocess as _sp  # already imported via execute_command path
                os.environ["PASSWD"] = password   # smbclient reads this automatically
        else:
            command.append("-N")   # anonymous / no-pass

        command += ["-c", smb_command]

        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in smbclient endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Ffuf
# ---------------------------------------------------------------------------
@tools_bp.route("/ffuf", methods=["POST"])
def ffuf():
    """Fast web fuzzer — directories, parameters, vhosts, subdomains."""
    try:
        params          = request.json
        url             = params.get("url", "")
        wordlist        = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        fuzz_keyword    = params.get("fuzz_keyword", "FUZZ")
        method          = params.get("method", "GET")
        data            = params.get("data", "")
        headers         = params.get("headers", {})
        filter_codes    = params.get("filter_codes", "")    # e.g. "404,403"
        match_codes     = params.get("match_codes", "")     # e.g. "200,301"
        additional_args = params.get("additional_args", "")

        if not url:
            return jsonify({"error": "URL parameter is required"}), 400

        # Ensure the keyword is present in the URL (or data)
        if fuzz_keyword not in url and fuzz_keyword not in data:
            url = url.rstrip("/") + f"/{fuzz_keyword}"

        command = ["ffuf", "-u", url, "-w", f"{wordlist}:{fuzz_keyword}", "-X", method, "-s"]

        for key, value in headers.items():
            command += ["-H", f"{key}: {value}"]
        if data:
            command += ["-d", data]
        if filter_codes:
            command += ["-fc", filter_codes]
        if match_codes:
            command += ["-mc", match_codes]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in ffuf endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# CrackMapExec / NetExec
# ---------------------------------------------------------------------------
@tools_bp.route("/crackmapexec", methods=["POST"])
def crackmapexec():
    """SMB/AD Swiss army knife — crackmapexec (or nxc alias)."""
    try:
        params          = request.json
        protocol        = params.get("protocol", "smb")
        target          = params.get("target", "")
        username        = params.get("username", "")
        password        = params.get("password", "")
        hash_value      = params.get("hash", "")
        domain          = params.get("domain", "")
        additional_args = params.get("additional_args", "")

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        # Prefer nxc (newer name) but fall back to crackmapexec
        binary = "nxc" if os.path.isfile("/usr/bin/nxc") else "crackmapexec"
        command = [binary, protocol, target]

        if username:
            command += ["-u", username]
        if hash_value:
            command += ["-H", hash_value]
        elif password:
            command += ["-p", password]
        if domain:
            command += ["-d", domain]
        if additional_args:
            command += shlex.split(additional_args)

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in crackmapexec endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Netcat listener
# ---------------------------------------------------------------------------
@tools_bp.route("/listener", methods=["POST"])
def listener():
    """Start a netcat listener to catch reverse shells."""
    try:
        params     = request.json
        port       = params.get("port", "")
        duration   = params.get("duration", "60")   # seconds to listen before timing out
        use_rlwrap = params.get("use_rlwrap", False)

        if not port:
            return jsonify({"error": "Port parameter is required"}), 400

        # Use ncat (from nmap) if available — better TTY handling
        if os.path.isfile("/usr/bin/ncat"):
            command = ["ncat", "-lvnp", str(port)]
        else:
            command = ["nc", "-lvnp", str(port)]

        if use_rlwrap and os.path.isfile("/usr/bin/rlwrap"):
            command = ["rlwrap"] + command

        # Wrap with timeout so the endpoint doesn't hang indefinitely
        command = ["timeout", str(duration)] + command

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in listener endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Metasploit — interactive TTY session via pexpect
# ---------------------------------------------------------------------------
@tools_bp.route("/msf_console", methods=["POST"])
def msf_console():
    """
    Drive msfconsole interactively over a real PTY using pexpect.

    Accepts a list of commands to send in sequence.  Each command is sent
    after the previous prompt is seen, so multi-step flows work correctly:

        use exploit/...  →  set RHOSTS ...  →  run  →  sessions -i 1  →  whoami

    The full transcript (everything msfconsole printed) is returned so the
    agent can read output at each step.
    """
    try:
        import pexpect

        params        = request.json
        commands      = params.get("commands", [])        # list of strings
        prompt_regex  = params.get("prompt_regex", r"msf\d*\s[>\(][^)]*[>\)]\s*$")
        step_timeout  = int(params.get("step_timeout", 30))   # per-command wait
        startup_timeout = int(params.get("startup_timeout", 60))

        if not commands:
            return jsonify({"error": "commands list is required"}), 400

        transcript = ""

        child = pexpect.spawnu(
            "msfconsole -q",
            timeout=startup_timeout,
            codec_errors="replace",
        )

        # Collect everything msfconsole prints
        def _flush():
            nonlocal transcript
            transcript += child.before or ""
            transcript += child.after  if isinstance(child.after, str) else ""

        # Wait for the first prompt before sending anything
        try:
            child.expect(prompt_regex, timeout=startup_timeout)
            _flush()
        except pexpect.TIMEOUT:
            child.close(force=True)
            return jsonify({
                "error":      "msfconsole did not produce a prompt within startup_timeout",
                "transcript": transcript + (child.before or ""),
                "success":    False,
            }), 500
        except pexpect.EOF:
            child.close(force=True)
            return jsonify({
                "error":      "msfconsole exited unexpectedly during startup",
                "transcript": transcript + (child.before or ""),
                "success":    False,
            }), 500

        step_results = []

        for cmd in commands:
            child.sendline(cmd)
            try:
                child.expect(prompt_regex, timeout=step_timeout)
                _flush()
                step_results.append({"command": cmd, "output": child.before or "", "success": True})
            except pexpect.TIMEOUT:
                # Capture whatever arrived so far — useful for long-running exploits
                partial = child.before or ""
                transcript += partial
                step_results.append({
                    "command": cmd,
                    "output":  partial,
                    "success": False,
                    "note":    f"Timed out after {step_timeout}s waiting for prompt",
                })
                # Don't abort — the agent may still want to send more commands
            except pexpect.EOF:
                partial = child.before or ""
                transcript += partial
                step_results.append({
                    "command": cmd,
                    "output":  partial,
                    "success": False,
                    "note":    "msfconsole exited (EOF)",
                })
                break

        # Graceful exit
        try:
            child.sendline("exit -y")
            child.expect(pexpect.EOF, timeout=10)
            transcript += child.before or ""
        except Exception:
            child.close(force=True)

        return jsonify({
            "transcript":   transcript,
            "step_results": step_results,
            "success":      all(s["success"] for s in step_results),
        })

    except ImportError:
        return jsonify({"error": "pexpect not installed — run: pip install pexpect"}), 500
    except Exception as e:
        logger.error(f"Error in msf_console endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500
