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
