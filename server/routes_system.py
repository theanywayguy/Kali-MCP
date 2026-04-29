"""
server/routes_system.py
───────────────────────
Flask Blueprint for system-level endpoints:
  - POST /api/command   — run any arbitrary shell command
  - GET  /health        — check server + tool availability
  - GET  /mcp/capabilities        (stub)
  - POST /mcp/tools/kali_tools/<tool_name>  (stub)
"""

import logging
import traceback

from flask import Blueprint, jsonify, request

from server.executor import execute_command

logger = logging.getLogger(__name__)

system_bp = Blueprint("system", __name__)


# ---------------------------------------------------------------------------
# Generic command execution
# ---------------------------------------------------------------------------
@system_bp.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any shell command provided in the request body."""
    try:
        params  = request.json
        command = params.get("command", "")

        if not command:
            return jsonify({"error": "Command parameter is required"}), 400

        return jsonify(execute_command(command))
    except Exception as e:
        logger.error(f"Error in command endpoint: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Server error: {e}"}), 500


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@system_bp.route("/health", methods=["GET"])
def health_check():
    """Return server health and tool availability."""
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}

    for tool in essential_tools:
        try:
            result = execute_command(["which", tool])
            tools_status[tool] = result["success"]
        except Exception:
            tools_status[tool] = False

    return jsonify({
        "status":                      "healthy",
        "message":                     "Kali Linux Tools API Server is running",
        "tools_status":                tools_status,
        "all_essential_tools_available": all(tools_status.values()),
    })


# ---------------------------------------------------------------------------
# MCP stubs (reserved for future direct-MCP integration)
# ---------------------------------------------------------------------------
@system_bp.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    """Return MCP tool capabilities (stub — not yet implemented)."""
    pass


@system_bp.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    """Direct MCP tool execution without the API layer (stub — not yet implemented)."""
    pass
