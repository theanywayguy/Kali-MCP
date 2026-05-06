"""
client/http_client.py
─────────────────────
KaliToolsClient — thin HTTP wrapper around server.py (Flask).

Every public method returns a plain dict so callers never have to
deal with requests exceptions or raw HTTP responses.
"""

import logging
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_REQUEST_TIMEOUT = 300   # 5 minutes — default for most tools

# Tools that routinely run longer than the default
_LONG_RUNNING_TIMEOUTS = {
    "api/tools/linpeas":    600,   # 10 min — full PEAS sweep
    "api/tools/hashcat":    900,   # 15 min — GPU cracking
    "api/tools/john":       600,   # 10 min — CPU cracking
    "api/tools/nikto":      600,   # 10 min — deep web scan
    "api/tools/sqlmap":     600,   # 10 min — blind injection timing
    "api/tools/msf_console": 600,  # 10 min — interactive MSF session
}


class KaliToolsClient:
    """Thin HTTP wrapper around the Flask API (server.py)."""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout    = timeout
        logger.info(f"KaliToolsClient → {server_url}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        HTTP GET helper.

        Returns {"error": ..., "success": False} on any failure instead of
        raising, which keeps the MCP agent stable.
        """
        url = f"{self.server_url}/{endpoint}"
        try:
            response = requests.get(url, params=params or {}, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"GET {url} failed: {e}")
            return {"error": str(e), "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        HTTP POST helper — same pattern as safe_get.

        All mutating tool calls are POSTs because they have a body and side-effects.
        Long-running tools get an automatically elevated timeout from
        _LONG_RUNNING_TIMEOUTS so callers don't have to think about it.
        """
        url     = f"{self.server_url}/{endpoint}"
        # Strip leading slash for consistent key lookup
        key     = endpoint.lstrip("/")
        timeout = _LONG_RUNNING_TIMEOUTS.get(key, self.timeout)
        try:
            response = requests.post(url, json=json_data, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"POST {url} failed: {e}")
            return {"error": str(e), "success": False}

    # ------------------------------------------------------------------
    # Public API methods (used by MCP tools)
    # ------------------------------------------------------------------
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Run any shell command on the Kali server."""
        return self.safe_post("api/command", {"command": command})

    def check_health(self) -> Dict[str, Any]:
        """Ask server.py whether the essential tools are installed."""
        return self.safe_get("health")
