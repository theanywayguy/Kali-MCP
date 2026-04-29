#!/usr/bin/env python3
"""
client.py  (entry point)
────────────────────────
Connects the MCP AI agent to the Kali Linux Flask API (server.py).

Project layout
──────────────
client.py               ← you are here (run this)
client/
  __init__.py
  safety.py             ← SAFETY_INSTRUCTIONS constant
  http_client.py        ← KaliToolsClient (HTTP wrapper)
  tools.py              ← register_tools()
  resources.py          ← register_resources()
  prompts.py            ← register_prompts()
"""

import argparse
import logging
import sys

from mcp.server.fastmcp import FastMCP

from client.safety      import SAFETY_INSTRUCTIONS
from client.http_client import KaliToolsClient, DEFAULT_REQUEST_TIMEOUT
from client.tools       import register_tools
from client.resources   import register_resources
from client.prompts     import register_prompts

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger(__name__)

DEFAULT_KALI_SERVER = "http://localhost:5000"


# ---------------------------------------------------------------------------
# MCP server factory
# ---------------------------------------------------------------------------
def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Create a FastMCP instance and register all tools, resources, and prompts.

    STRUCTURE
    ─────────
    @mcp.tool      → has side-effects (runs a Kali command)
    @mcp.resource  → read-only data the agent can pull at any time
    @mcp.prompt    → reusable instruction templates for common workflows
    """
    mcp = FastMCP("kali_mcp", instructions=SAFETY_INSTRUCTIONS)

    register_tools(mcp, kali_client)
    register_resources(mcp, kali_client)
    register_prompts(mcp)

    return mcp


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Kali MCP Client")
    parser.add_argument("--server",  default=DEFAULT_KALI_SERVER,
                        help=f"Flask API URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                        help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug",   action="store_true",
                        help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # 1. Init HTTP client
    kali_client = KaliToolsClient(args.server, args.timeout)

    # 2. Health-check Flask before registering tools
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Cannot reach Kali API at {args.server}: {health['error']}")
        logger.warning("MCP server will start but tool calls will fail until Flask is running")
    else:
        logger.info(f"Connected to Kali API — status: {health.get('status')}")
        missing = [t for t, ok in health.get("tools_status", {}).items() if not ok]
        if missing:
            logger.warning(f"Missing tools on Kali server: {', '.join(missing)}")

    # 3. Register everything and start the stdio loop
    mcp = setup_mcp_server(kali_client)
    logger.info("MCP server starting — listening on stdio")
    mcp.run()


if __name__ == "__main__":
    main()
