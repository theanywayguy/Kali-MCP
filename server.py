#!/usr/bin/env python3
"""
server.py  (entry point)
────────────────────────
Creates the Flask app, registers route blueprints, and starts the server.

Project layout
──────────────
server.py               ← you are here (run this)
server/
  __init__.py
  executor.py           ← CommandExecutor + execute_command()
  routes_tools.py       ← Blueprint: /api/tools/*
  routes_system.py      ← Blueprint: /api/command, /health, /mcp/*
"""

import argparse
import logging
import os
import sys

from flask import Flask

from server.routes_tools  import tools_bp
from server.routes_system import system_bp

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_PORT   = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(tools_bp)
    app.register_blueprint(system_bp)
    return app


app = create_app()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Kali Linux Tools API Server")
    parser.add_argument("--debug",  action="store_true",
                        help="Enable debug mode")
    parser.add_argument("--port",   type=int, default=API_PORT,
                        help=f"Port to listen on (default: {API_PORT})")
    parser.add_argument("--ip",     type=str, default="127.0.0.1",
                        help="IP address to bind to (default: 127.0.0.1)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    logger.info(f"Starting Kali Linux Tools API Server on {args.ip}:{API_PORT}")
    app.run(host=args.ip, port=API_PORT, debug=DEBUG_MODE)
