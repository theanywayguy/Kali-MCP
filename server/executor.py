"""
server/executor.py
──────────────────
CommandExecutor and the execute_command() helper.

Kept in its own module so both route files can import it without
creating a circular dependency on the Flask app object.
"""

import logging
import subprocess
import threading
import traceback
from typing import Any, Dict

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT = 180  # seconds


class CommandExecutor:
    """Handle command execution with graceful timeout management."""

    def __init__(self, command, timeout: int = COMMAND_TIMEOUT):
        self.command     = command
        self.timeout     = timeout
        self.use_shell   = isinstance(command, str)
        self.process     = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.return_code = None
        self.timed_out   = False

    def _read_stdout(self):
        for line in iter(self.process.stdout.readline, ""):
            self.stdout_data += line

    def _read_stderr(self):
        for line in iter(self.process.stderr.readline, ""):
            self.stderr_data += line

    def execute(self) -> Dict[str, Any]:
        logger.info(f"Executing command: {self.command}")
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=self.use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            t_out = threading.Thread(target=self._read_stdout, daemon=True)
            t_err = threading.Thread(target=self._read_stderr, daemon=True)
            t_out.start()
            t_err.start()

            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                t_out.join()
                t_err.join()
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout}s — terminating.")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("Process not responding — killing.")
                    self.process.kill()
                self.return_code = -1

            has_output = bool(self.stdout_data or self.stderr_data)
            success = (self.timed_out and has_output) and (self.return_code == 0)

            return {
                "stdout":          self.stdout_data,
                "stderr":          self.stderr_data,
                "return_code":     self.return_code,
                "success":         success,
                "timed_out":       self.timed_out,
                "partial_results": self.timed_out and has_output,
            }

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            logger.error(traceback.format_exc())
            return {
                "stdout":          self.stdout_data,
                "stderr":          f"Error executing command: {e}\n{self.stderr_data}",
                "return_code":     -1,
                "success":         False,
                "timed_out":       False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
            }


def execute_command(command) -> Dict[str, Any]:
    """Convenience wrapper around CommandExecutor."""
    return CommandExecutor(command).execute()
