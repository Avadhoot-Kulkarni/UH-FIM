"""
logger.py
---------
Sets up a dual-output logger:
  1. Colored terminal output  (for the live demo)
  2. Plain structured log file  → logs/uhfim.log

Every important event is logged:
  - File scanned, category assigned, hash computed
  - Risk score computed with breakdown
  - Alerts raised
  - Baseline created/loaded
  - Monitor started/stopped
"""

import logging
import os
from datetime import datetime

# ── Paths ─────────────────────────────────────────────────────────────────────
LOG_DIR  = os.path.join(os.path.dirname(__file__), "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "uhfim.log")

os.makedirs(LOG_DIR, exist_ok=True)


# ── Custom formatter for the log FILE (plain, structured) ─────────────────────
class FileFormatter(logging.Formatter):
    def format(self, record):
        timestamp = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        level     = record.levelname.ljust(8)
        return f"[{timestamp}] [{level}] {record.getMessage()}"


# ── Custom formatter for TERMINAL (adds visual separators for alerts) ──────────
class TerminalFormatter(logging.Formatter):
    COLORS = {
        "DEBUG":    "\033[90m",    # grey
        "INFO":     "\033[94m",    # blue
        "WARNING":  "\033[93m",    # yellow
        "ERROR":    "\033[91m",    # red
        "CRITICAL": "\033[95m",    # magenta
    }
    RESET = "\033[0m"

    def format(self, record):
        color     = self.COLORS.get(record.levelname, "")
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        return f"{color}[{timestamp}] {record.getMessage()}{self.RESET}"


def get_logger(name: str = "uhfim") -> logging.Logger:
    """
    Returns a configured logger. Safe to call multiple times —
    handlers are only added once.
    """
    logger = logging.getLogger(name)

    if logger.handlers:          # already configured
        return logger

    logger.setLevel(logging.DEBUG)

    # ── File handler (logs EVERYTHING including DEBUG) ──────────────────────
    fh = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(FileFormatter())

    # ── Console handler (INFO and above only — keeps terminal clean) ────────
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(TerminalFormatter())

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


def log_separator(logger: logging.Logger, title: str = ""):
    """Writes a visual separator to BOTH log file and terminal."""
    line = "─" * 60
    msg  = f"\n{line}\n  {title}\n{line}" if title else f"\n{line}"
    logger.info(msg)
