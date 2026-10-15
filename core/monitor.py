"""
monitor.py
----------
Real-time file system monitoring using the watchdog library.

How it works:
  1. Registers a FileSystemEventHandler with watchdog's Observer
  2. On any file event (modify, create, delete), the handler fires
  3. The handler calls verify_file() against the baseline
  4. If a change is detected, compute_risk() scores it
  5. Alert is printed to terminal AND logged to file

Also supports a one-shot 'scan' mode:
  Walks all files in the directory and checks each against baseline.
  Useful for checking integrity without live monitoring.
"""

import os
import time
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events    import FileSystemEventHandler

from core.baseline      import load_baseline, verify_file
from core.risk          import compute_risk, get_alert_level, get_alert_color
from utils.logger       import get_logger, log_separator

logger = get_logger()

RESET = "\033[0m"
BOLD  = "\033[1m"


# ── Alert printer ──────────────────────────────────────────────────────────────

def _print_alert(result: dict, risk: dict, filepath: str):
    """
    Prints a formatted alert to the terminal.
    Also logs the full details to the log file.
    """
    level  = risk["level"]
    score  = risk["score"]
    color  = get_alert_color(level)
    event  = result.get("event", "MODIFIED")
    rpath  = result["rel_path"]

    # ── Terminal output ──────────────────────────────────────────────────────
    border = "═" * 62
    print(f"\n{color}{BOLD}{border}{RESET}")
    print(f"{color}{BOLD}  [{level}] ALERT — Score: {score}/100{RESET}")
    print(f"{color}{border}{RESET}")
    print(f"  File     : {rpath}")
    print(f"  Event    : {event}")
    print(f"  Category : {result['category']}")

    if result.get("strategy"):
        print(f"  Strategy : {result['strategy']} hashing")

    if result.get("old_hash"):
        print(f"  Old Hash : {result['old_hash'][:32]}...")
    if result.get("new_hash"):
        print(f"  New Hash : {result['new_hash'][:32]}...")
    if result.get("old_size") is not None and result.get("new_size") is not None:
        delta = result["new_size"] - result["old_size"]
        sign  = "+" if delta >= 0 else ""
        print(f"  Size     : {result['old_size']} → {result['new_size']} bytes ({sign}{delta})")

    print(f"\n  {color}Risk Breakdown:{RESET}")
    print(f"    Sensitivity  : {risk['sensitivity']:.2f}  (file criticality)")
    print(f"    Time Anomaly : {risk['time_anomaly']:.2f}  (hour={datetime.now().hour}:00)")
    print(f"    Frequency    : {risk['frequency']:.2f}  (change rate)")
    print(f"    Final Score  : {score}/100  → {level}")
    print(f"{color}{border}{RESET}\n")

    # ── Log file output (full detail) ────────────────────────────────────────
    logger.warning(
        f"\n"
        f"  ┌─ ALERT ──────────────────────────────────────────────┐\n"
        f"  │  Level    : {level:<10}  Score: {score}/100              │\n"
        f"  │  File     : {rpath:<44} │\n"
        f"  │  Event    : {event:<44} │\n"
        f"  │  Category : {result['category']:<44} │\n"
        f"  │  Strategy : {result.get('strategy','N/A'):<44} │\n"
        f"  │  Old Hash : {str(result.get('old_hash','N/A'))[:44]:<44} │\n"
        f"  │  New Hash : {str(result.get('new_hash','N/A'))[:44]:<44} │\n"
        f"  │  Risk     : {risk['breakdown'][:44]:<44} │\n"
        f"  └──────────────────────────────────────────────────────┘"
    )


# ── Watchdog event handler ─────────────────────────────────────────────────────

class FIMEventHandler(FileSystemEventHandler):
    """
    Fires on every file system event inside the monitored directory.
    Ignores directory events — we care only about files.
    """

    def __init__(self, directory: str, baseline: dict):
        super().__init__()
        self.directory = directory
        self.baseline  = baseline

    def _handle(self, filepath: str):
        """Common logic for any file event."""
        if not os.path.isfile(filepath):
            return   # skip directories

        # Skip the baseline file itself (it's not in demo_files)
        if "baseline.json" in filepath or "baseline.checksum" in filepath:
            return

        result = verify_file(filepath, self.directory, self.baseline)

        if result is None:
            # New file not in baseline
            logger.info(f"NEW FILE | {os.path.relpath(filepath, self.directory)}")
            return

        if result["changed"]:
            risk = compute_risk(filepath, result["category"])
            _print_alert(result, risk, filepath)
        else:
            logger.debug(f"NO CHANGE | {result['rel_path']}")

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            logger.info(f"NEW FILE CREATED | {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            rel = os.path.relpath(event.src_path, self.directory)
            logger.warning(f"FILE DELETED | {rel}")
            # Compute risk for deletion as CRITICAL-equivalent
            risk = {
                "score": 90.0, "level": "CRITICAL",
                "sensitivity": 1.0, "time_anomaly": 0.8, "frequency": 1.0,
                "breakdown": "Deletion event — maximum risk"
            }
            result = {
                "changed": True, "event": "DELETED",
                "rel_path": rel,
                "category": "UNKNOWN",
                "old_hash": "?", "new_hash": None,
            }
            _print_alert(result, risk, event.src_path)


# ── One-shot scan ──────────────────────────────────────────────────────────────

def run_scan(directory: str):
    """
    Walks all files in directory and checks each against the baseline.
    Prints a summary at the end.
    """
    baseline = load_baseline()
    if not baseline:
        return

    log_separator(logger, "ONE-SHOT INTEGRITY SCAN")
    logger.info(f"Scanning: {os.path.abspath(directory)}")

    changed_files = []
    ok_files      = []

    for root, _, files in os.walk(directory):
        for fname in files:
            filepath = os.path.join(root, fname)
            result   = verify_file(filepath, directory, baseline)

            if result is None:
                logger.info(f"NEW (not in baseline) | {os.path.relpath(filepath, directory)}")
            elif result["changed"]:
                risk = compute_risk(filepath, result["category"])
                _print_alert(result, risk, filepath)
                changed_files.append((result["rel_path"], risk["score"], risk["level"]))
            else:
                ok_files.append(result["rel_path"])

    # ── Summary ──────────────────────────────────────────────────────────────
    log_separator(logger, "SCAN SUMMARY")
    print(f"\n  ✅ Unchanged : {len(ok_files)} files")
    print(f"  ⚠️  Changed   : {len(changed_files)} files\n")

    if changed_files:
        print("  Modified files (sorted by risk):")
        for path, score, level in sorted(changed_files, key=lambda x: -x[1]):
            color = get_alert_color(level)
            print(f"    {color}[{level:<8} {score:>5}/100]{RESET}  {path}")

    logger.info(f"SCAN DONE | OK={len(ok_files)} | CHANGED={len(changed_files)}")


# ── Live monitor ───────────────────────────────────────────────────────────────

def run_monitor(directory: str):
    """
    Starts the live watchdog-based file monitor.
    Blocks until Ctrl+C is pressed.
    """
    baseline = load_baseline()
    if not baseline:
        return

    log_separator(logger, "LIVE MONITORING STARTED")
    logger.info(f"Watching: {os.path.abspath(directory)}")
    logger.info("Press Ctrl+C to stop monitoring.")
    print(f"\n  👁  Monitoring '{directory}' in real-time. Press Ctrl+C to stop.\n")

    handler  = FIMEventHandler(directory, baseline)
    observer = Observer()
    observer.schedule(handler, path=directory, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        log_separator(logger, "MONITORING STOPPED")
        logger.info("Monitor stopped by user.")
        print("\n  Monitoring stopped.")

    observer.join()
