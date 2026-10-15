"""
uhfim.py — UH-FIM: Unified Hash-Based File Integrity Monitor
─────────────────────────────────────────────────────────────
The main command-line entry point.

Usage:
  python uhfim.py baseline <directory>    Create a fresh baseline snapshot
  python uhfim.py scan     <directory>    One-shot integrity check (no live watch)
  python uhfim.py monitor  <directory>    Live real-time monitoring (watchdog)
  python uhfim.py demo                    Set up demo files and run a demo

Examples:
  python uhfim.py baseline demo_files/
  python uhfim.py monitor  demo_files/
  python uhfim.py scan     demo_files/
"""

import sys
import os

# ── Make sure sibling packages are importable ──────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from core.baseline  import create_baseline
from core.monitor   import run_monitor, run_scan
from utils.logger   import get_logger, log_separator

logger = get_logger()

RESET = "\033[0m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"

BANNER = f"""
{CYAN}{BOLD}
  ██╗   ██╗██╗  ██╗      ███████╗██╗███╗   ███╗
  ██║   ██║██║  ██║      ██╔════╝██║████╗ ████║
  ██║   ██║███████║█████╗█████╗  ██║██╔████╔██║
  ██║   ██║██╔══██║╚════╝██╔══╝  ██║██║╚██╔╝██║
  ╚██████╔╝██║  ██║      ██║     ██║██║ ╚═╝ ██║
   ╚═════╝ ╚═╝  ╚═╝      ╚═╝     ╚═╝╚═╝     ╚═╝

  Unified Hash-Based File Integrity Monitor
  Adaptive Hashing · Risk Scoring · Real-Time Detection
{RESET}"""

HELP = f"""
{CYAN}Usage:{RESET}
  python uhfim.py baseline <dir>   Create baseline snapshot
  python uhfim.py scan     <dir>   One-shot scan against baseline
  python uhfim.py monitor  <dir>   Live real-time monitoring
  python uhfim.py demo             Run the built-in demo

{CYAN}Log file:{RESET}
  All activity is logged to logs/uhfim.log
"""


# ── Demo setup ─────────────────────────────────────────────────────────────────

def setup_demo():
    """
    Creates a demo_files/ folder with sample files of each category,
    baselines them, then guides the user through a live demo.
    """
    demo_dir = os.path.join(os.path.dirname(__file__), "demo_files")
    os.makedirs(os.path.join(demo_dir, "system"),      exist_ok=True)
    os.makedirs(os.path.join(demo_dir, "executables"), exist_ok=True)
    os.makedirs(os.path.join(demo_dir, "data_files"),  exist_ok=True)
    os.makedirs(os.path.join(demo_dir, "logs"),        exist_ok=True)

    # ── CRITICAL files ───────────────────────────────────────────────────────
    with open(os.path.join(demo_dir, "system", "passwd"), "w") as f:
        f.write("root:x:0:0:root:/root:/bin/bash\n")
        f.write("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
        f.write("user1:x:1000:1000:User One:/home/user1:/bin/bash\n")

    with open(os.path.join(demo_dir, "system", "kernel_config"), "w") as f:
        f.write("CONFIG_X86_64=y\nCONFIG_SMP=y\nCONFIG_PREEMPT=y\n")

    # ── EXECUTABLE files ─────────────────────────────────────────────────────
    with open(os.path.join(demo_dir, "executables", "app.py"), "w") as f:
        f.write('#!/usr/bin/env python3\n')
        f.write('"""Main application script."""\n\n')
        f.write('def main():\n')
        f.write('    print("Application started")\n\n')
        f.write('if __name__ == "__main__":\n')
        f.write('    main()\n')

    with open(os.path.join(demo_dir, "executables", "deploy.sh"), "w") as f:
        f.write("#!/bin/bash\n")
        f.write("echo 'Deploying application...'\n")
        f.write("cd /var/www && git pull origin main\n")
        f.write("systemctl restart app\n")

    # ── DATA files ───────────────────────────────────────────────────────────
    with open(os.path.join(demo_dir, "data_files", "config.json"), "w") as f:
        f.write('{\n  "db_host": "localhost",\n  "db_port": 5432,\n')
        f.write('  "debug": false,\n  "secret_key": "changeme"\n}\n')

    with open(os.path.join(demo_dir, "data_files", "readme.txt"), "w") as f:
        f.write("Application v1.0\nInstallation guide.\n")

    with open(os.path.join(demo_dir, "logs", "app.log"), "w") as f:
        f.write("[2025-04-01 10:00:00] INFO  Server started on port 8080\n")
        f.write("[2025-04-01 10:00:01] INFO  Database connected\n")
        f.write("[2025-04-01 10:00:05] INFO  Health check passed\n")

    print(f"\n  {CYAN}Demo files created in: {demo_dir}{RESET}")
    print("\n  Step 1: Creating baseline...\n")
    create_baseline(demo_dir)

    print(f"""
{CYAN}{BOLD}  ── DEMO INSTRUCTIONS ──────────────────────────────────────────{RESET}

  Now open a SECOND terminal and try these modifications:

  {CYAN}[HIGH RISK — executable tampered]{RESET}
    echo "import os; os.system('rm -rf /')" >> demo_files/executables/app.py

  {CYAN}[CRITICAL RISK — system file changed]{RESET}
    echo "attacker:x:0:0:hacker:/root:/bin/bash" >> demo_files/system/passwd

  {CYAN}[LOW RISK — log file updated]{RESET}
    echo "[2025-04-01 11:00] INFO Health check" >> demo_files/logs/app.log

  Then run the scan in THIS terminal:
    python uhfim.py scan demo_files/

  Or start live monitoring:
    python uhfim.py monitor demo_files/

{CYAN}{BOLD}  ────────────────────────────────────────────────────────────────{RESET}
""")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    if len(sys.argv) < 2:
        print(HELP)
        sys.exit(0)

    command = sys.argv[1].lower()

    log_separator(logger, f"SESSION START — command: {command}")
    logger.info(f"Arguments: {sys.argv}")

    if command == "baseline":
        if len(sys.argv) < 3:
            print("  Usage: python uhfim.py baseline <directory>")
            sys.exit(1)
        directory = sys.argv[2]
        if not os.path.isdir(directory):
            print(f"  ERROR: '{directory}' is not a directory.")
            sys.exit(1)
        create_baseline(directory)

    elif command == "scan":
        if len(sys.argv) < 3:
            print("  Usage: python uhfim.py scan <directory>")
            sys.exit(1)
        directory = sys.argv[2]
        run_scan(directory)

    elif command == "monitor":
        if len(sys.argv) < 3:
            print("  Usage: python uhfim.py monitor <directory>")
            sys.exit(1)
        directory = sys.argv[2]
        run_monitor(directory)

    elif command == "demo":
        setup_demo()

    else:
        print(f"  Unknown command: '{command}'")
        print(HELP)
        sys.exit(1)


if __name__ == "__main__":
    main()
