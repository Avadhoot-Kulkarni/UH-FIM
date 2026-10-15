"""
categorizer.py
--------------
Decides which hashing strategy to use for a given file.

Three categories (directly from UH-FIM research paper):
  CRITICAL   → Full SHA-256 hash   (kernel, system configs, boot files)
  EXECUTABLE → Block-based hash    (scripts, binaries, libraries)
  DATA       → Sector-sample hash  (logs, text, user data)
"""

import os

# ── File extension → category mapping ─────────────────────────────────────────

CRITICAL_EXTENSIONS = {
    # OS / kernel / boot
    ".sys", ".ko", ".mod", ".img", ".iso",
    # Certificates and keys
    ".pem", ".key", ".crt", ".cer",
    # No extension files that are typically critical (matched by name below)
}

CRITICAL_NAMES = {
    # Unix system config files (no extension)
    "passwd", "shadow", "sudoers", "hosts",
    "fstab", "crontab", "sshd_config", "ssh_config",
    "bashrc", "profile", "bash_profile",
    "kernel_config", "grub.conf",
    # Windows equivalents
    "sam", "system", "security",
}

EXECUTABLE_EXTENSIONS = {
    # Compiled binaries
    ".exe", ".dll", ".so", ".dylib",
    # Scripts — any script can be tampered to run malicious code
    ".py", ".sh", ".bash", ".zsh", ".rb",
    ".js", ".ts", ".php", ".pl", ".lua",
    # Java / JVM
    ".jar", ".class",
    # Compiled objects
    ".o", ".a",
}

DATA_EXTENSIONS = {
    # Logs and plain text
    ".log", ".txt", ".out", ".err",
    # Structured data
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    # Tabular data
    ".csv", ".tsv",
    # Markup
    ".html", ".htm", ".md",
    # Database dumps
    ".sql", ".db", ".sqlite",
}


def get_category(filepath: str) -> str:
    """
    Returns one of: 'CRITICAL', 'EXECUTABLE', 'DATA', 'UNKNOWN'

    Logic:
      1. Check filename (no-extension critical files like 'passwd')
      2. Check extension
      3. Fall back to EXECUTABLE for unknown binary-like files
    """
    filename  = os.path.basename(filepath).lower()
    _, ext    = os.path.splitext(filename)
    ext       = ext.lower()

    # Step 1: name-based check (catches passwd, shadow, hosts, etc.)
    if filename in CRITICAL_NAMES:
        return "CRITICAL"

    # Step 2: extension-based check
    if ext in CRITICAL_EXTENSIONS:
        return "CRITICAL"
    if ext in EXECUTABLE_EXTENSIONS:
        return "EXECUTABLE"
    if ext in DATA_EXTENSIONS:
        return "DATA"

    # Step 3: if file has no extension and is not a known critical name,
    #         treat as executable (safe default — don't under-monitor)
    if ext == "":
        return "EXECUTABLE"

    # Step 4: everything else (images, fonts, etc.) → DATA level monitoring
    return "DATA"


def get_sensitivity_score(category: str) -> float:
    """
    Returns a float 0.0–1.0 representing how sensitive a file category is.
    Used later by the Risk Scorer.
    """
    return {
        "CRITICAL":   1.0,
        "EXECUTABLE": 0.7,
        "DATA":       0.3,
        "UNKNOWN":    0.5,
    }.get(category, 0.5)
