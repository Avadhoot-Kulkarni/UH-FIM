from __future__ import annotations

from datetime import datetime
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parent
TARGET = ROOT / "core" / "baseline.py"

if not (ROOT / "uhfim.py").is_file() or not (ROOT / "core" / "hasher.py").is_file():
    raise SystemExit(
        "ERROR: Put patch_uhfim_cave.py in the UH-FIM project root, "
        "next to uhfim.py and the core/ directory."
    )
if not TARGET.is_file():
    raise SystemExit(f"ERROR: Cannot find {TARGET}")

NEW_SOURCE = r'''"""UH-FIM baseline management with coverage-aware full-hash escalation.

The baseline retains the adaptive hash used by the existing design and also
stores a trusted full-file SHA-256. Verification first checks the adaptive
hash and basic file metadata. If metadata or the adaptive hash indicates a
possible change, a full-file SHA-256 is compared with the baseline reference.

This catches the evaluation suite's changes outside sampled BLOCK/SAMPLE
regions when the file's metadata changes. It does not defeat an attacker who
can modify content while preserving metadata and avoiding sampled regions;
periodic full scans or stronger OS-level telemetry are needed for that threat.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime

from core.hasher import compute_hash
from utils.logger import get_logger, log_separator

logger = get_logger()

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
BASELINE_FILE = os.path.join(DATA_DIR, "baseline.json")
CHECKSUM_FILE = os.path.join(DATA_DIR, "baseline.checksum")
os.makedirs(DATA_DIR, exist_ok=True)


def _compute_file_checksum(filepath: str) -> str:
    """SHA-256 of the baseline JSON file itself."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _compute_content_sha256(filepath: str) -> str:
    """Trusted full-file content digest used for escalation checks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_metadata(filepath: str) -> tuple[int, int]:
    stat = os.stat(filepath)
    mtime_ns = getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000))
    return int(stat.st_size), int(mtime_ns)


def _save_checksum(checksum: str) -> None:
    with open(CHECKSUM_FILE, "w", encoding="utf-8") as f:
        f.write(checksum)


def _load_checksum() -> str | None:
    if not os.path.exists(CHECKSUM_FILE):
        return None
    with open(CHECKSUM_FILE, encoding="utf-8") as f:
        return f.read().strip()


def _verify_baseline_integrity() -> bool:
    """Return False if the baseline JSON differs from its stored checksum."""
    stored = _load_checksum()
    if stored is None:
        logger.warning(
            "BASELINE | No checksum file found - cannot verify baseline integrity"
        )
        return True

    computed = _compute_file_checksum(BASELINE_FILE)
    if stored != computed:
        logger.critical(
            "BASELINE TAMPERED! The baseline database itself has been modified. "
            "Recreate it from a trusted state."
        )
        return False

    logger.debug("BASELINE | Integrity checksum verified")
    return True


def _collect_files(directory: str) -> list[str]:
    """Recursively collect all files beneath directory."""
    collected: list[str] = []
    for root, _, filenames in os.walk(directory):
        for filename in filenames:
            collected.append(os.path.join(root, filename))
    return sorted(collected)


def create_baseline(directory: str) -> dict:
    """Create a baseline with adaptive and full-file digests for each file."""
    log_separator(logger, "BASELINE CREATION STARTED")
    directory = os.path.abspath(directory)
    logger.info(f"Scanning directory: {directory}")

    files = _collect_files(directory)
    baseline = {
        "_meta": {
            "created_at": datetime.now().isoformat(),
            "directory": directory,
            "file_count": len(files),
            "baseline_version": 2,
            "verification_mode": "adaptive plus coverage-aware full-hash escalation",
        },
        "files": {},
    }
    stats = {"CRITICAL": 0, "EXECUTABLE": 0, "DATA": 0}

    for filepath in files:
        rel_path = os.path.relpath(filepath, directory)
        try:
            # The adaptive digest preserves existing BLOCK/SAMPLE behavior.
            adaptive = compute_hash(filepath)
            # The full digest is the trusted reference used during escalation.
            full_hash = _compute_content_sha256(filepath)
            size, mtime_ns = _file_metadata(filepath)
            baseline["files"][rel_path] = {
                "hash": adaptive["hash"],
                "full_hash": full_hash,
                "strategy": adaptive["strategy"],
                "category": adaptive["category"],
                "size": size,
                "mtime_ns": mtime_ns,
                "hashed_at": datetime.now().isoformat(),
            }
            stats[adaptive["category"]] = stats.get(adaptive["category"], 0) + 1
            logger.info(
                f"  BASELINED | {rel_path:<40} | {adaptive['category']:<10} | "
                f"{adaptive['strategy']:<6} | {size:>8} bytes"
            )
        except Exception as exc:
            logger.warning(f"  SKIPPED | {rel_path} | Reason: {exc}")

    os.makedirs(os.path.dirname(os.path.abspath(BASELINE_FILE)), exist_ok=True)
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)
    checksum = _compute_file_checksum(BASELINE_FILE)
    _save_checksum(checksum)

    log_separator(logger)
    logger.info(
        f"BASELINE COMPLETE | {len(files)} files | "
        f"CRITICAL={stats.get('CRITICAL', 0)} | "
        f"EXECUTABLE={stats.get('EXECUTABLE', 0)} | "
        f"DATA={stats.get('DATA', 0)}"
    )
    logger.info(f"Baseline saved -> {BASELINE_FILE}")
    return baseline


def load_baseline() -> dict | None:
    """Load the baseline only when its local checksum validates."""
    if not os.path.exists(BASELINE_FILE):
        logger.error("No baseline found. Run with 'baseline <directory>' first.")
        return None
    if not _verify_baseline_integrity():
        return None
    with open(BASELINE_FILE, encoding="utf-8") as f:
        baseline = json.load(f)
    meta = baseline.get("_meta", {})
    logger.info(
        f"BASELINE LOADED | Created: {meta.get('created_at', '?')} | "
        f"Files: {meta.get('file_count', '?')} | Dir: {meta.get('directory', '?')}"
    )
    return baseline


def verify_file(filepath: str, directory: str, baseline: dict) -> dict | None:
    """Verify a file; full-hash escalation catches changes outside sampled areas.

    Returns None for a new file. For baseline-known missing paths, returns a
    DELETED event. Existing legacy baselines without ``full_hash`` retain the
    old adaptive-only behavior until their baseline is recreated.
    """
    rel_path = os.path.relpath(filepath, directory)
    stored = baseline.get("files", {}).get(rel_path)
    if stored is None:
        logger.info(f"NEW FILE DETECTED | {rel_path}")
        return None

    if not os.path.isfile(filepath):
        logger.warning(f"FILE DELETED | {rel_path}")
        return {
            "changed": True,
            "event": "DELETED",
            "rel_path": rel_path,
            "category": stored.get("category", "UNKNOWN"),
            "old_hash": stored.get("full_hash", stored.get("hash")),
            "new_hash": None,
        }

    try:
        current_size, current_mtime_ns = _file_metadata(filepath)
        current = compute_hash(filepath)
    except FileNotFoundError:
        # Handle a file disappearing between the initial check and hashing.
        return {
            "changed": True,
            "event": "DELETED",
            "rel_path": rel_path,
            "category": stored.get("category", "UNKNOWN"),
            "old_hash": stored.get("full_hash", stored.get("hash")),
            "new_hash": None,
        }

    metadata_changed = (
        current_size != stored.get("size")
        or current_mtime_ns != stored.get("mtime_ns")
    )
    adaptive_changed = current["hash"] != stored.get("hash")
    trusted_full_hash = stored.get("full_hash")

    # Legacy baselines lack full_hash. Keep their original semantics and make
    # the limitation explicit rather than pretending they have full coverage.
    if not trusted_full_hash:
        if adaptive_changed:
            return {
                "changed": True,
                "event": "MODIFIED",
                "rel_path": rel_path,
                "category": stored.get("category", current["category"]),
                "strategy": current["strategy"],
                "old_hash": stored.get("hash"),
                "new_hash": current["hash"],
                "old_size": stored.get("size"),
                "new_size": current_size,
                "verification_mode": "legacy adaptive-only",
            }
        return {"changed": False, "rel_path": rel_path, "category": stored.get("category", current["category"])}

    # Escalate on metadata changes or on an adaptive-hash mismatch.
    # Full SHA-256 is compared with the immutable baseline content reference.
    if metadata_changed or adaptive_changed:
        current_full_hash = _compute_content_sha256(filepath)
        if current_full_hash != trusted_full_hash:
            return {
                "changed": True,
                "event": "MODIFIED",
                "rel_path": rel_path,
                "category": stored.get("category", current["category"]),
                "strategy": current["strategy"],
                "old_hash": trusted_full_hash,
                "new_hash": current_full_hash,
                "adaptive_old_hash": stored.get("hash"),
                "adaptive_new_hash": current["hash"],
                "old_size": stored.get("size"),
                "new_size": current_size,
                "verification_mode": "full-hash escalation",
            }

    return {
        "changed": False,
        "rel_path": rel_path,
        "category": stored.get("category", current["category"]),
        "verification_mode": (
            "adaptive plus full-hash escalation"
            if trusted_full_hash
            else "legacy adaptive-only"
        ),
    }
'''

# Syntax-check the candidate before altering the project.
compile(NEW_SOURCE, str(TARGET), "exec")
stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
backup = TARGET.with_name(f"baseline.py.pre_cave_{stamp}.bak")
backup.write_bytes(TARGET.read_bytes())
TARGET.write_text(NEW_SOURCE, encoding="utf-8", newline="\n")

# Verify that the file on disk still compiles.
compile(TARGET.read_text(encoding="utf-8"), str(TARGET), "exec")
print("UH-FIM CAVE patch applied successfully.")
print(f"Backup created: {backup.name}")
print("Next run: py -3 .\\uhfim_dataset_eval.py all")
print("Then inspect: .\\uhfim_evaluation_dataset\\results\\validation_summary.json")
print("Note: the evaluation suite measures controlled scenarios, not production-wide accuracy.")
