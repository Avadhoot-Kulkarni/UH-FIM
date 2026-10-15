"""
hasher.py
---------
The Adaptive Multi-Granularity Hashing Engine.

Three hashing strategies — chosen based on file category:

  FULL (CRITICAL files)
  ─────────────────────
  Reads the entire file and computes SHA-256.
  Maximum accuracy. Any byte change = detection.
  Cost: O(n) where n = file size.

  BLOCK (EXECUTABLE files)
  ─────────────────────────
  Reads three fixed-size blocks from the file:
    · First  BLOCK_SIZE bytes  → catches header/entry-point injection
    · Middle BLOCK_SIZE bytes  → catches code-cave injection
    · Last   BLOCK_SIZE bytes  → catches appended payload
  Then computes SHA-256 over the concatenation of the three blocks.
  Cost: O(1) — always reads exactly 3 × BLOCK_SIZE bytes regardless of file size.

  SAMPLE (DATA files)
  ────────────────────
  Reads SAMPLE_COUNT evenly-spaced sectors across the file.
  Each sector = SECTOR_SIZE bytes.
  SHA-256 is computed over the concatenated sample.
  Detects structural overwrites and deletions without reading every byte.
  Cost: O(k) where k = SAMPLE_COUNT (constant).
"""

import hashlib
import os
import random

from utils.categorizer import get_category
from utils.logger       import get_logger

logger = get_logger()

# ── Tunable constants ──────────────────────────────────────────────────────────
BLOCK_SIZE   = 512     # bytes read per block in BLOCK strategy
SECTOR_SIZE  = 512     # bytes per sector in SAMPLE strategy
SAMPLE_COUNT = 8       # number of random sectors sampled in SAMPLE strategy


# ── Strategy implementations ───────────────────────────────────────────────────

def _hash_full(filepath: str) -> str:
    """
    Read entire file → SHA-256.
    Used for CRITICAL files where any deviation must be caught.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):   # 64KB chunks for memory efficiency
            h.update(chunk)
    return h.hexdigest()


def _hash_block(filepath: str) -> str:
    """
    Read 3 strategic blocks → SHA-256 of their concatenation.
    Used for EXECUTABLE files.

    Block positions:
      • Start  : byte 0
      • Middle : byte (filesize // 2)
      • End    : byte (filesize - BLOCK_SIZE)
    """
    size = os.path.getsize(filepath)
    h    = hashlib.sha256()

    positions = []
    positions.append(0)                            # header / entry point

    if size > BLOCK_SIZE * 2:
        positions.append((size // 2) - (BLOCK_SIZE // 2))   # middle
    if size > BLOCK_SIZE:
        positions.append(max(0, size - BLOCK_SIZE))          # tail / appended payload

    with open(filepath, "rb") as f:
        for pos in positions:
            f.seek(pos)
            data = f.read(BLOCK_SIZE)
            h.update(data)

    return h.hexdigest()


def _hash_sample(filepath: str) -> str:
    """
    Read SAMPLE_COUNT evenly-spaced sectors → SHA-256 of concatenation.
    Used for DATA files (logs, text, configs).

    We use FIXED spacing (not random) so the hash is deterministic —
    same file always produces the same hash.
    """
    size = os.path.getsize(filepath)
    h    = hashlib.sha256()

    if size == 0:
        h.update(b"")
        return h.hexdigest()

    # Evenly distribute sample points across the file
    step = max(1, size // SAMPLE_COUNT)

    with open(filepath, "rb") as f:
        for i in range(SAMPLE_COUNT):
            pos = min(i * step, size - 1)
            f.seek(pos)
            data = f.read(SECTOR_SIZE)
            h.update(data)

    return h.hexdigest()


# ── Public API ─────────────────────────────────────────────────────────────────

def compute_hash(filepath: str) -> dict:
    """
    Main entry point. Automatically:
      1. Categorizes the file
      2. Selects the appropriate strategy
      3. Computes and returns the hash with metadata

    Returns a dict:
      {
        "hash"     : str,    # hex digest
        "strategy" : str,    # FULL / BLOCK / SAMPLE
        "category" : str,    # CRITICAL / EXECUTABLE / DATA
        "size"     : int,    # bytes
      }
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Cannot hash — file not found: {filepath}")

    category = get_category(filepath)
    size     = os.path.getsize(filepath)

    if category == "CRITICAL":
        strategy   = "FULL"
        hash_value = _hash_full(filepath)
    elif category == "EXECUTABLE":
        strategy   = "BLOCK"
        hash_value = _hash_block(filepath)
    else:                          # DATA or UNKNOWN
        strategy   = "SAMPLE"
        hash_value = _hash_sample(filepath)

    logger.debug(
        f"HASH | {os.path.basename(filepath):<30} | "
        f"Category={category:<10} | Strategy={strategy:<6} | "
        f"Size={size:>8} bytes | Hash={hash_value[:16]}..."
    )

    return {
        "hash"     : hash_value,
        "strategy" : strategy,
        "category" : category,
        "size"     : size,
    }
