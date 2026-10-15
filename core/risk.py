"""
risk.py
-------
Contextual Risk Assessment Module.

Computes a risk score (0–100) for a detected file change.

Formula (from UH-FIM paper, Section: Core Component 3):
  Risk Score = α × File_Sensitivity
             + β × Time_Anomaly
             + γ × Change_Frequency

Weights:
  α = 0.50  (file sensitivity is the dominant factor)
  β = 0.30  (time of day matters — 3AM changes are suspicious)
  γ = 0.20  (how often has this file changed recently?)

Each sub-score is a float 0.0–1.0, then multiplied by its weight.
Final score is scaled to 0–100 and rounded to 1 decimal.

Alert Thresholds:
  80–100 → CRITICAL  (immediate investigation needed)
  60–79  → HIGH      (likely malicious or unauthorized)
  40–59  → MEDIUM    (investigate during working hours)
  20–39  → LOW       (probably benign, log and watch)
   0–19  → INFO      (expected system activity)
"""

import os
from datetime import datetime
from collections import defaultdict

from utils.categorizer import get_sensitivity_score
from utils.logger       import get_logger

logger = get_logger()

# ── Weights (must sum to 1.0) ──────────────────────────────────────────────────
ALPHA = 0.50   # file sensitivity weight
BETA  = 0.30   # time anomaly weight
GAMMA = 0.20   # change frequency weight

# ── Suspicious hours (22:00–06:00) ────────────────────────────────────────────
SUSPICIOUS_HOURS = set(range(22, 24)) | set(range(0, 6))   # 10PM–6AM

# ── In-memory change frequency tracker ────────────────────────────────────────
# Tracks timestamps of recent changes per file
_change_history: dict = defaultdict(list)
FREQUENCY_WINDOW_SECS = 300    # look back 5 minutes
HIGH_FREQUENCY_THRESHOLD = 5   # 5+ changes in the window = suspicious


# ── Sub-score calculators ──────────────────────────────────────────────────────

def _score_sensitivity(category: str) -> float:
    """
    Returns raw sensitivity 0.0–1.0 based on file category.
    CRITICAL=1.0, EXECUTABLE=0.7, DATA=0.3
    """
    return get_sensitivity_score(category)


def _score_time_anomaly() -> float:
    """
    Returns 0.8 if current hour is in the suspicious window (10PM–6AM),
    otherwise 0.1.
    Rationale: Legitimate sysadmin changes rarely happen at 3AM.
    """
    current_hour = datetime.now().hour
    return 0.8 if current_hour in SUSPICIOUS_HOURS else 0.1


def _score_change_frequency(filepath: str) -> float:
    """
    Tracks how many times this file has changed in the last FREQUENCY_WINDOW_SECS.
    Returns 0.0–1.0 proportional to frequency.
    """
    now        = datetime.now().timestamp()
    history    = _change_history[filepath]

    # Prune old entries outside the window
    _change_history[filepath] = [t for t in history if now - t < FREQUENCY_WINDOW_SECS]
    _change_history[filepath].append(now)

    count = len(_change_history[filepath])

    if count <= 1:
        return 0.0
    elif count >= HIGH_FREQUENCY_THRESHOLD:
        return 1.0
    else:
        return (count - 1) / (HIGH_FREQUENCY_THRESHOLD - 1)


# ── Alert level ────────────────────────────────────────────────────────────────

def get_alert_level(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"


def get_alert_color(level: str) -> str:
    """ANSI color codes for terminal output."""
    return {
        "CRITICAL": "\033[91m",   # red
        "HIGH":     "\033[93m",   # yellow
        "MEDIUM":   "\033[94m",   # blue
        "LOW":      "\033[92m",   # green
        "INFO":     "\033[90m",   # grey
    }.get(level, "\033[0m")


# ── Main public function ───────────────────────────────────────────────────────

def compute_risk(filepath: str, category: str) -> dict:
    """
    Computes the full risk score for a file change event.

    Returns a dict:
      {
        "score"       : float,   # 0–100
        "level"       : str,     # CRITICAL / HIGH / MEDIUM / LOW / INFO
        "sensitivity" : float,   # sub-score (0–1)
        "time_anomaly": float,   # sub-score (0–1)
        "frequency"   : float,   # sub-score (0–1)
        "breakdown"   : str,     # human-readable formula result
      }
    """
    s_sensitivity = _score_sensitivity(category)
    s_time        = _score_time_anomaly()
    s_freq        = _score_change_frequency(filepath)

    raw   = ALPHA * s_sensitivity + BETA * s_time + GAMMA * s_freq
    score = round(raw * 100, 1)
    level = get_alert_level(score)

    breakdown = (
        f"α({ALPHA})×Sensitivity({s_sensitivity:.2f}) + "
        f"β({BETA})×TimeAnomaly({s_time:.2f}) + "
        f"γ({GAMMA})×Frequency({s_freq:.2f}) = {score}/100"
    )

    # ── Log the full breakdown to file ──────────────────────────────────────
    logger.debug(
        f"RISK | {os.path.basename(filepath):<30} | "
        f"Score={score:>5}/100 | Level={level:<8} | {breakdown}"
    )

    return {
        "score"       : score,
        "level"       : level,
        "sensitivity" : s_sensitivity,
        "time_anomaly": s_time,
        "frequency"   : s_freq,
        "breakdown"   : breakdown,
    }
