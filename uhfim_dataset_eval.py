#!/usr/bin/env python3
"""UH-FIM synthetic dataset generator and validation harness.

Put this file in the UH-FIM project root (the same directory as uhfim.py,
core/, and utils/). It uses the project's current categorizer, hashing,
baseline, verifier, and risk-scoring functions; it does not modify the
project's normal data/baseline.json or data/baseline.checksum.

Commands:
    python uhfim_dataset_eval.py generate
    python uhfim_dataset_eval.py validate
    python uhfim_dataset_eval.py all

This creates a controlled synthetic file-integrity dataset, a manifest with
full-file SHA-256 ground truth, test-case results, and a hashing benchmark.
The generated files are test fixtures only; do not execute them.
"""
from __future__ import annotations

import argparse
import builtins
import csv
import hashlib
import json
import os
import logging
import shutil
import statistics
import sys
import time
from pathlib import Path
from typing import Callable

PROJECT_ROOT = Path(__file__).resolve().parent
if not (PROJECT_ROOT / "uhfim.py").is_file() or not (PROJECT_ROOT / "core" / "hasher.py").is_file():
    raise SystemExit(
        "ERROR: Save this script in the UH-FIM project root, next to uhfim.py, core/, and utils/."
    )
sys.path.insert(0, str(PROJECT_ROOT))

# Import the real project modules so the tests exercise the submitted code.
import core.baseline as baseline_module  # noqa: E402
import core.hasher as hasher_module  # noqa: E402
import core.risk as risk_module  # noqa: E402
from core.hasher import compute_hash  # noqa: E402
from utils.categorizer import get_category  # noqa: E402

DATASET_ROOT = PROJECT_ROOT / "uhfim_evaluation_dataset"
CLEAN_DIR = DATASET_ROOT / "clean"
WORK_DIR = DATASET_ROOT / "work"
RESULTS_DIR = DATASET_ROOT / "results"
MANIFEST_CSV = DATASET_ROOT / "manifest.csv"
MANIFEST_JSON = DATASET_ROOT / "manifest.json"

SIZE_BANDS = [
    ("small_4KiB", 4 * 1024),
    ("medium_64KiB", 64 * 1024),
    ("large_1MiB", 1024 * 1024),
]

# Exactly 15 files in each category: five files in each size band.
FILE_SPECS = [
    # Critical filenames/extensions are deliberately chosen to match the
    # categorizer.py rules currently present in the uploaded UH-FIM project.
    ("system/passwd", "CRITICAL", "small_4KiB", 4096),
    ("system/shadow", "CRITICAL", "small_4KiB", 4096),
    ("system/hosts", "CRITICAL", "small_4KiB", 4096),
    ("system/kernel_config", "CRITICAL", "small_4KiB", 4096),
    ("system/sshd_config", "CRITICAL", "small_4KiB", 4096),
    ("system/cert_01.pem", "CRITICAL", "medium_64KiB", 65536),
    ("system/cert_02.key", "CRITICAL", "medium_64KiB", 65536),
    ("system/cert_03.crt", "CRITICAL", "medium_64KiB", 65536),
    ("system/cert_04.cer", "CRITICAL", "medium_64KiB", 65536),
    ("system/cert_05.key", "CRITICAL", "medium_64KiB", 65536),
    ("system/large_01.sys", "CRITICAL", "large_1MiB", 1048576),
    ("system/large_02.ko", "CRITICAL", "large_1MiB", 1048576),
    ("system/large_03.img", "CRITICAL", "large_1MiB", 1048576),
    ("system/large_04.iso", "CRITICAL", "large_1MiB", 1048576),
    ("system/large_05.key", "CRITICAL", "large_1MiB", 1048576),

    ("executables/tiny_app.py", "EXECUTABLE", "small_4KiB", 4096),
    ("executables/job.sh", "EXECUTABLE", "small_4KiB", 4096),
    ("executables/tool.exe", "EXECUTABLE", "small_4KiB", 4096),
    ("executables/module.so", "EXECUTABLE", "small_4KiB", 4096),
    ("executables/helper.dll", "EXECUTABLE", "small_4KiB", 4096),
    ("executables/worker.py", "EXECUTABLE", "medium_64KiB", 65536),
    ("executables/deploy_medium.sh", "EXECUTABLE", "medium_64KiB", 65536),
    ("executables/scanner.exe", "EXECUTABLE", "medium_64KiB", 65536),
    ("executables/agent.so", "EXECUTABLE", "medium_64KiB", 65536),
    ("executables/parser.py", "EXECUTABLE", "medium_64KiB", 65536),
    ("executables/large_script.py", "EXECUTABLE", "large_1MiB", 1048576),
    ("executables/large_deploy.sh", "EXECUTABLE", "large_1MiB", 1048576),
    ("executables/payload.so", "EXECUTABLE", "large_1MiB", 1048576),
    ("executables/service.dll", "EXECUTABLE", "large_1MiB", 1048576),
    ("executables/worker_app.py", "EXECUTABLE", "large_1MiB", 1048576),

    ("data_files/config.json", "DATA", "small_4KiB", 4096),
    ("data_files/readme.txt", "DATA", "small_4KiB", 4096),
    ("data_files/app.log", "DATA", "small_4KiB", 4096),
    ("data_files/records.csv", "DATA", "small_4KiB", 4096),
    ("data_files/delete_me.txt", "DATA", "small_4KiB", 4096),
    ("data_files/preferences.json", "DATA", "medium_64KiB", 65536),
    ("data_files/memo.md", "DATA", "medium_64KiB", 65536),
    ("data_files/audit.log", "DATA", "medium_64KiB", 65536),
    ("data_files/events.csv", "DATA", "medium_64KiB", 65536),
    ("data_files/dataset.txt", "DATA", "medium_64KiB", 65536),
    ("data_files/large_sample.txt", "DATA", "large_1MiB", 1048576),
    ("data_files/archive.csv", "DATA", "large_1MiB", 1048576),
    ("data_files/telemetry.log", "DATA", "large_1MiB", 1048576),
    ("data_files/large_data.json", "DATA", "large_1MiB", 1048576),
    ("data_files/body.txt", "DATA", "large_1MiB", 1048576),
]

EXPECTED_STRATEGY = {"CRITICAL": "FULL", "EXECUTABLE": "BLOCK", "DATA": "SAMPLE"}


def full_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deterministic_payload(relative_path: str, size: int, seed: int = 20261015) -> bytes:
    """Repeatable byte payload; fixture files are never executed as programs."""
    output = bytearray()
    counter = 0
    while len(output) < size:
        block = hashlib.sha256(
            f"UH-FIM-SYNTHETIC-DATASET|{seed}|{relative_path}|{counter}".encode("utf-8")
        ).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:size])


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if fieldnames:
            writer.writeheader()
            writer.writerows(rows)


def generate_dataset() -> None:
    if CLEAN_DIR.exists():
        shutil.rmtree(CLEAN_DIR)
    CLEAN_DIR.mkdir(parents=True, exist_ok=True)

    manifest = []
    for rel, expected_category, size_band, size in FILE_SPECS:
        path = CLEAN_DIR / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(deterministic_payload(rel, size))
        actual_category = get_category(str(path))
        if actual_category != expected_category:
            raise RuntimeError(
                f"Dataset category mismatch for {rel}: expected {expected_category}, got {actual_category}. "
                "Check utils/categorizer.py before continuing."
            )
        computed = compute_hash(str(path))
        manifest.append({
            "relative_path": rel.replace("\\", "/"),
            "category_expected": expected_category,
            "category_actual": actual_category,
            "strategy_actual": computed["strategy"],
            "size_band": size_band,
            "size_bytes": size,
            "full_sha256_ground_truth": full_sha256(path),
            "adaptive_hash_at_generation": computed["hash"],
            "content_type": "deterministic synthetic byte fixture; not for execution",
        })

    write_csv(MANIFEST_CSV, manifest)
    MANIFEST_JSON.write_text(json.dumps({
        "dataset_name": "UH-FIM Controlled Synthetic Integrity Dataset",
        "seed": 20261015,
        "file_count": len(manifest),
        "category_counts": {
            category: sum(row["category_actual"] == category for row in manifest)
            for category in ("CRITICAL", "EXECUTABLE", "DATA")
        },
        "size_bands": {name: size for name, size in SIZE_BANDS},
        "note": (
            "Synthetic, deterministic byte fixtures designed to test file hashing and integrity-change detection. "
            "Extensions/names exercise the uploaded UH-FIM categorizer. Files are not real OS files or executable code."
        ),
        "files": manifest,
    }, indent=2), encoding="utf-8")

    print(f"Dataset generated: {CLEAN_DIR}")
    print(f"Files: {len(manifest)} (15 CRITICAL, 15 EXECUTABLE, 15 DATA)")
    print(f"Manifest CSV: {MANIFEST_CSV}")
    print(f"Manifest JSON: {MANIFEST_JSON}")


def _set_evaluation_baseline_paths() -> None:
    """Redirect baseline persistence into evaluation results, preserving user's baseline."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    baseline_module.BASELINE_FILE = str(RESULTS_DIR / "evaluation_baseline.json")
    baseline_module.CHECKSUM_FILE = str(RESULTS_DIR / "evaluation_baseline.checksum")


def _quiet_project_logger():
    logger = logging.getLogger("uhfim")
    old_level = logger.level
    old_disabled = logger.disabled
    logger.setLevel(logging.CRITICAL + 1)
    logger.disabled = False
    return logger, old_level, old_disabled


def _restore_logger(state) -> None:
    logger, old_level, old_disabled = state
    logger.setLevel(old_level)
    logger.disabled = old_disabled


def _fresh_working_copy() -> None:
    if WORK_DIR.exists():
        shutil.rmtree(WORK_DIR)
    shutil.copytree(CLEAN_DIR, WORK_DIR)


def _make_baseline():
    # Use the actual project's create_baseline and load_baseline functions.
    baseline_module.create_baseline(str(WORK_DIR))
    baseline = baseline_module.load_baseline()
    if not baseline:
        raise RuntimeError("UH-FIM could not load its evaluation baseline. Check logs/uhfim.log.")
    return baseline


def _flip_byte(path: Path, offset: int) -> None:
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if offset < 0 or offset >= size:
        raise ValueError(f"Byte offset {offset} is outside {path} (size={size})")
    with path.open("r+b") as handle:
        handle.seek(offset)
        old = handle.read(1)
        handle.seek(offset)
        handle.write(b"\x00" if old != b"\x00" else b"\x01")


def _check_result(path: Path, baseline: dict) -> tuple[bool, str, dict | None]:
    """True means the API identifies change/new-file/deletion in this scenario."""
    result = baseline_module.verify_file(str(path), str(WORK_DIR), baseline)
    if result is None:
        # In this project's API, None means the file is new/not in baseline.
        return True, "NEW_FILE", None
    if result.get("changed"):
        return True, result.get("event", "MODIFIED"), result
    return False, "UNCHANGED", result


def _risk_fields(path: Path, category: str, detected: bool) -> tuple[str, str]:
    if not detected:
        return "", ""
    risk_module._change_history.clear()
    result = risk_module.compute_risk(str(path), category)
    return str(result["score"]), str(result["level"])


def _test_row(
    test_case: str,
    relative_path: str,
    expected_change: bool,
    detected: bool,
    event: str,
    category: str,
    strategy: str,
    old_full_sha: str,
    new_full_sha: str,
    details: str,
    risk_score: str = "",
    risk_level: str = "",
) -> dict:
    return {
        "test_case": test_case,
        "relative_path": relative_path,
        "category": category,
        "strategy": strategy,
        "expected_change": int(expected_change),
        "detected_by_uhfim_api": int(detected),
        "event_reported_by_api": event,
        "old_full_sha256": old_full_sha,
        "new_full_sha256": new_full_sha,
        "risk_score_0_100": risk_score,
        "risk_level": risk_level,
        "details": details,
    }


def run_validation() -> None:
    if not CLEAN_DIR.is_dir():
        raise SystemExit("Dataset not found. Run: python uhfim_dataset_eval.py generate")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _set_evaluation_baseline_paths()
    logger_state = _quiet_project_logger()
    rows: list[dict] = []

    try:
        # Negative control: all 45 files are left unchanged after baseline creation.
        _fresh_working_copy()
        baseline = _make_baseline()
        for rel in sorted(baseline.get("files", {})):
            path = WORK_DIR / rel
            old_sha = full_sha256(path)
            detected, event, result = _check_result(path, baseline)
            category = baseline["files"][rel]["category"]
            strategy = baseline["files"][rel]["strategy"]
            rows.append(_test_row(
                "clean_control", rel.replace("\\", "/"), False, detected, event,
                category, strategy, old_sha, full_sha256(path),
                "Expected no alert: file was not modified.",
            ))

        # Each positive scenario starts from a clean copy and a new UH-FIM baseline.
        scenarios: list[tuple[str, str, str, Callable[[Path], None], str]] = [
            (
                "critical_full_hash_detects",
                "system/passwd",
                "CRITICAL",
                lambda p: _flip_byte(p, 2000),
                "Change byte 2000 in a 4 KiB CRITICAL file; FULL SHA-256 should detect it.",
            ),
            (
                "block_sample_region_detects",
                "executables/large_script.py",
                "EXECUTABLE",
                lambda p: _flip_byte(p, 100),
                "Change inside the executable's first 512-byte BLOCK region.",
            ),
            (
                "block_unselected_region_probe",
                "executables/large_script.py",
                "EXECUTABLE",
                lambda p: _flip_byte(p, 8192),
                "Change outside the first/middle/last BLOCK regions; this probes a known partial-hash blind spot.",
            ),
            (
                "sampled_region_detects",
                "data_files/large_sample.txt",
                "DATA",
                lambda p: _flip_byte(p, (1048576 // 8) + 10),
                "Change byte 10 inside the SAMPLE region starting at offset 131072.",
            ),
            (
                "unsampled_region_probe",
                "data_files/large_sample.txt",
                "DATA",
                lambda p: _flip_byte(p, 32768),
                "Change outside the eight sampled regions; this probes a known partial-hash blind spot.",
            ),
        ]

        for case_name, relative_path, category, mutation, details in scenarios:
            _fresh_working_copy()
            path = WORK_DIR / relative_path
            before = full_sha256(path)
            baseline = _make_baseline()
            mutation(path)
            after = full_sha256(path)
            detected, event, result = _check_result(path, baseline)
            actual_category = get_category(str(path))
            strategy = baseline["files"][os.path.normpath(relative_path)]["strategy"]
            score, level = _risk_fields(path, actual_category, detected)
            rows.append(_test_row(
                case_name, relative_path, before != after, detected, event,
                actual_category, strategy, before, after, details, score, level,
            ))

        # New file: the current API represents this as None (caller interprets as NEW_FILE).
        _fresh_working_copy()
        baseline = _make_baseline()
        new_rel = "data_files/new_evaluation_file.txt"
        new_path = WORK_DIR / new_rel
        new_path.write_text("UH-FIM synthetic new-file test\n", encoding="utf-8")
        detected, event, result = _check_result(new_path, baseline)
        new_sha = full_sha256(new_path)
        score, level = _risk_fields(new_path, get_category(str(new_path)), detected)
        rows.append(_test_row(
            "new_file_detection", new_rel, True, detected, event,
            get_category(str(new_path)), "SAMPLE", "", new_sha,
            "verify_file() returns None for a file absent from the baseline; caller must label it NEW_FILE.",
            score, level,
        ))

        # Deletion: verify_file can report deletion for a known baseline path. The
        # current one-shot run_scan loop does not independently enumerate missing paths.
        _fresh_working_copy()
        baseline = _make_baseline()
        delete_rel = "data_files/delete_me.txt"
        delete_path = WORK_DIR / delete_rel
        before = full_sha256(delete_path)
        delete_path.unlink()
        detected, event, result = _check_result(delete_path, baseline)
        rows.append(_test_row(
            "deleted_file_verification", delete_rel, True, detected, event,
            baseline["files"][os.path.normpath(delete_rel)]["category"], baseline["files"][os.path.normpath(delete_rel)]["strategy"],
            before, "", "Directly tested verify_file() with a baseline-known path that no longer exists.",
        ))

    finally:
        _restore_logger(logger_state)

    result_fields = [
        "test_case", "relative_path", "category", "strategy", "expected_change",
        "detected_by_uhfim_api", "event_reported_by_api", "old_full_sha256",
        "new_full_sha256", "risk_score_0_100", "risk_level", "details",
    ]
    write_csv(RESULTS_DIR / "validation_results.csv", rows, result_fields)

    tp = sum(r["expected_change"] == 1 and r["detected_by_uhfim_api"] == 1 for r in rows)
    fn = sum(r["expected_change"] == 1 and r["detected_by_uhfim_api"] == 0 for r in rows)
    fp = sum(r["expected_change"] == 0 and r["detected_by_uhfim_api"] == 1 for r in rows)
    tn = sum(r["expected_change"] == 0 and r["detected_by_uhfim_api"] == 0 for r in rows)
    detection_rate = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * precision * detection_rate / (precision + detection_rate)) if (precision + detection_rate) else 0.0

    summary = {
        "warning": "Small, controlled synthetic test suite; do not interpret these results as production or cloud-scale performance.",
        "total_validation_rows": len(rows),
        "clean_control_files": sum(r["test_case"] == "clean_control" for r in rows),
        "positive_change_scenarios": sum(r["expected_change"] == 1 for r in rows),
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "detection_rate_recall": round(detection_rate, 6),
        "precision": round(precision, 6),
        "false_positive_rate": round(fpr, 6),
        "f1_score": round(f1, 6),
        "interpretation": (
            "A missed change in a partial-hash probe is a false negative for integrity-change detection. "
            "The block/sample negative probes intentionally test regions outside the selected hash regions."
        ),
    }
    (RESULTS_DIR / "validation_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    benchmark_rows = run_benchmark()
    write_csv(RESULTS_DIR / "benchmark_by_file.csv", benchmark_rows)
    benchmark_summary = summarize_benchmarks(benchmark_rows)
    write_csv(RESULTS_DIR / "benchmark_summary.csv", benchmark_summary)

    print("\nUH-FIM validation completed.")
    print(f"Validation results: {RESULTS_DIR / 'validation_results.csv'}")
    print(f"Validation metrics: {RESULTS_DIR / 'validation_summary.json'}")
    print(f"Per-file benchmark: {RESULTS_DIR / 'benchmark_by_file.csv'}")
    print(f"Grouped benchmark: {RESULTS_DIR / 'benchmark_summary.csv'}")
    print("\nControlled-test metrics (specific to this synthetic suite):")
    print(f"  TP={tp}  FN={fn}  FP={fp}  TN={tn}")
    print(f"  Detection/recall: {detection_rate * 100:.1f}%")
    print(f"  Precision:        {precision * 100:.1f}%")
    print(f"  False-positive rate: {fpr * 100:.1f}%")
    print(f"  F1:               {f1:.3f}")
    print("\nRead the CSV and JSON outputs before making any claims in the paper.")


class _CountingReader:
    def __init__(self, wrapped, counter: list[int]):
        self._wrapped = wrapped
        self._counter = counter

    def read(self, size: int = -1):
        data = self._wrapped.read(size)
        self._counter[0] += len(data)
        return data

    def __enter__(self):
        self._wrapped.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._wrapped.__exit__(exc_type, exc, tb)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


def adaptive_bytes_read(path: Path) -> int:
    """Count bytes returned by reads inside core.hasher for this exact path."""
    counter = [0]
    real_open = builtins.open
    target = str(path.resolve())

    def tracked_open(file, mode="r", *args, **kwargs):
        try:
            same_file = str(Path(file).resolve()) == target
        except (TypeError, ValueError, OSError):
            same_file = False
        opened = real_open(file, mode, *args, **kwargs)
        if same_file and "r" in mode and "b" in mode:
            return _CountingReader(opened, counter)
        return opened

    had_local_open = "open" in hasher_module.__dict__
    old_local_open = hasher_module.__dict__.get("open")
    hasher_module.open = tracked_open
    try:
        compute_hash(str(path))
    finally:
        if had_local_open:
            hasher_module.open = old_local_open
        else:
            delattr(hasher_module, "open")
    return counter[0]


def timed_ms(fn: Callable[[], object], repeats: int = 3) -> float:
    times = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(times)


def run_benchmark() -> list[dict]:
    """Compare the actual adaptive hasher with reference full-file SHA-256."""
    benchmark_rows = []
    original_logger_state = _quiet_project_logger()
    try:
        for manifest_row in csv.DictReader(MANIFEST_CSV.open(encoding="utf-8", newline="")):
            path = CLEAN_DIR / manifest_row["relative_path"]
            info = compute_hash(str(path))
            adaptive_read = adaptive_bytes_read(path)
            full_read = path.stat().st_size  # the reference loop consumes the entire file
            adaptive_ms = timed_ms(lambda: compute_hash(str(path)))
            full_ms = timed_ms(lambda: full_sha256(path))
            bytes_saved_pct = (1.0 - adaptive_read / full_read) * 100.0 if full_read else 0.0
            benchmark_rows.append({
                "relative_path": manifest_row["relative_path"],
                "category": info["category"],
                "strategy": info["strategy"],
                "size_bytes": path.stat().st_size,
                "adaptive_bytes_read_measured": adaptive_read,
                "full_sha256_bytes_read": full_read,
                "estimated_io_reduction_pct": round(bytes_saved_pct, 3),
                "adaptive_median_time_ms_3_runs": round(adaptive_ms, 6),
                "full_sha256_median_time_ms_3_runs": round(full_ms, 6),
                "note": "Runtime is machine/cache dependent; bytes read are measured from file read() calls.",
            })
    finally:
        _restore_logger(original_logger_state)
    return benchmark_rows


def summarize_benchmarks(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, int], list[dict]] = {}
    for row in rows:
        key = (row["category"], int(row["size_bytes"]))
        groups.setdefault(key, []).append(row)
    summary = []
    for (category, size), group in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1])):
        summary.append({
            "category": category,
            "size_bytes": size,
            "file_count": len(group),
            "strategy": group[0]["strategy"],
            "mean_adaptive_bytes_read": round(statistics.mean(float(r["adaptive_bytes_read_measured"]) for r in group), 2),
            "full_sha256_bytes_read_per_file": size,
            "mean_io_reduction_pct": round(statistics.mean(float(r["estimated_io_reduction_pct"]) for r in group), 3),
            "median_adaptive_time_ms": round(statistics.median(float(r["adaptive_median_time_ms_3_runs"]) for r in group), 6),
            "median_full_sha256_time_ms": round(statistics.median(float(r["full_sha256_median_time_ms_3_runs"]) for r in group), 6),
        })
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate and evaluate a synthetic dataset with current UH-FIM code.")
    parser.add_argument("command", choices=["generate", "validate", "all"], help="generate dataset, validate, or do both")
    args = parser.parse_args()

    if args.command in ("generate", "all"):
        generate_dataset()
    if args.command in ("validate", "all"):
        run_validation()


if __name__ == "__main__":
    main()
