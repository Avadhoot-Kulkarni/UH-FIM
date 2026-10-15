#!/usr/bin/env python3
"""Evaluate UH-FIM against the included 300-file synthetic benchmark.

Run from the UH-FIM project root after extracting the dataset package there.
The evaluator uses the installed project's categorizer, hashing, and baseline
verification API. It redirects baseline files into the dataset's results/ to
avoid touching the normal project baseline.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, logging, os, shutil, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if not (ROOT / "core" / "baseline.py").is_file() or not (ROOT / "core" / "hasher.py").is_file():
    raise SystemExit("ERROR: Save this script in your UH-FIM project root, beside core/ and uhfim.py.")
sys.path.insert(0, str(ROOT))
import core.baseline as baseline_module
from core.hasher import compute_hash
from utils.categorizer import get_category

DATASET_ROOT = ROOT / "uhfim_300_dataset"
CLEAN_ROOT = DATASET_ROOT / "clean"
WORK_ROOT = DATASET_ROOT / "work"
RESULTS_ROOT = DATASET_ROOT / "results"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_manifest() -> list[dict]:
    with (DATASET_ROOT / "manifest.csv").open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def validate_manifest(rows: list[dict]) -> None:
    if len(rows) != 300:
        raise SystemExit(f"Expected 300 manifest rows; found {len(rows)}.")
    counts = {c: 0 for c in ("CRITICAL", "EXECUTABLE", "DATA")}
    for row in rows:
        path = CLEAN_ROOT / row["relative_path"]
        if not path.is_file():
            raise SystemExit(f"Dataset file missing: {path}")
        if path.stat().st_size != int(row["size_bytes"]):
            raise SystemExit(f"Size mismatch: {path}")
        got = sha256_file(path)
        if got != row["sha256"]:
            raise SystemExit(f"SHA-256 mismatch: {path}")
        actual = get_category(str(path))
        if actual != row["category_expected"]:
            raise SystemExit(f"Category mismatch for {path}: manifest={row['category_expected']}, project={actual}")
        counts[actual] += 1
    if counts != {"CRITICAL": 100, "EXECUTABLE": 100, "DATA": 100}:
        raise SystemExit(f"Unexpected category distribution: {counts}")
    print("Manifest verified: 300 files, hashes/sizes/categories match; 100 per category.")


def flip_byte(path: Path, offset: int) -> int:
    with path.open("r+b") as f:
        f.seek(offset)
        old = f.read(1)
        if not old:
            raise ValueError(f"Invalid byte offset {offset} in {path}")
        f.seek(offset)
        f.write(bytes([old[0] ^ 1]))
    return old[0]


def set_mtime(path: Path, atime_ns: int, mtime_ns: int) -> None:
    os.utime(path, ns=(atime_ns, mtime_ns))


def mutation_offset(category: str, size: int) -> tuple[int, str]:
    """Choose an unselected region where one exists; else a selected region.

    Standard edits deliberately update metadata, simulating ordinary writes.
    CAVE should escalate to a full hash when that metadata changes.
    """
    if category == "CRITICAL":
        return size // 2, "full_hash_region"
    if category == "EXECUTABLE":
        offset = 1024 if size <= 8192 else 4096
        return offset, "outside_block_regions"
    # DATA samples all bytes for 4 KiB files with the current 8x512-byte sampler.
    if size <= 4096:
        return min(1024, size - 1), "within_sampled_coverage_small_file"
    return 4096, "outside_sampled_regions"


def check_result(path: Path, root: Path, baseline: dict) -> tuple[bool, str, dict | None]:
    result = baseline_module.verify_file(str(path), str(root), baseline)
    if result is None:
        return True, "NEW_FILE", None
    if result.get("changed"):
        return True, str(result.get("event", "MODIFIED")), result
    return False, "UNCHANGED", result


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)


def confusion(rows: list[dict]) -> dict:
    tp = sum(int(r["expected_change"]) == 1 and int(r["detected"]) == 1 for r in rows)
    fn = sum(int(r["expected_change"]) == 1 and int(r["detected"]) == 0 for r in rows)
    fp = sum(int(r["expected_change"]) == 0 and int(r["detected"]) == 1 for r in rows)
    tn = sum(int(r["expected_change"]) == 0 and int(r["detected"]) == 0 for r in rows)
    total = tp + fn + fp + tn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "rows": total, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision, "recall_detection_rate": recall,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
    }


def choose_stealth_candidates(manifest_rows: list[dict]) -> list[dict]:
    # Diagnostic-only stress tests: medium/large EXECUTABLE and DATA files.
    chosen = []
    for cat in ("EXECUTABLE", "DATA"):
        candidates = [r for r in manifest_rows if r["category_expected"] == cat and r["size_band"] != "small_4KiB"]
        step = max(1, len(candidates) // 15)
        chosen.extend(candidates[::step][:15])
    return chosen[:30]


def run() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-stealth-stress", action="store_true", help="Skip the separate preserved-metadata limitation probes.")
    args = parser.parse_args()
    if not CLEAN_ROOT.is_dir():
        raise SystemExit(f"Dataset not found at {CLEAN_ROOT}. Extract the dataset package into the UH-FIM project root.")
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    manifest_rows = read_manifest()
    validate_manifest(manifest_rows)

    # Redirect only this evaluation's baseline files.
    baseline_module.BASELINE_FILE = str(RESULTS_ROOT / "evaluation_baseline.json")
    baseline_module.CHECKSUM_FILE = str(RESULTS_ROOT / "evaluation_baseline.checksum")
    logger = logging.getLogger("uhfim")
    old_level, old_disabled = logger.level, logger.disabled
    logger.setLevel(logging.CRITICAL + 1)
    logger.disabled = False
    main_rows: list[dict] = []
    stealth_rows: list[dict] = []
    try:
        if WORK_ROOT.exists():
            shutil.rmtree(WORK_ROOT)
        shutil.copytree(CLEAN_ROOT, WORK_ROOT)
        baseline_module.create_baseline(str(WORK_ROOT))
        baseline = baseline_module.load_baseline()
        if not baseline:
            raise RuntimeError("Could not load evaluation baseline; inspect the project logger and baseline checksum.")
        has_full_hash = all("full_hash" in item for item in baseline.get("files", {}).values())
        print("CAVE full-hash references:", "present" if has_full_hash else "NOT PRESENT (run patch_uhfim_cave.py first for escalation testing)")

        # 300 unchanged controls.
        for row in manifest_rows:
            rel = row["relative_path"]
            p = WORK_ROOT / rel
            detected, event, _ = check_result(p, WORK_ROOT, baseline)
            main_rows.append({
                "test_case": "clean_control", "relative_path": rel,
                "category": row["category_expected"], "size_bytes": row["size_bytes"],
                "mutation_offset": "", "probe_type": "none",
                "expected_change": 0, "detected": int(detected), "event": event,
                "ground_truth_changed": 0,
            })

        # One normal metadata-changing content edit per file; restore bytes and timestamps.
        for idx, row in enumerate(manifest_rows, start=1):
            rel = row["relative_path"]
            p = WORK_ROOT / rel
            original_stat = p.stat()
            old_full = sha256_file(p)
            offset, probe = mutation_offset(row["category_expected"], p.stat().st_size)
            old_byte = flip_byte(p, offset)
            # Explicitly advance the mtime to make the metadata-trigger contract
            # deterministic across filesystems with coarse timestamp precision.
            set_mtime(p, original_stat.st_atime_ns, original_stat.st_mtime_ns + 2_000_000_000)
            new_full = sha256_file(p)
            detected, event, result = check_result(p, WORK_ROOT, baseline)
            main_rows.append({
                "test_case": "single_byte_mutation", "relative_path": rel,
                "category": row["category_expected"], "size_bytes": row["size_bytes"],
                "mutation_offset": offset, "probe_type": probe,
                "expected_change": 1, "detected": int(detected), "event": event,
                "ground_truth_changed": int(old_full != new_full),
            })
            # Restore exact baseline content and timestamps before next test.
            with p.open("r+b") as f:
                f.seek(offset); f.write(bytes([old_byte]))
            set_mtime(p, original_stat.st_atime_ns, original_stat.st_mtime_ns)

        # New file and deleted file API cases, tested as two additional positives.
        new_path = WORK_ROOT / "data" / "added_after_baseline.txt"
        new_path.write_bytes(b"synthetic new-file detection probe\n")
        detected, event, _ = check_result(new_path, WORK_ROOT, baseline)
        main_rows.append({"test_case": "new_file", "relative_path": "data/added_after_baseline.txt", "category": "DATA", "size_bytes": new_path.stat().st_size, "mutation_offset": "", "probe_type": "new_file", "expected_change": 1, "detected": int(detected), "event": event, "ground_truth_changed": 1})
        new_path.unlink()

        deletion_rel = manifest_rows[-1]["relative_path"]
        delete_path = WORK_ROOT / deletion_rel
        delete_sha = sha256_file(delete_path)
        delete_path.unlink()
        detected, event, _ = check_result(delete_path, WORK_ROOT, baseline)
        main_rows.append({"test_case": "deleted_file", "relative_path": deletion_rel, "category": manifest_rows[-1]["category_expected"], "size_bytes": manifest_rows[-1]["size_bytes"], "mutation_offset": "", "probe_type": "deletion", "expected_change": 1, "detected": int(detected), "event": event, "ground_truth_changed": int(bool(delete_sha))})
        # Put it back so the work directory is a clean fixture after evaluation.
        shutil.copy2(CLEAN_ROOT / deletion_rel, delete_path)

        main_metrics = confusion(main_rows)
        main_summary = {
            "dataset": "UH-FIM 300-file synthetic integrity benchmark",
            "dataset_file_count": 300,
            "positive_file_mutation_cases": 300,
            "clean_control_cases": 300,
            "additional_positive_cases": 2,
            "metrics": main_metrics,
            "methodology_note": "Main cases simulate ordinary content changes whose file modification time changes. The score is specific to this controlled synthetic suite, not production accuracy. The separate stealth stress set preserves metadata and is reported independently.",
            "caveat": "The content and extension distribution are synthetic. Verify all result CSVs before reporting metrics in a paper.",
        }
        write_csv(RESULTS_ROOT / "validation_results_300.csv", main_rows)
        (RESULTS_ROOT / "validation_summary_300.json").write_text(json.dumps(main_summary, indent=2), encoding="utf-8")

        if not args.no_stealth_stress:
            # Separate stress suite: change unsampled bytes and deliberately restore mtime.
            # These tests expose a limitation when both mtime and the sampled hash remain unchanged.
            if WORK_ROOT.exists(): shutil.rmtree(WORK_ROOT)
            shutil.copytree(CLEAN_ROOT, WORK_ROOT)
            baseline_module.create_baseline(str(WORK_ROOT))
            baseline = baseline_module.load_baseline()
            for row in choose_stealth_candidates(manifest_rows):
                rel = row["relative_path"]
                p = WORK_ROOT / rel
                original_stat = p.stat()
                size = p.stat().st_size
                offset, probe = mutation_offset(row["category_expected"], size)
                if probe not in ("outside_block_regions", "outside_sampled_regions"):
                    continue
                old_full = sha256_file(p)
                old_byte = flip_byte(p, offset)
                set_mtime(p, original_stat.st_atime_ns, original_stat.st_mtime_ns)
                meta_preserved = p.stat().st_size == original_stat.st_size and p.stat().st_mtime_ns == original_stat.st_mtime_ns
                new_full = sha256_file(p)
                detected, event, result = check_result(p, WORK_ROOT, baseline)
                stealth_rows.append({
                    "test_case": "preserved_metadata_unsampled_mutation", "relative_path": rel,
                    "category": row["category_expected"], "size_bytes": size,
                    "mutation_offset": offset, "probe_type": probe,
                    "expected_change": 1, "detected": int(detected), "event": event,
                    "ground_truth_changed": int(old_full != new_full),
                    "metadata_preserved": int(meta_preserved),
                })
                with p.open("r+b") as f:
                    f.seek(offset); f.write(bytes([old_byte]))
                set_mtime(p, original_stat.st_atime_ns, original_stat.st_mtime_ns)
            stealth_metrics = confusion(stealth_rows)
            stealth_summary = {
                "stress_test_count": len(stealth_rows),
                "metrics": stealth_metrics,
                "purpose": "Diagnostic-only adversarial probes mutate bytes outside adaptive coverage while restoring size and modification time.",
                "interpretation": "Misses are an expected limitation of metadata-triggered escalation when no signal changes. A periodic full scan or always-on full hashing is needed to cover this case; do not merge this subset into the main score without labelling it.",
            }
            write_csv(RESULTS_ROOT / "stealth_stress_results.csv", stealth_rows)
            (RESULTS_ROOT / "stealth_stress_summary.json").write_text(json.dumps(stealth_summary, indent=2), encoding="utf-8")

    finally:
        logger.setLevel(old_level)
        logger.disabled = old_disabled

    print("\nMain validation completed.")
    print(json.dumps(main_summary["metrics"], indent=2))
    print("Main CSV:", RESULTS_ROOT / "validation_results_300.csv")
    print("Main summary:", RESULTS_ROOT / "validation_summary_300.json")
    if not args.no_stealth_stress:
        print("\nSeparate preserved-metadata stress set:")
        print(json.dumps(stealth_summary, indent=2))
        print("Stress CSV:", RESULTS_ROOT / "stealth_stress_results.csv")
        print("Stress summary:", RESULTS_ROOT / "stealth_stress_summary.json")

if __name__ == "__main__":
    run()
