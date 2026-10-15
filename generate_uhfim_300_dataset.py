#!/usr/bin/env python3
"""Generate a reproducible 300-file synthetic UH-FIM evaluation dataset.

The content is synthetic byte-level fixture data, not genuine system files or
runnable binaries. File names/extensions exercise the project's categorizer.
"""
from __future__ import annotations
import csv, hashlib, json, random
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATASET_ROOT = ROOT / "uhfim_300_dataset"
CLEAN_ROOT = DATASET_ROOT / "clean"
SEED = 20261015
SIZE_BANDS = [("small_4KiB", 4 * 1024), ("medium_64KiB", 64 * 1024), ("large_256KiB", 256 * 1024)]
CATEGORY_EXTENSIONS = {
    "CRITICAL": [".sys", ".ko", ".img", ".iso", ".pem", ".key", ".crt", ".cer"],
    "EXECUTABLE": [".exe", ".dll", ".so", ".dylib", ".py", ".sh", ".bash", ".rb", ".js", ".ts", ".php", ".pl", ".lua", ".jar", ".class", ".o", ".a"],
    "DATA": [".log", ".txt", ".out", ".err", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".csv", ".tsv", ".html", ".htm", ".md", ".sql", ".db", ".sqlite"],
}

def deterministic_bytes(rng: random.Random, size: int) -> bytes:
    # random.Random.randbytes is available on modern Python; this fallback keeps
    # the generator usable on older Windows Python installs as well.
    if hasattr(rng, "randbytes"):
        return rng.randbytes(size)
    return bytes(rng.getrandbits(8) for _ in range(size))

def main() -> None:
    if CLEAN_ROOT.exists():
        import shutil
        shutil.rmtree(CLEAN_ROOT)
    CLEAN_ROOT.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    rows = []
    for category in ("CRITICAL", "EXECUTABLE", "DATA"):
        folder = {"CRITICAL": "critical", "EXECUTABLE": "executables", "DATA": "data"}[category]
        # 100 files/category, balanced across three file sizes (33/34/33).
        for idx in range(100):
            band, size = SIZE_BANDS[idx % 3]
            ext = CATEGORY_EXTENSIONS[category][idx % len(CATEGORY_EXTENSIONS[category])]
            rel = f"{folder}/{category.lower()}_{idx+1:03d}{ext}"
            path = CLEAN_ROOT / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = deterministic_bytes(rng, size)
            path.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            rows.append({
                "relative_path": rel.replace("\\", "/"),
                "category_expected": category,
                "size_band": band,
                "size_bytes": size,
                "sha256": digest,
                "seed": SEED,
                "fixture_type": "synthetic_byte_fixture_not_for_execution",
            })
    rows.sort(key=lambda x: x["relative_path"])
    with (DATASET_ROOT / "manifest.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader(); writer.writerows(rows)
    meta = {
        "dataset_name": "UH-FIM 300-file synthetic integrity benchmark",
        "seed": SEED,
        "file_count": len(rows),
        "category_counts": {c: sum(r["category_expected"] == c for r in rows) for c in CATEGORY_EXTENSIONS},
        "size_bands": {name: size for name, size in SIZE_BANDS},
        "size_distribution_per_category": {"small_4KiB": 34, "medium_64KiB": 33, "large_256KiB": 33},
        "sha256_definition": "SHA-256 of every complete file at generation time; this is the ground-truth manifest.",
        "limitations": [
            "Synthetic content, not a representative sample of real operating-system files or malware.",
            "Extensions are selected to exercise UH-FIM categorization; contents are intentionally opaque bytes.",
            "No dataset can guarantee a target score. Results measure the specified evaluation scenarios only.",
        ],
        "files": rows,
    }
    (DATASET_ROOT / "manifest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Created {len(rows)} files at: {CLEAN_ROOT}")
    print(f"Manifest: {DATASET_ROOT / 'manifest.csv'}")
    print("Counts: CRITICAL=100, EXECUTABLE=100, DATA=100")

if __name__ == "__main__":
    main()
