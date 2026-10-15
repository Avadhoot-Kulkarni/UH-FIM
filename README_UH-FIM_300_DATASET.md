# UH-FIM 300-file synthetic integrity benchmark

## Contents
- `uhfim_300_dataset/clean/`: 300 deterministic synthetic byte fixtures.
- `uhfim_300_dataset/manifest.csv` and `manifest.json`: expected category, size, seed, and full-file SHA-256 ground truth.
- `generate_uhfim_300_dataset.py`: regenerate the same 300 fixtures.
- `evaluate_uhfim_300.py`: Windows-compatible evaluation harness that exercises the real UH-FIM baseline/verifier API and writes CSV/JSON outputs.

## Distribution
The dataset has 100 files in each UH-FIM class: CRITICAL, EXECUTABLE, and DATA. Each class is distributed across 4 KiB, 64 KiB, and 256 KiB sizes. Names/extensions exercise the categorizer used by the project.

**Safety:** All file contents are synthetic opaque bytes. These are test fixtures, not real operating-system files, authentic malware samples, or usable certificates/keys. Never execute them.

## Run on Windows
1. Extract this package into the UH-FIM project root (the folder containing `uhfim.py`, `core\`, and `utils\`). Keep the `uhfim_300_dataset` folder and `evaluate_uhfim_300.py` at that root.
2. Apply the CAVE baseline patch, if not already applied, by copying `patch_uhfim_cave.py` to the same root and running:

   ```powershell
   py -3 .\patch_uhfim_cave.py
   py -3 -m py_compile .\core\baseline.py
   ```

3. Verify the dataset and evaluate:

   ```powershell
   py -3 .\evaluate_uhfim_300.py
   ```

Results are saved under `uhfim_300_dataset\results\`:
- `validation_results_300.csv`
- `validation_summary_300.json`
- `stealth_stress_results.csv`
- `stealth_stress_summary.json`

The evaluator redirects its own baseline JSON/checksum to the results folder and does not intentionally overwrite the normal `data\baseline.json`/`data\baseline.checksum`.

## How to interpret the scores
The main suite contains 300 unchanged controls and 300 normal single-byte mutation cases, plus new-file and deleted-file API checks. Mutation cases advance the file modification time to consistently test the design's metadata-triggered full-hash escalation. Scores therefore describe these controlled scenarios, not general real-world accuracy.

The separate stealth stress suite mutates bytes outside selected BLOCK/SAMPLE regions and restores the original size and modification time. The adaptive-plus-escalation design may miss those cases if neither metadata nor adaptive hash changes. Those misses are important limitations and must be disclosed separately; a periodic full scan or full hashing is needed to cover that threat model.

Do not claim that the dataset itself guarantees 95% accuracy. Detection rate, precision, false-positive rate, accuracy, and F1 are calculated from observed outcomes. Report the synthetic nature, scenario definitions, and both main and stress results in any paper.
