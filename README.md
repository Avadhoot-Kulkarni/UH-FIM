# UH-FIM — Unified Hash-Based File Integrity Monitor

UH-FIM is a file integrity monitoring system that combines adaptive file hashing with context-aware risk scoring. It is designed to detect changes to monitored files, classify their potential significance, and prioritize alerts based on file sensitivity and observed activity.

The project explores whether different hashing strategies can be applied to different file categories while maintaining useful integrity checks and reducing unnecessary work on frequently changing data.

## Features

- **Adaptive hashing:** Supports full-file, block-based, and sampled hashing strategies.
- **File classification:** Categorizes monitored files as critical, executable, or data files.
- **Integrity verification:** Creates a baseline of file metadata and hashes, then compares subsequent scans against it.
- **Risk-based alerts:** Assigns risk scores using file sensitivity, time-based anomalies, and change frequency.
- **Live monitoring:** Detects file-system events through Watchdog.
- **Logging:** Records monitoring activity, integrity checks, and alerts for later inspection.
- **Benchmark evaluation:** Includes a synthetic 300-file dataset, manifests, evaluation scripts, and validation results.

## How It Works

UH-FIM follows a baseline-and-monitoring workflow:

1. **Classification** — Each file is assigned a category based on its type and configured rules.
2. **Hashing** — The system selects a hashing strategy according to the file category and implementation settings.
3. **Baseline creation** — File hashes and associated metadata are stored as a reference snapshot.
4. **Integrity checking** — A scan or file-system event triggers verification against the baseline.
5. **Risk assessment** — Detected changes are evaluated using the configured risk-scoring model.
6. **Alerting and logging** — The system reports changes and records relevant events.

## Hashing Strategies

UH-FIM implements three hashing approaches:

| Strategy | Description |
|---|---|
| FULL | Hashes the entire file. |
| BLOCK | Hashes selected blocks of a file. |
| SAMPLE | Hashes selected portions of a file. |

The intended trade-off is between the cost of hashing and the ability to detect content changes. Partial hashing can reduce the amount of data read, but it may miss modifications outside the sampled or selected regions. Full-file hashing provides broader content coverage at a higher I/O cost.

The strategy assigned to a file depends on the project's categorization and hashing logic.

## Risk Scoring

UH-FIM combines file sensitivity, time-based anomalies, and change frequency into a configurable risk score.

The model uses the following weighted components:

| Component | Weight | Purpose |
|---|---:|---|
| File sensitivity | 0.50 | Reflects the importance of the affected file category. |
| Time anomaly | 0.30 | Represents whether a change occurs during an unusual time window. |
| Change frequency | 0.20 | Represents repeated changes within a defined interval. |

The score is calculated as:

\[
R = 100 \times (0.50S + 0.30T + 0.20F)
\]

where \(S\), \(T\), and \(F\) are normalized values between 0 and 1 for sensitivity, time anomaly, and change frequency, respectively.

The implementation defines alert thresholds for different severity levels. These weights and thresholds are configurable design choices, not universal measures of security risk.

## Requirements

- Python 3
- Watchdog

Install the dependency from the project directory:

```bash
python -m pip install watchdog
```

## Usage

Run commands from the repository root, where `uhfim.py` is located.

### Run the demo

```bash
python uhfim.py demo
```

The demo exercises the monitoring workflow using the project's sample files.

### Create a baseline

```bash
python uhfim.py baseline demo_files/
```

This records the initial state of the monitored files.

### Scan for changes

```bash
python uhfim.py scan demo_files/
```

A one-shot scan compares the current files against the stored baseline and reports detected changes.

### Monitor files continuously

```bash
python uhfim.py monitor demo_files/
```

The live monitor uses file-system events to initiate checks when monitored files change.

### Review logs

```bash
cat logs/uhfim.log
```

The log is generated at runtime and is excluded from version control.

## Demonstration

For a controlled test, create a baseline first:

```bash
python uhfim.py baseline demo_files/
```

In another terminal, modify a sample file:

```bash
echo "# integrity test" >> demo_files/data_files/readme.txt
```

Then run a scan:

```bash
python uhfim.py scan demo_files/
```

The result depends on the configured hashing strategy, baseline state, and implementation behavior. Restore or regenerate the sample baseline before repeating the experiment.

**Safety note:** The files under `demo_files/` are test inputs. Use the sample directory for experiments rather than pointing the monitor at sensitive system files.

## Benchmark Dataset

The repository includes a synthetic benchmark containing 300 files across three categories:

- `critical` — 100 files
- `data` — 100 files
- `executables` — 100 files

The dataset includes SHA-256 manifests and supporting evaluation scripts. Validation outputs and a separate stealth-stress test are available under `uhfim_300_dataset/results/`.

The benchmark is intended to make the evaluation repeatable. Its results should be interpreted in the context of the generated files and test conditions; they do not establish detection performance for every real-world workload.

See [README_UH-FIM_300_DATASET.md](README_UH-FIM_300_DATASET.md) for dataset details and [README_VALIDATION.md](README_VALIDATION.md) for additional validation information.

## Repository Structure

```text
UH-FIM/
├── core/
│   ├── baseline.py
│   ├── hasher.py
│   ├── monitor.py
│   └── risk.py
├── data/                         # Runtime baseline state
├── demo_files/                   # Sample monitoring targets
├── utils/
│   ├── categorizer.py
│   └── logger.py
├── uhfim_300_dataset/
│   ├── clean/
│   ├── manifest.csv
│   ├── manifest.json
│   └── results/
├── uhfim.py
├── uhfim_dataset_eval.py
├── evaluate_uhfim_300.py
├── generate_uhfim_300_dataset.py
├── README_UH-FIM_300_DATASET.md
└── README_VALIDATION.md
```

Runtime baseline files and logs are generated locally and are not included in the repository.

## Scope and Limitations

UH-FIM is a research implementation intended to explore adaptive hashing and risk-based prioritization. Partial hashing cannot guarantee detection of arbitrary changes to unexamined file regions. Results from synthetic benchmarks should not be treated as proof of complete detection coverage or as a substitute for testing against representative workloads.

The effectiveness of the system depends on its hashing strategy, file categorization, baseline integrity, monitoring configuration, and the environment in which it runs.
