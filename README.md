# UH-FIM: Unified Hash-Based File Integrity Monitor

**Research Project — Review 2 Implementation**
Adaptive Multi-Granularity Hashing + Contextual Risk Scoring

---

## Folder Structure

```
uhfim/
│
├── uhfim.py                  ← MAIN ENTRY POINT (run this)
│
├── core/
│   ├── hasher.py             ← Adaptive hashing engine (FULL / BLOCK / SAMPLE)
│   ├── baseline.py           ← Baseline creation, loading, tamper detection
│   ├── monitor.py            ← Live watchdog monitor + one-shot scan
│   └── risk.py               ← Risk scoring formula
│
├── utils/
│   ├── categorizer.py        ← Maps file type → category → strategy
│   └── logger.py             ← Dual output: terminal + log file
│
├── data/
│   ├── baseline.json         ← Auto-generated: hash snapshot of monitored files
│   └── baseline.checksum     ← Auto-generated: tamper-detect checksum of baseline
│
├── logs/
│   └── uhfim.log             ← Auto-generated: full execution log
│
├── demo_files/               ← The folder being MONITORED (your test target)
│   ├── system/               ← CRITICAL files (passwd, kernel_config)
│   ├── executables/          ← EXECUTABLE files (app.py, deploy.sh)
│   ├── data_files/           ← DATA files (config.json, readme.txt)
│   └── logs/                 ← DATA files (app.log)
│
└── requirements.txt
```

---

## Setup

```bash
# 1. Install dependencies
pip install watchdog

# 2. Navigate to project folder
cd uhfim/
```

---

## Usage

### Step 1 — Run the full demo (easiest way)
```bash
python uhfim.py demo
```
This creates demo_files/, baselines them, and shows you exactly what to modify.

---

### Step 2 — Or manually: Create a baseline first
```bash
python uhfim.py baseline demo_files/
```
This scans every file, assigns it a category, computes the appropriate hash,
and saves everything to data/baseline.json.

---

### Step 3a — One-shot scan (check all files once)
```bash
python uhfim.py scan demo_files/
```
Walks all files, compares hashes, prints risk-scored alerts.

### Step 3b — Live monitor (real-time watchdog)
```bash
python uhfim.py monitor demo_files/
```
Watches for changes in real-time. Every file save triggers immediate verification.

---

## Demo Script (for your presentation)

**Terminal 1 — Start monitoring:**
```bash
python uhfim.py baseline demo_files/
python uhfim.py monitor demo_files/
```

**Terminal 2 — Simulate attacks:**
```bash
# Simulate attacker adding a backdoor user (CRITICAL file)
echo "attacker:x:0:0:hacker:/root:/bin/bash" >> demo_files/system/passwd

# Simulate malware injected into script (EXECUTABLE file)
echo "import os; os.system('rm -rf /')" >> demo_files/executables/app.py

# Simulate normal log rotation (DATA file — low risk)
echo "[INFO] Health check OK" >> demo_files/logs/app.log
```

**What you'll see:**
- `passwd` → CRITICAL/MEDIUM alert (sensitivity=1.0, full hash detected 1-byte change)
- `app.py`  → LOW/HIGH alert (sensitivity=0.7, block hash caught tail injection)
- `app.log` → INFO alert (sensitivity=0.3, normal log growth = low priority)

**The contrast between these three alerts = your research contribution.**

---

## How It Differs From Existing Tools (for your teacher)

| Feature | Tripwire / AIDE | UH-FIM (this project) |
|---|---|---|
| Hashing | Uniform SHA-256 on ALL files | Adaptive: FULL / BLOCK / SAMPLE |
| Performance | O(n) for every file | O(1) for executables, O(k) for data |
| Alert priority | All alerts equal | Risk-scored 0–100 |
| Context | None | Time anomaly + frequency tracking |
| False positives | High (log rotations = alerts) | Reduced by risk scoring |

---

## Risk Score Formula

```
Risk Score (0–100) = α × Sensitivity + β × TimeAnomaly + γ × Frequency

Where:
  α = 0.50  (file sensitivity: CRITICAL=1.0, EXEC=0.7, DATA=0.3)
  β = 0.30  (time: 10PM–6AM = 0.8, daytime = 0.1)
  γ = 0.20  (frequency: 5+ changes in 5 min = 1.0)
```

Alert thresholds: CRITICAL ≥ 80 · HIGH ≥ 60 · MEDIUM ≥ 40 · LOW ≥ 20 · INFO < 20

---

## Log File

All activity is written to `logs/uhfim.log`. This includes:
- Every file scanned with its category, strategy, and hash
- Every risk score computed with full formula breakdown
- Every alert raised with old/new hashes and size delta
- Baseline creation and integrity verification events
- Session start/stop markers


# Step 1 — show teacher the baseline being created
python uhfim.py demo

# Step 2 — modify files LIVE
echo "attacker:x:0:0:hacker:/root:/bin/bash" >> demo_files/system/passwd
echo "import os; os.system('rm -rf /')" >> demo_files/executables/app.py
echo "[INFO] health check" >> demo_files/logs/app.log

# Step 3 — scan and show risk scores
python uhfim.py scan demo_files/

# Step 4 — optionally show the log file
cat logs/uhfim.log
