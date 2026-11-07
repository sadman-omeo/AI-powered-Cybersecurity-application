
# Local AI Security Log Analyzer

A Python-based web application that detects potential cybersecurity threats in server logs using a **locally running AI model**.

### Features
- Local AI inference using Qwen3.5 0.8B and llama.cpp
- Token-aware log splitting (2,048-token context)
- Cross-chunk attack detection and correlation
- SQL injection, brute-force, scanning, and request-rate detection
- JSON validation and error handling
- Web dashboard with upload, progress tracking, and downloadable reports
- Offline operation after initial setup

## Quick Start (Windows)

**Requirements:** Python 3.11+, Git, and llama.cpp.

### 1. Set up Python

Open PowerShell in the project directory:

    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt

### 2. Install llama.cpp

    winget install -e --id ggml.llamacpp

Restart the terminal after installation. Alternatively, download it from the [official releases](https://github.com/ggml-org/llama.cpp/releases).

### 3. Download the AI model

    New-Item -ItemType Directory -Force models
    hf download gguf/Qwen3.5-0.8B-GGUF qwen3.5-0.8b-Q4_K_M.gguf --local-dir models

### 4. Start the local AI server

In Terminal 1:

    llama-server -m "models/qwen3.5-0.8b-Q4_K_M.gguf" -c 2048 -t 2 -np 1 -ngl 0 --reasoning-budget 0 --host 127.0.0.1 --port 8080

Keep this terminal running.

### 5. Start the web application

In Terminal 2:

    python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000

Open **http://127.0.0.1:8000**.

### 6. Analyze Logs

1. Upload a `.log` or `.txt` file (maximum 10 MB).
2. Click **Start Security Analysis**.
3. Monitor processing progress.
4. View detected threats, severity, evidence, and suggested actions.
5. Download the JSON report.

## Architecture

**Frontend:** HTML, CSS, JavaScript  
**Backend:** Python, FastAPI  
**AI:** Qwen3.5 0.8B (GGUF Q4_K_M)  
**Inference:** llama.cpp (CPU-only)  
**Storage:** JSON and JSONL

Processing pipeline:

Upload → Log Parsing → Token-Based Chunking → Local AI → Cross-Chunk Correlation → Consolidated Report

## Testing

Run from the project root while the local model server is active:

    python -m scripts.test_chunking
    python -m scripts.test_ai_once

Analyze a file directly:

    python -m scripts.run_analysis "data\sample.log"

Generated reports are saved to `data/results/`.

## Example Results

A local analysis of a 258-entry sample log produced:

- **15** consolidated security findings
- **13** findings supported by local AI
- **0** model-call errors
- **Complete** processing status

These results reflect application output, not independently verified attack classifications.

## Limitations

- Small models may produce inaccurate security findings.
- Total memory usage has not been independently verified under a 4 GB limit.
- Automatic restart recovery is not fully implemented.
- Very large individual log records may exceed the token budget.
- The application is designed for local use rather than public deployment.

**All AI inference runs locally. No cloud AI API is required.**
