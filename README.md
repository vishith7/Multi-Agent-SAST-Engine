# CTS SAST Engine

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Phase Status](https://img.shields.io/badge/Phase%201%20%26%202-COMPLETE-green.svg)](#current-implementation-status)

An enterprise-grade **Multi-Stage Agentic Static Application Security Testing (SAST)** Engine.

> 📖 **Detailed Implementation Summary**: See [`IMPLEMENTATION_SUMMARY.md`](file:///c:/Multi-Stage%20Agentic%20SAST%20Engine/IMPLEMENTATION_SUMMARY.md) for a comprehensive architectural and component breakdown of implemented modules.

---

## Current Implementation Status

```
========================================================================
CURRENT STATUS: PHASE 0, PHASE 1 (PREPARE), AND PHASE 2 (SCAN) COMPLETE
Stages 3 (Validate) & 4 (Prove) are next in the implementation roadmap.
========================================================================
```

- [x] **Phase 0: Pre-Implementation Preparation (COMPLETE)** — Orchestrator CLI, diagnostics engine, Docker infrastructure, configuration schemas.
- [x] **Phase 1: Prepare Stage (COMPLETE)** — Language & framework analysis, dependency fingerprinting, security scope filtering, Joern CPG generation, and caching engine.
- [x] **Phase 2: Scan Stage (COMPLETE)** — YAML rule parsing & validation, CPGQL query transpilation, async Joern client, graph taint reachability analyzer.
- [ ] **Phase 3: Validate (Planned)** — Multi-agent LLM reasoning (LangGraph + OpenRouter) for false positive elimination.
- [ ] **Phase 4: Prove (Planned)** — Exploitability PoC synthesis, regression tests, and remediation.

---

## 1. Project Overview

CTS SAST Engine is architected to solve the primary challenges of traditional SAST tools: high false-positive rates and lack of contextual exploitability understanding. By marrying deterministic graph-based code analysis (via Joern and CPGQL) with multi-stage agentic LLM reasoning (via LangGraph and OpenRouter), CTS SAST Engine validates candidate taint paths with deep contextual awareness before producing actionable findings, proof-of-concept tests, and fixes.

---

## 2. Architecture

The engine operates on a four-stage pipeline:

```
+------------------+
| Target Codebase  |
+------------------+
         |
         v
+------------------+
|  Stage 1: PREPARE|  --> Code normalization, dependency fingerprinting, CPG generation
+------------------+
         |
         v
+------------------+
|  Stage 2: SCAN   |  --> CPGQL rule queries, AST/CFG traversal, candidate taint flows
+------------------+
         |
         v
+------------------+
| Stage 3: VALIDATE|  --> LangGraph multi-agent LLM reasoning & sanitizer verification
+------------------+
         |
         v
+------------------+
|  Stage 4: PROVE  |  --> PoC payload synthesis, regression tests, remediation patches
+------------------+
```

For complete architectural details, see [docs/architecture.md](docs/architecture.md).

---

## 3. Technology Stack

- **Core Runtime**: Python 3.11+ (Python 3.14 compatible)
- **Static Analysis & CPG**: Joern 2.0+ and CPGQL (`cpgqls-client`)
- **Agentic Workflow**: LangGraph
- **LLM Reasoning**: OpenAI SDK / OpenRouter API
- **Vector Embeddings**: ChromaDB
- **API Framework**: FastAPI, Uvicorn, Pydantic v2
- **Container Infrastructure**: Docker & Docker Compose

---

### Quick Start (Windows One-Click Startup)
Simply execute `start_local.bat` in Command Prompt or PowerShell to set up environment, start services, and open the web dashboard:
```powershell
.\start_local.bat
```

### Step 1: Manual Clone and Create Virtual Environment
```powershell
# In PowerShell:
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

```bash
# In Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate
```

### Step 2: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Populate `.env` with your API keys and configuration:
- `OPENROUTER_API_KEY`: API key for OpenRouter models.
- `JOERN_ENDPOINT`: Joern server URL (default `http://localhost:8080`).
- `CHROMA_HOST` / `CHROMA_PORT`: ChromaDB vector store coordinates.

---

## 5. Joern Verification

Joern can be run either containerized (recommended) or natively on host.

### Containerized Joern (Docker)
```bash
docker compose up -d joern
```

### Local Joern CLI
Download and install Joern from [https://docs.joern.io/installation/](https://docs.joern.io/installation/):
```bash
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" -o joern-install.sh
chmod +x ./joern-install.sh
./joern-install.sh --interactive
```

---

## 6. Diagnostic & Health Verification

Run the Phase 0 diagnostic tool:
```bash
python -m diagnostics
```
Or via the orchestrator:
```bash
python orchestrator.py --check-health
```

The diagnostic command verifies Python version, package imports, Joern accessibility, Docker tooling, and repository structure.

---

## 7. Pipeline Execution (Phase 1 & Phase 2)

Execute repository preparation, CPG generation, and fingerprinting (Phase 1):
```powershell
python orchestrator.py --target-repo ./test_repos/sample_py --prepare
```

---

## 8. Running Tests
Run all unit and integration tests using `pytest`:
```bash
python -m pytest -v
```

---

## 8. Docker Compose Foundation

Start the complete infrastructure foundation:
```bash
docker compose up -d
```

View service logs:
```bash
docker compose logs -f
```

Stop services:
```bash
docker compose down
```

---

## 9. Security Notes

- **Never Commit Secrets**: Keep `.env` out of version control (enforced via `.gitignore`).
- **Untrusted Repositories**: Target repositories are treated as untrusted data; never execute repository code directly.
- **Least Privilege**: Docker containers run as non-root system users (`sastuser`).
- **No Direct LLM Execution of Arbitrary Code**: Agentic validation operates purely via static prompt analysis.

---

## 10. Troubleshooting

- **`ImportError: No module named ...`**: Ensure the `.venv` is activated and `pip install -r requirements.txt` was executed.
- **Joern Connection Failed**: Ensure Docker container is running (`docker compose up -d joern`) or check `JOERN_ENDPOINT` in `.env`.
- **Docker Compose Errors**: Confirm Docker Desktop is running and compose version is v2+.

For detailed guide and API reference, see:
- [docs/user_guide.md](docs/user_guide.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/api_reference.md](docs/api_reference.md)
