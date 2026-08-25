# Taintlace Web Interface

A professional browser-based dashboard and control layer built on top of the **Taintlace Multi-Stage Agentic SAST Engine**. 

This interface allows you to start scans, monitor parsing and validation pipelines in real-time, view detailed vulnerabilities (with physical source-to-sink code tracing), inspect LLM cascade validations, and manage integrations like DefectDojo—all from your browser.

---

## Folder Structure

```
web/
├── backend/
│   ├── main.py                    # FastAPI application setup and static mounting
│   ├── routes/                    # API route controllers
│   ├── services/                  # CLI and engine orchestration wrappers
│   ├── schemas/                   # Pydantic validation input/output schemas
│   └── utils/                     # Path resolution and error handlers
├── frontend/
│   ├── index.html                 # Main dashboard UI
│   ├── scans.html                 # Scan scheduling UI and log listing
│   ├── scan-details.html          # Individual scan stages tracker
│   ├── finding-details.html       # Finding inspector, trace visualizer, and actions
│   ├── css/                       # Premium light mode styling
│   └── js/                        # Unified fetch client and DOM controllers
├── tests/
│   └── test_api.py                # Pytest suite with mock service tests
└── README.md                      # This documentation file
```

---

## Installation & Setup

1. **Verify Engine Requirements**: Ensure Joern (`joern` and `joern-parse`) is installed and available in your system path.
2. **Create and Set Up Virtual Environment**:
   From the project root directory, run:
   ```bash
   # Create a virtual environment
   python -m venv venv
   
   # Install dependencies from requirements.txt
   venv\Scripts\pip install -r requirements.txt
   ```
3. **Configure Environment Variables**: The backend automatically inherits configuration (like `GROQ_API_KEY`, `DEFECTDOJO_URL`, etc.) from the `.env` file located in the project root directory.

---

## Starting the Server

Launch the FastAPI server by running the following command from the **workspace root directory**:

```bash
.\venv\Scripts\python -m uvicorn web.backend.main:app --reload --port 8022
```

> [!NOTE]
> If ports `8080` and `8081` are occupied in your system, the server is configured here to default to port **`8022`** (or you can specify any custom port using the `--port` flag).

Once running, navigate to the web panel in your browser:
* **Web UI URL**: [http://localhost:8022](http://localhost:8022)
* **Interactive Swagger Documentation**: [http://localhost:8022/docs](http://localhost:8022/docs)

---

## Key Features

1. **Integrated Dashboard**: View aggregates of total findings, severity distributions, and active SLA compliance targets (overdue, approaching, on-track status).
2. **Background Pipelines**: Clicking "Start Scan" immediately schedules the smart router analysis, prepare step, query run, and LLM verification cascade asynchronously. You can view progress logs and current stages dynamically.
3. **Dataflow Trace Visualizer**: Browse expandable step-by-step intermediate node details from source method parameters down to sensitive code sinks with syntax preview.
4. **Remediation SLAs**: Priority policies (`P1` to `P4`) and escalation deadlines are calculated on-the-fly from original yaml rules.
5. **DefectDojo Integration**: Push approved vulnerabilities directly to engagement queues. Credentials remain securely stored inside the host's keyring.

---

## Verification and Testing

To run the REST API test suite:

```bash
.\venv\Scripts\pytest web/tests/test_api.py
```

---

## Troubleshooting

* **Backend Offline / API Failures**: Verify that the FastAPI uvicorn daemon is running on the expected port. Make sure `.env` contains the required keys.
* **Smart Router Falling Back to Full Scan**: Verify that `git` is installed and available in the system PATH.
* **DefectDojo push fails**: Ensure credentials are set correctly by running the secure interactive setup CLI:
  ```bash
  python cli.py configure-defectdojo
  ```
