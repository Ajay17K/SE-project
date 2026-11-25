# FinReq AI — Agentic AI Requirement Engineering & SDLC Platform

**FinReq AI** is an autonomous, human-governed multi-agent LLM system designed for automated requirement gathering, quality verification, regulatory compliance mapping, risk analysis, artifact generation, and SDLC selection in **Payment Processing & Fraud Detection** under **Indian financial regulations** (RBI, NPCI/UPI, DPDP Act 2023, PMLA/FIU-IND, CERT-In, PCI-DSS v4.0).

## Key Capabilities

- **13-Agent Orchestrated Pipeline:** `CoordinatorAgent`, `StakeholderInteractionAgent`, `RequirementExtractionAgent`, `ClarificationAgent`, `ClassificationAgent`, `ConflictDetectionAgent`, `ComplianceAgent`, `SecurityPrivacyAgent`, `RiskAnalysisAgent`, `SDLCSelectionAgent`, `DocumentationAgent`, `ValidationAgent`, and `HumanApprovalAgent`.
- **Pluggable LLM Adapter:** Supports **Google Gemini**, **OpenAI**, **Local Ollama**, and a **Deterministic Grounded Fallback** mode (runs out-of-the-box offline with zero API key).
- **Pre-LLM Security & Privacy Gateway:** Automatic PII/PCI entity detection & masking (Aadhaar, Indian PAN, Luhn Card PAN, CVV/PIN, UPI VPA, IFSC, phone, secrets), prompt-injection protection, RBAC across 9 stakeholder roles, MFA checks, agent least-privilege enforcement, and SHA-256 hash-chained audit logs.
- **Version-Controlled Allowlisted KB & Hybrid RAG:** BM25 + TF-IDF cosine retriever over 18+ Indian payment/fraud/regulatory documents (unapproved items strictly blocked), citation verification, and automatic low-confidence human escalation.
- **Hybrid SDLC Engine:** Derives 13 SDLC decision factors, ranks 7 methodologies via deterministic rules + weighted MCDA + LLM justification, and builds a customized 5-phase financial SDLC workflow.
- **11 Exportable Traceable Artifacts:** SRS, User Stories (Gherkin), Use Cases, Process Workflows, Data Requirements, Interface Requirements, Threat & Risk Register, Compliance Matrix, Requirements Traceability Matrix (RTM), Assumptions & Dependencies, and Open-Issues List.
- **Automated Evaluation Suite:** Benchmarks Precision, Recall, F1, Completeness, Ambiguity/Conflict Detection, Regulatory Control Coverage, Hallucination Rate, Citation Correctness, SDLC Accuracy, and Time Saved vs. Manual RE.

## Running Locally

### 1. Run Tests & Evaluation
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

### 2. Start Backend & Production UI (Single Port `8000`)
```powershell
cd frontend
npm run build
cd ..
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000` in your browser.

### 3. Development Mode (Hot Reload)
Terminal 1 (Backend):
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --port 8000
```
Terminal 2 (Frontend):
```powershell
cd frontend
npm run dev
```
Open `http://localhost:5173`.

## Architecture Documentation
See [ARCHITECTURE.md](docs/ARCHITECTURE.md).
