# SutraTrace — Evidence Graph & Provenance Ledger
### AI-Powered Digital Forensics Investigation Framework

> **One-Line Pitch:** *“SutraTrace turns scattered digital artifacts into a traceable incident story—without losing the chain of custody.”*

---

## 1. Executive Overview & Problem Statement

Digital investigations are notoriously fragmented: traces exist across endpoint operating-system logs, browser history, egress firewalls, cloud audit trails, and file manifests. Forensic examiners face a critical tension: **forensic admissibility demands absolute reproducibility, cryptographic integrity, and strict provenance**, whereas **probabilistic AI/LLMs risk hallucinations, false certainty, and susceptibility to evidence prompt-injection**.

**SutraTrace resolves this tension by building an evidence-first investigation workbench, not an “AI judge.”**
- **Deterministic Core:** Cryptographic SHA-256 hashing, immutable read-only original vault, hash-chained append-only audit ledger (`SHA256(prev_hash || canonical_json)`), timezone/clock-skew normalization, source row locators, and MITRE ATT&CK triage rules.
- **Explainable AI Assistant:** Retrieval-grounded reasoning where **every single assertion links back to concrete artifact and event IDs**, with strict server-side citation validation, prompt-injection defense, and explicit segregation of **Facts**, **Inferences**, **Counter-Evidence**, and **Unresolved Assumptions**.

---

## 2. Key Capabilities & Architecture

```
                       ┌────────────────────────────────────────┐
                       │     Investigator Forensic UI           │
                       │ (Overview, Vault, Timeline, Graph, AI) │
                       └──────────────────┬─────────────────────┘
                                          │ REST API
                                          ▼
                       ┌────────────────────────────────────────┐
                       │       SutraTrace FastAPI Core          │
                       └─────┬────────────┬─────────────┬───────┘
                             │            │             │
              ┌──────────────┴───┐        │       ┌─────┴───────────────┐
              ▼                  ▼        ▼       ▼                     ▼
     ┌─────────────────┐ ┌───────────────┐ ┌────────────────┐ ┌──────────────────┐
     │ Immutable Vault │ │ Cryptographic │ │ Multi-Source   │ │ Grounded RAG     │
     │  & SHA-256      │ │ Hash-Chain    │ │ Normalization  │ │ AI Assistant     │
     │  Verification   │ │ Audit Ledger  │ │ & Graph Engine │ │ (No False IDs)   │
     └─────────────────┘ └───────────────┘ └────────────────┘ └──────────────────┘
```

1. **Evidence Vault & Real-Time Integrity Verification:**
   - Immediately calculates SHA-256 upon file receipt.
   - Preserves pristine read-only originals in `evidence_vault/originals/` and generates isolated working copies in `evidence_vault/working_copies/` for parsers.
   - Built-in **Simulate Tamper Test** flips 1 byte in a working copy to demonstrate immediate cryptographic mismatch detection (`TAMPER DETECTED`) and allows 1-click restoration from original.

2. **Cryptographic Audit Ledger (Hash-Chain):**
   - Implements block-chained event provenance: `event_hash = SHA256(previous_event_hash || canonical_json)`.
   - Live audit verification audits every action (ingestion, parsing, verification, triage, findings review) from Genesis (`0000...`) to current head.

3. **Multi-Source Parsers & Precise Locators:**
   - Dedicated parsers for Authentication (CSV/JSON), Sysmon & Endpoint processes, Chrome/Browser history, Egress Firewall/Proxy logs, Filesystem catalogs, and Cloud audit logs.
   - Every event preserves `source_locator: {file, row}` and original timestamp strings alongside normalized UTC.

4. **Interactive Evidence & Entity Correlation Graph:**
   - Powered by Cytoscape.js.
   - Visualizes relations across Users, Hosts, Hashes, Domains, and Network IPs with explicit match strengths (`strong_technical`, `moderate`, `weak_contextual`).

5. **Deterministic Triage Rules & MITRE ATT&CK Mapping:**
   - Evaluates multi-source anomaly sequences:
     - `T1078.002` (Valid Accounts - External IP Auth)
     - `T1560.001` (Archive Collected Data - 7z Compression)
     - `T1567.002` (Exfiltration Over Web Service - Browser visit + Proxy egress transfer)
     - `T1036` (Masquerading / Exact Hash Match across systems)
     - `T1530` (Cloud Storage Blueprint Download Preceding Staging)

6. **Legal Compliance Statement (Section 63, BSA 2023 & ISO/IEC 27037):**
   - Automatically generates certified legal reports formatted under Section 63 of India's **Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023)** and SWGDE evidence guidelines.
   - Exportable to Markdown, HTML, and browser Print-to-PDF.

---

## 3. Quick Start Guide

### Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Web Browser (Chrome, Edge, Firefox, Brave)

### Installation
All dependencies (`fastapi`, `uvicorn`, `python-multipart`, `pytest`, `httpx`, `python-dateutil`) can be installed via:
```bash
python -m pip install fastapi uvicorn python-multipart pytest httpx python-dateutil
```

### Launch the Application
Navigate to the project directory and run:
```bash
python run.py
```
Then open your browser at:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 4. Four-Minute Hackathon Demo Script

1. **Context (0:00 - 0:20):**
   - *"A defense contractor suspects that aerospace blueprints were leaked after hours. The traces are scattered across 6 separate log and file exports."*
2. **Command Center & Preloaded Orion Case (0:20 - 0:50):**
   - Open **Command Center**. Point out the pre-loaded **Project Orion** incident.
   - Show 6 evidence items, 18 correlated events, 5 triage findings, and the green **100% Cryptographically Verified** banner.
3. **Live Tamper Demonstration (0:50 - 1:30):**
   - Go to **Evidence Vault**. Click **"Tamper Test"** on `01_auth_logs.csv`.
   - Watch the status banner turn RED: `⚠️ TAMPER DETECTED: Working Copy Hash Mismatch!`
   - Show how SutraTrace pinpoints the altered working copy while the preserved original remains untouched. Click **"Restore"** to re-clone the clean original and verify it returns to green.
4. **Normalized Multi-Lane Timeline (1:30 - 2:10):**
   - Open **Normalized Timeline**. Filter by source lanes (Cloud -> Auth -> Endpoint -> Browser -> Proxy).
   - Show the chronological sequence: S3 blueprint download (23:38 IST) -> External VPN login (23:45 IST) -> 7z archive creation (23:51 IST) -> Browser drop-share visit (23:55 IST) -> 48.2 MB proxy upload (23:57 IST).
5. **Interactive Correlation Graph (2:10 - 2:40):**
   - Open **Correlation Graph**. Click the `Project-Orion.zip` node and inspect its `same_hash_as` edge linking the endpoint process to the secondary directory audit via `strong_technical` SHA-256 match.
6. **Grounded AI Forensic Assistant (2:40 - 3:20):**
   - Open **AI Assistant & Triage**. Click the prompt: *"Which artifacts support the theory that the file left the workstation?"*
   - Show how the AI provides:
     - Cited observed facts (`[EVT-xxx]`) with 100% server-validated links.
     - Forensic interpretation.
     - **Counter-evidence & limitations** (e.g., HTTPS encryption prevents verifying raw payload bytes from proxy log alone; account-to-human physical attribution unresolved).
7. **Legal Report & Cryptographic Audit Ledger (3:20 - 4:00):**
   - Switch to **Legal Report & Audit**.
   - Show the certified legal report with **Section 63 BSA 2023** certificate and the tamper-evident **Cryptographic Hash-Chain Ledger**.
   - Click **"Verify Audit Hash Chain"** to demonstrate real-time mathematical validation of the entire case history from genesis to head.

---

## 5. Automated Test Suite

Run the full pytest suite verifying hashing, tamper detection, timestamp normalization, citation validation, prompt-injection defense, and REST APIs:
```bash
python -m pytest tests/test_sutratrace.py -v
```
*(All 11 tests pass in ~1.4 seconds with 100% success rate!)*

---

## 6. Project File Structure

```
sutratrace/
├── run.py                          # Application entry point & Uvicorn launcher
├── README.md                       # Comprehensive framework documentation
├── sutratrace.db                   # SQLite relational database
├── sutratrace/
│   ├── app.py                      # FastAPI server & REST API routes
│   ├── models.py                   # Pydantic data schemas
│   ├── database.py                 # SQLite persistence layer & queries
│   ├── evidence_store.py           # Vault, SHA-256 hashing & tamper simulator
│   ├── audit_ledger.py             # Cryptographic hash-chain audit ledger
│   ├── correlation_engine.py       # Entity normalization & Cytoscape graph
│   ├── triage_rules.py             # Deterministic rules & MITRE ATT&CK mapping
│   ├── ai_assistant.py             # Grounded RAG assistant & citation validator
│   ├── reporting.py                # BSA 2023 / ISO 27037 legal report generator
│   ├── synthetic_dataset.py        # Project Orion synthetic scenario builder
│   ├── parsers/
│   │   ├── time_engine.py          # Timezone, offset & uncertainty engine
│   │   ├── parser_registry.py      # Dispatcher & processing run telemetry
│   │   ├── auth_log_parser.py      # Authentication logs parser
│   │   ├── endpoint_process_parser.py # Sysmon process & file activity parser
│   │   ├── browser_history_parser.py  # Browser visits & downloads parser
│   │   ├── network_proxy_parser.py    # Firewall / Egress proxy parser
│   │   ├── file_inventory_parser.py   # Filesystem hash catalog parser
│   │   └── cloud_audit_parser.py      # Cloud object & IAM audit parser
│   ├── static/
│   │   ├── app.js                  # Workbench dynamic UI logic
│   │   └── style.css               # Forensic styling & animations
│   ├── templates/
│   │   └── index.html              # 6-screen forensic workbench HTML
│   └── evidence_vault/
│       ├── originals/              # Immutable read-only original store
│       └── working_copies/         # Working copies for analysis
├── data/
│   └── project_orion/              # Synthetic evidence fixtures
└── tests/
    └── test_sutratrace.py          # Automated test suite (11 unit/API tests)
```

---

## 7. Standards & Legal Citations

- **ISO/IEC 27037:2012:** Guidelines for identification, collection, acquisition, and preservation of digital evidence.
- **SWGDE (Scientific Working Group on Digital Evidence):** Best Practices for Digital Evidence Collection and Computer Forensic Acquisitions.
- **NIST SP 800-86:** Guide to Integrating Forensic Techniques into Incident Response.
- **Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023):** Section 63 electronic record certification conditions and digital custody documentation.
- **MITRE ATT&CK Framework:** Enterprise tactics & techniques mapping for adversary behavioral triage.
