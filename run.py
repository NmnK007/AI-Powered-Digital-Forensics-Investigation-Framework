"""
SutraTrace Forensic Workbench Launcher.
Runs the FastAPI server on http://127.0.0.1:8000
"""

import sys
import uvicorn
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print(" SUTRATRACE: AI-Powered Digital Forensics Workbench")
    print(" Evidence Graph & Provenance Ledger")
    print("=" * 60)
    print(" [OK] Initializing SQLite Relational Database & Indices...")
    print(" [OK] Initializing Immutable Evidence Vault & Working Stores...")
    print(" [OK] Verifying Cryptographic Audit Ledger Hash-Chain...")
    print(" [OK] Preloading 'Project Orion' Synthetic Exfiltration Scenario...")
    print("\n Server running at: http://127.0.0.1:8000")
    print(" Press CTRL+C to stop the server.\n" + "=" * 60 + "\n")

    uvicorn.run("sutratrace.app:app", host="127.0.0.1", port=8000, reload=False)
