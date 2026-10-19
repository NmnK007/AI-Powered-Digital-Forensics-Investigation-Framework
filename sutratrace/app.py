"""
SutraTrace: FastAPI Application & Forensic Workbench Server.
Implements REST API endpoints, static assets, and interactive frontend serving.
"""

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from sutratrace import database, evidence_store, audit_ledger, reporting
from sutratrace.models import (
    Case, CaseCreate, EvidenceItem, Event, Finding, AuditEvent,
    AskQuestionRequest, AskQuestionResponse, ReviewFindingRequest
)
from sutratrace.parsers import parser_registry
from sutratrace.correlation_engine import extract_and_correlate, get_cytoscape_elements
from sutratrace.triage_rules import run_triage_rules
from sutratrace.ai_assistant import answer_investigation_question
from sutratrace.synthetic_dataset import load_orion_demo_case

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    evidence_store.ensure_vault_directories()
    cases = database.list_cases()
    if not cases:
        load_orion_demo_case()
    yield

# Initialize immediately for server and test environments
database.init_db()
evidence_store.ensure_vault_directories()
cases = database.list_cases()
if not cases:
    load_orion_demo_case()

app = FastAPI(
    title="SutraTrace Forensic Workbench",
    description="AI-Powered Digital Forensics Investigation Framework: Evidence Graph & Provenance Ledger",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------- FRONTEND ROUTES ----------------------
@app.get("/", response_class=HTMLResponse)
def index_page():
    index_file = TEMPLATES_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>SutraTrace Workbench</h1><p>UI loading error: index.html not found.</p>")


# ---------------------- CASE MANAGEMENT ----------------------
@app.get("/api/cases", response_model=List[Dict[str, Any]])
def get_cases():
    return database.list_cases()


@app.post("/api/cases", response_model=Dict[str, Any])
def create_case(req: CaseCreate):
    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    now_utc = datetime.now(timezone.utc).isoformat()
    record = {
        "case_id": case_id,
        "title": req.title,
        "description": req.description,
        "created_by": req.created_by,
        "created_at": now_utc,
        "case_timezone": req.case_timezone,
        "scope_notes": req.scope_notes,
        "status": "active"
    }
    database.insert_case(record)
    audit_ledger.record_audit_event(
        case_id=case_id,
        actor=req.created_by,
        action="case_created",
        reason="Created new forensics case workspace",
        details={"case_title": req.title}
    )
    return record


@app.get("/api/cases/{case_id}")
def get_case_summary(case_id: str):
    case = database.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    evidence_list = database.list_evidence_for_case(case_id)
    events = database.list_events_for_case(case_id)
    findings = database.list_findings_for_case(case_id)
    chain_check = audit_ledger.verify_audit_chain(case_id)

    # Verification banner logic: green only when all hashes verified
    all_verified = len(evidence_list) > 0 and all(ev["verification_status"] == "verified" for ev in evidence_list)
    has_tamper = any(ev["verification_status"] == "mismatch" for ev in evidence_list)

    return {
        "case": case,
        "evidence_count": len(evidence_list),
        "events_count": len(events),
        "findings_count": len(findings),
        "hash_verification_status": "TAMPER_DETECTED" if has_tamper else ("ALL_VERIFIED_MATCH" if all_verified else "PENDING_VERIFICATION"),
        "audit_chain_valid": chain_check["valid"],
        "chain_head": chain_check.get("chain_head")
    }


# ---------------------- EVIDENCE MANAGEMENT ----------------------
@app.get("/api/cases/{case_id}/evidence")
def list_evidence(case_id: str):
    return database.list_evidence_for_case(case_id)


@app.post("/api/cases/{case_id}/evidence")
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    source_type: str = Form("general"),
    source_description: str = Form("Forensic upload"),
    operator: str = Form("Examiner")
):
    case = database.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    content = await file.read()
    evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"

    sha256_hash, storage_uri, size_bytes = evidence_store.store_evidence_file(
        case_id=case_id,
        evidence_id=evidence_id,
        filename=file.filename,
        content=content
    )

    now_utc = datetime.now(timezone.utc).isoformat()
    ev_record = {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "original_filename": file.filename,
        "source_type": source_type,
        "source_description": source_description,
        "storage_uri": storage_uri,
        "size_bytes": size_bytes,
        "detected_mime_type": file.content_type or "application/octet-stream",
        "sha256_initial": sha256_hash,
        "sha256_current": sha256_hash,
        "verification_status": "verified",
        "received_at": now_utc,
        "received_by": operator,
        "acquisition_time": now_utc,
        "acquisition_timezone": case.get("case_timezone", "UTC"),
        "authorization_reference": "Forensic Ingestion Gateway",
        "collection_notes": "Preserved byte-for-byte in immutable storage.",
        "parser_status": "pending",
        "created_at": now_utc
    }
    database.insert_evidence(ev_record)

    audit_ledger.record_audit_event(
        case_id=case_id,
        actor=operator,
        action="ingested",
        reason=f"Ingested evidence file {file.filename}",
        details={"evidence_id": evidence_id, "sha256": sha256_hash, "size": size_bytes},
        evidence_id=evidence_id
    )

    # Automatically parse the uploaded item
    events, run_record = parser_registry.dispatch_parser(ev_record, case_tz=case.get("case_timezone", "UTC"))
    audit_ledger.record_audit_event(
        case_id=case_id,
        actor="SystemParser",
        action="parsed",
        reason=f"Parsed with {run_record['parser_name']}",
        details={"events_extracted": len(events), "status": run_record["status"]},
        evidence_id=evidence_id
    )

    # Re-correlate & run triage
    extract_and_correlate(case_id)
    run_triage_rules(case_id)

    return {
        "evidence": ev_record,
        "events_extracted": len(events),
        "run": run_record
    }


@app.post("/api/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: str):
    # Find evidence item across cases
    conn = database.get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM evidence_items WHERE evidence_id = ?", (evidence_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    ev = dict(row)
    res = evidence_store.verify_evidence_integrity(
        case_id=ev["case_id"],
        evidence_id=evidence_id,
        filename=ev["original_filename"],
        expected_hash=ev["sha256_initial"]
    )

    new_status = "verified" if res["match"] else "mismatch"
    database.update_evidence_hash(evidence_id, res["current_sha256"] or ev["sha256_current"], new_status)

    audit_ledger.record_audit_event(
        case_id=ev["case_id"],
        actor="Examiner",
        action="verified",
        reason="Executed cryptographic integrity verification",
        details=res,
        evidence_id=evidence_id
    )

    return res


@app.post("/api/evidence/{evidence_id}/tamper_test_simulate")
def tamper_test_simulate(evidence_id: str):
    """
    Hackathon Demo Tool:
    Injects a 1-byte alteration into the working copy to demonstrate live tamper detection to judges.
    """
    conn = database.get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM evidence_items WHERE evidence_id = ?", (evidence_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    ev = dict(row)
    tamper_res = evidence_store.simulate_tampering_for_demo(
        case_id=ev["case_id"],
        evidence_id=evidence_id,
        filename=ev["original_filename"]
    )

    # Immediately update status to mismatch in DB
    database.update_evidence_hash(evidence_id, tamper_res["new_hash"], "mismatch")

    audit_ledger.record_audit_event(
        case_id=ev["case_id"],
        actor="DemoSimulator",
        action="tampered_simulated",
        reason="Simulated 1-byte alteration on working copy for tamper verification demo",
        details=tamper_res,
        evidence_id=evidence_id
    )

    return tamper_res


@app.post("/api/evidence/{evidence_id}/restore")
def restore_evidence(evidence_id: str):
    """Restores the working copy from the clean, untouched immutable original."""
    conn = database.get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM evidence_items WHERE evidence_id = ?", (evidence_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    ev = dict(row)
    restored_hash = evidence_store.restore_working_copy_from_original(
        case_id=ev["case_id"],
        evidence_id=evidence_id,
        filename=ev["original_filename"]
    )
    database.update_evidence_hash(evidence_id, restored_hash, "verified")

    audit_ledger.record_audit_event(
        case_id=ev["case_id"],
        actor="Examiner",
        action="restored",
        reason="Restored working copy from immutable original store",
        details={"restored_hash": restored_hash},
        evidence_id=evidence_id
    )

    return {"restored": True, "sha256": restored_hash, "status": "verified"}


# ---------------------- EVENTS & TIMELINE ----------------------
@app.get("/api/cases/{case_id}/events")
def get_events(
    case_id: str,
    q: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None)
):
    events = database.list_events_for_case(case_id)
    if q:
        q_l = q.lower()
        events = [e for e in events if q_l in e["summary"].lower() or any(q_l in ent for ent in e.get("entities", []))]
    if event_type:
        events = [e for e in events if event_type.lower() in e["event_type"].lower()]
    return events


@app.get("/api/cases/{case_id}/timeline")
def get_timeline(case_id: str):
    """Returns chronological events grouped with source lane classification."""
    events = database.list_events_for_case(case_id)

    # Assign source lanes
    lanes = {
        "auth": "Authentication / Access",
        "endpoint": "Endpoint Process & Files",
        "browser": "Browser & Web Visits",
        "network": "Network Perimeter / Proxy",
        "cloud": "Cloud Storage & IAM",
        "file_inventory": "Filesystem Directory Audit"
    }

    categorized = []
    for ev in events:
        lane = "Other"
        for k, v in lanes.items():
            if k in ev["event_type"]:
                lane = v
                break
        categorized.append({
            **ev,
            "lane": lane
        })

    return categorized


# ---------------------- GRAPH CORRELATION ----------------------
@app.get("/api/cases/{case_id}/graph")
def get_case_graph(case_id: str):
    return get_cytoscape_elements(case_id)


# ---------------------- TRIAGE & FINDINGS ----------------------
@app.get("/api/cases/{case_id}/findings")
def get_findings(case_id: str):
    return database.list_findings_for_case(case_id)


@app.post("/api/cases/{case_id}/triage")
def trigger_triage(case_id: str):
    extract_and_correlate(case_id)
    findings = run_triage_rules(case_id)
    return {"findings_count": len(findings), "findings": findings}


@app.patch("/api/findings/{finding_id}")
def review_finding(finding_id: str, req: ReviewFindingRequest):
    now_utc = datetime.now(timezone.utc).isoformat()
    database.update_finding_review(
        finding_id=finding_id,
        status=req.status,
        notes=req.reviewer_notes,
        reviewer_id=req.reviewer_id,
        reviewed_at=now_utc
    )

    # Find finding's case
    conn = database.get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT case_id, title FROM findings WHERE finding_id = ?", (finding_id,))
    row = cur.fetchone()
    conn.close()

    if row:
        audit_ledger.record_audit_event(
            case_id=row["case_id"],
            actor=req.reviewer_id,
            action="finding_updated",
            reason=f"Investigator updated status of {finding_id} to {req.status}",
            details={"finding_id": finding_id, "title": row["title"], "notes": req.reviewer_notes}
        )

    return {"status": "success", "finding_id": finding_id, "new_status": req.status}


# ---------------------- GROUNDED AI ASSISTANT ----------------------
@app.post("/api/cases/{case_id}/ask", response_model=AskQuestionResponse)
def ask_ai(case_id: str, req: AskQuestionRequest):
    res = answer_investigation_question(req.question, case_id)
    audit_ledger.record_audit_event(
        case_id=case_id,
        actor="Investigator",
        action="queried",
        reason="AI forensic query executed",
        details={"question": req.question, "cited_events": res.cited_event_ids, "validated": res.validated}
    )
    return res


# ---------------------- REPORTING & AUDIT ----------------------
@app.get("/api/cases/{case_id}/report")
def get_report_markdown(case_id: str):
    md = reporting.generate_forensic_report_markdown(case_id)
    return PlainTextResponse(content=md, media_type="text/markdown")


@app.get("/api/cases/{case_id}/report/html")
def get_report_html(case_id: str):
    html = reporting.generate_forensic_report_html(case_id)
    return HTMLResponse(content=html)


@app.get("/api/cases/{case_id}/audit")
def get_audit_trail(case_id: str):
    return database.list_audit_events_for_case(case_id)


@app.get("/api/cases/{case_id}/audit/verify")
def verify_audit_trail(case_id: str):
    return audit_ledger.verify_audit_chain(case_id)


# ---------------------- ONE-CLICK DEMO LOADER ----------------------
@app.post("/api/demo/load_orion")
def load_orion():
    return load_orion_demo_case()


# Mount static assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
