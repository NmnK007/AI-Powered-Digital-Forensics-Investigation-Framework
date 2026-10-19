"""
Synthetic Forensic Dataset Generator & Demo Preloader for SutraTrace.
Implements the 'Project Orion' insider-data-exfiltration scenario from Section 12.
"""

import json
from pathlib import Path
from typing import Dict, Any, List
from sutratrace import database, evidence_store, audit_ledger
from sutratrace.parsers import parser_registry
from sutratrace.correlation_engine import extract_and_correlate
from sutratrace.triage_rules import run_triage_rules

DATA_DIR = Path("C:/Users/P C/.gemini/antigravity/scratch/sutratrace/data/project_orion")

ORION_HASH = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"

FILES_DATA = {
    "01_auth_logs.csv": """timestamp,timezone,user,host,source_ip,action,status,auth_method
2026-09-08 22:15:00,Asia/Kolkata,sarah,WS-02,10.0.1.20,login,success,kerberos
2026-09-08 22:30:15,Asia/Kolkata,david,WS-05,10.0.1.25,login,success,kerberos
2026-09-08 23:45:10,Asia/Kolkata,alex,WS-07,203.0.113.24,login,success,vpn_external_ip
2026-09-08 23:46:02,Asia/Kolkata,alex,WS-07,10.0.1.45,privilege_escalation,success,sudo_elevation
""",

    "02_sysmon_endpoint.json": json.dumps([
        {
            "timestamp": "2026-09-08 23:48:15",
            "timezone": "Asia/Kolkata",
            "host": "WS-07",
            "user": "alex",
            "event_type": "ProcessCreate",
            "image": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c whoami /priv",
            "parent_process": "explorer.exe"
        },
        {
            "timestamp": "2026-09-08 23:51:22",
            "timezone": "Asia/Kolkata",
            "host": "WS-07",
            "user": "alex",
            "event_type": "ProcessCreate",
            "image": "C:\\Program Files\\7-Zip\\7z.exe",
            "command_line": "7z.exe a -tzip C:\\Users\\alex\\AppData\\Local\\Temp\\Project-Orion.zip C:\\Engineering\\Blueprints\\*",
            "parent_process": "cmd.exe"
        },
        {
            "timestamp": "2026-09-08 23:51:58",
            "timezone": "Asia/Kolkata",
            "host": "WS-07",
            "user": "alex",
            "event_type": "FileCreate",
            "image": "C:\\Program Files\\7-Zip\\7z.exe",
            "target_file": "C:\\Users\\alex\\AppData\\Local\\Temp\\Project-Orion.zip",
            "sha256": ORION_HASH
        }
    ], indent=2),

    "03_browser_history.csv": """timestamp,timezone,user,url,domain,title
2026-09-08 22:40:12,Asia/Kolkata,alex,https://internal-wiki.corp/docs,internal-wiki.corp,Internal Documentation
2026-09-08 23:55:04,Asia/Kolkata,alex,https://temp-dropfile-share.org/upload,temp-dropfile-share.org,Temporary Anonymous File Drop & Storage
2026-09-08 23:58:30,Asia/Kolkata,alex,https://temp-dropfile-share.org/download/orion-77a,temp-dropfile-share.org,File Transfer Completed
""",

    "04_proxy_firewall.csv": """timestamp,timezone,src_ip,dst_ip,domain,port,method,bytes_sent,action
2026-09-08 23:10:00,Asia/Kolkata,10.0.1.20,198.51.100.12,api.github.com,443,GET,1420,allowed
2026-09-08 23:57:12,Asia/Kolkata,10.0.1.45,198.51.100.88,temp-dropfile-share.org,443,POST,50541312,allowed
2026-09-09 00:02:15,Asia/Kolkata,10.0.1.45,198.51.100.88,temp-dropfile-share.org,443,GET,2048,allowed
""",

    "05_file_inventory.csv": f"""timestamp,timezone,file_path,sha256,size_bytes,owner
2026-09-08 23:52:00,Asia/Kolkata,C:\\Users\\alex\\AppData\\Local\\Temp\\Project-Orion.zip,{ORION_HASH},50541312,alex
2026-09-08 21:00:00,Asia/Kolkata,C:\\Engineering\\Blueprints\\avionics_schematic_v2.cad,a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0,14820100,corp_admin
""",

    "06_cloud_audit.json": json.dumps([
        {
            "timestamp": "2026-09-08 23:38:00",
            "timezone": "Asia/Kolkata",
            "user": "alex",
            "action": "GetObject",
            "resource": "s3://corporate-blueprints-prod/avionics_schematic_v2.cad",
            "source_ip": "203.0.113.24"
        },
        {
            "timestamp": "2026-09-08 23:39:15",
            "timezone": "Asia/Kolkata",
            "user": "alex",
            "action": "ListBucket",
            "resource": "s3://corporate-blueprints-prod/",
            "source_ip": "203.0.113.24"
        }
    ], indent=2)
}


def write_synthetic_files():
    """Generates synthetic evidence files on disk."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in FILES_DATA.items():
        (DATA_DIR / name).write_text(content, encoding="utf-8")


def load_orion_demo_case(db_path: Path = database.DB_PATH) -> Dict[str, Any]:
    """
    Creates and populates the Project Orion demonstration case.
    """
    write_synthetic_files()
    case_id = "CASE-2026-ORION"

    # Check if already exists
    existing = database.get_case(case_id, db_path=db_path)
    if existing:
        return {"status": "exists", "case_id": case_id}

    # 1. Create Case
    case_record = {
        "case_id": case_id,
        "title": "Project Orion: Suspected After-Hours Data Exfiltration",
        "description": "Investigation into unauthorized after-hours archive creation on workstation WS-07 and large external transfer to unapproved cloud drop service.",
        "created_by": "Senior Forensic Examiner (CERT-In / DFIR)",
        "created_at": "2026-09-09T02:00:00Z",
        "case_timezone": "Asia/Kolkata",
        "scope_notes": "Authorized incident response per Security Operations ticket SEC-2026-9041.",
        "status": "active"
    }
    database.insert_case(case_record, db_path=db_path)

    audit_ledger.record_audit_event(
        case_id=case_id,
        actor="Examiner",
        action="case_created",
        reason="Initiated formal digital forensics case workspace for Project Orion",
        details={"case_title": case_record["title"]},
        db_path=db_path
    )

    # 2. Ingest Evidence Items
    meta_info = {
        "01_auth_logs.csv": ("auth_log", "Domain Controller Kerberos & VPN Authentication Export"),
        "02_sysmon_endpoint.json": ("endpoint_process", "Workstation WS-07 Sysmon Event Log Export"),
        "03_browser_history.csv": ("browser_history", "Chrome Browser Profile History on WS-07"),
        "04_proxy_firewall.csv": ("firewall_proxy", "Egress Perimeter Proxy Log Export"),
        "05_file_inventory.csv": ("file_inventory", "Post-Incident Forensic Directory Hash Catalog"),
        "06_cloud_audit.json": ("cloud_audit", "Cloud Object Storage Audit Trail")
    }

    evidence_ids = []
    for idx, (filename, content) in enumerate(FILES_DATA.items(), 1):
        ev_id = f"EV-ORION-{idx:02d}"
        source_type, desc = meta_info[filename]
        content_bytes = content.encode("utf-8")

        # Store in vault (computes SHA-256 and creates immutable original + working copy)
        sha256_hash, storage_uri, size_bytes = evidence_store.store_evidence_file(
            case_id=case_id,
            evidence_id=ev_id,
            filename=filename,
            content=content_bytes
        )

        ev_record = {
            "evidence_id": ev_id,
            "case_id": case_id,
            "original_filename": filename,
            "source_type": source_type,
            "source_description": desc,
            "storage_uri": storage_uri,
            "size_bytes": size_bytes,
            "detected_mime_type": "text/csv" if filename.endswith(".csv") else "application/json",
            "sha256_initial": sha256_hash,
            "sha256_current": sha256_hash,
            "verification_status": "verified",
            "received_at": "2026-09-09T02:10:00Z",
            "received_by": "Senior Forensic Examiner",
            "acquisition_time": "2026-09-09T01:30:00Z",
            "acquisition_timezone": "Asia/Kolkata",
            "authorization_reference": "Warrant/Auth-SEC-9041",
            "collection_notes": "Acquired using lawful forensic export tools with SHA-256 validation.",
            "parser_status": "pending",
            "created_at": "2026-09-09T02:15:00Z"
        }
        database.insert_evidence(ev_record, db_path=db_path)
        evidence_ids.append(ev_id)

        # Audit custody
        audit_ledger.record_audit_event(
            case_id=case_id,
            actor="Examiner",
            action="ingested",
            reason=f"Ingested evidence item {filename}",
            details={"evidence_id": ev_id, "sha256": sha256_hash, "size": size_bytes},
            evidence_id=ev_id,
            db_path=db_path
        )

    # 3. Parse all evidence items
    for ev in database.list_evidence_for_case(case_id, db_path=db_path):
        events, run_record = parser_registry.dispatch_parser(ev, case_tz="Asia/Kolkata", db_path=db_path)
        audit_ledger.record_audit_event(
            case_id=case_id,
            actor="SystemParser",
            action="parsed",
            reason=f"Executed {run_record['parser_name']} v{run_record['parser_version']}",
            details={"events_extracted": len(events), "status": run_record["status"]},
            evidence_id=ev["evidence_id"],
            db_path=db_path
        )

    # 4. Correlate entities and build graph
    corr_stats = extract_and_correlate(case_id, db_path=db_path)

    # 5. Run deterministic triage rules
    triage_findings = run_triage_rules(case_id, db_path=db_path)

    audit_ledger.record_audit_event(
        case_id=case_id,
        actor="TriageEngine",
        action="triage_completed",
        reason="Automated triage rules executed",
        details={"findings_count": len(triage_findings), "entities_count": corr_stats["entities_count"]},
        db_path=db_path
    )

    return {
        "status": "success",
        "case_id": case_id,
        "evidence_count": len(evidence_ids),
        "findings_count": len(triage_findings),
        "entities_count": corr_stats["entities_count"]
    }
