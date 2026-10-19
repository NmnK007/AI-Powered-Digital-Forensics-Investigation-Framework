"""
Central Parser Registry & Worker Dispatcher for SutraTrace.
Executes source-specific parsers in safe wrappers and stores processing run telemetry.
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple
from sutratrace import database
from sutratrace.parsers import (
    auth_log_parser,
    endpoint_process_parser,
    browser_history_parser,
    network_proxy_parser,
    file_inventory_parser,
    cloud_audit_parser
)


def dispatch_parser(evidence: Dict[str, Any], case_tz: str = "UTC", db_path: Path = database.DB_PATH) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Selects and executes the appropriate parser for an evidence item.
    Returns: (list_of_normalized_events, processing_run_record)
    """
    file_path = Path(evidence["storage_uri"])
    evidence_id = evidence["evidence_id"]
    case_id = evidence["case_id"]
    source_type = evidence["source_type"].lower()
    filename = evidence["original_filename"].lower()

    run_id = f"run_{uuid.uuid4().hex[:8]}"
    start_time = datetime.now(timezone.utc).isoformat()

    parser_name = "unknown"
    parser_ver = "1.0.0"
    events: List[Dict[str, Any]] = []
    warnings: List[str] = []
    status = "completed"
    error_summary = None

    try:
        if "auth" in source_type or "login" in filename or "auth" in filename:
            parser_name = auth_log_parser.PARSER_NAME
            parser_ver = auth_log_parser.PARSER_VERSION
            events, warnings = auth_log_parser.parse_auth_logs(file_path, evidence_id, case_id, case_tz)

        elif "sysmon" in source_type or "endpoint" in source_type or "process" in source_type or "sysmon" in filename:
            parser_name = endpoint_process_parser.PARSER_NAME
            parser_ver = endpoint_process_parser.PARSER_VERSION
            events, warnings = endpoint_process_parser.parse_endpoint_logs(file_path, evidence_id, case_id, case_tz)

        elif "browser" in source_type or "history" in filename or "download" in filename:
            parser_name = browser_history_parser.PARSER_NAME
            parser_ver = browser_history_parser.PARSER_VERSION
            events, warnings = browser_history_parser.parse_browser_logs(file_path, evidence_id, case_id, case_tz)

        elif "firewall" in source_type or "proxy" in source_type or "network" in source_type or "proxy" in filename:
            parser_name = network_proxy_parser.PARSER_NAME
            parser_ver = network_proxy_parser.PARSER_VERSION
            events, warnings = network_proxy_parser.parse_network_logs(file_path, evidence_id, case_id, case_tz)

        elif "inventory" in source_type or "catalog" in filename or "inventory" in filename or "hash" in filename:
            parser_name = file_inventory_parser.PARSER_NAME
            parser_ver = file_inventory_parser.PARSER_VERSION
            events, warnings = file_inventory_parser.parse_file_inventory(file_path, evidence_id, case_id, case_tz)

        elif "cloud" in source_type or "audit" in source_type or "cloud" in filename:
            parser_name = cloud_audit_parser.PARSER_NAME
            parser_ver = cloud_audit_parser.PARSER_VERSION
            events, warnings = cloud_audit_parser.parse_cloud_logs(file_path, evidence_id, case_id, case_tz)

        else:
            # Fallback to endpoint or generic
            parser_name = endpoint_process_parser.PARSER_NAME
            parser_ver = endpoint_process_parser.PARSER_VERSION
            events, warnings = endpoint_process_parser.parse_endpoint_logs(file_path, evidence_id, case_id, case_tz)

    except Exception as e:
        status = "failed"
        error_summary = str(e)
        warnings.append(f"Unhandled parser exception: {str(e)}")

    end_time = datetime.now(timezone.utc).isoformat()

    run_record = {
        "run_id": run_id,
        "evidence_id": evidence_id,
        "parser_name": parser_name,
        "parser_version": parser_ver,
        "started_at": start_time,
        "ended_at": end_time,
        "status": status,
        "events_count": len(events),
        "warnings": warnings,
        "error_summary": error_summary
    }

    # Store run in db
    conn = database.get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO processing_runs (
            run_id, evidence_id, parser_name, parser_version,
            started_at, ended_at, status, events_count, warnings, error_summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        run_id, evidence_id, parser_name, parser_ver,
        start_time, end_time, status, len(events),
        ", ".join(warnings) if warnings else None, error_summary
    ))
    conn.commit()
    conn.close()

    # Update evidence parser status
    database.update_evidence_parser_status(
        evidence_id,
        "parsed" if status == "completed" and len(events) > 0 else ("warnings" if warnings else "failed"),
        db_path=db_path
    )

    # Insert events into DB
    for ev in events:
        database.insert_event(ev, db_path=db_path)

    return events, run_record
