"""
Authentication Log Parser for SutraTrace.
Parses CSV and JSON authentication records (logins, logouts, privilege escalations).
"""

import csv
import json
import uuid
from typing import List, Dict, Any, Tuple
from pathlib import Path
from sutratrace.parsers.time_engine import normalize_timestamp

PARSER_NAME = "auth_log_parser"
PARSER_VERSION = "1.0.0"


def parse_auth_logs(file_path: Path, evidence_id: str, case_id: str, case_tz: str = "UTC") -> Tuple[List[Dict[str, Any]], List[str]]:
    events = []
    warnings = []

    content = file_path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        warnings.append(f"File {file_path.name} is empty.")
        return events, warnings

    if content.startswith("[") or content.startswith("{"):
        # JSON format
        try:
            data = json.loads(content)
            records = data if isinstance(data, list) else [data]
            for idx, row in enumerate(records):
                ev = _record_to_event(row, idx + 1, file_path.name, evidence_id, case_id, case_tz)
                if ev:
                    events.append(ev)
        except Exception as e:
            warnings.append(f"JSON parsing error: {str(e)}")
    else:
        # CSV format
        reader = csv.DictReader(content.splitlines())
        for idx, row in enumerate(reader):
            ev = _record_to_event(row, idx + 2, file_path.name, evidence_id, case_id, case_tz)
            if ev:
                events.append(ev)

    return events, warnings


def _record_to_event(row: Dict[str, Any], line_num: int, filename: str, evidence_id: str, case_id: str, case_tz: str) -> Optional[Dict[str, Any]]:
    # Extract timestamp
    raw_time = row.get("timestamp") or row.get("time") or row.get("event_time") or ""
    source_tz = row.get("timezone") or row.get("tz")
    raw_ts, tz_orig, utc_ts, quality = normalize_timestamp(raw_time, declared_source_tz=source_tz, default_case_tz=case_tz)

    user = (row.get("user") or row.get("username") or row.get("account") or "").strip()
    host = (row.get("host") or row.get("workstation") or row.get("computer_name") or "").strip()
    ip = (row.get("source_ip") or row.get("ip") or row.get("src_ip") or "").strip()
    action = (row.get("action") or row.get("event_type") or row.get("status") or "auth_event").strip()
    auth_method = row.get("auth_method") or row.get("method") or "password"

    entities = []
    if user:
        entities.append(f"user:{user.lower()}")
    if host:
        entities.append(f"host:{host.lower()}")
    if ip:
        entities.append(f"ip:{ip.lower()}")

    summary = f"Authentication event: {action} for user '{user}' on host '{host}' from IP {ip or 'local'} ({auth_method})"

    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    return {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "event_type": f"auth_{action.lower()}",
        "summary": summary,
        "raw_timestamp": raw_ts,
        "timezone_original": tz_orig,
        "timestamp_utc": utc_ts,
        "timestamp_quality": quality,
        "source_locator": {"file": filename, "row": line_num},
        "parser_name": PARSER_NAME,
        "parser_version": PARSER_VERSION,
        "raw_fields": row,
        "entities": entities
    }
