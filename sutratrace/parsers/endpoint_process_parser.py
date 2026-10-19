"""
Endpoint Process & File Activity Parser for SutraTrace.
Parses Sysmon, EDR, and OS process/file event logs.
"""

import csv
import json
import uuid
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from sutratrace.parsers.time_engine import normalize_timestamp

PARSER_NAME = "endpoint_process_parser"
PARSER_VERSION = "1.0.0"


def parse_endpoint_logs(file_path: Path, evidence_id: str, case_id: str, case_tz: str = "UTC") -> Tuple[List[Dict[str, Any]], List[str]]:
    events = []
    warnings = []

    content = file_path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        warnings.append(f"File {file_path.name} is empty.")
        return events, warnings

    records = []
    if content.startswith("[") or content.startswith("{"):
        try:
            data = json.loads(content)
            records = data if isinstance(data, list) else [data]
        except Exception as e:
            warnings.append(f"JSON parsing error: {str(e)}")
    else:
        # Check CSV
        lines = content.splitlines()
        reader = csv.DictReader(lines)
        records = list(reader)

    for idx, row in enumerate(records):
        ev = _record_to_event(row, idx + 1, file_path.name, evidence_id, case_id, case_tz)
        if ev:
            events.append(ev)

    return events, warnings


def _record_to_event(row: Dict[str, Any], line_num: int, filename: str, evidence_id: str, case_id: str, case_tz: str) -> Optional[Dict[str, Any]]:
    raw_time = row.get("timestamp") or row.get("UtcTime") or row.get("event_time") or ""
    source_tz = row.get("timezone") or row.get("tz")
    raw_ts, tz_orig, utc_ts, quality = normalize_timestamp(raw_time, declared_source_tz=source_tz, default_case_tz=case_tz)

    user = (row.get("user") or row.get("User") or "").strip()
    host = (row.get("host") or row.get("Computer") or "").strip()
    event_type = (row.get("event_type") or row.get("EventName") or row.get("event_id") or "process_activity").strip()
    image = (row.get("image") or row.get("process") or row.get("Image") or "").strip()
    command_line = (row.get("command_line") or row.get("CommandLine") or "").strip()
    parent = (row.get("parent_process") or row.get("ParentImage") or "").strip()
    target_file = (row.get("target_file") or row.get("TargetFilename") or "").strip()
    file_hash = (row.get("sha256") or row.get("hash") or row.get("Hashes") or "").strip()

    # Clean up hash if prefixed e.g. SHA256=...
    if "SHA256=" in file_hash:
        for part in file_hash.split(','):
            if "SHA256=" in part:
                file_hash = part.split("SHA256=")[-1].strip()

    entities = []
    if user:
        entities.append(f"user:{user.lower()}")
    if host:
        entities.append(f"host:{host.lower()}")
    if image:
        entities.append(f"process:{Path(image).name.lower()}")
    if target_file:
        entities.append(f"file_path:{target_file.lower()}")
    if file_hash and len(file_hash) == 64:
        entities.append(f"file_hash:{file_hash.lower()}")

    if "file" in event_type.lower() or target_file:
        summary = f"File event '{event_type}' on '{target_file}' by process '{image or 'system'}' (User: {user}, Host: {host})"
    else:
        summary = f"Process '{Path(image).name or image}' launched: {command_line[:120]} (User: {user}, Host: {host})"

    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    return {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "event_type": f"endpoint_{event_type.lower()}",
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
