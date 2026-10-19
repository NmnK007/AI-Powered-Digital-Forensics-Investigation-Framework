"""
Cloud Audit & Object Storage Access Parser for SutraTrace.
Parses cloud activity trails (IAM actions, object access, permissions).
"""

import csv
import json
import uuid
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from sutratrace.parsers.time_engine import normalize_timestamp

PARSER_NAME = "cloud_audit_parser"
PARSER_VERSION = "1.0.0"


def parse_cloud_logs(file_path: Path, evidence_id: str, case_id: str, case_tz: str = "UTC") -> Tuple[List[Dict[str, Any]], List[str]]:
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
        reader = csv.DictReader(content.splitlines())
        records = list(reader)

    for idx, row in enumerate(records):
        ev = _record_to_event(row, idx + 1, file_path.name, evidence_id, case_id, case_tz)
        if ev:
            events.append(ev)

    return events, warnings


def _record_to_event(row: Dict[str, Any], line_num: int, filename: str, evidence_id: str, case_id: str, case_tz: str) -> Optional[Dict[str, Any]]:
    raw_time = row.get("timestamp") or row.get("eventTime") or row.get("time") or ""
    source_tz = row.get("timezone") or row.get("tz")
    raw_ts, tz_orig, utc_ts, quality = normalize_timestamp(raw_time, declared_source_tz=source_tz, default_case_tz=case_tz)

    user = (row.get("user") or row.get("principal") or row.get("userIdentity") or "").strip()
    action = (row.get("action") or row.get("eventName") or "cloud_access").strip()
    resource = (row.get("resource") or row.get("bucket_object") or row.get("key") or "").strip()
    source_ip = (row.get("source_ip") or row.get("sourceIPAddress") or "").strip()

    entities = []
    if user:
        entities.append(f"user:{user.lower()}")
    if source_ip:
        entities.append(f"ip:{source_ip.lower()}")
    if resource:
        entities.append(f"cloud_resource:{resource.lower()}")

    summary = f"Cloud audit: {action} on '{resource}' by '{user}' from IP {source_ip or 'internal'}"

    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    return {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "event_type": f"cloud_{action.lower()}",
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
