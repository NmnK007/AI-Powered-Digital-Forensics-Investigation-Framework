"""
Browser Activity & Download Parser for SutraTrace.
Parses browser navigation history and download records.
"""

import csv
import json
import uuid
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from sutratrace.parsers.time_engine import normalize_timestamp

PARSER_NAME = "browser_history_parser"
PARSER_VERSION = "1.0.0"


def parse_browser_logs(file_path: Path, evidence_id: str, case_id: str, case_tz: str = "UTC") -> Tuple[List[Dict[str, Any]], List[str]]:
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
    raw_time = row.get("timestamp") or row.get("visit_time") or row.get("download_time") or ""
    source_tz = row.get("timezone") or row.get("tz")
    raw_ts, tz_orig, utc_ts, quality = normalize_timestamp(raw_time, declared_source_tz=source_tz, default_case_tz=case_tz)

    user = (row.get("user") or row.get("profile") or "").strip()
    url = (row.get("url") or "").strip()
    domain = (row.get("domain") or "").strip()
    title = (row.get("title") or "").strip()
    download_path = (row.get("target_path") or row.get("download_path") or row.get("file_path") or "").strip()

    if not domain and url:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
        except Exception:
            pass

    entities = []
    if user:
        entities.append(f"user:{user.lower()}")
    if domain:
        entities.append(f"domain:{domain.lower()}")
    if download_path:
        entities.append(f"file_path:{download_path.lower()}")

    if download_path:
        ev_type = "browser_download"
        summary = f"Browser download from '{domain or url}' to '{download_path}' (User: {user or 'unknown'})"
    else:
        ev_type = "browser_visit"
        summary = f"Browser visited '{domain or url}' - '{title}' (User: {user or 'unknown'})"

    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    return {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "event_type": ev_type,
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
