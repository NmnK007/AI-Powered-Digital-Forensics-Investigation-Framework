"""
File Inventory & Hash Listing Parser for SutraTrace.
Parses filesystem catalogs, hash manifests, and directory dumps.
"""

import csv
import json
import uuid
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from sutratrace.parsers.time_engine import normalize_timestamp

PARSER_NAME = "file_inventory_parser"
PARSER_VERSION = "1.0.0"


def parse_file_inventory(file_path: Path, evidence_id: str, case_id: str, case_tz: str = "UTC") -> Tuple[List[Dict[str, Any]], List[str]]:
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
    raw_time = row.get("timestamp") or row.get("modified_time") or row.get("mtime") or row.get("created_time") or ""
    source_tz = row.get("timezone") or row.get("tz")
    raw_ts, tz_orig, utc_ts, quality = normalize_timestamp(raw_time, declared_source_tz=source_tz, default_case_tz=case_tz)

    file_path = (row.get("file_path") or row.get("path") or row.get("filename") or "").strip()
    sha256 = (row.get("sha256") or row.get("hash") or "").strip().lower()
    size_str = (row.get("size_bytes") or row.get("size") or "0").strip()
    owner = (row.get("owner") or row.get("user") or "").strip()

    entities = []
    if file_path:
        entities.append(f"file_path:{file_path.lower()}")
    if sha256 and len(sha256) == 64:
        entities.append(f"file_hash:{sha256}")
    if owner:
        entities.append(f"user:{owner.lower()}")

    summary = f"File catalog entry: '{file_path}' (Size: {size_str} bytes, SHA256: {sha256[:16]}..., Owner: {owner or 'unknown'})"

    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    return {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "event_type": "file_inventory_record",
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
