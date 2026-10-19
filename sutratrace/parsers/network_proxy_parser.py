"""
Network Proxy & Firewall Log Parser for SutraTrace.
Parses proxy, firewall, and gateway traffic logs.
"""

import csv
import json
import uuid
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from sutratrace.parsers.time_engine import normalize_timestamp

PARSER_NAME = "network_proxy_parser"
PARSER_VERSION = "1.0.0"


def parse_network_logs(file_path: Path, evidence_id: str, case_id: str, case_tz: str = "UTC") -> Tuple[List[Dict[str, Any]], List[str]]:
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
    raw_time = row.get("timestamp") or row.get("time") or row.get("DateTime") or ""
    source_tz = row.get("timezone") or row.get("tz")
    raw_ts, tz_orig, utc_ts, quality = normalize_timestamp(raw_time, declared_source_tz=source_tz, default_case_tz=case_tz)

    src_ip = (row.get("src_ip") or row.get("source_ip") or row.get("ClientIP") or "").strip()
    dst_ip = (row.get("dst_ip") or row.get("destination_ip") or row.get("DestIP") or "").strip()
    domain = (row.get("domain") or row.get("host") or row.get("DestinationHost") or "").strip()
    port = (row.get("port") or row.get("dst_port") or "443").strip()
    action = (row.get("action") or row.get("verdict") or "allowed").strip()
    method = (row.get("method") or row.get("http_method") or "POST").strip()
    bytes_sent = row.get("bytes_sent") or row.get("bytes_out") or row.get("bytes_transferred") or "0"

    entities = []
    if src_ip:
        entities.append(f"ip:{src_ip.lower()}")
    if dst_ip:
        entities.append(f"ip:{dst_ip.lower()}")
    if domain:
        entities.append(f"domain:{domain.lower()}")

    try:
        bytes_val = int(bytes_sent)
        mb = bytes_val / (1024 * 1024)
        size_str = f"{mb:.2f} MB" if mb >= 1.0 else f"{bytes_val} bytes"
    except Exception:
        size_str = f"{bytes_sent} bytes"

    summary = f"Outbound {method} traffic to {domain or dst_ip}:{port} ({size_str}, Action: {action}, Src: {src_ip})"

    event_id = f"evt_{uuid.uuid4().hex[:8]}"

    return {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "event_type": "network_transfer" if method.upper() in ["POST", "PUT"] or (int(bytes_sent) if bytes_sent.isdigit() else 0) > 1000000 else "network_connection",
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
