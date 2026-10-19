"""
Cryptographic Audit Ledger for SutraTrace.
Maintains a tamper-evident SHA-256 hash-chain of all chain-of-custody, ingestion,
investigation, and reporting operations.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from sutratrace import database


GENESIS_HASH = "0" * 64


def canonical_json_representation(data: Dict[str, Any]) -> str:
    """Produces a deterministic, whitespace-stripped, sorted JSON string."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def compute_audit_event_hash(previous_hash: str, canonical_event: str) -> str:
    """Calculates SHA256(previous_event_hash || canonical_event_json)."""
    hasher = hashlib.sha256()
    hasher.update((previous_hash + canonical_event).encode('utf-8'))
    return hasher.hexdigest()


def record_audit_event(
    case_id: str,
    actor: str,
    action: str,
    reason: str,
    details: Optional[Dict[str, Any]] = None,
    evidence_id: Optional[str] = None,
    db_path: Path = database.DB_PATH
) -> Dict[str, Any]:
    """
    Appends a new cryptographically chained audit event to the case ledger.
    """
    if details is None:
        details = {}

    latest = database.get_latest_audit_event(case_id, db_path=db_path)
    previous_hash = latest["event_hash"] if latest else GENESIS_HASH

    audit_id = f"aud_{uuid.uuid4().hex[:12]}"
    now_utc = datetime.now(timezone.utc).isoformat()

    canonical_dict = {
        "audit_id": audit_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "actor": actor,
        "action": action,
        "timestamp": now_utc,
        "reason": reason,
        "details": details
    }
    canonical_str = canonical_json_representation(canonical_dict)
    event_hash = compute_audit_event_hash(previous_hash, canonical_str)

    audit_record = {
        "audit_id": audit_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "actor": actor,
        "action": action,
        "timestamp": now_utc,
        "timezone": "UTC",
        "reason": reason,
        "details": details,
        "previous_event_hash": previous_hash,
        "event_hash": event_hash,
        "signature_reference": None
    }

    database.insert_audit_event(audit_record, db_path=db_path)
    return audit_record


def verify_audit_chain(case_id: str, db_path: Path = database.DB_PATH) -> Dict[str, Any]:
    """
    Verifies the integrity of the entire cryptographic hash chain for a case.
    Walks each link from genesis to current head.
    """
    events = database.list_audit_events_for_case(case_id, db_path=db_path)
    if not events:
        return {
            "valid": True,
            "total_events": 0,
            "message": "Empty audit chain (no events recorded)."
        }

    expected_prev = GENESIS_HASH

    for idx, ev in enumerate(events):
        # 1. Verify previous_hash link
        if ev["previous_event_hash"] != expected_prev:
            return {
                "valid": False,
                "broken_index": idx,
                "broken_audit_id": ev["audit_id"],
                "reason": "Previous hash link broken",
                "expected_previous_hash": expected_prev,
                "actual_previous_hash": ev["previous_event_hash"]
            }

        # 2. Recalculate event hash
        canonical_dict = {
            "audit_id": ev["audit_id"],
            "case_id": ev["case_id"],
            "evidence_id": ev.get("evidence_id"),
            "actor": ev["actor"],
            "action": ev["action"],
            "timestamp": ev["timestamp"],
            "reason": ev["reason"],
            "details": ev.get("details", {})
        }
        canonical_str = canonical_json_representation(canonical_dict)
        recalculated_hash = compute_audit_event_hash(expected_prev, canonical_str)

        if recalculated_hash != ev["event_hash"]:
            return {
                "valid": False,
                "broken_index": idx,
                "broken_audit_id": ev["audit_id"],
                "reason": "Event content altered: hash verification failed",
                "expected_hash": ev["event_hash"],
                "recalculated_hash": recalculated_hash
            }

        expected_prev = ev["event_hash"]

    return {
        "valid": True,
        "total_events": len(events),
        "chain_head": expected_prev,
        "message": f"Cryptographic audit chain intact: {len(events)} events verified from genesis to head."
    }
