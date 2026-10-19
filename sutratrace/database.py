"""
Database access and SQLite schema for SutraTrace.
Normalized relational storage with indices for high-performance forensic querying.
"""

import json
import sqlite3
from pathlib import Path
from typing import List, Optional, Dict, Any

DB_PATH = Path("C:/Users/P C/.gemini/antigravity/scratch/sutratrace/sutratrace.db")


def get_db_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        case_timezone TEXT DEFAULT 'UTC',
        scope_notes TEXT,
        status TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS evidence_items (
        evidence_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        source_type TEXT NOT NULL,
        source_description TEXT NOT NULL,
        storage_uri TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        detected_mime_type TEXT NOT NULL,
        sha256_initial TEXT NOT NULL,
        sha256_current TEXT NOT NULL,
        verification_status TEXT DEFAULT 'unverified',
        received_at TEXT NOT NULL,
        received_by TEXT NOT NULL,
        acquisition_time TEXT,
        acquisition_timezone TEXT,
        authorization_reference TEXT,
        collection_notes TEXT,
        parser_status TEXT DEFAULT 'pending',
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS processing_runs (
        run_id TEXT PRIMARY KEY,
        evidence_id TEXT NOT NULL,
        parser_name TEXT NOT NULL,
        parser_version TEXT NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT NOT NULL,
        status TEXT NOT NULL,
        events_count INTEGER DEFAULT 0,
        warnings TEXT,
        error_summary TEXT,
        FOREIGN KEY (evidence_id) REFERENCES evidence_items(evidence_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        summary TEXT NOT NULL,
        raw_timestamp TEXT NOT NULL,
        timezone_original TEXT NOT NULL,
        timestamp_utc TEXT NOT NULL,
        timestamp_quality TEXT NOT NULL,
        source_locator TEXT NOT NULL,
        parser_name TEXT NOT NULL,
        parser_version TEXT NOT NULL,
        raw_fields TEXT NOT NULL,
        entities TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence_items(evidence_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS entities (
        entity_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        canonical_value TEXT NOT NULL,
        normalization_method TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        event_count INTEGER DEFAULT 0,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS event_entities (
        event_id TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        role TEXT NOT NULL,
        match_method TEXT NOT NULL,
        match_strength TEXT NOT NULL,
        notes TEXT,
        PRIMARY KEY (event_id, entity_id),
        FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE,
        FOREIGN KEY (entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS relationships (
        relationship_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        source_entity_id TEXT NOT NULL,
        target_entity_id TEXT NOT NULL,
        source_label TEXT,
        target_label TEXT,
        source_type TEXT,
        target_type TEXT,
        relationship_type TEXT NOT NULL,
        supporting_event_ids TEXT NOT NULL,
        rule_id TEXT,
        strength TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
        FOREIGN KEY (source_entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE,
        FOREIGN KEY (target_entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        title TEXT NOT NULL,
        claim_text TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        supporting_event_ids TEXT NOT NULL,
        contradicting_event_ids TEXT NOT NULL,
        related_evidence_ids TEXT NOT NULL,
        rule_or_model_id TEXT NOT NULL,
        mitre_attack_id TEXT,
        mitre_attack_name TEXT,
        confidence_label TEXT NOT NULL,
        confidence_rationale TEXT NOT NULL,
        status TEXT DEFAULT 'proposed',
        reviewer_id TEXT,
        reviewed_at TEXT,
        reviewer_notes TEXT,
        limitations TEXT NOT NULL,
        next_steps TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_events (
        audit_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        evidence_id TEXT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        timezone TEXT DEFAULT 'UTC',
        reason TEXT NOT NULL,
        details TEXT NOT NULL,
        previous_event_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        signature_reference TEXT,
        FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence_items(case_id);
    CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
    CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp_utc);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_entities_case ON entities(case_id, canonical_value);
    CREATE INDEX IF NOT EXISTS idx_relationships_case ON relationships(case_id);
    CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
    CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id, timestamp);
    """)
    conn.commit()
    conn.close()


# Case Repository Functions
def insert_case(case_data: Dict[str, Any], db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO cases (case_id, title, description, created_by, created_at, case_timezone, scope_notes, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_data["case_id"],
        case_data["title"],
        case_data["description"],
        case_data["created_by"],
        case_data["created_at"],
        case_data.get("case_timezone", "UTC"),
        case_data.get("scope_notes"),
        case_data.get("status", "active")
    ))
    conn.commit()
    conn.close()


def get_case(case_id: str, db_path: Path = DB_PATH) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_cases(db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM cases ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# Evidence Repository Functions
def insert_evidence(ev: Dict[str, Any], db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO evidence_items (
            evidence_id, case_id, original_filename, source_type, source_description,
            storage_uri, size_bytes, detected_mime_type, sha256_initial, sha256_current,
            verification_status, received_at, received_by, acquisition_time,
            acquisition_timezone, authorization_reference, collection_notes,
            parser_status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ev["evidence_id"], ev["case_id"], ev["original_filename"], ev["source_type"],
        ev["source_description"], ev["storage_uri"], ev["size_bytes"], ev["detected_mime_type"],
        ev["sha256_initial"], ev["sha256_current"], ev["verification_status"],
        ev["received_at"], ev["received_by"], ev.get("acquisition_time"),
        ev.get("acquisition_timezone"), ev.get("authorization_reference"),
        ev.get("collection_notes"), ev.get("parser_status", "pending"), ev["created_at"]
    ))
    conn.commit()
    conn.close()


def update_evidence_hash(evidence_id: str, sha256_current: str, status: str, db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        UPDATE evidence_items
        SET sha256_current = ?, verification_status = ?
        WHERE evidence_id = ?
    """, (sha256_current, status, evidence_id))
    conn.commit()
    conn.close()


def update_evidence_parser_status(evidence_id: str, status: str, db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE evidence_items SET parser_status = ? WHERE evidence_id = ?", (status, evidence_id))
    conn.commit()
    conn.close()


def get_evidence(evidence_id: str, db_path: Path = DB_PATH) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM evidence_items WHERE evidence_id = ?", (evidence_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_evidence_for_case(case_id: str, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM evidence_items WHERE case_id = ? ORDER BY received_at ASC", (case_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# Event Repository Functions
def insert_event(event: Dict[str, Any], db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO events (
            event_id, case_id, evidence_id, event_type, summary,
            raw_timestamp, timezone_original, timestamp_utc, timestamp_quality,
            source_locator, parser_name, parser_version, raw_fields, entities
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["event_id"], event["case_id"], event["evidence_id"], event["event_type"],
        event["summary"], event["raw_timestamp"], event["timezone_original"],
        event["timestamp_utc"], event["timestamp_quality"],
        json.dumps(event.get("source_locator", {})),
        event["parser_name"], event["parser_version"],
        json.dumps(event.get("raw_fields", {})),
        json.dumps(event.get("entities", []))
    ))
    conn.commit()
    conn.close()


def list_events_for_case(case_id: str, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM events WHERE case_id = ? ORDER BY timestamp_utc ASC", (case_id,))
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["source_locator"] = json.loads(d["source_locator"]) if d.get("source_locator") else {}
        d["raw_fields"] = json.loads(d["raw_fields"]) if d.get("raw_fields") else {}
        d["entities"] = json.loads(d["entities"]) if d.get("entities") else []
        results.append(d)
    return results


# Entity & Relationship Repository Functions
def upsert_entity(entity: Dict[str, Any], db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO entities (entity_id, case_id, entity_type, canonical_value, normalization_method, first_seen, last_seen, event_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(entity_id) DO UPDATE SET
            last_seen = excluded.last_seen,
            event_count = entities.event_count + 1
    """, (
        entity["entity_id"], entity["case_id"], entity["entity_type"],
        entity["canonical_value"], entity["normalization_method"],
        entity.get("first_seen"), entity.get("last_seen")
    ))
    conn.commit()
    conn.close()


def list_entities_for_case(case_id: str, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM entities WHERE case_id = ? ORDER BY event_count DESC", (case_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def insert_relationship(rel: Dict[str, Any], db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO relationships (
            relationship_id, case_id, source_entity_id, target_entity_id,
            source_label, target_label, source_type, target_type,
            relationship_type, supporting_event_ids, rule_id, strength, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rel["relationship_id"], rel["case_id"], rel["source_entity_id"], rel["target_entity_id"],
        rel.get("source_label", ""), rel.get("target_label", ""),
        rel.get("source_type", ""), rel.get("target_type", ""),
        rel["relationship_type"], json.dumps(rel.get("supporting_event_ids", [])),
        rel.get("rule_id"), rel.get("strength", "strong_technical"), rel["created_at"]
    ))
    conn.commit()
    conn.close()


def list_relationships_for_case(case_id: str, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM relationships WHERE case_id = ?", (case_id,))
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["supporting_event_ids"] = json.loads(d["supporting_event_ids"]) if d.get("supporting_event_ids") else []
        results.append(d)
    return results


# Finding Repository Functions
def insert_finding(f: Dict[str, Any], db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO findings (
            finding_id, case_id, title, claim_text, finding_type,
            supporting_event_ids, contradicting_event_ids, related_evidence_ids,
            rule_or_model_id, mitre_attack_id, mitre_attack_name,
            confidence_label, confidence_rationale, status, reviewer_id, reviewed_at,
            reviewer_notes, limitations, next_steps
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        f["finding_id"], f["case_id"], f["title"], f["claim_text"], f["finding_type"],
        json.dumps(f.get("supporting_event_ids", [])),
        json.dumps(f.get("contradicting_event_ids", [])),
        json.dumps(f.get("related_evidence_ids", [])),
        f["rule_or_model_id"], f.get("mitre_attack_id"), f.get("mitre_attack_name"),
        f["confidence_label"], f["confidence_rationale"],
        f.get("status", "proposed"), f.get("reviewer_id"), f.get("reviewed_at"),
        f.get("reviewer_notes"), f["limitations"], f["next_steps"]
    ))
    conn.commit()
    conn.close()


def update_finding_review(finding_id: str, status: str, notes: Optional[str], reviewer_id: str, reviewed_at: str, db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        UPDATE findings
        SET status = ?, reviewer_notes = ?, reviewer_id = ?, reviewed_at = ?
        WHERE finding_id = ?
    """, (status, notes, reviewer_id, reviewed_at, finding_id))
    conn.commit()
    conn.close()


def list_findings_for_case(case_id: str, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings WHERE case_id = ? ORDER BY finding_id ASC", (case_id,))
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["supporting_event_ids"] = json.loads(d["supporting_event_ids"]) if d.get("supporting_event_ids") else []
        d["contradicting_event_ids"] = json.loads(d["contradicting_event_ids"]) if d.get("contradicting_event_ids") else []
        d["related_evidence_ids"] = json.loads(d["related_evidence_ids"]) if d.get("related_evidence_ids") else []
        results.append(d)
    return results


# Audit Ledger Repository Functions
def insert_audit_event(audit: Dict[str, Any], db_path: Path = DB_PATH):
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_events (
            audit_id, case_id, evidence_id, actor, action, timestamp, timezone,
            reason, details, previous_event_hash, event_hash, signature_reference
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        audit["audit_id"], audit["case_id"], audit.get("evidence_id"),
        audit["actor"], audit["action"], audit["timestamp"],
        audit.get("timezone", "UTC"), audit["reason"],
        json.dumps(audit.get("details", {})),
        audit["previous_event_hash"], audit["event_hash"],
        audit.get("signature_reference")
    ))
    conn.commit()
    conn.close()


def get_latest_audit_event(case_id: str, db_path: Path = DB_PATH) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_events WHERE case_id = ? ORDER BY timestamp DESC LIMIT 1", (case_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["details"] = json.loads(d["details"]) if d.get("details") else {}
        return d
    return None


def list_audit_events_for_case(case_id: str, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_events WHERE case_id = ? ORDER BY timestamp ASC", (case_id,))
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d["details"]) if d.get("details") else {}
        results.append(d)
    return results
