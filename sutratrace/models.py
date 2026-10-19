"""
Pydantic Data Models for SutraTrace Digital Forensics Framework.
Compliant with NIST SP 800-86, ISO/IEC 27037, and SWGDE guidelines.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field


class Case(BaseModel):
    case_id: str
    title: str
    description: str
    created_by: str
    created_at: str
    case_timezone: str = "UTC"
    scope_notes: Optional[str] = None
    status: str = "active"  # active, archived, closed


class CaseCreate(BaseModel):
    title: str
    description: str
    created_by: str = "Examiner"
    case_timezone: str = "UTC"
    scope_notes: Optional[str] = None


class EvidenceItem(BaseModel):
    evidence_id: str
    case_id: str
    original_filename: str
    source_type: str  # auth_log, endpoint_process, browser_history, firewall_proxy, file_inventory, cloud_audit, email_eml, general
    source_description: str
    storage_uri: str
    size_bytes: int
    detected_mime_type: str
    sha256_initial: str
    sha256_current: str
    verification_status: str  # verified, mismatch, unverified
    received_at: str
    received_by: str
    acquisition_time: Optional[str] = None
    acquisition_timezone: Optional[str] = None
    authorization_reference: Optional[str] = None
    collection_notes: Optional[str] = None
    parser_status: str = "pending"  # pending, parsed, failed, skipped
    created_at: str


class ProcessingRun(BaseModel):
    run_id: str
    evidence_id: str
    parser_name: str
    parser_version: str
    started_at: str
    ended_at: str
    status: str  # completed, failed, warnings
    events_count: int = 0
    warnings: List[str] = Field(default_factory=list)
    error_summary: Optional[str] = None


class Event(BaseModel):
    event_id: str
    case_id: str
    evidence_id: str
    event_type: str
    summary: str
    raw_timestamp: str
    timezone_original: str
    timestamp_utc: str
    timestamp_quality: str  # verified_utc, source_timezone_declared, unverified_local, clock_skew_suspected
    source_locator: Dict[str, Any]  # e.g. {"file": "auth.csv", "row": 12}
    parser_name: str
    parser_version: str
    raw_fields: Dict[str, Any] = Field(default_factory=dict)
    entities: List[str] = Field(default_factory=list)  # e.g. ["user:alex", "ip:203.0.113.24", "hash:abcd..."]


class Entity(BaseModel):
    entity_id: str
    case_id: str
    entity_type: str  # user, host, ip, domain, file_hash, file_path, process, cloud_resource
    canonical_value: str
    normalization_method: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    event_count: int = 0


class EventEntity(BaseModel):
    event_id: str
    entity_id: str
    role: str  # actor, target, source, artifact, network_endpoint
    match_method: str  # exact_extracted, parsed_url, hash_digest
    match_strength: str  # strong_technical, moderate, weak_contextual
    notes: Optional[str] = None


class Relationship(BaseModel):
    relationship_id: str
    case_id: str
    source_entity_id: str
    target_entity_id: str
    source_label: str = ""
    target_label: str = ""
    source_type: str = ""
    target_type: str = ""
    relationship_type: str  # observed_on, downloaded_from, same_hash_as, connected_to, created_by, accessed
    supporting_event_ids: List[str] = Field(default_factory=list)
    rule_id: Optional[str] = None
    strength: str = "strong_technical"  # strong_technical, moderate, weak_contextual
    created_at: str


class Finding(BaseModel):
    finding_id: str
    case_id: str
    title: str
    claim_text: str
    finding_type: str  # anomaly, pattern, exfiltration, tamper, time_skew
    supporting_event_ids: List[str] = Field(default_factory=list)
    contradicting_event_ids: List[str] = Field(default_factory=list)
    related_evidence_ids: List[str] = Field(default_factory=list)
    rule_or_model_id: str
    mitre_attack_id: Optional[str] = None
    mitre_attack_name: Optional[str] = None
    confidence_label: str  # High, Moderate, Low, Needs Corroboration
    confidence_rationale: str
    status: str = "proposed"  # proposed, reviewed, accepted, rejected, needs_followup
    reviewer_id: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewer_notes: Optional[str] = None
    limitations: str
    next_steps: str


class AuditEvent(BaseModel):
    audit_id: str
    case_id: str
    evidence_id: Optional[str] = None
    actor: str
    action: str  # ingested, verified, parsed, queried, exported, tampered_simulated, finding_updated, case_created
    timestamp: str
    timezone: str = "UTC"
    reason: str
    details: Dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: str
    event_hash: str
    signature_reference: Optional[str] = None


class AskQuestionRequest(BaseModel):
    question: str
    case_id: str


class AskQuestionResponse(BaseModel):
    question: str
    observed_records: str
    interpretation: str
    counter_evidence: str
    unresolved_assumptions: str
    suggested_next_steps: str
    cited_event_ids: List[str]
    cited_evidence_ids: List[str]
    validated: bool
    model_name: str
    confidence_label: str


class ReviewFindingRequest(BaseModel):
    status: str  # accepted, rejected, needs_followup, reviewed
    reviewer_notes: Optional[str] = None
    reviewer_id: str = "Lead Investigator"
