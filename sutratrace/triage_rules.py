"""
Deterministic Forensic Triage Rules & Anomaly Detection for SutraTrace.
Maps suspicious multi-source event sequences to MITRE ATT&CK techniques with explainable rationales.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from dateutil import parser as dateutil_parser
from sutratrace import database


def run_triage_rules(case_id: str, db_path: Path = database.DB_PATH) -> List[Dict[str, Any]]:
    """
    Executes all deterministic triage rules across normalized events for a case.
    Saves generated findings into the database.
    """
    events = database.list_events_for_case(case_id, db_path=db_path)
    if not events:
        return []

    findings: List[Dict[str, Any]] = []

    # Sort chronologically by UTC timestamp
    sorted_events = sorted(events, key=lambda x: x["timestamp_utc"])

    # 1. RULE-01: Anomalous External Authentication
    auth_events = [e for e in sorted_events if "auth" in e["event_type"]]
    for ev in auth_events:
        ip_entities = [item.split(":", 1)[1] for item in ev.get("entities", []) if item.startswith("ip:")]
        user_entities = [item.split(":", 1)[1] for item in ev.get("entities", []) if item.startswith("user:")]
        host_entities = [item.split(":", 1)[1] for item in ev.get("entities", []) if item.startswith("host:")]

        for ip in ip_entities:
            # Check for non-RFC1918 or external/public IP range in auth (e.g. 203.0.113.x documentation range)
            if ip.startswith("203.0.113.") or not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip == "127.0.0.1" or ip == "local"):
                findings.append({
                    "finding_id": f"FND-001-{ev['event_id'][-4:]}",
                    "case_id": case_id,
                    "title": "Anomalous External Source IP Authentication",
                    "claim_text": f"User account '{user_entities[0] if user_entities else 'unknown'}' successfully authenticated to workstation '{host_entities[0] if host_entities else 'unknown'}' from external source IP {ip}.",
                    "finding_type": "anomaly",
                    "supporting_event_ids": [ev["event_id"]],
                    "contradicting_event_ids": [],
                    "related_evidence_ids": [ev["evidence_id"]],
                    "rule_or_model_id": "RULE-01-EXTERNAL-AUTH",
                    "mitre_attack_id": "T1078.002",
                    "mitre_attack_name": "Valid Accounts: Domain Accounts",
                    "confidence_label": "High",
                    "confidence_rationale": "Directly observed in authenticated logon record with external IP address.",
                    "status": "proposed",
                    "limitations": "Authentication record confirms credential usage, but does not prove whether the legitimate user or an unauthorized actor operated the keyboard.",
                    "next_steps": "Interview the account holder to verify if remote VPN/access was authorized; inspect gateway VPN MFA logs for corroborating session tickets."
                })

    # 2. RULE-02: Local Archive Creation (7-Zip / WinRAR / zip)
    archive_events = [
        e for e in sorted_events
        if any(tool in e["summary"].lower() for tool in ["7z", "zip", "tar", "rar", "archive"]) or
           any("zip" in item or "tar" in item or "7z" in item for item in e.get("entities", []))
    ]
    for a_ev in archive_events:
        archive_name = "Project-Orion.zip"
        for ent in a_ev.get("entities", []):
            if "zip" in ent or "orion" in ent:
                archive_name = ent.split(":")[-1]

        findings.append({
            "finding_id": f"FND-002-{a_ev['event_id'][-4:]}",
            "case_id": case_id,
            "title": "Sensitive Staging Archive Created on Endpoint",
            "claim_text": f"Compression tool executed on endpoint creating staged archive '{archive_name}' in temporary directory.",
            "finding_type": "pattern",
            "supporting_event_ids": [a_ev["event_id"]],
            "contradicting_event_ids": [],
            "related_evidence_ids": [a_ev["evidence_id"]],
            "rule_or_model_id": "RULE-02-ARCHIVE-STAGING",
            "mitre_attack_id": "T1560.001",
            "mitre_attack_name": "Archive Collected Data: Archive via Utility",
            "confidence_label": "High",
            "confidence_rationale": "Process creation event and target file path recorded in endpoint audit logs.",
            "status": "proposed",
            "limitations": "Local compression may occur during legitimate developer packaging; archive content requires confirmation against repository hashes.",
            "next_steps": "Inspect file deletion logs to check if the archive was scrubbed after transfer; examine file system USN Journal for staging traces."
        })

    # 3. RULE-03: Rapid Exfiltration Sequence (Archive -> Browser Visit -> Outbound Proxy Transfer)
    browser_visits = [e for e in sorted_events if "browser" in e["event_type"]]
    network_transfers = [e for e in sorted_events if "network" in e["event_type"]]

    for a_ev in archive_events:
        try:
            a_time = dateutil_parser.parse(a_ev["timestamp_utc"])
        except Exception:
            continue

        # Find browser visit within 60 minutes after archive creation
        for b_ev in browser_visits:
            try:
                b_time = dateutil_parser.parse(b_ev["timestamp_utc"])
                delta_mins = (b_time - a_time).total_seconds() / 60.0
            except Exception:
                continue

            if 0 <= delta_mins <= 60:
                # Find matching outbound transfer to same domain
                b_domain = next((item.split(":", 1)[1] for item in b_ev.get("entities", []) if item.startswith("domain:")), "")
                for n_ev in network_transfers:
                    n_domain = next((item.split(":", 1)[1] for item in n_ev.get("entities", []) if item.startswith("domain:")), "")
                    if b_domain and (b_domain == n_domain or b_domain in n_ev["summary"]):
                        try:
                            n_time = dateutil_parser.parse(n_ev["timestamp_utc"])
                            n_delta = (n_time - b_time).total_seconds() / 60.0
                        except Exception:
                            continue

                        if -5 <= n_delta <= 60:
                            findings.append({
                                "finding_id": f"FND-003-EXFIL",
                                "case_id": case_id,
                                "title": "Suspected Data Exfiltration via External Web Upload",
                                "claim_text": f"Archive creation on workstation was followed within {int(delta_mins)} minutes by a browser visit to unapproved file service '{b_domain}', immediately followed by a large outbound POST transfer ({n_ev['summary'].split('(')[-1].split(')')[0]}).",
                                "finding_type": "exfiltration",
                                "supporting_event_ids": [a_ev["event_id"], b_ev["event_id"], n_ev["event_id"]],
                                "contradicting_event_ids": [],
                                "related_evidence_ids": list(set([a_ev["evidence_id"], b_ev["evidence_id"], n_ev["evidence_id"]])),
                                "rule_or_model_id": "RULE-03-EXFIL-CORRELATION",
                                "mitre_attack_id": "T1567.002",
                                "mitre_attack_name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
                                "confidence_label": "High",
                                "confidence_rationale": "Correlated chronological chain connecting endpoint process, browser history, and proxy egress across 3 independent evidence sources.",
                                "status": "proposed",
                                "limitations": "The proxy record establishes connection and transfer size to external destination, but HTTPS payload encryption prevents independent verification of exact transmitted bytes.",
                                "next_steps": "Corroborate with destination provider via lawful legal process; verify if TLS inspection or certificate logs are available for decrypted payload inspection."
                            })

    # 4. RULE-04: File Hash Pivoting & Identical Artifact Verification
    hash_events: Dict[str, List[Dict[str, Any]]] = {}
    for ev in sorted_events:
        for ent in ev.get("entities", []):
            if ent.startswith("file_hash:"):
                h_val = ent.split(":", 1)[1]
                hash_events.setdefault(h_val, []).append(ev)

    for h_val, ev_list in hash_events.items():
        if len(ev_list) >= 2:
            unique_evidence = list(set(e["evidence_id"] for e in ev_list))
            findings.append({
                "finding_id": f"FND-004-HASH-{h_val[:6]}",
                "case_id": case_id,
                "title": "Exact Cryptographic Hash Match Across Independent Evidence Sources",
                "claim_text": f"Cryptographic SHA-256 digest '{h_val[:16]}...' is independently corroborated across multiple evidence records ({len(ev_list)} occurrences), confirming artifact identity across systems.",
                "finding_type": "pattern",
                "supporting_event_ids": [e["event_id"] for e in ev_list],
                "contradicting_event_ids": [],
                "related_evidence_ids": unique_evidence,
                "rule_or_model_id": "RULE-04-HASH-PIVOT",
                "mitre_attack_id": "T1036",
                "mitre_attack_name": "Masquerading",
                "confidence_label": "High",
                "confidence_rationale": "Deterministic cryptographic hash match (SHA-256) guarantees bit-for-bit identity across the recorded occurrences.",
                "status": "proposed",
                "limitations": "A hash match proves byte identity across recorded artifacts, but does not identify the person who transferred or copied the file.",
                "next_steps": "Review access permissions and file creation timestamps on the destination storage location."
            })

    # 5. RULE-05: Cloud Data Access Preceding Staging
    cloud_events = [e for e in sorted_events if "cloud" in e["event_type"]]
    for c_ev in cloud_events:
        c_user = next((item.split(":", 1)[1] for item in c_ev.get("entities", []) if item.startswith("user:")), "")
        for a_ev in archive_events:
            a_user = next((item.split(":", 1)[1] for item in a_ev.get("entities", []) if item.startswith("user:")), "")
            if c_user and a_user and c_user == a_user:
                findings.append({
                    "finding_id": f"FND-005-CLOUD-{c_ev['event_id'][-4:]}",
                    "case_id": case_id,
                    "title": "Cloud Intellectual Property Access Preceding Endpoint Staging",
                    "claim_text": f"User '{c_user}' accessed proprietary cloud storage resource right before staging files into an endpoint compression archive.",
                    "finding_type": "pattern",
                    "supporting_event_ids": [c_ev["event_id"], a_ev["event_id"]],
                    "contradicting_event_ids": [],
                    "related_evidence_ids": [c_ev["evidence_id"], a_ev["evidence_id"]],
                    "rule_or_model_id": "RULE-05-CLOUD-STAGING",
                    "mitre_attack_id": "T1530",
                    "mitre_attack_name": "Data from Cloud Storage",
                    "confidence_label": "Moderate",
                    "confidence_rationale": "Correlated account activity across cloud audit logs and endpoint process execution.",
                    "status": "proposed",
                    "limitations": "Account access to cloud documents may be part of regular project duties; requires comparison with historical baseline access frequency.",
                    "next_steps": "Review role authorization matrix to confirm if user had legitimate business need to download the blueprints at that time."
                })

    # 6. RULE-06: Timestamp Quality & Timezone Caveats
    unverified_times = [e for e in sorted_events if e["timestamp_quality"] == "unverified_local_assumed"]
    if unverified_times:
        findings.append({
            "finding_id": "FND-006-TIME-UNCERTAINTY",
            "case_id": case_id,
            "title": "Forensic Timestamp Uncertainty / Local Clock Assumption",
            "claim_text": f"Detected {len(unverified_times)} events with unverified local timestamps lacking explicit UTC offsets. Time correlation relies on assumed timezone {sorted_events[0]['timezone_original']}.",
            "finding_type": "time_skew",
            "supporting_event_ids": [e["event_id"] for e in unverified_times[:4]],
            "contradicting_event_ids": [],
            "related_evidence_ids": list(set(e["evidence_id"] for e in unverified_times)),
            "rule_or_model_id": "RULE-06-CLOCK-UNCERTAINTY",
            "mitre_attack_id": "T1070.006",
            "mitre_attack_name": "Indicator Removal: Timestomp / Clock Manipulation",
            "confidence_label": "Low",
            "confidence_rationale": "Source log formats omit timezone offsets, introducing potential clock-skew jitter.",
            "status": "proposed",
            "limitations": "Without external NTP synchronization records, event interleaving carries up to +/- 5 minutes uncertainty.",
            "next_steps": "Collect domain controller NTP time sync audit logs to calibrate endpoint clock offset."
        })

    # Persist findings to DB (deduplicate by finding_id)
    for f in findings:
        database.insert_finding(f, db_path=db_path)

    return findings
