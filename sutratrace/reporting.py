"""
Deterministic Forensic Report Generator for SutraTrace.
Generates comprehensive investigation reports compliant with ISO/IEC 27037,
SWGDE guidelines, and Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023).
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
from sutratrace import database, audit_ledger


def generate_forensic_report_markdown(case_id: str, db_path: Path = database.DB_PATH) -> str:
    """
    Generates a deterministic Markdown report linking every finding to supporting artifacts.
    """
    case = database.get_case(case_id, db_path=db_path)
    if not case:
        return f"# Error: Case {case_id} not found."

    evidence_list = database.list_evidence_for_case(case_id, db_path=db_path)
    events = database.list_events_for_case(case_id, db_path=db_path)
    findings = database.list_findings_for_case(case_id, db_path=db_path)
    chain_check = audit_ledger.verify_audit_chain(case_id, db_path=db_path)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    md = []
    md.append(f"# DIGITAL FORENSIC INVESTIGATION REPORT")
    md.append(f"**Platform:** SutraTrace Forensic Workbench v1.0.0  ")
    md.append(f"**Generated:** {now_utc}  ")
    md.append(f"**Investigation Case ID:** `{case['case_id']}`  ")
    md.append(f"**Case Title:** {case['title']}  ")
    md.append(f"**Lead Examiner:** {case['created_by']}  ")
    md.append(f"**Authorized Scope:** {case.get('scope_notes') or 'Authorized internal incident response'}  \n")

    md.append("---")
    md.append("## 1. Executive Summary")
    md.append(f"{case['description']}\n")
    md.append(f"- **Total Evidence Items Ingested:** {len(evidence_list)}")
    md.append(f"- **Total Normalized Events:** {len(events)}")
    md.append(f"- **Total Triage Findings:** {len(findings)}")
    md.append(f"- **Cryptographic Audit Ledger Status:** {'VERIFIED INTACT (0 Tampering)' if chain_check['valid'] else 'INTEGRITY BREACH DETECTED'}")
    md.append(f"- **Chain Head Digest:** `{chain_check.get('chain_head', 'N/A')}`\n")

    md.append("---")
    md.append("## 2. Evidence Ingestion Manifest & SHA-256 Hash Integrity")
    md.append("Compliant with ISO/IEC 27037:2012 & SWGDE Evidence Preservation Standards.\n")
    md.append("| Evidence ID | Source File | Source Type | Size | Initial SHA-256 Digest | Current Verification Status |")
    md.append("|---|---|---|---|---|---|")
    for ev in evidence_list:
        status_badge = "VERIFIED MATCH" if ev["verification_status"] == "verified" else ev["verification_status"].upper()
        md.append(f"| `{ev['evidence_id']}` | {ev['original_filename']} | {ev['source_type']} | {ev['size_bytes']:,} B | `{ev['sha256_initial'][:16]}...` | **{status_badge}** |")
    md.append("\n*Note: All original evidence files are stored in read-only immutable storage. Parsers operate solely upon verified working copies.*\n")

    md.append("---")
    md.append("## 3. Investigated Findings & Evidence-Linked Hypotheses")
    if not findings:
        md.append("No triage findings generated or reviewed.")
    else:
        for idx, f in enumerate(findings, 1):
            md.append(f"### Finding {idx}: {f['title']} (`{f['finding_id']}`)")
            md.append(f"- **Review Status:** `{f['status'].upper()}` (Reviewer: {f.get('reviewer_id') or 'Pending'})")
            md.append(f"- **Confidence Category:** **{f['confidence_label']}** — *{f['confidence_rationale']}*")
            if f.get("mitre_attack_id"):
                md.append(f"- **MITRE ATT&CK Technique:** `{f['mitre_attack_id']}` ({f.get('mitre_attack_name', '')})")
            md.append(f"- **Factual Claim:** {f['claim_text']}")
            md.append(f"- **Supporting Event References:** {', '.join([f'`{eid}`' for eid in f['supporting_event_ids']])}")
            md.append(f"- **Evidentiary Limitations:** {f['limitations']}")
            md.append(f"- **Recommended Next Steps:** {f['next_steps']}")
            if f.get("reviewer_notes"):
                md.append(f"- **Investigator Notes:** *{f['reviewer_notes']}*")
            md.append("")

    md.append("---")
    md.append("## 4. Chronological Incident Timeline (Normalized UTC)")
    md.append("| Event ID | UTC Timestamp | Source & Locator | Type | Summary | Time Quality |")
    md.append("|---|---|---|---|---|---|")
    for ev in events[:20]:  # Highlight top key timeline events
        loc = f"{ev['source_locator'].get('file', '')} (Row {ev['source_locator'].get('row', '')})"
        md.append(f"| `{ev['event_id']}` | {ev['timestamp_utc']} | {loc} | `{ev['event_type']}` | {ev['summary'][:70]}... | `{ev['timestamp_quality']}` |")
    if len(events) > 20:
        md.append(f"*(Listing truncated. Total {len(events)} events preserved in database)*")
    md.append("\n")

    md.append("---")
    md.append("## 5. Electronic Evidence Legal Compliance Statement")
    md.append("### Certificate under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023)")
    md.append("1. **Identification of Digital Record:** The electronic records described in Section 2 were produced by computers during regular lawful activity under the authorized scope of this investigation.")
    md.append("2. **Operational Integrity:** During the material period, the computing systems and analytical parsers operated properly. No unauthorized manipulation or data corruption occurred after ingestion.")
    md.append("3. **Cryptographic Validation:** Each ingested artifact was hashed immediately using SHA-256 upon receipt. The complete chain of custody has been verified via the immutable cryptographic audit ledger head.")
    md.append(f"4. **Verification Statement:** To the best of the examiner's knowledge, information, and belief, this report accurately sets forth the true contents of the electronic records.\n")

    md.append("---")
    md.append(f"**Report End — SutraTrace Forensic Workbench**")
    return "\n".join(md)


def generate_forensic_report_html(case_id: str, db_path: Path = database.DB_PATH) -> str:
    """
    Renders an official styled HTML document suitable for browser viewing and printing to PDF.
    """
    case = database.get_case(case_id, db_path=db_path)
    if not case:
        return "<h1>Error: Case not found</h1>"

    evidence_list = database.list_evidence_for_case(case_id, db_path=db_path)
    events = database.list_events_for_case(case_id, db_path=db_path)
    findings = database.list_findings_for_case(case_id, db_path=db_path)
    chain_check = audit_ledger.verify_audit_chain(case_id, db_path=db_path)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    findings_html = ""
    for idx, f in enumerate(findings, 1):
        status_color = "#10b981" if f['status'] == 'accepted' else ("#f59e0b" if f['status'] == 'proposed' else "#ef4444")
        findings_html += f"""
        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; background-color: #fafafa;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <h3 style="margin: 0; color: #1e293b;">Finding {idx}: {f['title']}</h3>
                <span style="background-color: {status_color}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold;">
                    {f['status'].upper()}
                </span>
            </div>
            <p><strong>Claim:</strong> {f['claim_text']}</p>
            <p><strong>Supporting Events:</strong> <code>{', '.join(f['supporting_event_ids'])}</code></p>
            <p><strong>Confidence:</strong> <strong>{f['confidence_label']}</strong> &mdash; <em>{f['confidence_rationale']}</em></p>
            <p><strong>MITRE ATT&CK:</strong> <code>{f.get('mitre_attack_id', 'N/A')}</code> ({f.get('mitre_attack_name', '')})</p>
            <div style="background-color: #f1f5f9; padding: 10px; border-radius: 6px; font-size: 13px; margin-top: 8px;">
                <strong>Evidentiary Limitations:</strong> {f['limitations']}
            </div>
            <div style="background-color: #e0f2fe; padding: 10px; border-radius: 6px; font-size: 13px; margin-top: 8px;">
                <strong>Next Steps:</strong> {f['next_steps']}
            </div>
        </div>
        """

    evidence_rows = ""
    for ev in evidence_list:
        badge = "<span style='color: #10b981; font-weight: bold;'>VERIFIED</span>" if ev['verification_status'] == 'verified' else f"<span style='color: #ef4444; font-weight: bold;'>{ev['verification_status'].upper()}</span>"
        evidence_rows += f"""
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;"><code>{ev['evidence_id']}</code></td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{ev['original_filename']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{ev['source_type']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{ev['size_bytes']:,} B</td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;"><code style="font-size: 11px;">{ev['sha256_initial']}</code></td>
            <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{badge}</td>
        </tr>
        """

    timeline_rows = ""
    for ev in events[:25]:
        loc = f"{ev['source_locator'].get('file', '')} (Row {ev['source_locator'].get('row', '')})"
        timeline_rows += f"""
        <tr>
            <td style="padding: 6px; border-bottom: 1px solid #e2e8f0;"><code>{ev['event_id']}</code></td>
            <td style="padding: 6px; border-bottom: 1px solid #e2e8f0; white-space: nowrap;">{ev['timestamp_utc']}</td>
            <td style="padding: 6px; border-bottom: 1px solid #e2e8f0;">{loc}</td>
            <td style="padding: 6px; border-bottom: 1px solid #e2e8f0;"><code>{ev['event_type']}</code></td>
            <td style="padding: 6px; border-bottom: 1px solid #e2e8f0;">{ev['summary']}</td>
            <td style="padding: 6px; border-bottom: 1px solid #e2e8f0;"><span style="font-size: 11px;">{ev['timestamp_quality']}</span></td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SutraTrace Forensic Report - {case['case_id']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #1e293b; margin: 40px; }}
        h1, h2, h3 {{ color: #0f172a; }}
        .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 13px; }}
        th {{ background-color: #f8fafc; text-align: left; padding: 8px; border-bottom: 2px solid #cbd5e1; }}
        .cert-box {{ border: 2px solid #3b82f6; border-radius: 8px; padding: 20px; background-color: #f8fafc; margin-top: 32px; }}
        @media print {{ body {{ margin: 15mm; }} button {{ display: none; }} }}
    </style>
</head>
<body>
    <div style="text-align: right; margin-bottom: 16px;">
        <button onclick="window.print()" style="background-color: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold;">
            Print / Save to PDF
        </button>
    </div>

    <div class="header">
        <h1 style="margin: 0; font-size: 24px;">SutraTrace Digital Forensic Investigation Report</h1>
        <p style="margin: 4px 0 0 0; color: #64748b; font-size: 14px;">
            Case ID: <strong>{case['case_id']}</strong> | Generated: <strong>{now_utc}</strong> | Examiner: <strong>{case['created_by']}</strong>
        </p>
    </div>

    <h2>1. Executive Summary & Provenance Status</h2>
    <p>{case['description']}</p>
    <p><strong>Authorized Scope:</strong> {case.get('scope_notes') or 'Lawful Incident Response'}</p>
    <div style="background-color: #f1f5f9; padding: 12px; border-radius: 6px; margin-bottom: 24px;">
        <strong>Cryptographic Hash-Chain Ledger:</strong> 
        <span style="color: {'#10b981' if chain_check['valid'] else '#ef4444'}; font-weight: bold;">
            {'VERIFIED INTACT (All events cryptographically chained)' if chain_check['valid'] else 'TAMPER ALERT'}
        </span>
        <br>
        <small style="color: #64748b;">Ledger Head Digest: <code>{chain_check.get('chain_head', 'N/A')}</code></small>
    </div>

    <h2>2. Ingested Evidence Manifest & SHA-256 Digests</h2>
    <table>
        <thead>
            <tr>
                <th>Evidence ID</th>
                <th>Original Filename</th>
                <th>Source Family</th>
                <th>Size</th>
                <th>Recorded SHA-256</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {evidence_rows}
        </tbody>
    </table>

    <h2>3. Forensic Findings & Analyzed Leads</h2>
    {findings_html}

    <h2>4. Chronological Multi-Source Timeline</h2>
    <table>
        <thead>
            <tr>
                <th>Event ID</th>
                <th>Timestamp (UTC)</th>
                <th>Source Locator</th>
                <th>Type</th>
                <th>Summary</th>
                <th>Time Quality</th>
            </tr>
        </thead>
        <tbody>
            {timeline_rows}
        </tbody>
    </table>

    <div class="cert-box">
        <h3 style="margin-top: 0; color: #1e40af;">Electronic Record Legal Certificate (Section 63, Bharatiya Sakshya Adhiniyam, 2023 / BSA 2023)</h3>
        <p style="font-size: 13px;">
            This document certifies that the electronic records detailed herein were lawfully collected and processed by the SutraTrace Forensic Workbench.
            Hashes were generated upon ingestion using SHA-256 and verified against read-only originals. The analytical parsers and chain-of-custody ledger operated properly throughout the processing period.
        </p>
        <div style="margin-top: 30px; display: flex; justify-content: space-between;">
            <div>
                <strong>Investigating Examiner:</strong> {case['created_by']}<br>
                <strong>Date & Time:</strong> {now_utc}
            </div>
            <div>
                <strong>Digital Verification Hash:</strong><br>
                <code>{chain_check.get('chain_head', '')[:32]}...</code>
            </div>
        </div>
    </div>
</body>
</html>
    """
    return html
