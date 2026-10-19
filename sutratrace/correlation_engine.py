"""
Entity Extraction, Normalization & Graph Correlation Engine for SutraTrace.
Builds the cross-source relationship graph with explicit match strengths.
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple
from sutratrace import database


def extract_and_correlate(case_id: str, db_path: Path = database.DB_PATH) -> Dict[str, Any]:
    """
    Scans all parsed events for the case:
    1. Extracts and normalizes canonical entities (users, hosts, IPs, domains, file hashes).
    2. Links events to entities in event_entities table.
    3. Builds cross-source relationships with explicit match strength and provenance.
    """
    events = database.list_events_for_case(case_id, db_path=db_path)
    if not events:
        return {"entities_count": 0, "relationships_count": 0}

    entity_map: Dict[str, Dict[str, Any]] = {}
    event_entity_links: List[Tuple[str, str, str, str, str]] = []

    # 1. Entity Extraction & Normalization
    for ev in events:
        ev_id = ev["event_id"]
        ev_time = ev["timestamp_utc"]

        for item in ev.get("entities", []):
            if ":" not in item:
                continue
            e_type, e_val = item.split(":", 1)
            e_type = e_type.strip().lower()
            e_val = e_val.strip().lower()

            entity_id = f"ent_{e_type}_{e_val.replace(' ', '_').replace('/', '_').replace(':', '_')[:32]}"

            if entity_id not in entity_map:
                entity_map[entity_id] = {
                    "entity_id": entity_id,
                    "case_id": case_id,
                    "entity_type": e_type,
                    "canonical_value": e_val,
                    "normalization_method": f"lowercase_canonical_{e_type}",
                    "first_seen": ev_time,
                    "last_seen": ev_time,
                    "event_count": 1
                }
            else:
                ent = entity_map[entity_id]
                if ev_time < ent["first_seen"]:
                    ent["first_seen"] = ev_time
                if ev_time > ent["last_seen"]:
                    ent["last_seen"] = ev_time
                ent["event_count"] += 1

            # Match strength logic
            strength = "strong_technical" if e_type in ["file_hash", "ip"] else "moderate"
            event_entity_links.append((ev_id, entity_id, "observed_entity", "exact_extracted", strength))

    # Upsert entities into DB
    for ent in entity_map.values():
        database.upsert_entity(ent, db_path=db_path)

    # 2. Build Multi-Source Relationships
    relationships: List[Dict[str, Any]] = []
    now_str = datetime.now(timezone.utc).isoformat()

    # (a) Co-occurrence in single events (e.g. user on host, user created file_path, file_path has file_hash)
    for ev in events:
        ev_id = ev["event_id"]
        ev_entities = [item for item in ev.get("entities", []) if ":" in item]

        # Group entities in this event by type
        typed_entities: Dict[str, List[str]] = {}
        for item in ev_entities:
            t, v = item.split(":", 1)
            t = t.lower()
            v = v.lower()
            typed_entities.setdefault(t, []).append(v)

        # Link User -> Host
        for u in typed_entities.get("user", []):
            u_id = f"ent_user_{u[:32]}"
            for h in typed_entities.get("host", []):
                h_id = f"ent_host_{h[:32]}"
                relationships.append({
                    "relationship_id": f"rel_{u}_{h}_{ev['event_type']}",
                    "case_id": case_id,
                    "source_entity_id": u_id,
                    "target_entity_id": h_id,
                    "source_label": f"User: {u}",
                    "target_label": f"Host: {h}",
                    "source_type": "user",
                    "target_type": "host",
                    "relationship_type": "logged_in_to" if "auth" in ev["event_type"] else "observed_on",
                    "supporting_event_ids": [ev_id],
                    "strength": "strong_technical" if "auth" in ev["event_type"] else "moderate",
                    "rule_id": "CORR-01-USER-HOST",
                    "created_at": now_str
                })

            # Link User -> File Path / Archive
            for fp in typed_entities.get("file_path", []):
                fp_id = f"ent_file_path_{fp.replace(' ', '_').replace('/', '_').replace(':', '_')[:32]}"
                relationships.append({
                    "relationship_id": f"rel_{u}_{fp[:16]}",
                    "case_id": case_id,
                    "source_entity_id": u_id,
                    "target_entity_id": fp_id,
                    "source_label": f"User: {u}",
                    "target_label": f"File: {Path(fp).name or fp}",
                    "source_type": "user",
                    "target_type": "file_path",
                    "relationship_type": "accessed_or_created",
                    "supporting_event_ids": [ev_id],
                    "strength": "moderate",
                    "rule_id": "CORR-02-USER-FILE",
                    "created_at": now_str
                })

        # Link File Path -> File Hash (Strong Technical Match!)
        for fp in typed_entities.get("file_path", []):
            fp_id = f"ent_file_path_{fp.replace(' ', '_').replace('/', '_').replace(':', '_')[:32]}"
            for fh in typed_entities.get("file_hash", []):
                fh_id = f"ent_file_hash_{fh[:32]}"
                relationships.append({
                    "relationship_id": f"rel_hash_{fp[:16]}_{fh[:8]}",
                    "case_id": case_id,
                    "source_entity_id": fp_id,
                    "target_entity_id": fh_id,
                    "source_label": f"File: {Path(fp).name or fp}",
                    "target_label": f"SHA256: {fh[:12]}...",
                    "source_type": "file_path",
                    "target_type": "file_hash",
                    "relationship_type": "same_hash_as",
                    "supporting_event_ids": [ev_id],
                    "strength": "strong_technical",
                    "rule_id": "CORR-03-HASH-EXACT",
                    "created_at": now_str
                })

        # Link Host / IP -> Domain (Network activity)
        for d in typed_entities.get("domain", []):
            d_id = f"ent_domain_{d[:32]}"
            for ip in typed_entities.get("ip", []):
                ip_id = f"ent_ip_{ip[:32]}"
                relationships.append({
                    "relationship_id": f"rel_net_{ip[:10]}_{d[:16]}",
                    "case_id": case_id,
                    "source_entity_id": ip_id,
                    "target_entity_id": d_id,
                    "source_label": f"IP: {ip}",
                    "target_label": f"Domain: {d}",
                    "source_type": "ip",
                    "target_type": "domain",
                    "relationship_type": "connected_to",
                    "supporting_event_ids": [ev_id],
                    "strength": "strong_technical",
                    "rule_id": "CORR-04-IP-DOMAIN",
                    "created_at": now_str
                })

    # (b) Cross-source correlation: User visiting Domain in Browser AND Proxy seeing Outbound POST to same Domain
    browser_visits = [e for e in events if "browser" in e["event_type"]]
    proxy_transfers = [e for e in events if "network" in e["event_type"]]

    for bv in browser_visits:
        b_domains = [item.split(":", 1)[1] for item in bv.get("entities", []) if item.startswith("domain:")]
        b_users = [item.split(":", 1)[1] for item in bv.get("entities", []) if item.startswith("user:")]

        for dom in b_domains:
            dom_id = f"ent_domain_{dom[:32]}"
            for pt in proxy_transfers:
                p_domains = [item.split(":", 1)[1] for item in pt.get("entities", []) if item.startswith("domain:")]
                if dom in p_domains:
                    for usr in b_users:
                        usr_id = f"ent_user_{usr[:32]}"
                        relationships.append({
                            "relationship_id": f"rel_cross_{usr[:8]}_{dom[:16]}",
                            "case_id": case_id,
                            "source_entity_id": usr_id,
                            "target_entity_id": dom_id,
                            "source_label": f"User: {usr}",
                            "target_label": f"Destination: {dom}",
                            "source_type": "user",
                            "target_type": "domain",
                            "relationship_type": "initiated_transfer_to",
                            "supporting_event_ids": [bv["event_id"], pt["event_id"]],
                            "strength": "moderate",
                            "rule_id": "CORR-05-CROSS-BROWSER-PROXY",
                            "created_at": now_str
                        })

    # Deduplicate relationships by relationship_id
    deduped_rels: Dict[str, Dict[str, Any]] = {}
    for r in relationships:
        r_id = r["relationship_id"]
        if r_id in deduped_rels:
            # Combine supporting events
            existing = deduped_rels[r_id]
            for se in r["supporting_event_ids"]:
                if se not in existing["supporting_event_ids"]:
                    existing["supporting_event_ids"].append(se)
        else:
            deduped_rels[r_id] = r

    for r in deduped_rels.values():
        database.insert_relationship(r, db_path=db_path)

    return {
        "entities_count": len(entity_map),
        "relationships_count": len(deduped_rels)
    }


def get_cytoscape_elements(case_id: str, db_path: Path = database.DB_PATH) -> Dict[str, List[Dict[str, Any]]]:
    """
    Transforms entities and relationships into Cytoscape.js format for interactive UI rendering.
    """
    entities = database.list_entities_for_case(case_id, db_path=db_path)
    relationships = database.list_relationships_for_case(case_id, db_path=db_path)

    nodes = []
    # Palette by entity type
    type_colors = {
        "user": "#3b82f6",          # blue
        "host": "#8b5cf6",          # purple
        "file_hash": "#10b981",     # green
        "file_path": "#059669",     # dark green
        "domain": "#f59e0b",        # amber
        "ip": "#ec4899",            # pink
        "process": "#6366f1",       # indigo
        "cloud_resource": "#06b6d4" # cyan
    }

    for ent in entities:
        e_type = ent["entity_type"]
        val = ent["canonical_value"]
        short_val = (val[:24] + "...") if len(val) > 24 else val
        nodes.append({
            "data": {
                "id": ent["entity_id"],
                "label": f"{e_type.upper()}: {short_val}",
                "full_label": val,
                "type": e_type,
                "color": type_colors.get(e_type, "#64748b"),
                "event_count": ent["event_count"]
            }
        })

    edges = []
    for rel in relationships:
        edges.append({
            "data": {
                "id": rel["relationship_id"],
                "source": rel["source_entity_id"],
                "target": rel["target_entity_id"],
                "label": rel["relationship_type"].replace('_', ' '),
                "strength": rel["strength"],
                "rule_id": rel.get("rule_id", ""),
                "supporting_events": rel["supporting_event_ids"]
            }
        })

    return {"nodes": nodes, "edges": edges}
