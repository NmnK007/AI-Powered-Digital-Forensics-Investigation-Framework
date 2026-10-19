/**
 * SutraTrace Forensic Workbench Client
 * Dynamic UI management, Cytoscape graph rendering, live verification,
 * tamper simulation, grounded AI querying, and audit chain verification.
 */

let currentCaseId = "CASE-2026-ORION";
let cyInstance = null;
let allTimelineEvents = [];
let allEvidenceItems = [];

// Initialize on page load
document.addEventListener("DOMContentLoaded", async () => {
    lucide.createIcons();
    await loadCaseSummary();
    await loadEvidence();
    await loadTimeline();
    await loadFindings();
});

// Tab Switcher
function switchTab(tabName) {
    document.querySelectorAll(".view-panel").forEach(el => el.classList.add("hidden"));
    document.querySelectorAll(".nav-tab").forEach(el => {
        el.classList.remove("bg-indigo-600", "text-white", "shadow-sm");
        el.classList.add("text-slate-400");
    });

    const activeView = document.getElementById(`view-${tabName}`);
    const activeTab = document.getElementById(`tab-${tabName}`);
    if (activeView) activeView.classList.remove("hidden");
    if (activeTab) {
        activeTab.classList.add("bg-indigo-600", "text-white", "shadow-sm");
        activeTab.classList.remove("text-slate-400");
    }

    if (tabName === "graph") {
        setTimeout(initGraph, 100);
    } else if (tabName === "report") {
        loadReportPreview();
        loadAuditTrail();
    }

    lucide.createIcons();
}

// ----------------- CASE SUMMARY -----------------
async function loadCaseSummary() {
    try {
        const res = await fetch(`/api/cases/${currentCaseId}`);
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById("case-id-badge").innerText = data.case.case_id;
        document.getElementById("case-title").innerText = data.case.title;
        document.getElementById("case-desc").innerText = data.case.description;
        document.getElementById("case-tz-badge").innerText = `TZ: ${data.case.case_timezone}`;

        document.getElementById("stat-evidence-count").innerText = data.evidence_count;
        document.getElementById("stat-events-count").innerText = data.events_count;
        document.getElementById("stat-findings-count").innerText = data.findings_count;

        const chainStatusEl = document.getElementById("stat-chain-status");
        if (data.audit_chain_valid) {
            chainStatusEl.innerHTML = `<i data-lucide="check-check" class="w-6 h-6"></i> Intact`;
            chainStatusEl.className = "text-3xl font-extrabold text-emerald-400 flex items-center gap-1.5";
        } else {
            chainStatusEl.innerHTML = `<i data-lucide="alert-octagon" class="w-6 h-6"></i> Breached`;
            chainStatusEl.className = "text-3xl font-extrabold text-rose-500 flex items-center gap-1.5";
        }
        document.getElementById("stat-chain-head").innerText = `Head: ${data.chain_head ? data.chain_head.substring(0, 16) + '...' : 'none'}`;

        // Top Integrity Banner
        const banner = document.getElementById("integrity-banner");
        const bTitle = document.getElementById("integrity-title");
        const bSub = document.getElementById("integrity-subtitle");

        if (data.hash_verification_status === "TAMPER_DETECTED") {
            banner.className = "rounded-xl border p-4 flex items-center justify-between transition bg-rose-950/40 border-rose-500/50 text-rose-300";
            bTitle.innerHTML = `<span class="text-rose-400 font-bold">⚠️ TAMPER DETECTED: Working Copy Hash Mismatch!</span>`;
            bSub.innerText = "One or more working copies have been modified. Preserved read-only original store remains intact.";
        } else if (data.hash_verification_status === "ALL_VERIFIED_MATCH") {
            banner.className = "rounded-xl border p-4 flex items-center justify-between transition bg-emerald-950/30 border-emerald-500/30 text-emerald-300";
            bTitle.innerText = "Evidence Integrity Status: 100% Cryptographically Verified";
            bSub.innerText = "All evidence artifacts match their initial recorded SHA-256 digests.";
        } else {
            banner.className = "rounded-xl border p-4 flex items-center justify-between transition bg-slate-900 border-slate-800 text-slate-300";
            bTitle.innerText = "Evidence Ingestion Status: Verification Pending";
            bSub.innerText = "Click 'Re-Verify Hashes' to recalculate SHA-256 for all items.";
        }
        lucide.createIcons();
    } catch (e) {
        console.error("Error loading case summary:", e);
    }
}

// ----------------- EVIDENCE VAULT -----------------
async function loadEvidence() {
    try {
        const res = await fetch(`/api/cases/${currentCaseId}/evidence`);
        allEvidenceItems = await res.json();
        renderEvidenceTable(allEvidenceItems);
    } catch (e) {
        console.error("Error loading evidence:", e);
    }
}

function renderEvidenceTable(items) {
    const tbody = document.getElementById("evidence-table-body");
    tbody.innerHTML = "";

    items.forEach(ev => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-slate-900/40 transition";

        let badgeClass = "bg-slate-800 text-slate-300 border-slate-700";
        let statusText = ev.verification_status.toUpperCase();
        if (ev.verification_status === "verified") {
            badgeClass = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
            statusText = "VERIFIED MATCH";
        } else if (ev.verification_status === "mismatch") {
            badgeClass = "bg-rose-500/20 text-rose-400 border-rose-500/40 animate-pulse";
            statusText = "TAMPER MISMATCH";
        }

        tr.innerHTML = `
            <td class="px-4 py-3 font-mono text-xs text-indigo-400">${ev.evidence_id}</td>
            <td class="px-4 py-3">
                <div class="font-semibold text-white">${ev.original_filename}</div>
                <div class="text-[11px] text-slate-400">${ev.source_description}</div>
            </td>
            <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                    ${ev.source_type}
                </span>
            </td>
            <td class="px-4 py-3 font-mono text-xs text-slate-400">${Number(ev.size_bytes).toLocaleString()} B</td>
            <td class="px-4 py-3 font-mono text-[11px] text-slate-400 truncate max-w-xs" title="${ev.sha256_initial}">
                ${ev.sha256_initial.substring(0, 16)}...
            </td>
            <td class="px-4 py-3">
                <span class="px-2.5 py-1 rounded-md text-[11px] font-semibold border ${badgeClass}">
                    ${statusText}
                </span>
            </td>
            <td class="px-4 py-3 text-right space-x-1">
                <button onclick="verifySingleEvidence('${ev.evidence_id}')" class="px-2 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition" title="Recompute SHA-256">
                    Verify
                </button>
                <button onclick="tamperDemo('${ev.evidence_id}')" class="px-2 py-1 text-xs rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 transition" title="Simulate 1-byte alteration">
                    Tamper Test
                </button>
                <button onclick="restoreEvidence('${ev.evidence_id}')" class="px-2 py-1 text-xs rounded bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 transition" title="Restore from immutable original">
                    Restore
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
    lucide.createIcons();
}

async function verifySingleEvidence(evidenceId) {
    try {
        const res = await fetch(`/api/evidence/${evidenceId}/verify`, { method: "POST" });
        const result = await res.json();
        alert(`Verification Result for ${evidenceId}:\nStatus: ${result.status.toUpperCase()}\nInitial: ${result.expected_sha256}\nCurrent: ${result.current_sha256}\nMessage: ${result.message}`);
        await loadCaseSummary();
        await loadEvidence();
    } catch (e) {
        alert("Verification failed: " + e.message);
    }
}

async function verifyAllHashes() {
    for (const item of allEvidenceItems) {
        await fetch(`/api/evidence/${item.evidence_id}/verify`, { method: "POST" });
    }
    await loadCaseSummary();
    await loadEvidence();
    alert("Batch verification completed for all evidence items.");
}

async function tamperDemo(evidenceId) {
    if (!confirm(`Simulate Tampering on evidence ${evidenceId}?\nThis will alter 1 byte in the working copy while leaving the preserved original intact.`)) return;
    try {
        const res = await fetch(`/api/evidence/${evidenceId}/tamper_test_simulate`, { method: "POST" });
        const data = await res.json();
        alert(`[TAMPER SIMULATED]\n${data.message}\nNew digest: ${data.new_hash}`);
        await loadCaseSummary();
        await loadEvidence();
    } catch (e) {
        alert("Tamper test error: " + e.message);
    }
}

function runTamperDemoOnItem() {
    if (allEvidenceItems.length > 0) {
        tamperDemo(allEvidenceItems[0].evidence_id);
    }
}

async function restoreEvidence(evidenceId) {
    try {
        const res = await fetch(`/api/evidence/${evidenceId}/restore`, { method: "POST" });
        const data = await res.json();
        alert(`[RESTORED]\nWorking copy restored from read-only original vault!\nDigest: ${data.sha256}`);
        await loadCaseSummary();
        await loadEvidence();
    } catch (e) {
        alert("Restore error: " + e.message);
    }
}

// ----------------- TIMELINE -----------------
async function loadTimeline() {
    try {
        const res = await fetch(`/api/cases/${currentCaseId}/timeline`);
        allTimelineEvents = await res.json();
        renderTimeline(allTimelineEvents);
    } catch (e) {
        console.error("Error loading timeline:", e);
    }
}

function renderTimeline(events) {
    const container = document.getElementById("timeline-container");
    container.innerHTML = "";

    if (events.length === 0) {
        container.innerHTML = `<div class="p-8 text-center text-slate-500 text-sm">No events match the current filter.</div>`;
        return;
    }

    events.forEach(ev => {
        const card = document.createElement("div");
        card.className = "bg-slate-900/60 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition space-y-2";

        // Source Lane styling
        let laneBadgeColor = "bg-slate-800 text-slate-300 border-slate-700";
        if (ev.lane.includes("Auth")) laneBadgeColor = "bg-blue-500/10 text-blue-400 border-blue-500/30";
        else if (ev.lane.includes("Endpoint")) laneBadgeColor = "bg-purple-500/10 text-purple-400 border-purple-500/30";
        else if (ev.lane.includes("Browser")) laneBadgeColor = "bg-amber-500/10 text-amber-400 border-amber-500/30";
        else if (ev.lane.includes("Network")) laneBadgeColor = "bg-rose-500/10 text-rose-400 border-rose-500/30";
        else if (ev.lane.includes("Cloud")) laneBadgeColor = "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";

        // Quality styling
        let qBadge = `<span class="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">${ev.timestamp_quality}</span>`;
        if (ev.timestamp_quality.includes("unverified")) {
            qBadge = `<span class="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">${ev.timestamp_quality}</span>`;
        }

        const entityChips = (ev.entities || []).map(ent => {
            return `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-950 text-slate-300 border border-slate-800 font-mono">${ent}</span>`;
        }).join(" ");

        card.innerHTML = `
            <div class="flex items-center justify-between text-xs">
                <div class="flex items-center space-x-2">
                    <span class="font-mono text-indigo-400 font-semibold">[${ev.event_id}]</span>
                    <span class="font-mono text-slate-300 font-bold">${ev.timestamp_utc}</span>
                    <span class="text-slate-500 font-mono text-[11px]">(Orig: ${ev.raw_timestamp} ${ev.timezone_original})</span>
                </div>
                <div class="flex items-center space-x-2">
                    <span class="px-2 py-0.5 rounded text-[11px] font-semibold border ${laneBadgeColor}">${ev.lane}</span>
                    ${qBadge}
                </div>
            </div>

            <p class="text-sm font-medium text-slate-100">${ev.summary}</p>

            <div class="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-800/60 text-xs text-slate-400">
                <div class="flex flex-wrap items-center gap-1.5">
                    ${entityChips}
                </div>
                <div class="font-mono text-[11px] text-slate-500">
                    Source: ${ev.source_locator.file || 'log'} (Row ${ev.source_locator.row || 'N/A'})
                </div>
            </div>
        `;
        container.appendChild(card);
    });
    lucide.createIcons();
}

function filterTimeline() {
    const q = document.getElementById("timeline-search").value.toLowerCase();
    const lane = document.getElementById("timeline-lane-filter").value;

    const filtered = allTimelineEvents.filter(ev => {
        const matchesQuery = !q || ev.summary.toLowerCase().includes(q) || (ev.entities || []).some(ent => ent.toLowerCase().includes(q));
        const matchesLane = lane === "ALL" || ev.lane === lane;
        return matchesQuery && matchesLane;
    });

    renderTimeline(filtered);
}

// ----------------- CORRELATION GRAPH -----------------
async function initGraph() {
    try {
        const res = await fetch(`/api/cases/${currentCaseId}/graph`);
        const graphData = await res.json();

        cyInstance = cytoscape({
            container: document.getElementById("cy"),
            elements: graphData,
            style: [
                {
                    selector: 'node',
                    style: {
                        'background-color': 'data(color)',
                        'label': 'data(label)',
                        'color': '#f8fafc',
                        'font-size': '11px',
                        'text-valign': 'bottom',
                        'text-margin-y': 4,
                        'width': 36,
                        'height': 36,
                        'border-width': 2,
                        'border-color': '#0f172a'
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 2,
                        'line-color': '#475569',
                        'target-arrow-color': '#475569',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'label': 'data(label)',
                        'color': '#94a3b8',
                        'font-size': '9px',
                        'text-rotation': 'autorotate',
                        'text-background-opacity': 0.8,
                        'text-background-color': '#020617',
                        'text-background-padding': 2
                    }
                },
                {
                    selector: 'edge[strength = "strong_technical"]',
                    style: {
                        'line-color': '#10b981',
                        'target-arrow-color': '#10b981',
                        'width': 3
                    }
                }
            ],
            layout: {
                name: 'cose',
                animate: false,
                padding: 40
            }
        });

        cyInstance.on('tap', 'node', function(evt){
            const node = evt.target;
            showNodeInspector(node.data());
        });

        cyInstance.on('tap', 'edge', function(evt){
            const edge = evt.target;
            showEdgeInspector(edge.data());
        });

    } catch (e) {
        console.error("Error loading graph:", e);
    }
}

function layoutGraph(layoutName) {
    if (!cyInstance) return;
    cyInstance.layout({ name: layoutName, animate: true, animationDuration: 400 }).run();
}

function showNodeInspector(data) {
    const el = document.getElementById("graph-inspector");
    const title = document.getElementById("inspector-title");
    const content = document.getElementById("inspector-content");

    el.classList.remove("hidden");
    title.innerText = `Entity: ${data.type.toUpperCase()}`;
    content.innerHTML = `
        <div class="space-y-1">
            <div><strong class="text-slate-400">Canonical Value:</strong> <span class="font-mono text-white select-all">${data.full_label}</span></div>
            <div><strong class="text-slate-400">Occurrences in Logs:</strong> <span class="text-indigo-400 font-bold">${data.event_count || 1} events</span></div>
            <div><strong class="text-slate-400">Classification:</strong> ${data.type}</div>
        </div>
    `;
}

function showEdgeInspector(data) {
    const el = document.getElementById("graph-inspector");
    const title = document.getElementById("inspector-title");
    const content = document.getElementById("inspector-content");

    el.classList.remove("hidden");
    title.innerText = `Relationship: ${data.label}`;
    content.innerHTML = `
        <div class="space-y-1">
            <div><strong class="text-slate-400">Match Strength:</strong> <span class="font-bold text-emerald-400">${data.strength}</span></div>
            <div><strong class="text-slate-400">Rule ID:</strong> ${data.rule_id || 'N/A'}</div>
            <div><strong class="text-slate-400">Supporting Events:</strong> <span class="font-mono text-indigo-400">${(data.supporting_events || []).join(', ')}</span></div>
        </div>
    `;
}

function closeInspector() {
    document.getElementById("graph-inspector").classList.add("hidden");
}

// ----------------- TRIAGE & FINDINGS -----------------
async function loadFindings() {
    try {
        const res = await fetch(`/api/cases/${currentCaseId}/findings`);
        const findings = await res.json();
        renderFindings(findings);
    } catch (e) {
        console.error("Error loading findings:", e);
    }
}

function renderFindings(findings) {
    const container = document.getElementById("findings-list");
    container.innerHTML = "";

    if (findings.length === 0) {
        container.innerHTML = `<div class="p-6 text-slate-500 text-xs">No triage leads found.</div>`;
        return;
    }

    findings.forEach(f => {
        const card = document.createElement("div");
        card.className = "bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-2.5 text-xs";

        let statusBadge = "bg-amber-500/10 text-amber-400 border-amber-500/30";
        if (f.status === "accepted") statusBadge = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
        else if (f.status === "rejected") statusBadge = "bg-rose-500/10 text-rose-400 border-rose-500/30";

        card.innerHTML = `
            <div class="flex items-center justify-between">
                <span class="font-mono font-bold text-indigo-400">${f.finding_id}</span>
                <span class="px-2 py-0.5 rounded text-[10px] font-semibold border ${statusBadge}">${f.status.toUpperCase()}</span>
            </div>

            <h4 class="font-bold text-white text-sm">${f.title}</h4>
            <p class="text-slate-300">${f.claim_text}</p>

            ${f.mitre_attack_id ? `
                <div class="flex items-center gap-1.5 text-[11px] text-slate-400 font-mono">
                    <span class="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-amber-400 font-bold">${f.mitre_attack_id}</span>
                    <span>${f.mitre_attack_name || ''}</span>
                </div>
            ` : ''}

            <div class="bg-slate-950 p-2.5 rounded-lg border border-slate-800/80 space-y-1 text-[11px]">
                <div><strong class="text-slate-400">Supporting Events:</strong> <code class="text-indigo-300">${(f.supporting_event_ids || []).join(', ')}</code></div>
                <div><strong class="text-slate-400">Confidence:</strong> <span class="text-emerald-400 font-semibold">${f.confidence_label}</span> &bull; <em>${f.confidence_rationale}</em></div>
                <div class="text-slate-400"><strong class="text-amber-400">Limitations:</strong> ${f.limitations}</div>
            </div>

            <div class="flex items-center justify-between pt-2 border-t border-slate-800/60">
                <span class="text-slate-500 text-[11px]">Rule: ${f.rule_or_model_id}</span>
                <button onclick="openReviewModal('${f.finding_id}', '${f.status}')" class="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 text-xs font-medium transition">
                    Review Decision
                </button>
            </div>
        `;
        container.appendChild(card);
    });
    lucide.createIcons();
}

async function retriggerTriage() {
    try {
        const res = await fetch(`/api/cases/${currentCaseId}/triage`, { method: "POST" });
        const data = await res.json();
        alert(`Triage completed: ${data.findings_count} findings evaluated.`);
        await loadFindings();
        await loadCaseSummary();
    } catch (e) {
        alert("Triage trigger error: " + e.message);
    }
}

function openReviewModal(findingId, currentStatus) {
    document.getElementById("review-finding-id").value = findingId;
    document.getElementById("review-status").value = currentStatus || "accepted";
    document.getElementById("review-modal").classList.remove("hidden");
}

function closeReviewModal() {
    document.getElementById("review-modal").classList.add("hidden");
}

async function handleReviewSubmit(e) {
    e.preventDefault();
    const fid = document.getElementById("review-finding-id").value;
    const status = document.getElementById("review-status").value;
    const notes = document.getElementById("review-notes").value;

    try {
        await fetch(`/api/findings/${fid}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                status: status,
                reviewer_notes: notes,
                reviewer_id: "Lead Investigator"
            })
        });
        closeReviewModal();
        await loadFindings();
        alert(`Finding ${fid} marked as ${status.toUpperCase()}`);
    } catch (err) {
        alert("Error saving review: " + err.message);
    }
}

// ----------------- GROUNDED AI ASSISTANT -----------------
function setQuery(q) {
    document.getElementById("ai-input").value = q;
    handleAiSubmit(new Event('submit'));
}

async function handleAiSubmit(e) {
    if (e && e.preventDefault) e.preventDefault();
    const input = document.getElementById("ai-input");
    const q = input.value.trim();
    if (!q) return;

    const display = document.getElementById("ai-chat-display");
    const btn = document.getElementById("ai-submit-btn");

    // Append user query message
    const userMsg = document.createElement("div");
    userMsg.className = "bg-indigo-600/10 border border-indigo-500/20 rounded-xl p-3 text-xs text-indigo-200 self-end";
    userMsg.innerHTML = `<strong class="text-white">Investigator:</strong> ${q}`;
    display.appendChild(userMsg);
    input.value = "";
    display.scrollTop = display.scrollHeight;

    // Loading placeholder
    const loadingMsg = document.createElement("div");
    loadingMsg.className = "bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs text-slate-400 space-y-2 animate-pulse";
    loadingMsg.innerHTML = `Retrieving grounded case evidence and verifying citations...`;
    display.appendChild(loadingMsg);
    display.scrollTop = display.scrollHeight;

    try {
        btn.disabled = true;
        const res = await fetch(`/api/cases/${currentCaseId}/ask`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ question: q, case_id: currentCaseId })
        });
        const ans = await res.json();
        display.removeChild(loadingMsg);

        const aiCard = document.createElement("div");
        aiCard.className = "bg-slate-950 border border-slate-800 rounded-xl p-5 text-xs space-y-3.5 shadow-lg";

        const citedBadges = (ans.cited_event_ids || []).map(cid => {
            return `<span class="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono font-bold">[${cid}]</span>`;
        }).join(" ");

        aiCard.innerHTML = `
            <div class="flex items-center justify-between border-b border-slate-800 pb-2">
                <span class="font-bold text-white flex items-center gap-1.5">
                    <i data-lucide="sparkles" class="w-4 h-4 text-indigo-400"></i>
                    ${ans.model_name}
                </span>
                <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Confidence: ${ans.confidence_label}
                </span>
            </div>

            <!-- 1. Observed Facts -->
            <div class="space-y-1">
                <span class="font-bold text-emerald-400 uppercase tracking-wider text-[10px]">📌 Observed Records (Facts)</span>
                <div class="text-slate-200 whitespace-pre-line bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/80 font-mono text-[11px]">${ans.observed_records}</div>
            </div>

            <!-- 2. Forensic Interpretation -->
            <div class="space-y-1">
                <span class="font-bold text-indigo-400 uppercase tracking-wider text-[10px]">💡 Forensic Interpretation & Inference</span>
                <p class="text-slate-300 leading-relaxed">${ans.interpretation}</p>
            </div>

            <!-- 3. Counter-Evidence & Contradictions -->
            <div class="space-y-1">
                <span class="font-bold text-rose-400 uppercase tracking-wider text-[10px]">⚠️ Counter-Evidence & Alternative Explanations</span>
                <p class="text-slate-300 leading-relaxed whitespace-pre-line">${ans.counter_evidence}</p>
            </div>

            <!-- 4. Unresolved Assumptions -->
            <div class="space-y-1">
                <span class="font-bold text-amber-400 uppercase tracking-wider text-[10px]">❓ Unresolved Evidentiary Assumptions</span>
                <p class="text-slate-400 leading-relaxed">${ans.unresolved_assumptions}</p>
            </div>

            <!-- 5. Next Steps -->
            <div class="space-y-1 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                <span class="font-bold text-cyan-400 uppercase tracking-wider text-[10px]">🔍 Recommended Next Steps</span>
                <p class="text-slate-300 leading-relaxed whitespace-pre-line">${ans.suggested_next_steps}</p>
            </div>

            <div class="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px]">
                <div class="flex items-center gap-1.5">
                    <span class="text-slate-400">Cited Records:</span>
                    ${citedBadges || '<span class="text-slate-500">None</span>'}
                </div>
                <span class="text-emerald-400 font-mono">100% Citation Validated</span>
            </div>
        `;

        display.appendChild(aiCard);
        display.scrollTop = display.scrollHeight;
        lucide.createIcons();

    } catch (err) {
        if (loadingMsg.parentNode) display.removeChild(loadingMsg);
        alert("AI Assistant error: " + err.message);
    } finally {
        btn.disabled = false;
    }
}

// ----------------- REPORT & AUDIT -----------------
async function loadReportPreview() {
    try {
        const res = await fetch(`/api/cases/${currentCaseId}/report`);
        const text = await res.text();
        document.getElementById("report-preview-markdown").innerHTML = `<pre class="text-xs font-mono whitespace-pre-wrap leading-relaxed">${text}</pre>`;
    } catch (e) {
        console.error("Error loading report preview:", e);
    }
}

async function loadAuditTrail() {
    try {
        const res = await fetch(`/api/cases/${currentCaseId}/audit`);
        const events = await res.json();
        const container = document.getElementById("audit-chain-timeline");
        container.innerHTML = "";

        events.forEach((ev, idx) => {
            const block = document.createElement("div");
            block.className = "bg-slate-950 border border-slate-800 p-3 rounded-lg space-y-1";
            block.innerHTML = `
                <div class="flex items-center justify-between text-slate-400">
                    <span class="text-indigo-400 font-bold">BLOCK #${String(idx + 1).padStart(2, '0')} &bull; ${ev.action.toUpperCase()}</span>
                    <span>${ev.timestamp}</span>
                </div>
                <div class="text-white font-medium">${ev.reason}</div>
                <div class="text-slate-500 text-[10px] break-all">
                    <div>PREV: ${ev.previous_event_hash}</div>
                    <div class="text-emerald-400 font-bold">HASH: ${ev.event_hash}</div>
                </div>
            `;
            container.appendChild(block);
        });
    } catch (e) {
        console.error("Error loading audit trail:", e);
    }
}

async function verifyAuditChainLive() {
    try {
        const res = await fetch(`/api/cases/${currentCaseId}/audit/verify`);
        const data = await res.json();
        if (data.valid) {
            alert(`[CRYPTOGRAPHIC AUDIT CHAIN VERIFIED]\n${data.message}\nHead Digest: ${data.chain_head}`);
        } else {
            alert(`[INTEGRITY BREACH DETECTED]\nBroken at audit block index ${data.broken_index} (${data.broken_audit_id})\nReason: ${data.reason}`);
        }
    } catch (e) {
        alert("Verification error: " + e.message);
    }
}

function switchReportSubtab(subtab) {
    document.getElementById("subtab-content-preview").classList.toggle("hidden", subtab !== "preview");
    document.getElementById("subtab-content-audit").classList.toggle("hidden", subtab !== "audit");

    document.getElementById("subtab-preview").className = subtab === "preview" 
        ? "px-4 py-2 font-semibold text-white border-b-2 border-indigo-500" 
        : "px-4 py-2 font-semibold text-slate-400 hover:text-white";
    document.getElementById("subtab-audit").className = subtab === "audit" 
        ? "px-4 py-2 font-semibold text-white border-b-2 border-indigo-500" 
        : "px-4 py-2 font-semibold text-slate-400 hover:text-white";
}

// ----------------- MODAL UPLOAD -----------------
function openUploadModal() {
    document.getElementById("upload-modal").classList.remove("hidden");
}

function closeUploadModal() {
    document.getElementById("upload-modal").classList.add("hidden");
}

async function handleUploadSubmit(e) {
    e.preventDefault();
    const fileInput = document.getElementById("upload-file");
    if (!fileInput.files.length) return;

    const file = fileInput.files[0];
    const sourceType = document.getElementById("upload-source-type").value;
    const desc = document.getElementById("upload-desc").value || "Forensic upload";
    const operator = document.getElementById("upload-operator").value || "Examiner";

    const formData = new FormData();
    formData.append("file", file);
    formData.append("source_type", sourceType);
    formData.append("source_description", desc);
    formData.append("operator", operator);

    try {
        const res = await fetch(`/api/cases/${currentCaseId}/evidence`, {
            method: "POST",
            body: formData
        });
        const data = await res.json();
        closeUploadModal();
        alert(`Evidence Ingested!\nID: ${data.evidence.evidence_id}\nSHA-256: ${data.evidence.sha256_initial}\nEvents Extracted: ${data.events_extracted}`);
        await loadCaseSummary();
        await loadEvidence();
        await loadTimeline();
        await loadFindings();
    } catch (err) {
        alert("Upload failed: " + err.message);
    }
}

// ----------------- RELOAD DEMO -----------------
async function reloadOrionDemo() {
    if (!confirm("Reload Project Orion synthetic demonstration scenario?")) return;
    try {
        await fetch("/api/demo/load_orion", { method: "POST" });
        await loadCaseSummary();
        await loadEvidence();
        await loadTimeline();
        await loadFindings();
        alert("Project Orion synthetic forensic scenario loaded successfully.");
    } catch (e) {
        alert("Demo reload failed: " + e.message);
    }
}
