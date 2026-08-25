// Finding Details Page Logic

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const fingerprint = urlParams.get('id');
    const scanId = urlParams.get('scan_id');

    if (!fingerprint) {
        window.location.href = 'scans.html';
        return;
    }

    // Configure Back button
    const backBtn = document.getElementById('btn-back');
    if (scanId) {
        backBtn.href = `scan-details.html?id=${scanId}`;
    } else {
        backBtn.href = `findings.html`;
    }

    const titleEl = document.getElementById('finding-title');
    const fingerprintEl = document.getElementById('finding-fingerprint');
    
    const badgeSeverity = document.getElementById('badge-severity');
    const badgeVerdict = document.getElementById('badge-verdict');
    const badgeDojoStatus = document.getElementById('badge-defectdojo-status');
    const slaTextEl = document.getElementById('sla-remaining-text');
    
    const valCategory = document.getElementById('val-category');
    const valSubtype = document.getElementById('val-subtype');
    const valConfidence = document.getElementById('val-confidence');
    const valPriority = document.getElementById('val-priority');
    
    const traceFlowList = document.getElementById('trace-flow-list');
    
    const panelPoc = document.getElementById('panel-poc-container');
    const pocPayload = document.getElementById('poc-payload');
    const pocInstructions = document.getElementById('poc-instructions');
    
    const reasoningTier = document.getElementById('reasoning-tier');
    const reasoningConfidence = document.getElementById('reasoning-confidence');
    const reasoningText = document.getElementById('reasoning-text');
    
    const reviewDDBtn = document.getElementById('btn-review-dd');

    loadFinding();

    async function loadFinding() {
        try {
            const f = await api.getFinding(fingerprint);
            if (!f) throw new Error('Vulnerability details not found');

            // 1. Overview panel
            titleEl.textContent = `${f.category} - ${f.subtype || 'Vulnerability'}`;
            fingerprintEl.textContent = `FINGERPRINT: ${f.fingerprint}`;
            
            // Severity badge
            badgeSeverity.textContent = f.severity || 'Medium';
            badgeSeverity.className = `badge badge-${(f.severity || 'Medium').toLowerCase()}`;
            
            // Verdict badge
            badgeVerdict.textContent = f.verdict || 'NEEDS_REVIEW';
            if (f.verdict === 'VALID') {
                badgeVerdict.className = 'badge badge-success';
            } else if (f.verdict === 'FALSE_POSITIVE') {
                badgeVerdict.className = 'badge badge-warning';
            } else {
                badgeVerdict.className = 'badge badge-low';
            }

            // DefectDojo Link button
            if (f.defectdojo_url) {
                reviewDDBtn.href = f.defectdojo_url;
                reviewDDBtn.style.display = 'inline-flex';
            } else {
                reviewDDBtn.style.display = 'none';
            }

            // DefectDojo verification status badge
            const dojoStatus = f.defectdojo_status || 'Awaiting Verification';
            badgeDojoStatus.textContent = dojoStatus;
            if (dojoStatus === 'Verified') {
                badgeDojoStatus.className = 'badge badge-approved'; // green
            } else if (dojoStatus === 'False Positive') {
                badgeDojoStatus.className = 'badge badge-rejected'; // red
            } else {
                badgeDojoStatus.className = 'badge badge-warning'; // yellow
            }

            // SLA Remaining status
            if (f.sla_status && f.sla_status.status !== 'unknown') {
                const status = f.sla_status.status;
                if (status === 'remediated') {
                    slaTextEl.textContent = 'SLA STATUS: REMEDIATED (FALSE POSITIVE)';
                    slaTextEl.className = 'sla-text text-green';
                } else if (status === 'overdue') {
                    slaTextEl.textContent = `SLA STATUS: OVERDUE (${Math.abs(f.sla_status.days_remaining)} days ago)`;
                    slaTextEl.className = 'sla-text text-red';
                } else if (status === 'approaching') {
                    slaTextEl.textContent = `SLA STATUS: APPROACHING DEADLINE (${f.sla_status.days_remaining} days left)`;
                    slaTextEl.className = 'sla-text text-orange';
                } else {
                    slaTextEl.textContent = `SLA STATUS: ON TRACK (${f.sla_status.days_remaining} days left)`;
                    slaTextEl.className = 'sla-text text-green';
                }
            } else {
                slaTextEl.textContent = 'SLA STATUS: N/A';
                slaTextEl.className = 'sla-text';
            }

            // Meta Details
            valCategory.textContent = f.category || '-';
            valSubtype.textContent = f.subtype || '-';
            valConfidence.textContent = (f.verdict_confidence || f.confidence || 0).toFixed(2);
            valPriority.textContent = `${f.priority || 'P3'} (${f.sla_days || 14}d SLA)`;

            // 2. Dataflow Trace
            traceFlowList.innerHTML = '';
            if (f.path && f.path.length > 0) {
                f.path.forEach((node, i) => {
                    const stepDiv = document.createElement('div');
                    stepDiv.className = 'trace-flow-node';
                    
                    let fileAndLine = 'unknown';
                    let codeLine = '';
                    
                    if (typeof node === 'string') {
                        codeLine = node;
                    } else if (typeof node === 'object') {
                        fileAndLine = `${node.file || 'unknown'} : Line ${node.line || '?'}`;
                        codeLine = node.code || '';
                    }

                    stepDiv.innerHTML = `
                        <div class="node-index">${i + 1}</div>
                        <div class="node-content">
                            <div class="node-meta">${fileAndLine}</div>
                            <pre class="node-code"><code>${escapeHtml(codeLine)}</code></pre>
                        </div>
                    `;
                    traceFlowList.appendChild(stepDiv);
                });
            } else {
                traceFlowList.innerHTML = '<p class="text-muted">No trace data available.</p>';
            }

            // 3. Diagnostics
            reasoningTier.textContent = f.validation_tier || 'N/A';
            reasoningConfidence.textContent = (f.verdict_confidence || f.confidence || 0).toFixed(2);
            reasoningText.textContent = f.reasoning || f.llm_reasoning || 'No diagnostics reasoning was output by the LLM.';

            // Render Security Intelligence details
            const intelCwe = document.getElementById('intel-cwe-id');
            const intelEpss = document.getElementById('intel-epss');
            const intelKev = document.getElementById('intel-kev');
            const recRemediation = document.getElementById('remediation-recommendation');

            const secMeta = f.security_metadata || {};
            intelCwe.textContent = secMeta.cwe_id || f.subtype || 'N/A';
            
            if (secMeta.epss_score !== undefined && secMeta.epss_score !== null) {
                const scorePct = (secMeta.epss_score * 100).toFixed(4);
                const percentilePct = (secMeta.epss_percentile * 100).toFixed(2);
                intelEpss.textContent = `${scorePct}% (Pct: ${percentilePct}%)`;
            } else {
                intelEpss.textContent = 'N/A';
            }

            if (secMeta.known_exploited) {
                intelKev.innerHTML = `<span style="color: var(--critical); font-weight: bold;">Yes (Added: ${secMeta.date_added_to_kev || 'N/A'})</span>`;
            } else if (secMeta.known_exploited === false) {
                intelKev.textContent = 'No';
            } else {
                intelKev.textContent = 'N/A';
            }

            recRemediation.textContent = f.remediation || 'No specific remediation recommendation was provided.';

            // 4. Proof of Concept
            const poc = f.proof_of_concept || f.generated_poc;
            if (poc && (poc.payload || poc.input) && (poc.available !== false)) {
                panelPoc.style.display = 'block';
                pocPayload.textContent = poc.input || poc.payload || '';
                pocInstructions.textContent = poc.description || poc.instructions || 'Follow the payload injection instructions above to replicate this issue.';
            } else {
                panelPoc.style.display = 'none';
            }

            // 5. Proposed Remediation Fix
            const panelRemediation = document.getElementById('panel-remediation-container');
            const fixConfidence = document.getElementById('fix-confidence');
            const fixStatus = document.getElementById('fix-status');
            const remStrategy = document.getElementById('remediation-strategy');
            const fixPatchCode = document.getElementById('fix-patch-code');
            const commentArea = document.getElementById('triage-comment');

            const fix = f.fix;
            if (fix && fix.available) {
                panelRemediation.style.display = 'block';
                fixConfidence.textContent = fix.confidence ? `${(fix.confidence * 100).toFixed(1)}%` : 'N/A';
                
                const status = fix.status || 'PROPOSED';
                fixStatus.textContent = status;
                
                // Color fix status badge
                if (status === 'APPLIED') {
                    fixStatus.style.color = 'var(--success)';
                } else if (status === 'CONFLICT' || status === 'FAILED' || status === 'REJECTED') {
                    fixStatus.style.color = 'var(--critical)';
                } else if (status === 'APPROVED') {
                    fixStatus.style.color = 'var(--success)';
                } else {
                    fixStatus.style.color = 'var(--warning)';
                }
                
                remStrategy.textContent = fix.strategy || fix.summary || 'Apply the proposed patch below.';
                fixPatchCode.textContent = fix.patch || '';
                
                // Populate previous comment if exists
                if (f.human_validation && f.human_validation.comment) {
                    commentArea.value = f.human_validation.comment;
                }
                
                // Disable controls if already applied
                if (status === 'APPLIED') {
                    document.getElementById('btn-approve-fix').disabled = true;
                    document.getElementById('btn-reject-fix').disabled = true;
                    document.getElementById('btn-needs-review-fix').disabled = true;
                    commentArea.disabled = true;
                }
            } else {
                panelRemediation.style.display = 'none';
            }

        } catch (err) {
            console.error('Failed to load finding details:', err);
            titleEl.textContent = 'Error Loading Details';
            reasoningText.textContent = err.message;
        }
    }

    // Bind Triage Actions
    document.getElementById('btn-approve-fix').addEventListener('click', async () => {
        const comment = document.getElementById('triage-comment').value;
        const reviewer = prompt("Enter reviewer/admin name:", "Security Admin") || "Security Admin";
        
        try {
            // 1. Submit Human Validation
            await api.updateHumanValidation(fingerprint, 'APPROVED', reviewer, comment);
            // 2. Apply patch
            const res = await api.applyProposedFix(fingerprint, reviewer);
            if (res.success) {
                alert('Vulnerability fix approved and patch applied successfully.');
            } else {
                alert(`Fix status updated, but patch application failed: ${res.error}`);
            }
            loadFinding(); // Refresh details
        } catch (e) {
            alert(`Approval / Patch failed: ${e.message}`);
        }
    });

    document.getElementById('btn-reject-fix').addEventListener('click', async () => {
        const comment = document.getElementById('triage-comment').value;
        const reviewer = prompt("Enter reviewer/admin name:", "Security Admin") || "Security Admin";
        
        try {
            await api.updateHumanValidation(fingerprint, 'REJECTED', reviewer, comment);
            alert('Vulnerability fix rejected successfully.');
            loadFinding(); // Refresh details
        } catch (e) {
            alert(`Rejection failed: ${e.message}`);
        }
    });

    document.getElementById('btn-needs-review-fix').addEventListener('click', async () => {
        const comment = document.getElementById('triage-comment').value;
        const reviewer = prompt("Enter reviewer/admin name:", "Security Admin") || "Security Admin";
        
        try {
            await api.updateHumanValidation(fingerprint, 'NEEDS_REVIEW', reviewer, comment);
            alert('Vulnerability status updated to Needs Review.');
            loadFinding(); // Refresh details
        } catch (e) {
            alert(`Action failed: ${e.message}`);
        }
    });

    function escapeHtml(string) {
        return String(string).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
});
