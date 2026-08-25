document.addEventListener('DOMContentLoaded', () => {
    let globalData = null;
    let activeFingerprintToPush = null;

    fetch('/api/data')
        .then(response => response.json())
        .then(data => {
            globalData = data;
            initDashboard(data);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
            document.getElementById('repo-name').textContent = "Error loading data";
        });

    function initDashboard(data) {
        const meta = data.scan_metadata || {};
        const findings = data.findings || [];

        // 1. Header Info
        document.getElementById('repo-name').textContent = meta.repo || "Unknown Repository";
        const date = new Date(meta.timestamp);
        document.getElementById('scan-timestamp').textContent = `Scanned: ${date.toLocaleString()}`;

        // 2. Stats
        document.getElementById('total-findings').textContent = findings.length;
        
        const highConf = findings.filter(f => {
            const conf = f.confidence || f.verdict_confidence || 0;
            return conf > 0.7;
        }).length;
        document.getElementById('high-confidence').textContent = highConf;

        const pocCount = findings.filter(f => {
            const poc = f.proof_of_concept || f.generated_poc;
            return poc && (poc.payload || poc.input) && (poc.available !== false);
        }).length;
        document.getElementById('poc-count').textContent = pocCount;

        // 3. Telemetry Grid
        const telGrid = document.getElementById('telemetry-grid');
        telGrid.innerHTML = '';
        if (meta.per_rule_stats) {
            meta.per_rule_stats.forEach(stat => {
                const div = document.createElement('div');
                div.className = 'tel-badge';
                div.innerHTML = `<span>${stat.rule_id}</span> <strong>${stat.findings_returned}</strong>`;
                telGrid.appendChild(div);
            });
        }

        // 4. Render Findings
        renderFindings(findings);

        // 5. Setup Filter
        window.applyFilters = function() {
            const verdictVal = document.getElementById('filter-verdict').value;
            const pocVal = document.getElementById('filter-poc').value;

            let filtered = globalData ? (globalData.findings || []) : findings;

            if (verdictVal !== 'ALL') {
                filtered = filtered.filter(f => f.verdict === verdictVal);
            }

            if (pocVal !== 'ALL') {
                filtered = filtered.filter(f => {
                    const poc = f.proof_of_concept || f.generated_poc;
                    const hasPoc = poc && (poc.payload || poc.input) && (poc.available !== false);
                    return pocVal === 'HAS_POC' ? hasPoc : !hasPoc;
                });
            }

            renderFindings(filtered);
        };

        document.getElementById('filter-verdict').addEventListener('change', window.applyFilters);
        document.getElementById('filter-poc').addEventListener('change', window.applyFilters);

        // 6. Modal Close
        document.getElementById('modal-close').addEventListener('click', closeModal);
        document.getElementById('finding-modal').addEventListener('click', (e) => {
            if (e.target.id === 'finding-modal') closeModal();
        });

        // 7. DefectDojo Push
        document.getElementById('btn-push-defectdojo').addEventListener('click', (e) => {
            activeFingerprintToPush = null;
            pushToDefectDojo(e.target);
        });
        document.getElementById('modal-btn-push').addEventListener('click', (e) => {
            pushToDefectDojo(e.target);
        });
    }

    async function setApprovalStatus(fingerprint, state) {
        try {
            const res = await fetch('/api/approve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fingerprint, state })
            });
            if (res.ok) {
                // Update local state
                const finding = globalData.findings.find(f => f.fingerprint === fingerprint);
                if (finding) {
                    finding.approval_state = state;
                    
                    if (state === 'APPROVED') {
                        let badgeClass = 'badge-needs-review';
                        if (finding.verdict === 'VALID') badgeClass = 'badge-valid';
                        if (finding.verdict === 'FALSE_POSITIVE') badgeClass = 'badge-false-positive';
                        const verdict = finding.verdict || 'NEEDS_REVIEW';
                        openModal(finding, badgeClass, verdict);
                    }
                }
                // Re-render
                if (window.applyFilters) {
                    window.applyFilters();
                } else {
                    renderFindings(globalData.findings);
                }
            } else {
                alert('Failed to update approval status.');
            }
        } catch (e) {
            console.error(e);
            alert('Error updating approval status.');
        }
    }
    window.setApprovalStatus = setApprovalStatus;

    async function pushToDefectDojo(btn) {
        const origText = btn.textContent;
        btn.textContent = "Pushing...";
        btn.disabled = true;

        try {
            const payload = {};
            if (activeFingerprintToPush) {
                payload.fingerprint = activeFingerprintToPush;
            }
            
            const res = await fetch('/api/push_defectdojo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            const data = await res.json();
            if (res.ok) {
                alert(`Success! Pushed ${data.pushed} findings to DefectDojo.\n${data.errors.length > 0 ? 'Errors: ' + data.errors.join(', ') : ''}`);
            } else {
                alert(`Error: ${data.error || 'Failed to push findings'}`);
            }
        } catch (e) {
            console.error(e);
            alert('Network error while pushing to DefectDojo.');
        } finally {
            btn.textContent = origText;
            btn.disabled = false;
        }
    }

    function renderFindings(findings) {
        const list = document.getElementById('findings-list');
        list.innerHTML = '';

        if (findings.length === 0) {
            list.innerHTML = '<div class="loading-state">No findings match the filter.</div>';
            return;
        }

        findings.forEach((finding, idx) => {
            const card = document.createElement('div');
            card.className = 'finding-card glass-panel';
            
            let badgeClass = 'badge-needs-review';
            if (finding.verdict === 'VALID') badgeClass = 'badge-valid';
            if (finding.verdict === 'FALSE_POSITIVE') badgeClass = 'badge-false-positive';

            let approvalState = finding.approval_state || 'NEEDS_REVIEW';
            let approvalBadge = '';
            if (approvalState === 'APPROVED') approvalBadge = '<span class="finding-badge badge-approved" style="margin-left: 0.5rem;">APPROVED</span>';
            if (approvalState === 'REJECTED') approvalBadge = '<span class="finding-badge badge-rejected" style="margin-left: 0.5rem;">REJECTED</span>';

            const verdict = finding.verdict || 'NEEDS_REVIEW';
            
            let sinkStr = 'Unknown Sink';
            if (finding.sink && finding.sink.file) {
                sinkStr = finding.sink.file + ':' + finding.sink.line;
            } else if (finding.instances && finding.instances.length > 0) {
                sinkStr = finding.instances[0].sink_file + ':' + finding.instances[0].sink_line;
            }
            const hasPoc = (() => {
                const poc = finding.proof_of_concept || finding.generated_poc;
                return poc && (poc.payload || poc.input) && (poc.available !== false);
            })();

            const severity = finding.severity || 'Medium';
            const priority = finding.priority || 'P3';
            const slaDays = finding.sla_days !== undefined ? finding.sla_days : 14;

            let sevClass = 'sev-medium';
            if (severity === 'Critical') sevClass = 'sev-critical';
            else if (severity === 'High') sevClass = 'sev-high';
            else if (severity === 'Medium') sevClass = 'sev-medium';
            else if (severity === 'Low') sevClass = 'sev-low';
            
            card.innerHTML = `
                <div>
                    <div class="finding-badge ${badgeClass}">${verdict}</div>
                    ${approvalBadge}
                </div>
                <div class="finding-info" style="cursor: pointer;">
                    <h4>${finding.category} - ${finding.subtype}</h4>
                    <p>${sinkStr}</p>
                </div>
                <div class="finding-meta">
                    <span class="conf-pill"><i class="ph ph-target"></i> Conf: ${finding.confidence || finding.verdict_confidence || '0.00'}</span>
                    <span class="conf-pill ${sevClass}"><i class="ph ph-warning"></i> ${severity}</span>
                    <span class="conf-pill prio-pill"><i class="ph ph-flag"></i> ${priority}</span>
                    <span class="conf-pill sla-pill"><i class="ph ph-clock"></i> ${slaDays}d SLA</span>
                    ${hasPoc ? '<span class="poc-pill"><i class="ph ph-code"></i> PoC</span>' : ''}
                </div>
                <div class="card-actions">
                    <button class="action-btn approve ${approvalState === 'APPROVED' ? 'active' : ''}" onclick="event.stopPropagation(); setApprovalStatus('${finding.fingerprint}', 'APPROVED')">
                        <i class="ph ph-check-circle"></i> Approve
                    </button>
                    <button class="action-btn reject ${approvalState === 'REJECTED' ? 'active' : ''}" onclick="event.stopPropagation(); setApprovalStatus('${finding.fingerprint}', 'REJECTED')">
                        <i class="ph ph-x-circle"></i> Reject
                    </button>
                </div>
            `;

            card.querySelector('.finding-info').addEventListener('click', () => openModal(finding, badgeClass, verdict));
            list.appendChild(card);
        });
    }

    function openModal(finding, badgeClass, verdict) {
        activeFingerprintToPush = finding.fingerprint;
        
        const pushBtn = document.getElementById('modal-btn-push');
        if (finding.approval_state === 'APPROVED') {
            pushBtn.style.display = 'block';
        } else {
            pushBtn.style.display = 'none';
        }

        document.getElementById('modal-verdict').className = `finding-badge badge ${badgeClass}`;
        document.getElementById('modal-verdict').textContent = verdict;
        document.getElementById('modal-title').textContent = `${finding.category} Vulnerability`;
        
        document.getElementById('modal-category').textContent = finding.category;
        document.getElementById('modal-subtype').textContent = finding.subtype || 'N/A';
        document.getElementById('modal-confidence').textContent = finding.confidence || finding.verdict_confidence || '0.00';
        document.getElementById('modal-severity').textContent = finding.severity || 'Medium';
        document.getElementById('modal-priority').textContent = finding.priority || 'P3';
        document.getElementById('modal-sla').textContent = finding.sla_days !== undefined ? `${finding.sla_days} days` : '14 days';

        // Trace
        let traceStr = "";
        if (finding.path && finding.path.length > 0) {
            finding.path.forEach((node, i) => {
                if (typeof node === 'string') {
                    traceStr += `[${i+1}] ${node}\n`;
                } else if (typeof node === 'object') {
                    traceStr += `[${i+1}] ${node.file || 'unknown'}:${node.line || '?'} -> \n${node.code || ''}\n\n`;
                }
            });
        } else {
            traceStr = "No structured path available.";
        }
        document.getElementById('modal-trace').textContent = traceStr;

        // Reasoning
        const reasoning = finding.reasoning || (finding.evidence ? (finding.evidence.validation_notes || finding.evidence) : finding.llm_reasoning);
        document.getElementById('modal-reasoning').textContent = reasoning || 'No LLM reasoning provided.';

        // PoC
        const pocSection = document.getElementById('poc-section');
        const poc = finding.proof_of_concept || finding.generated_poc;
        if (poc && (poc.payload || poc.input) && (poc.available !== false)) {
            pocSection.style.display = 'block';
            const type = poc.type || poc.poc_type || 'N/A';
            const payload = poc.input || poc.payload || '';
            const instructions = poc.description || poc.instructions || 'N/A';
            const status = poc.verification_status || 'NOT_EXECUTED';
            
            let pocText = `Type: ${type}\n`;
            pocText += `Verification Status: ${status}\n\n`;
            pocText += `Payload/Input:\n${payload}\n\n`;
            pocText += `Description/Instructions:\n${instructions}`;
            document.getElementById('modal-poc').textContent = pocText;
        } else {
            pocSection.style.display = 'none';
        }

        document.getElementById('finding-modal').classList.add('active');
    }

    function closeModal() {
        document.getElementById('finding-modal').classList.remove('active');
    }
});
