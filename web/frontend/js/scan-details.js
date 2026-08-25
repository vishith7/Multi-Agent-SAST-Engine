// Scan Details JS Logic

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('id');
    
    if (!scanId) {
        window.location.href = 'scans.html';
        return;
    }

    const scanRepoEl = document.getElementById('scan-repo');
    const scanStatusEl = document.getElementById('scan-status');
    const scanIdValEl = document.getElementById('scan-id-val');
    const scanTypeValEl = document.getElementById('scan-type-val');
    const scanStartedEl = document.getElementById('scan-started');
    const scanFindingsCountEl = document.getElementById('scan-findings-count');
    const findingsListEl = document.getElementById('scan-findings-list');
    const syncDDBtn = document.getElementById('btn-sync-dd');
    const goToDDBtn = document.getElementById('btn-go-to-dd');
    const retryDDBtn = document.getElementById('btn-retry-upload-dd');
    
    let poller = null;
 
    // Load Details
    loadDetails();
 
    // DefectDojo sync handler
    syncDDBtn.addEventListener('click', async () => {
        const origText = syncDDBtn.innerHTML;
        syncDDBtn.disabled = true;
        syncDDBtn.innerHTML = '<span class="loading-spinner" style="width: 12px; height: 12px; margin-right: 0.5rem;"></span> Syncing...';
        
        try {
            await api.syncScanDefectDojo(scanId);
            loadDetails(); // Reload state
            alert('Scan finding statuses synchronized successfully from DefectDojo.');
        } catch (err) {
            alert(`Sync failed: ${err.message}`);
        } finally {
            syncDDBtn.disabled = false;
            syncDDBtn.innerHTML = origText;
        }
    });

    // DefectDojo retry upload handler
    retryDDBtn.addEventListener('click', async () => {
        const origText = retryDDBtn.innerHTML;
        retryDDBtn.disabled = true;
        retryDDBtn.innerHTML = '<span class="loading-spinner" style="width: 12px; height: 12px; margin-right: 0.5rem;"></span> Uploading...';
        
        try {
            await api.syncScanDefectDojo(scanId);
            loadDetails(); // Reload state
            alert('Scan findings uploaded successfully to DefectDojo.');
        } catch (err) {
            alert(`Upload failed: ${err.message}`);
        } finally {
            retryDDBtn.disabled = false;
            retryDDBtn.innerHTML = origText;
        }
    });
 
    async function loadDetails() {
        try {
            // Load Scan details and status
            const scanData = await api.getScan(scanId);
            const statusInfo = await api.getScanStatus(scanId);
            
            // Populate Meta fields
            scanRepoEl.textContent = scanData.scan_metadata.repo || 'unknown';
            scanIdValEl.textContent = scanId;
            
            const scanType = scanData.scan_metadata.scan_type || 'full';
            scanTypeValEl.textContent = scanType === 'diff-scoped' ? 'Diff-scoped' : 'Full Scan';
            
            const date = new Date(scanData.scan_metadata.timestamp);
            scanStartedEl.textContent = date.toLocaleString();
            scanFindingsCountEl.textContent = scanData.findings ? scanData.findings.length : 0;
            
            // Update Status Badge
            updateStatusBadge(statusInfo.status);
            
            // Populate Visual Pipeline Progress
            renderPipeline(statusInfo.stage, statusInfo.status);
            
            // Populate Findings Table
            renderFindingsTable(scanData.findings);
            
            // If scan is still active (running/queued), poll status
            if (statusInfo.status === 'running' || statusInfo.status === 'queued') {
                startPollingStatus();
                goToDDBtn.style.display = 'none';
                retryDDBtn.style.display = 'none';
            } else {
                // Check DefectDojo engagement link & retry button status
                try {
                    const config = await api.getDefectDojoConfig();
                    const engId = scanData.scan_metadata.defectdojo_engagement_id;
                    const uploadStatus = scanData.scan_metadata.defectdojo_upload_status;
                    
                    if (config.configured && config.url && engId && uploadStatus === 'success') {
                        goToDDBtn.href = `${config.url.replace(/\/$/, '')}/engagement/${engId}`;
                        goToDDBtn.style.display = 'inline-flex';
                        retryDDBtn.style.display = 'none';
                    } else if (config.configured) {
                        goToDDBtn.style.display = 'none';
                        retryDDBtn.style.display = 'inline-flex';
                    } else {
                        goToDDBtn.style.display = 'none';
                        retryDDBtn.style.display = 'none';
                    }
                } catch (e) {
                    goToDDBtn.style.display = 'none';
                    retryDDBtn.style.display = 'none';
                }
            }
            
        } catch (err) {
            console.error('Failed to load scan details:', err);
            findingsListEl.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">
                        <i class="ph ph-warning-circle" style="color: var(--critical);"></i>
                        <h3>Failed to load scan details</h3>
                        <p>${err.message}</p>
                    </td>
                </tr>
            `;
        }
    }

    function updateStatusBadge(status) {
        scanStatusEl.textContent = status.toUpperCase();
        if (status === 'completed') {
            scanStatusEl.className = 'badge badge-success';
        } else if (status === 'failed') {
            scanStatusEl.className = 'badge badge-critical';
        } else {
            scanStatusEl.className = 'badge badge-warning';
        }
    }

    function renderPipeline(activeStage, status) {
        const container = document.getElementById('pipeline-flow-container');
        container.innerHTML = '';

        // Standard workflow stages
        const stagesList = [
            { key: 'PREPARING', label: 'Prepare', icon: 'ph-folders' },
            { key: 'CPG_BUILD', label: 'CPG Parse', icon: 'ph-gear-six' },
            { key: 'SCANNING', label: 'Scan', icon: 'ph-shield-search' },
            { key: 'CHAIN_DETECTION', label: 'Chaining', icon: 'ph-link' },
            { key: 'DEDUPLICATION', label: 'Dedupe', icon: 'ph-stack' },
            { key: 'LLM_VALIDATION', label: 'LLM Cascade', icon: 'ph-cpu' },
            { key: 'PROVING', label: 'Prove', icon: 'ph-flask' },
            { key: 'DEFECTDOJO_UPLOAD', label: 'DefectDojo', icon: 'ph-plugs' }
        ];

        // Determine stage indexes
        let activeIdx = stagesList.findIndex(s => s.key === activeStage);
        if (activeStage === 'QUEUED') activeIdx = 0;
        if (activeStage === 'COMPLETED' || status === 'completed') activeIdx = stagesList.length; // all completed
        if (activeStage === 'FAILED' || status === 'failed') activeIdx = -1; // stop highlight

        stagesList.forEach((stage, idx) => {
            // Determine item state: completed, active, pending
            let itemClass = '';
            let isItemCompleted = false;
            let iconClass = stage.icon;
            
            if (activeIdx === -1) {
                // If failed
                itemClass = 'pending';
            } else if (idx < activeIdx) {
                itemClass = 'completed';
                isItemCompleted = true;
                iconClass = 'ph-check-circle';
            } else if (idx === activeIdx) {
                itemClass = 'active';
                iconClass = 'ph-spinner'; // loading spinner
            } else {
                itemClass = 'pending';
            }

            const stepDiv = document.createElement('div');
            stepDiv.className = `pipeline-step ${itemClass}`;
            stepDiv.innerHTML = `
                <div class="step-circle"><i class="ph ${iconClass} ${itemClass === 'active' ? 'loading-spinner' : ''}"></i></div>
                <span class="step-label">${stage.label}</span>
            `;
            container.appendChild(stepDiv);

            // Render connector lines
            if (idx < stagesList.length - 1) {
                let lineClass = '';
                if (idx < activeIdx - 1) lineClass = 'completed';
                else if (idx === activeIdx - 1) lineClass = 'active';
                
                const lineDiv = document.createElement('div');
                lineDiv.className = `pipeline-line ${lineClass}`;
                container.appendChild(lineDiv);
            }
        });
    }

    function renderFindingsTable(findings) {
        findingsListEl.innerHTML = '';
        
        if (!findings || findings.length === 0) {
            findingsListEl.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">
                        <i class="ph ph-bug-beetle"></i>
                        <h3>No findings found</h3>
                        <p>No vulnerabilities were detected in this scan.</p>
                    </td>
                </tr>
            `;
            return;
        }

        findings.forEach(f => {
            const tr = document.createElement('tr');
            
            // Severity decoration
            let sevBadge = '';
            const sev = f.severity || 'Medium';
            if (sev === 'Critical') {
                sevBadge = '<span class="badge badge-critical">Critical</span>';
            } else if (sev === 'High') {
                sevBadge = '<span class="badge badge-high">High</span>';
            } else if (sev === 'Medium') {
                sevBadge = '<span class="badge badge-medium">Medium</span>';
            } else {
                sevBadge = '<span class="badge badge-low">Low</span>';
            }
            
            // Verdict decoration
            let verdictBadge = '';
            const verdict = f.verdict || 'NEEDS_REVIEW';
            if (verdict === 'VALID') {
                verdictBadge = '<span class="badge badge-success">Valid</span>';
            } else if (verdict === 'FALSE_POSITIVE') {
                verdictBadge = '<span class="badge badge-warning">False Positive</span>';
            } else {
                verdictBadge = '<span class="badge badge-low">Needs Review</span>';
            }

            // Location
            let locStr = 'Unknown';
            if (f.sink && f.sink.file) {
                locStr = `${f.sink.file}:${f.sink.line}`;
            } else if (f.instances && f.instances.length > 0) {
                locStr = `${f.instances[0].sink_file}:${f.instances[0].sink_line}`;
            }
            // Truncate path for readability
            if (locStr.length > 40) {
                locStr = '...' + locStr.substring(locStr.length - 40);
            }

            const priority = f.defectdojo_priority || f.priority || 'Dojo';
            const sla = f.sla_status && f.sla_status.deadline ? f.sla_status.deadline : 'Dojo';
            
            let defectdojoBadge = '';
            const dojoStatus = f.defectdojo_status || 'Awaiting Verification';
            if (dojoStatus === 'Verified') {
                defectdojoBadge = '<span class="badge badge-success" style="margin-left:0.25rem;">Verified</span>';
            } else if (dojoStatus === 'False Positive') {
                defectdojoBadge = '<span class="badge badge-critical" style="margin-left:0.25rem;">False Positive</span>';
            } else {
                defectdojoBadge = '<span class="badge badge-warning" style="margin-left:0.25rem;">Awaiting Human</span>';
            }
 
            tr.innerHTML = `
                <td>${sevBadge}</td>
                <td>
                    <strong>${f.category}</strong>
                    <div style="font-size:0.75rem; color:var(--text-muted);">${f.subtype || ''}</div>
                </td>
                <td>${verdictBadge} ${defectdojoBadge}</td>
                <td>${(f.verdict_confidence || f.confidence || 0).toFixed(2)}</td>
                <td>${priority} (${sla})</td>
                <td style="font-family:var(--font-mono); font-size:0.75rem;">${locStr}</td>
                <td>
                    <a href="finding-details.html?id=${f.fingerprint}&scan_id=${scanId}" class="btn btn-secondary btn-sm">
                        <i class="ph ph-magnifying-glass"></i> Inspect
                    </a>
                </td>
            `;
            
            findingsListEl.appendChild(tr);
        });
    }

    function startPollingStatus() {
        if (poller) clearInterval(poller);
        
        poller = setInterval(async () => {
            try {
                const statusInfo = await api.getScanStatus(scanId);
                
                // Update Status Badge
                updateStatusBadge(statusInfo.status);
                
                // Update Visual Pipeline
                renderPipeline(statusInfo.stage, statusInfo.status);
                
                if (statusInfo.status === 'completed' || statusInfo.status === 'failed') {
                    // Stop polling and reload everything once to show findings table
                    clearInterval(poller);
                    poller = null;
                    loadDetails();
                }
            } catch (err) {
                console.error('Failed to poll status:', err);
            }
        }, 2000);
    }
});
