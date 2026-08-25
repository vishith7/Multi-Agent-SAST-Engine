// Scans Management Logic

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('form-start-scan');
    const listEl = document.getElementById('scan-history-list');
    const submitBtn = document.getElementById('btn-submit-scan');
    
    let activePollers = {};

    // Load Scan History
    loadScanHistory();

    // Pre-fill repo if query parameter exists
    const urlParams = new URLSearchParams(window.location.search);
    const repoParam = urlParams.get('repo');
    if (repoParam) {
        document.getElementById('repo_path').value = decodeURIComponent(repoParam);
    }

    // Start Scan Form Submission
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const repoPath = document.getElementById('repo_path').value.strip ? document.getElementById('repo_path').value.strip() : document.getElementById('repo_path').value;
        const scanMode = document.getElementById('scan_mode').value;
        const cpgName = document.getElementById('cpg_name').value;
        const output = document.getElementById('output').value || null;
        const revalidate = document.getElementById('revalidate').checked;

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="loading-spinner" style="width: 14px; height: 14px; margin-right: 0.5rem;"></span> Starting scan...';

        try {
            const res = await api.startScan(repoPath, scanMode, cpgName, output, revalidate);
            if (res.success) {
                // Reset form values
                document.getElementById('repo_path').value = '';
                document.getElementById('output').value = '';
                document.getElementById('revalidate').checked = false;
                
                // Reload list
                loadScanHistory();
            }
        } catch (err) {
            alert(`Failed to start scan: ${err.message}`);
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="ph ph-play-circle"></i> Start Analysis';
        }
    });

    // Event delegation for Delete button click
    listEl.addEventListener('click', async (e) => {
        const deleteBtn = e.target.closest('.btn-delete-scan');
        if (!deleteBtn) return;
        
        const scanId = deleteBtn.getAttribute('data-id');
        if (!confirm('Are you sure you want to delete this scan and all its findings?')) return;
        
        deleteBtn.disabled = true;
        deleteBtn.innerHTML = '<span class="loading-spinner" style="width: 10px; height: 10px;"></span>';
        
        try {
            const res = await api.deleteScan(scanId);
            if (res.success) {
                // Reload scans list
                loadScanHistory();
            }
        } catch (err) {
            alert(`Failed to delete scan: ${err.message}`);
            deleteBtn.disabled = false;
            deleteBtn.innerHTML = '<i class="ph ph-trash"></i> Delete';
        }
    });

    async function loadScanHistory() {
        try {
            const scans = await api.getScans();
            renderScansList(scans);
        } catch (err) {
            console.error('Error loading scans:', err);
            listEl.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <i class="ph ph-warning-circle" style="color: var(--critical);"></i>
                        <h3>Unable to connect to Taintlace backend</h3>
                        <p>Verify that your FastAPI backend is running.</p>
                    </td>
                </tr>
            `;
        }
    }

    function renderScansList(scans) {
        listEl.innerHTML = '';
        
        // Cancel all existing status pollers first to prevent duplicate timers
        for (const scanId in activePollers) {
            clearInterval(activePollers[scanId]);
            delete activePollers[scanId];
        }

        if (scans.length === 0) {
            listEl.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <i class="ph ph-shield-search"></i>
                        <h3>No scan runs detected</h3>
                        <p>Submit the form on the left to launch your first SAST analysis.</p>
                    </td>
                </tr>
            `;
            return;
        }

        scans.forEach(scan => {
            const tr = document.createElement('tr');
            tr.id = `scan-row-${scan.scan_id}`;
            
            let statusBadgeClass = 'badge-success';
            let statusText = 'Completed';
            if (scan.status === 'running') {
                statusBadgeClass = 'badge-warning';
                statusText = 'Scanning';
            } else if (scan.status === 'failed') {
                statusBadgeClass = 'badge-critical';
                statusText = 'Failed';
            } else if (scan.status === 'queued') {
                statusBadgeClass = 'badge-warning';
                statusText = 'Queued';
            }

            const scanTypeLabel = scan.scan_type === 'diff-scoped' ? 'Diff-scoped' : 'Full Scan';
            const findingsColor = scan.findings_count > 0 ? 'text-red' : 'text-green';
            const findingsDisplay = scan.status === 'running' || scan.status === 'queued' ? '...' : scan.findings_count;
            
            // Progress Bar HTML
            let progressHtml = '';
            if (scan.status === 'running') {
                progressHtml = `
                    <div class="progress-cell" id="progress-cell-${scan.scan_id}">
                        <div class="progress-track">
                            <div class="progress-bar" id="progress-bar-${scan.scan_id}" style="width: 10%"></div>
                        </div>
                        <span class="progress-label" id="progress-label-${scan.scan_id}">10%</span>
                    </div>
                `;
            } else if (scan.status === 'queued') {
                progressHtml = `
                    <div class="progress-cell" id="progress-cell-${scan.scan_id}">
                        <div class="progress-track">
                            <div class="progress-bar" id="progress-bar-${scan.scan_id}" style="width: 0%"></div>
                        </div>
                        <span class="progress-label" id="progress-label-${scan.scan_id}">0%</span>
                    </div>
                `;
            } else if (scan.status === 'failed') {
                progressHtml = '<span class="text-muted">N/A</span>';
            } else {
                progressHtml = `
                    <div class="progress-cell">
                        <div class="progress-track">
                            <div class="progress-bar" style="width: 100%; background-color: var(--success);"></div>
                        </div>
                        <span class="progress-label">100%</span>
                    </div>
                `;
            }

            // View and Delete actions. Only show Delete button if status is completed or failed.
            let deleteBtnHtml = '';
            if (scan.status === 'completed' || scan.status === 'failed') {
                deleteBtnHtml = `
                    <button class="btn btn-critical btn-sm btn-delete-scan" data-id="${scan.scan_id}" style="margin-left: 0.5rem; padding: 0.25rem 0.5rem; border: none; font-size: 0.8rem; border-radius: 4px; display: inline-flex; align-items: center; gap: 4px; cursor: pointer;">
                        <i class="ph ph-trash"></i> Delete
                    </button>
                `;
            }

            tr.innerHTML = `
                <td>
                    <strong>${scan.repo}</strong>
                    <div class="stage-text" id="stage-text-${scan.scan_id}">${scan.status === 'running' ? 'Initializing...' : ''}</div>
                </td>
                <td><span class="badge badge-low">${scanTypeLabel}</span></td>
                <td>
                    <span class="badge ${statusBadgeClass}" id="status-badge-${scan.scan_id}">${statusText}</span>
                </td>
                <td id="progress-container-${scan.scan_id}">${progressHtml}</td>
                <td><strong class="${findingsColor}" id="findings-count-${scan.scan_id}">${findingsDisplay}</strong></td>
                <td style="white-space: nowrap;">
                    <a href="scan-details.html?id=${scan.scan_id}" class="btn btn-secondary btn-sm" id="btn-view-${scan.scan_id}">
                        <i class="ph ph-eye"></i> View
                    </a>
                    ${deleteBtnHtml}
                </td>
            `;

            listEl.appendChild(tr);

            // If running, start polling status
            if (scan.status === 'running' || scan.status === 'queued') {
                pollScanStatus(scan.scan_id);
            }
        });
    }

    function pollScanStatus(scanId) {
        // Poll status every 2 seconds
        activePollers[scanId] = setInterval(async () => {
            try {
                const statusInfo = await api.getScanStatus(scanId);
                
                const badgeEl = document.getElementById(`status-badge-${scanId}`);
                const stageTextEl = document.getElementById(`stage-text-${scanId}`);
                const progressBarEl = document.getElementById(`progress-bar-${scanId}`);
                const progressLabelEl = document.getElementById(`progress-label-${scanId}`);
                const findingsCountEl = document.getElementById(`findings-count-${scanId}`);
                
                if (statusInfo.status === 'completed' || statusInfo.status === 'failed') {
                    // Stop polling
                    clearInterval(activePollers[scanId]);
                    delete activePollers[scanId];
                    
                    // Full reload to redraw table correctly
                    loadScanHistory();
                    return;
                }
                
                // Update UI elements in place
                if (badgeEl) {
                    badgeEl.className = 'badge badge-warning';
                    badgeEl.textContent = statusInfo.status === 'running' ? 'Scanning' : 'Queued';
                }
                
                if (stageTextEl) {
                    stageTextEl.textContent = statusInfo.stage;
                }
                
                if (progressBarEl) {
                    progressBarEl.style.width = `${statusInfo.progress}%`;
                }
                
                if (progressLabelEl) {
                    progressLabelEl.textContent = `${statusInfo.progress}%`;
                }
            } catch (err) {
                console.error(`Failed to poll status for scan ${scanId}:`, err);
            }
        }, 2000);
    }
});
