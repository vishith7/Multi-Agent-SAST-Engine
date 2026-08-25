// Global Findings Page Logic

document.addEventListener('DOMContentLoaded', () => {
    const listEl = document.getElementById('global-findings-list');
    const searchCategoryEl = document.getElementById('search-category');
    const filterVerdictEl = document.getElementById('filter-verdict');
    const filterSeverityEl = document.getElementById('filter-severity');
    const filterPriorityEl = document.getElementById('filter-priority');
    const filterRepoEl = document.getElementById('filter-repo');
    const filterSlaEl = document.getElementById('filter-sla');
    const resetBtn = document.getElementById('btn-reset-filters');

    // Populate Repository Filter & Load Findings
    init();

    // Bind Filter Events
    [filterVerdictEl, filterSeverityEl, filterPriorityEl, filterRepoEl, filterSlaEl].forEach(el => {
        el.addEventListener('change', loadFindings);
    });
    
    // Bind search with a small delay (debounce)
    let searchTimeout = null;
    searchCategoryEl.addEventListener('input', () => {
        if (searchTimeout) clearTimeout(searchTimeout);
        searchTimeout = setTimeout(loadFindings, 300);
    });

    // Reset Filters
    resetBtn.addEventListener('click', () => {
        searchCategoryEl.value = '';
        filterVerdictEl.value = 'ALL';
        filterSeverityEl.value = 'ALL';
        filterPriorityEl.value = 'ALL';
        filterRepoEl.value = 'ALL';
        filterSlaEl.value = 'ALL';
        loadFindings();
    });

    async function init() {
        try {
            // Populate Repos
            const repos = await api.getRepositories();
            repos.forEach(repo => {
                const opt = document.createElement('option');
                opt.value = repo.name;
                opt.textContent = repo.name;
                filterRepoEl.appendChild(opt);
            });
        } catch (e) {
            console.error('Failed to populate repositories filter:', e);
        }
        
        loadFindings();
    }

    async function loadFindings() {
        listEl.innerHTML = `
            <tr>
                <td colspan="8" class="empty-state">
                    <span class="loading-spinner"></span>
                    <p style="margin-top:0.5rem;">Querying findings database...</p>
                </td>
            </tr>
        `;

        const filters = {
            verdict: filterVerdictEl.value !== 'ALL' ? filterVerdictEl.value : null,
            severity: filterSeverityEl.value !== 'ALL' ? filterSeverityEl.value : null,
            priority: filterPriorityEl.value !== 'ALL' ? filterPriorityEl.value : null,
            repo: filterRepoEl.value !== 'ALL' ? filterRepoEl.value : null,
            sla_status: filterSlaEl.value !== 'ALL' ? filterSlaEl.value : null
        };

        try {
            let findings = await api.getFindings(filters);
            
            // Search locally on category / subtype text
            const searchVal = searchCategoryEl.value.trim().toLowerCase();
            if (searchVal) {
                findings = findings.filter(f => {
                    const cat = (f.category || '').toLowerCase();
                    const sub = (f.subtype || '').toLowerCase();
                    return cat.includes(searchVal) || sub.includes(searchVal);
                });
            }

            renderFindings(findings);
            
        } catch (err) {
            console.error('Failed to load findings:', err);
            listEl.innerHTML = `
                <tr>
                    <td colspan="8" class="empty-state">
                        <i class="ph ph-warning-circle" style="color: var(--critical);"></i>
                        <h3>Failed to load findings</h3>
                        <p>${err.message}</p>
                    </td>
                </tr>
            `;
        }
    }

    function renderFindings(findings) {
        listEl.innerHTML = '';
        
        if (findings.length === 0) {
            listEl.innerHTML = `
                <tr>
                    <td colspan="8" class="empty-state">
                        <i class="ph ph-bug-beetle"></i>
                        <h3>No findings found</h3>
                        <p>No vulnerabilities match the current filter criteria.</p>
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
            if (locStr.length > 30) {
                locStr = '...' + locStr.substring(locStr.length - 30);
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
                <td><strong>${f.repo || 'unknown'}</strong></td>
                <td style="font-family:var(--font-mono); font-size:0.75rem;">${locStr}</td>
                <td>${verdictBadge} ${defectdojoBadge}</td>
                <td>${(f.verdict_confidence || f.confidence || 0).toFixed(2)}</td>
                <td>${priority} (${sla})</td>
                <td>
                    <a href="finding-details.html?id=${f.fingerprint}&scan_id=${f.scan_id}" class="btn btn-secondary btn-sm">
                        <i class="ph ph-magnifying-glass"></i> Inspect
                    </a>
                </td>
            `;
            
            listEl.appendChild(tr);
        });
    }
});
