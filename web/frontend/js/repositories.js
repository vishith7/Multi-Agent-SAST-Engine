// Repositories Page Logic

document.addEventListener('DOMContentLoaded', async () => {
    const listEl = document.getElementById('repositories-list');
    
    try {
        const repos = await api.getRepositories();
        renderRepositories(repos);
    } catch (err) {
        console.error('Failed to load repositories:', err);
        listEl.innerHTML = `
            <tr>
                <td colspan="7" class="empty-state">
                    <i class="ph ph-warning-circle" style="color: var(--critical);"></i>
                    <h3>Failed to load repositories</h3>
                    <p>${err.message}</p>
                </td>
            </tr>
        `;
    }

    function renderRepositories(repos) {
        listEl.innerHTML = '';
        
        if (repos.length === 0) {
            listEl.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">
                        <i class="ph ph-folder-open"></i>
                        <h3>No repositories scanned yet</h3>
                        <p>Perform a scan to map repository metadata.</p>
                    </td>
                </tr>
            `;
            return;
        }

        repos.forEach(repo => {
            const tr = document.createElement('tr');
            
            const date = new Date(repo.last_scan);
            const dateStr = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            
            let statusBadge = '';
            if (repo.last_status === 'completed') {
                statusBadge = '<span class="badge badge-success">Completed</span>';
            } else if (repo.last_status === 'failed') {
                statusBadge = '<span class="badge badge-critical">Failed</span>';
            } else {
                statusBadge = '<span class="badge badge-warning">Running</span>';
            }
            
            const scanTypeLabel = repo.last_scan_type === 'diff-scoped' ? 'Diff-scoped' : 'Full Scan';
            const findingsColor = repo.finding_count > 0 ? 'text-red' : 'text-green';

            tr.innerHTML = `
                <td><strong>${repo.name}</strong></td>
                <td style="font-family:var(--font-mono); font-size:0.75rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${repo.path_or_url}">
                    ${repo.path_or_url}
                </td>
                <td style="white-space: nowrap;">${dateStr}</td>
                <td><span class="badge badge-low">${scanTypeLabel}</span></td>
                <td><strong class="${findingsColor}">${repo.finding_count}</strong></td>
                <td>${statusBadge}</td>
                <td>
                    <a href="scans.html?repo=${encodeURIComponent(repo.path_or_url)}" class="btn btn-secondary btn-sm">
                        <i class="ph ph-play-circle"></i> Scan Again
                    </a>
                </td>
            `;
            listEl.appendChild(tr);
        });
    }
});
