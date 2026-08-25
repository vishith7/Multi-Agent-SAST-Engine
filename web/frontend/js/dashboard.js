// Dashboard page logic

document.addEventListener('DOMContentLoaded', async () => {
    const healthStatusEl = document.getElementById('health-status');
    const healthIndicatorEl = document.querySelector('.status-indicator');
    
    // Check API Health
    try {
        const health = await api.getHealth();
        if (health.status === 'ok') {
            healthStatusEl.textContent = `Engine: ${health.engine}`;
            if (health.engine === 'available') {
                healthIndicatorEl.style.backgroundColor = 'var(--success)';
            } else {
                healthIndicatorEl.style.backgroundColor = 'var(--warning)';
            }
        }
    } catch (e) {
        healthStatusEl.textContent = 'Backend Offline';
        healthIndicatorEl.style.backgroundColor = 'var(--danger)';
    }

    // Fetch Dashboard Summary
    try {
        const summary = await api.getDashboardSummary();
        
        // Populate Summary Cards
        document.getElementById('stat-scans').textContent = summary.total_scans;
        document.getElementById('stat-findings').textContent = summary.total_findings;
        document.getElementById('stat-overdue').textContent = summary.sla_stats.overdue || 0;
        document.getElementById('stat-on-track').textContent = summary.sla_stats['on-track'] || 0;
        
        // Populate SLA Target Matrix
        document.getElementById('sla-overdue').textContent = summary.sla_stats.overdue || 0;
        document.getElementById('sla-approaching').textContent = summary.sla_stats.approaching || 0;
        document.getElementById('sla-ontrack').textContent = summary.sla_stats['on-track'] || 0;
        
        // Populate Severity Bar Chart
        const sev = summary.severity_stats;
        const totalSev = (sev.Critical || 0) + (sev.High || 0) + (sev.Medium || 0) + (sev.Low || 0);
        
        const updateBar = (barId, countId, count) => {
            document.getElementById(countId).textContent = count;
            const pct = totalSev > 0 ? (count / totalSev) * 100 : 0;
            document.getElementById(barId).style.width = `${pct}%`;
        };
        
        updateBar('bar-critical', 'count-critical', sev.Critical || 0);
        updateBar('bar-high', 'count-high', sev.High || 0);
        updateBar('bar-medium', 'count-medium', sev.Medium || 0);
        updateBar('bar-low', 'count-low', sev.Low || 0);
        
        // Populate Recent Scans Table
        const listEl = document.getElementById('recent-scans-list');
        listEl.innerHTML = '';
        
        if (!summary.recent_scans || summary.recent_scans.length === 0) {
            listEl.innerHTML = `
                <tr>
                    <td colspan="5" class="empty-state">
                        <i class="ph ph-shield-warning"></i>
                        <h3>No scans found</h3>
                        <p>Start a new scan to see results here.</p>
                    </td>
                </tr>
            `;
            return;
        }
        
        summary.recent_scans.forEach(scan => {
            const tr = document.createElement('tr');
            tr.style.cursor = 'pointer';
            tr.addEventListener('click', () => {
                window.location.href = `scan-details.html?id=${scan.scan_id}`;
            });
            
            const date = new Date(scan.timestamp);
            const dateStr = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            
            let statusBadge = '';
            if (scan.status === 'running') {
                statusBadge = '<span class="badge badge-warning">Running</span>';
            } else if (scan.status === 'failed') {
                statusBadge = '<span class="badge badge-critical">Failed</span>';
            } else {
                statusBadge = '<span class="badge badge-success">Completed</span>';
            }
            
            tr.innerHTML = `
                <td><strong>${scan.repo}</strong></td>
                <td style="text-transform: capitalize;">${scan.scan_type || 'full'}</td>
                <td>${statusBadge}</td>
                <td><strong class="${scan.findings_count > 0 ? 'text-red' : 'text-green'}">${scan.findings_count}</strong></td>
                <td style="white-space: nowrap;">${dateStr}</td>
            `;
            listEl.appendChild(tr);
        });
        
    } catch (e) {
        console.error('Failed to load dashboard summary:', e);
        const listEl = document.getElementById('recent-scans-list');
        listEl.innerHTML = `
            <tr>
                <td colspan="5" class="empty-state">
                    <i class="ph ph-warning-circle" style="color: var(--critical);"></i>
                    <h3>Unable to connect to Taintlace backend</h3>
                    <p>Make sure the FastAPI server is running and accessible.</p>
                </td>
            </tr>
        `;
    }
});
