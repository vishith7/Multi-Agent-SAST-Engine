// Unified Taintlace API Frontend Client

const API_BASE = '/api';

async function fetchJson(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        const data = await response.json();
        if (!response.ok) {
            // Handle Taintlace unified error format
            const errMsg = data.error ? data.error.message : 'HTTP Error ' + response.status;
            const errCode = data.error ? data.error.code : 'HTTP_ERROR';
            const error = new Error(errMsg);
            error.code = errCode;
            error.status = response.status;
            throw error;
        }
        return data;
    } catch (error) {
        console.error(`API Request to ${url} failed:`, error);
        throw error;
    }
}

const api = {
    async getHealth() {
        return fetchJson(`${API_BASE}/health`);
    },
    
    async getDashboardSummary() {
        return fetchJson(`${API_BASE}/dashboard/summary`);
    },
    
    async getScans() {
        return fetchJson(`${API_BASE}/scans`);
    },
    
    async startScan(repoPath, scanMode = 'AUTO', cpgName = 'cpg.bin', output = null, revalidate = false) {
        return fetchJson(`${API_BASE}/scans`, {
            method: 'POST',
            body: JSON.stringify({
                repo_path: repoPath,
                scan_mode: scanMode,
                cpg_name: cpgName,
                output: output,
                revalidate: revalidate
            })
        });
    },
    
    async getScan(scanId) {
        return fetchJson(`${API_BASE}/scans/${scanId}`);
    },
    
    async getScanStatus(scanId) {
        return fetchJson(`${API_BASE}/scans/${scanId}/status`);
    },
    
    async getScanFindings(scanId) {
        return fetchJson(`${API_BASE}/scans/${scanId}/findings`);
    },
    
    async getFindings(filters = {}) {
        const queryParams = new URLSearchParams();
        for (const [key, val] of Object.entries(filters)) {
            if (val) queryParams.append(key, val);
        }
        const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';
        return fetchJson(`${API_BASE}/findings${qs}`);
    },
    
    async getFinding(fingerprint) {
        return fetchJson(`${API_BASE}/findings/${fingerprint}`);
    },
    
    async pushFindingToDefectDojo(fingerprint) {
        return fetchJson(`${API_BASE}/findings/${fingerprint}/defectdojo`, {
            method: 'POST'
        });
    },
    
    async getDefectDojoConfig() {
        return fetchJson(`${API_BASE}/defectdojo/config`);
    },
    
    async saveDefectDojoConfig(url, token, engagementId, organization, defaultEngagement) {
        return fetchJson(`${API_BASE}/defectdojo/config`, {
            method: 'POST',
            body: JSON.stringify({ 
                url, 
                token, 
                engagement_id: engagementId,
                organization: organization,
                default_engagement: defaultEngagement
            })
        });
    },
    
    async syncScanDefectDojo(scanId) {
        return fetchJson(`${API_BASE}/scans/${scanId}/sync-defectdojo`, {
            method: 'POST'
        });
    },
    
    async updateHumanValidation(fingerprint, status, reviewer = null, comment = null) {
        return fetchJson(`${API_BASE}/findings/${fingerprint}/human-validation`, {
            method: 'POST',
            body: JSON.stringify({ status, reviewer, comment })
        });
    },
    
    async applyProposedFix(fingerprint, reviewer = 'Admin') {
        return fetchJson(`${API_BASE}/findings/${fingerprint}/apply-fix?reviewer=${encodeURIComponent(reviewer)}`, {
            method: 'POST'
        });
    },
    
    async getRepositories() {
        return fetchJson(`${API_BASE}/repositories`);
    },

    async deleteScan(scanId) {
        return fetchJson(`${API_BASE}/scans/${scanId}`, {
            method: 'DELETE'
        });
    }
};

window.api = api;
