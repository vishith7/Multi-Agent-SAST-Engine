// DefectDojo Page JS Logic

document.addEventListener('DOMContentLoaded', async () => {
    const indicatorBadge = document.getElementById('indicator-badge');
    const statusBox = document.getElementById('status-box-indicator');
    const ddUrlVal = document.getElementById('dd-url-val');
    const ddEngagementVal = document.getElementById('dd-engagement-val');
    const ddTokenVal = document.getElementById('dd-token-val');

    // Form fields
    const configForm = document.getElementById('dd-config-form');
    const urlInput = document.getElementById('dd-url-input');
    const tokenInput = document.getElementById('dd-token-input');
    const engagementInput = document.getElementById('dd-engagement-input');
    const orgInput = document.getElementById('dd-org-input');
    const defaultEngInput = document.getElementById('dd-default-eng-input');
    const btnSave = document.getElementById('btn-save-dd-config');
    const formError = document.getElementById('dd-form-error');
    const formSuccess = document.getElementById('dd-form-success');

    // Helper to render configuration status
    const renderConfigStatus = (config) => {
        let statusText = config.status || 'NOT CONFIGURED';
        
        if (config.configured && statusText === 'CONNECTED') {
            indicatorBadge.textContent = 'CONNECTED';
            indicatorBadge.className = 'badge badge-success';
            statusBox.style.backgroundColor = 'var(--success-bg)';
            statusBox.style.borderColor = 'var(--success)';
            ddTokenVal.textContent = 'Configured (Secure)';
            ddTokenVal.style.color = 'var(--success)';
        } else {
            indicatorBadge.textContent = statusText;
            indicatorBadge.className = 'badge badge-warning';
            statusBox.style.backgroundColor = 'var(--warning-bg)';
            statusBox.style.borderColor = 'var(--warning)';
            
            if (statusText.includes('FAILED') || statusText.includes('DENIED')) {
                indicatorBadge.className = 'badge badge-critical';
                statusBox.style.backgroundColor = 'var(--critical-bg)';
                statusBox.style.borderColor = 'var(--critical)';
                ddTokenVal.style.color = 'var(--critical)';
            } else {
                ddTokenVal.style.color = config.has_token ? 'var(--warning)' : 'var(--critical)';
            }
            ddTokenVal.textContent = config.has_token ? 'Configured (Secure)' : 'Missing Token';
        }

        ddUrlVal.textContent = config.url || 'Not set';
        ddEngagementVal.textContent = config.engagement_id || 'Auto-Provisioning Enabled';

        // Prefill form inputs
        if (config.url) urlInput.value = config.url;
        if (config.engagement_id) engagementInput.value = config.engagement_id;
        if (config.organization) orgInput.value = config.organization;
        if (config.default_engagement) defaultEngInput.value = config.default_engagement;
        if (config.has_token) {
            tokenInput.placeholder = '•••••••••••••••• (Leave blank to keep existing)';
            tokenInput.removeAttribute('required');
        } else {
            tokenInput.placeholder = 'Enter API token';
            tokenInput.setAttribute('required', 'true');
        }
    };

    // Load initial config
    try {
        const config = await api.getDefectDojoConfig();
        renderConfigStatus(config);
    } catch (err) {
        console.error('Failed to load DefectDojo configuration:', err);
        indicatorBadge.textContent = 'Error Fetching Configuration';
        indicatorBadge.className = 'badge badge-critical';
        statusBox.style.backgroundColor = 'var(--critical-bg)';
        statusBox.style.borderColor = 'var(--critical)';
        
        ddUrlVal.textContent = 'N/A';
        ddEngagementVal.textContent = 'N/A';
        ddTokenVal.textContent = 'Offline';
        ddTokenVal.style.color = 'var(--critical)';
    }

    // Handle Form Submit (Save Config)
    configForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        formError.style.display = 'none';
        formSuccess.style.display = 'none';
        
        const url = urlInput.value.trim();
        const token = tokenInput.value.trim();
        const engagementId = engagementInput.value.trim();
        const organization = orgInput.value.trim();
        const defaultEng = defaultEngInput.value.trim();
        
        btnSave.disabled = true;
        btnSave.innerHTML = '<i class="ph ph-spinner spinner"></i> Verifying & Saving...';
        
        try {
            const res = await api.saveDefectDojoConfig(url, token, engagementId, organization, defaultEng);
            if (res.success) {
                formSuccess.textContent = res.message || 'DefectDojo credentials verified and saved successfully!';
                formSuccess.style.display = 'block';
                
                // Fetch the updated config state to refresh indicators
                const updatedConfig = await api.getDefectDojoConfig();
                renderConfigStatus(updatedConfig);
                
                // Clear password input value
                tokenInput.value = '';
            }
        } catch (error) {
            console.error('Failed to save DefectDojo config:', error);
            formError.textContent = error.message || 'Failed to verify and save credentials.';
            formError.style.display = 'block';
        } finally {
            btnSave.disabled = false;
            btnSave.innerHTML = '<i class="ph ph-floppy-disk"></i> Verify & Save';
        }
    });
});
