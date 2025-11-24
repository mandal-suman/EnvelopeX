// EnvelopeX v1.0.0 - Email Forensics Platform

const AppState = {
    currentSection: 'analysis',
    currentAnalysis: null,
    analysisHistory: [],
    sidebarCollapsed: false
};

const StorageManager = {
    keys: {
        HISTORY: 'envelopex_history',
        STATS: 'envelopex_stats'
    },
    
    saveHistory(analysis) {
        const history = this.getHistory();
        history.unshift({
            id: Date.now(),
            timestamp: new Date().toISOString(),
            filename: analysis.filename,
            from: analysis.from,
            subject: analysis.subject,
            status: this.calculateStatus(analysis),
            riskScore: this.calculateRiskScore(analysis),
            data: analysis
        });
        
        // Keep only last 100 analyses
        if (history.length > 100) history.pop();
        
        localStorage.setItem(this.keys.HISTORY, JSON.stringify(history));
        this.updateStats();
    },
    
    getHistory() {
        const data = localStorage.getItem(this.keys.HISTORY);
        return data ? JSON.parse(data) : [];
    },
    
    clearHistory() {
        localStorage.removeItem(this.keys.HISTORY);
        this.updateStats();
    },
    
    calculateStatus(analysis) {
        const anomalies = analysis.anomalies?.length || 0;
        if (anomalies === 0) return 'safe';
        if (anomalies <= 2) return 'suspicious';
        return 'malicious';
    },
    
    calculateRiskScore(analysis) {
        let score = 0;
        const anomalies = analysis.anomalies?.length || 0;
        
        // Safely check authentication status (normalize different shapes)
        const rawSpf = analysis.authentication?.spf;
        const spfStatus = rawSpf || '';
        let normSpf = '';
        if (typeof rawSpf === 'string') normSpf = rawSpf.toLowerCase();
        else if (Array.isArray(rawSpf)) normSpf = rawSpf.join(' ').toLowerCase();
        else if (typeof rawSpf === 'object' && rawSpf !== null) normSpf = JSON.stringify(rawSpf).toLowerCase();
        else normSpf = String(rawSpf || '').toLowerCase();
        const authPass = normSpf.includes('pass') ? 0 : 20;
        
        score = Math.min(100, anomalies * 15 + authPass);
        return score;
    },
    
    updateStats() {
        const history = this.getHistory();
        const stats = {
            total: history.length,
            safe: history.filter(h => h.status === 'safe').length,
            suspicious: history.filter(h => h.status === 'suspicious').length,
            malicious: history.filter(h => h.status === 'malicious').length,
            avgTime: 2.3 // Placeholder
        };
        
        localStorage.setItem(this.keys.STATS, JSON.stringify(stats));
    },
    
    getStats() {
        const data = localStorage.getItem(this.keys.STATS);
        return data ? JSON.parse(data) : {
            total: 0,
            safe: 0,
            suspicious: 0,
            malicious: 0,
            avgTime: 0
        };
    }
};

// UI Components

const UIComponents = {
    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const iconMap = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        
        toast.innerHTML = `
            <i class="fas ${iconMap[type]} toast-icon"></i>
            <div class="toast-content">
                <div class="toast-title">${type.charAt(0).toUpperCase() + type.slice(1)}</div>
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        container.appendChild(toast);
        
        toast.querySelector('.toast-close').addEventListener('click', () => {
            toast.remove();
        });
        
        setTimeout(() => {
            toast.remove();
        }, 5000);
    },
    
    showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.add('active');
    },
    
    hideModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.remove('active');
    },
    
    updateBreadcrumb(section) {
        const breadcrumb = document.getElementById('currentSection');
        const sectionNames = {
            dashboard: 'Dashboard',
            analysis: 'New Analysis',
            history: 'Analysis History',
            statistics: 'Statistics',
            documentation: 'Documentation',
            results: 'Analysis Results'
        };
        
        if (breadcrumb) {
            breadcrumb.textContent = sectionNames[section] || section;
        }
    }
};

// Navigation

const Navigation = {
    init() {
        // Sidebar navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const section = item.dataset.section;
                this.switchSection(section);
            });
        });
        
        // Sidebar collapse toggle
        const collapseBtn = document.getElementById('sidebarCollapseBtn');
        const sidebar = document.querySelector('.sidebar');
        
        if (collapseBtn && sidebar) {
            collapseBtn.addEventListener('click', () => {
                sidebar.classList.toggle('collapsed');
                AppState.sidebarCollapsed = sidebar.classList.contains('collapsed');
                // Save state to localStorage
                localStorage.setItem('sidebar_collapsed', AppState.sidebarCollapsed);
            });
            
            // Restore collapsed state from localStorage
            const savedState = localStorage.getItem('sidebar_collapsed');
            if (savedState === 'true') {
                sidebar.classList.add('collapsed');
                AppState.sidebarCollapsed = true;
            }
        }
        
        // Mobile menu toggle
        const menuToggle = document.getElementById('menuToggle');
        
        if (menuToggle && sidebar) {
            menuToggle.addEventListener('click', () => {
                sidebar.classList.toggle('active');
            });
        }
    },
    
    switchSection(section) {
        // Update active nav item
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
            if (item.dataset.section === section) {
                item.classList.add('active');
            }
        });
        
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(sec => {
            sec.classList.remove('active');
            sec.style.display = 'none';
        });
        
        // Show target section
        const targetSection = document.getElementById(`${section}-section`);
        if (targetSection) {
            targetSection.classList.add('active');
            targetSection.style.display = 'block';
            AppState.currentSection = section;
            UIComponents.updateBreadcrumb(section);
            
            // Load section data
            if (section === 'dashboard') Dashboard.load();
            if (section === 'history') HistoryManager.load();
            if (section === 'statistics') StatisticsManager.load();
            
            // Reset file input when switching to analysis section
            if (section === 'analysis') {
                const fileInput = document.getElementById('emailFile');
                const selectedFile = document.getElementById('selectedFile');
                const dropZone = document.getElementById('dropZone');
                const fileError = document.getElementById('fileError');
                const analyzeBtn = document.getElementById('analyzeBtn');
                
                if (fileInput) fileInput.value = '';
                if (selectedFile) selectedFile.style.display = 'none';
                if (dropZone) dropZone.style.display = 'block';
                if (fileError) fileError.style.display = 'none';
                
                // Disable analyze button
                if (analyzeBtn) {
                    analyzeBtn.disabled = true;
                    analyzeBtn.style.opacity = '0.5';
                    analyzeBtn.style.cursor = 'not-allowed';
                }
            }
        }
    }
};

// Dashboard

const Dashboard = {
    load() {
        this.updateStats();
        this.loadRecentActivity();
        this.initializeCharts();
    },
    
    updateStats() {
        const stats = StorageManager.getStats();
        
        document.getElementById('totalAnalysisCount').textContent = stats.total;
        document.getElementById('safeEmailsCount').textContent = stats.safe;
        document.getElementById('threatsDetected').textContent = stats.malicious + stats.suspicious;
        document.getElementById('avgAnalysisTime').textContent = stats.avgTime + 's';
    },
    
    loadRecentActivity() {
        const history = StorageManager.getHistory().slice(0, 5);
        const container = document.getElementById('recentActivity');
        
        if (history.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-inbox"></i>
                    <p>No recent activity</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = history.map(item => `
            <div class="activity-item">
                <div class="activity-icon">
                    <i class="fas fa-file-alt"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${this.escapeHtml(item.filename)}</div>
                    <div class="activity-time">${this.formatTimestamp(item.timestamp)}</div>
                </div>
                <span class="status-badge ${item.status}">${item.status}</span>
            </div>
        `).join('');
    },
    
    initializeCharts() {
        if (typeof Chart === 'undefined') return;
        
        // Analysis Timeline Chart
        const analysisCtx = document.getElementById('analysisChart');
        if (analysisCtx) {
            new Chart(analysisCtx, {
                type: 'line',
                data: {
                    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                    datasets: [{
                        label: 'Analyses',
                        data: [12, 19, 15, 25, 22, 18, 20],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }
        
        // Threat Distribution Chart
        const threatCtx = document.getElementById('threatChart');
        if (threatCtx) {
            const stats = StorageManager.getStats();
            new Chart(threatCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Safe', 'Suspicious', 'Malicious'],
                    datasets: [{
                        data: [stats.safe, stats.suspicious, stats.malicious],
                        backgroundColor: ['#10b981', '#f59e0b', '#ef4444']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }
    },
    
    formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        
        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes}m ago`;
        if (hours < 24) return `${hours}h ago`;
        if (days < 7) return `${days}d ago`;
        return date.toLocaleDateString();
    },
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// File Upload Handler

const FileUploader = {
    allowedExtensions: ['.eml', '.msg', '.mbox', '.txt', '.emlx'],
    maxFileSize: 25 * 1024 * 1024, // 25MB
    currentFile: null, // Store the validated file
    
    init() {
        const form = document.getElementById('analyzeForm');
        const fileInput = document.getElementById('emailFile');
        const dropZone = document.getElementById('dropZone');
        const selectedFile = document.getElementById('selectedFile');
        const removeBtn = document.getElementById('removeFile');
        
        if (!form || !fileInput) return;
        
        // File input change
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) this.handleFile(file);
        });
        
        // Drag and drop
        if (dropZone) {
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                });
            });
            
            ['dragenter', 'dragover'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => {
                    dropZone.classList.add('drag-over');
                });
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => {
                    dropZone.classList.remove('drag-over');
                });
            });
            
            dropZone.addEventListener('drop', (e) => {
                const file = e.dataTransfer.files[0];
                if (file) {
                    fileInput.files = e.dataTransfer.files;
                    this.handleFile(file);
                }
            });
        }
        
        // Remove file
        if (removeBtn) {
            removeBtn.addEventListener('click', () => {
                const analyzeBtn = document.getElementById('analyzeBtn');
                fileInput.value = '';
                selectedFile.style.display = 'none';
                dropZone.style.display = 'block';
                this.clearError();
                this.currentFile = null; // Clear stored file
                
                // Disable submit button when no file
                if (analyzeBtn) {
                    analyzeBtn.disabled = true;
                    analyzeBtn.style.opacity = '0.5';
                    analyzeBtn.style.cursor = 'not-allowed';
                }
            });
        }
        
        // Form submission
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.submitAnalysis();
        });
    },
    
    handleFile(file) {
        const fileName = document.getElementById('fileName');
        const fileSize = document.getElementById('fileSize');
        const selectedFile = document.getElementById('selectedFile');
        const dropZone = document.getElementById('dropZone');
        const fileError = document.getElementById('fileError');
        const fileErrorMessage = document.getElementById('fileErrorMessage');
        const analyzeBtn = document.getElementById('analyzeBtn');
        const fileInput = document.getElementById('emailFile');
        
        // Step 1: Comprehensive file validation
        const validation = this.validateFile(file);
        
        if (!validation.valid) {
            this.showError(validation.error);
            fileInput.value = ''; // Clear the input
            this.currentFile = null;
            return;
        }
        
        // File is valid - store it and clear any previous errors
        this.currentFile = file;
        this.clearError();
        
        // Enable submit button
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.style.opacity = '1';
            analyzeBtn.style.cursor = 'pointer';
        }
        
        if (fileName) fileName.textContent = file.name;
        if (fileSize) fileSize.textContent = this.formatFileSize(file.size);
        if (selectedFile) selectedFile.style.display = 'flex';
        if (dropZone) dropZone.style.display = 'none';
        
        UIComponents.showToast('File validated successfully. Ready to analyze.', 'success');
    },
    
    validateFile(file) {
        // Check if file exists
        if (!file || !file.name) {
            return { valid: false, error: 'No file selected' };
        }
        
        // Check if file is empty
        if (file.size === 0) {
            return { valid: false, error: 'File is empty. Please select a valid email file.' };
        }
        
        // Validate file extension
        const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
        if (!this.allowedExtensions.includes(fileExtension)) {
            const supported = this.allowedExtensions.join(', ').toUpperCase();
            return { 
                valid: false, 
                error: `Invalid file format "${fileExtension.toUpperCase()}". Supported formats: ${supported}` 
            };
        }
        
        // Validate file size
        if (file.size > this.maxFileSize) {
            return { 
                valid: false, 
                error: `File too large (${this.formatFileSize(file.size)}). Maximum allowed: ${this.formatFileSize(this.maxFileSize)}` 
            };
        }
        
        // Additional validation: check file name length
        if (file.name.length > 255) {
            return { valid: false, error: 'File name too long. Maximum 255 characters.' };
        }
        
        // All validations passed
        return { valid: true };
    },
    
    showError(message) {
        const fileError = document.getElementById('fileError');
        const fileErrorMessage = document.getElementById('fileErrorMessage');
        const analyzeBtn = document.getElementById('analyzeBtn');
        const selectedFile = document.getElementById('selectedFile');
        const dropZone = document.getElementById('dropZone');
        
        if (fileErrorMessage) fileErrorMessage.textContent = message;
        if (fileError) fileError.style.display = 'flex';
        
        // Disable submit button
        if (analyzeBtn) {
            analyzeBtn.disabled = true;
            analyzeBtn.style.opacity = '0.5';
            analyzeBtn.style.cursor = 'not-allowed';
        }
        
        // Hide selected file, show drop zone
        if (selectedFile) selectedFile.style.display = 'none';
        if (dropZone) dropZone.style.display = 'block';
        
        UIComponents.showToast(message, 'error');
    },
    
    clearError() {
        const fileError = document.getElementById('fileError');
        if (fileError) fileError.style.display = 'none';
    },
    
    formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    },
    
    async submitAnalysis() {
        // Step 1: Verify we have a validated file
        if (!this.currentFile) {
            UIComponents.showToast('Please select a valid file to analyze', 'error');
            return;
        }
        
        // Step 2: Re-validate before submission (security measure)
        const validation = this.validateFile(this.currentFile);
        if (!validation.valid) {
            this.showError(validation.error);
            this.currentFile = null;
            return;
        }
        
        // Show results section with loading
        Navigation.switchSection('results');
        document.getElementById('loadingSection').style.display = 'block';
        document.getElementById('resultsContent').style.display = 'none';
        
        // Simulate loading steps
        this.animateLoadingSteps();
        
        // Step 3: Prepare structured payload for server
        const payload = await this.preparePayload(this.currentFile);
        
        try {
            // Step 4: Send structured request to server
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });
            
            const result = await response.json();
            
            // Step 5: Handle server response
            if (result.success) {
                AppState.currentAnalysis = result.data;
                StorageManager.saveHistory({
                    ...result.data,
                    filename: this.currentFile.name
                });
                
                // Hide loading, show results
                document.getElementById('loadingSection').style.display = 'none';
                document.getElementById('resultsContent').style.display = 'block';
                
                // Use new PhishTool-style renderer
                if (typeof NewResultsRenderer !== 'undefined') {
                    NewResultsRenderer.render(result.data);
                } else {
                    // Fallback to old renderer
                    ResultsRenderer.render(result.data);
                }
                
                UIComponents.showToast('Analysis completed successfully', 'success');
                Dashboard.updateStats();
                
                // Clear current file after successful analysis
                this.currentFile = null;
            } else {
                throw new Error(result.error || 'Analysis failed');
            }
        } catch (error) {
            console.error('Analysis error:', error);
            UIComponents.showToast(error.message || 'Analysis failed. Please try again.', 'error');
            Navigation.switchSection('analysis');
        }
    },
    
    async preparePayload(file) {
        // Step 2: Create structured payload with file data and metadata
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onload = (e) => {
                const base64Content = btoa(
                    new Uint8Array(e.target.result)
                        .reduce((data, byte) => data + String.fromCharCode(byte), '')
                );
                
                // Structured format for server
                const payload = {
                    file: {
                        name: file.name,
                        size: file.size,
                        type: file.type || 'application/octet-stream',
                        extension: '.' + file.name.split('.').pop().toLowerCase(),
                        content: base64Content,
                        lastModified: file.lastModified,
                        uploadedAt: new Date().toISOString()
                    },
                    metadata: {
                        clientTimestamp: new Date().toISOString(),
                        userAgent: navigator.userAgent,
                        platform: navigator.platform
                    }
                };
                
                resolve(payload);
            };
            
            reader.onerror = () => {
                reject(new Error('Failed to read file'));
            };
            
            reader.readAsArrayBuffer(file);
        });
    },
    
    animateLoadingSteps() {
        const steps = ['step1', 'step2', 'step3', 'step4'];
        let currentStep = 0;
        
        const interval = setInterval(() => {
            if (currentStep > 0) {
                const prevStep = document.getElementById(steps[currentStep - 1]);
                if (prevStep) {
                    prevStep.classList.add('active');
                    prevStep.querySelector('i').className = 'fas fa-check-circle';
                }
            }
            
            if (currentStep < steps.length) {
                const step = document.getElementById(steps[currentStep]);
                if (step) step.classList.add('active');
                currentStep++;
            } else {
                clearInterval(interval);
            }
        }, 800);
    }
};

// Results Renderer

const ResultsRenderer = {
    externalScriptsEnabled: false, // External scripts disabled by default
    currentEmailData: null,
    bodyEventListenersSetup: false, // Flag to prevent duplicate setup
    
    render(data) {
        this.currentEmailData = data; // Store for later use
        this.renderOverview(data);
        this.renderHeaders(data);
        this.renderAuthentication(data);
        this.renderMimeStructure(data);
        this.renderBody(data);
        this.renderAttachments(data);
        this.renderSecurity(data);
        this.initializeTabSwitching();
        // Export buttons now use global event delegation - no initialization needed
    },

    normalizeAuthStatus(status) {
        if (!status && status !== 0) return '';
        if (typeof status === 'string') return status.toLowerCase();
        if (Array.isArray(status)) return status.join(' ').toLowerCase();
        if (typeof status === 'object') return JSON.stringify(status).toLowerCase();
        return String(status).toLowerCase();
    },
    
    renderOverview(data) {
        // Extract metadata with fallbacks
        const metadata = data.metadata || {};
        const from = metadata.from || data.from || 'N/A';
        const to = metadata.to || data.to || 'N/A';
        const subject = metadata.subject || data.subject || 'N/A';
        const date = metadata.date || data.date || 'N/A';
        const messageId = metadata.message_id || data.message_id || 'None';
        const replyTo = metadata.reply_to || data.reply_to || 'None';
        const returnPath = metadata.return_path || data.return_path || 'None';
        const cc = metadata.cc || data.cc || 'None';
        const inReplyTo = metadata.in_reply_to || data.in_reply_to || 'None';
        
        // Extract display name from From header
        const displayName = this.extractDisplayName(from);
        
        // Populate Email Details
        document.getElementById('detailFrom').innerHTML = this.formatEmailAddress(from);
        document.getElementById('detailDisplayName').textContent = displayName || 'None';
        document.getElementById('detailReplyTo').innerHTML = this.formatEmailAddress(replyTo);
        document.getElementById('detailReturnPath').innerHTML = this.formatEmailAddress(returnPath);
        document.getElementById('detailTo').innerHTML = this.formatEmailAddress(to);
        document.getElementById('detailCc').innerHTML = this.formatEmailAddress(cc);
        document.getElementById('detailSubject').textContent = subject;
        document.getElementById('detailTimestamp').textContent = date;
        document.getElementById('detailMessageId').innerHTML = messageId !== 'None' ? `<code>${this.escapeHtml(messageId)}</code>` : '<span class="none">None</span>';
        document.getElementById('detailInReplyTo').innerHTML = inReplyTo !== 'None' ? `<code>${this.escapeHtml(inReplyTo)}</code>` : '<span class="none">None</span>';
        
        // Populate Network Information
        const headers = data.headers || {};
        
        // Use metadata values directly (from backend v1.0.0)
        const originatingIP = metadata.originating_ip || 
                             this.extractOriginatingIP(headers);
        const rdns = metadata.reverse_dns || 
                    (headers['Received'] ? this.extractRDNS(headers['Received']) : 'None');
        const receivedPath = this.extractReceivedPath(headers['Received']);
        
        document.getElementById('detailOriginatingIP').innerHTML = originatingIP ? `<code>${this.escapeHtml(originatingIP)}</code>` : '<span class="none">None</span>';
        document.getElementById('detailRDNS').textContent = rdns || 'None';
        document.getElementById('detailReceivedPath').innerHTML = receivedPath;
        
        // Populate Anomalies
        const anomalies = data.anomalies || [];
        const anomalyCount = document.getElementById('anomalyCount');
        const anomaliesContent = document.getElementById('anomaliesContent');
        
        if (anomalyCount) {
            anomalyCount.textContent = anomalies.length;
            anomalyCount.className = anomalies.length === 0 ? 'anomaly-count zero' : 'anomaly-count';
        }
        
        if (anomaliesContent) {
            if (anomalies.length === 0) {
                anomaliesContent.innerHTML = '<p class="text-success"><i class="fas fa-check-circle"></i> No anomalies detected</p>';
            } else {
                anomaliesContent.innerHTML = `
                    <ul class="anomaly-list">
                        ${anomalies.map(a => `
                            <li class="anomaly-item">
                                <i class="fas fa-exclamation-triangle"></i>
                                <span>${this.escapeHtml(a)}</span>
                            </li>
                        `).join('')}
                    </ul>
                `;
            }
        }
        
        // Populate Attachments Summary
        const attachments = data.attachments || [];
        const attachmentsSummaryCard = document.getElementById('attachmentsSummaryCard');
        const attachmentCountBadge = document.getElementById('attachmentCountBadge');
        const attachmentsSummaryContent = document.getElementById('attachmentsSummaryContent');
        
        if (attachments.length > 0) {
            if (attachmentsSummaryCard) attachmentsSummaryCard.style.display = 'block';
            if (attachmentCountBadge) attachmentCountBadge.textContent = attachments.length;
            
            if (attachmentsSummaryContent) {
                attachmentsSummaryContent.innerHTML = attachments.map(att => `
                    <div class="attachment-summary-item">
                        <div class="attachment-icon">
                            <i class="fas ${this.getFileIcon(att.filename)}"></i>
                        </div>
                        <div class="attachment-details">
                            <div class="attachment-name">${this.escapeHtml(att.filename || 'Unknown')}</div>
                            <div class="attachment-meta">
                                ${att.content_type || 'Unknown type'} • ${this.formatFileSize(att.size)}
                            </div>
                        </div>
                    </div>
                `).join('');
            }
        } else {
            if (attachmentsSummaryCard) attachmentsSummaryCard.style.display = 'none';
        }
    },
    
    extractDisplayName(fromHeader) {
        if (!fromHeader || fromHeader === 'N/A' || fromHeader === 'None') return null;
        const match = fromHeader.match(/^"?([^"<]+)"?\s*</);
        return match ? match[1].trim() : null;
    },
    
    formatEmailAddress(email) {
        if (!email || email === 'N/A' || email === 'None') {
            return '<span class="none">None</span>';
        }
        return `<code>${this.escapeHtml(email)}</code>`;
    },
    
    extractOriginatingIP(headers) {
        if (!headers || !headers['Received']) return null;
        const received = Array.isArray(headers['Received']) ? headers['Received'][0] : headers['Received'];
        const ipMatch = received.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
        return ipMatch ? ipMatch[1] : null;
    },
    
    extractRDNS(received) {
        if (!received) return 'None';
        const receivedStr = Array.isArray(received) ? received[0] : received;
        const match = receivedStr.match(/from\s+([^\s\[]+)/);
        return match ? match[1] : 'None';
    },
    
    extractReceivedPath(received) {
        if (!received) return '<span class="none">No path information</span>';
        
        const receivedArray = Array.isArray(received) ? received : [received];
        const path = receivedArray.slice(0, 5).map((hop, index) => {
            const fromMatch = hop.match(/from\s+([^\s\[]+)/);
            const ipMatch = hop.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
            
            const server = fromMatch ? fromMatch[1] : 'Unknown';
            const ip = ipMatch ? ipMatch[1] : '';
            
            return `
                <div class="received-path-item">
                    <i class="fas fa-server"></i>
                    <span><strong>${index + 1}.</strong> ${this.escapeHtml(server)}${ip ? ` [${ip}]` : ''}</span>
                </div>
            `;
        }).join('');
        
        return path || '<span class="none">No path information</span>';
    },
    
    getFileIcon(filename) {
        if (!filename) return 'fa-file';
        const ext = filename.split('.').pop().toLowerCase();
        const iconMap = {
            'pdf': 'fa-file-pdf',
            'doc': 'fa-file-word',
            'docx': 'fa-file-word',
            'xls': 'fa-file-excel',
            'xlsx': 'fa-file-excel',
            'ppt': 'fa-file-powerpoint',
            'pptx': 'fa-file-powerpoint',
            'zip': 'fa-file-archive',
            'rar': 'fa-file-archive',
            '7z': 'fa-file-archive',
            'jpg': 'fa-file-image',
            'jpeg': 'fa-file-image',
            'png': 'fa-file-image',
            'gif': 'fa-file-image',
            'txt': 'fa-file-alt',
            'csv': 'fa-file-csv'
        };
        return iconMap[ext] || 'fa-file';
    },
    
    formatFileSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        if (typeof bytes === 'string') return bytes;
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    
    renderHeaders(data) {
        const tbody = document.getElementById('headersTableBody');
        if (!tbody || !data.headers) return;
        
        const headers = Object.entries(data.headers || {});
        tbody.innerHTML = headers.map(([key, value]) => `
            <tr>
                <td><span class="badge badge-secondary">Standard</span></td>
                <td><strong>${this.escapeHtml(key)}</strong></td>
                <td>${this.escapeHtml(String(value))}</td>
                <td>
                    <button class="btn-icon" onclick="navigator.clipboard.writeText('${this.escapeHtml(String(value))}')">
                        <i class="fas fa-copy"></i>
                    </button>
                </td>
            </tr>
        `).join('');
        
        // Initialize header search
        const searchInput = document.getElementById('headerSearch');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                const query = e.target.value.toLowerCase();
                tbody.querySelectorAll('tr').forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(query) ? '' : 'none';
                });
            });
        }
    },
    
    renderAuthentication(data) {
        const auth = data.authentication || {};
        
        // Helper to format auth details
        const formatAuthDetails = (authData) => {
            if (!authData) return '<div class="auth-detail-item"><span class="auth-detail-value">Not available</span></div>';
            
            if (typeof authData === 'string') {
                return `<div class="auth-detail-item"><span class="auth-detail-value">${this.escapeHtml(authData)}</span></div>`;
            }
            
            if (typeof authData === 'object') {
                let html = '';
                for (const [key, value] of Object.entries(authData)) {
                    const displayValue = typeof value === 'object' ? JSON.stringify(value, null, 2) : value;
                    html += `
                        <div class="auth-detail-item">
                            <span class="auth-detail-label">${this.escapeHtml(key)}:</span>
                            <span class="auth-detail-value">${this.escapeHtml(String(displayValue))}</span>
                        </div>
                    `;
                }
                return html || '<div class="auth-detail-item"><span class="auth-detail-value">No details available</span></div>';
            }
            
            return `<div class="auth-detail-item"><span class="auth-detail-value">${this.escapeHtml(String(authData))}</span></div>`;
        };
        
        // SPF
        const spfContent = document.getElementById('spfContent');
        const spfBadge = document.getElementById('spfBadge');
        const spfProgress = document.getElementById('spfProgress');
        const spfResult = document.getElementById('spfResult');
        
        if (spfContent) {
            const rawSpf = auth.spf;
            const normSpf = this.normalizeAuthStatus(rawSpf);
            const isPass = normSpf.includes('pass') || normSpf.includes('neutral') || normSpf.includes('none') ? normSpf.includes('pass') : normSpf.includes('pass');
            spfContent.innerHTML = formatAuthDetails(rawSpf);
            if (spfBadge) {
                spfBadge.textContent = isPass ? 'PASS' : 'FAIL';
                spfBadge.className = `auth-badge ${isPass ? 'bg-success' : 'bg-danger'}`;
            }
            if (spfProgress) spfProgress.style.width = isPass ? '100%' : '0%';
            if (spfResult) spfResult.textContent = isPass ? 'PASS' : 'FAIL';
        }
        
        // DKIM
        const dkimContent = document.getElementById('dkimContent');
        const dkimBadge = document.getElementById('dkimBadge');
        const dkimProgress = document.getElementById('dkimProgress');
        const dkimResult = document.getElementById('dkimResult');
        
        if (dkimContent) {
            const rawDkim = auth.dkim;
            const normDkim = this.normalizeAuthStatus(rawDkim);
            const isPass = normDkim.includes('pass');
            dkimContent.innerHTML = formatAuthDetails(rawDkim);
            if (dkimBadge) {
                dkimBadge.textContent = isPass ? 'PASS' : 'FAIL';
                dkimBadge.className = `auth-badge ${isPass ? 'bg-success' : 'bg-danger'}`;
            }
            if (dkimProgress) dkimProgress.style.width = isPass ? '100%' : '0%';
            if (dkimResult) dkimResult.textContent = isPass ? 'PASS' : 'FAIL';
        }
        
        // DMARC
        const dmarcContent = document.getElementById('dmarcContent');
        const dmarcBadge = document.getElementById('dmarcBadge');
        const dmarcProgress = document.getElementById('dmarcProgress');
        const dmarcResult = document.getElementById('dmarcResult');
        
        if (dmarcContent) {
            const rawDmarc = auth.dmarc;
            const normDmarc = this.normalizeAuthStatus(rawDmarc);
            const isPass = normDmarc.includes('pass');
            dmarcContent.innerHTML = formatAuthDetails(rawDmarc);
            if (dmarcBadge) {
                dmarcBadge.textContent = isPass ? 'PASS' : 'FAIL';
                dmarcBadge.className = `auth-badge ${isPass ? 'bg-success' : 'bg-danger'}`;
            }
            if (dmarcProgress) dmarcProgress.style.width = isPass ? '100%' : '0%';
            if (dmarcResult) dmarcResult.textContent = isPass ? 'PASS' : 'FAIL';
        }
        
        // Authentication Results Header
        const authResultsHeader = document.getElementById('authResultsHeader');
        if (authResultsHeader) {
            const authHeader = data.headers?.['authentication-results'] || 
                             data.headers?.['Authentication-Results'] ||
                             'No Authentication-Results header found';
            authResultsHeader.textContent = authHeader;
        }
    },
    
    renderMimeStructure(data) {
        const container = document.getElementById('mimeStructureContent');
        if (!container) return;
        
        const structure = data.mime_structure || [];
        if (structure.length === 0) {
            container.innerHTML = '<p>No MIME structure available</p>';
            return;
        }
        
        container.innerHTML = `
            <div class="mime-tree">
                ${this.buildMimeTree(structure)}
            </div>
        `;
    },
    
    buildMimeTree(structure, level = 0) {
        return structure.map(item => `
            <div class="mime-node" style="margin-left: ${level * 20}px">
                <i class="fas fa-folder-open"></i>
                <strong>${this.escapeHtml(item.type || 'unknown')}</strong>
                ${item.filename ? `<span class="badge">${this.escapeHtml(item.filename)}</span>` : ''}
            </div>
        `).join('');
    },
    
    renderBody(data) {
        const plainBody = document.getElementById('plainBodyContent');
        const htmlBody = document.getElementById('htmlBodyContent');
        const previewFrame = document.getElementById('emailPreviewFrame');
        
            plainBody: !!plainBody,
            htmlBody: !!htmlBody,
            previewFrame: !!previewFrame
        });
        
        // Store the email data for later use
        this.currentEmailData = data;
        
        // Render plain text - show raw email content
        if (plainBody) {
            const plainText = data.body?.plain || data.body_plain || data.raw_email || 'No plain text content available';
            plainBody.textContent = plainText;
        }
        
        // Render HTML source (beautified)
        if (htmlBody) {
            const htmlSource = data.body?.html || data.body_html || '';
            if (htmlSource && htmlSource !== 'No HTML content available') {
                const beautifiedHtml = this.beautifyHtml(htmlSource);
                // Use textContent to display the raw HTML source code
                htmlBody.textContent = beautifiedHtml;
            } else {
                htmlBody.textContent = 'No HTML content available';
            }
        }
        
        // Setup iframe preview with external scripts disabled by default
        if (previewFrame) {
            const htmlContent = data.body?.html || data.body_html || '';
            if (htmlContent && htmlContent !== 'No HTML content available') {
                this.renderHtmlPreview(previewFrame, htmlContent, !this.externalScriptsEnabled);
            } else {
                previewFrame.srcdoc = '<div style="padding:20px;text-align:center;color:#666;">No HTML content to preview</div>';
            }
        }
        
        // Initialize body tab switching
        this.initializeBodyTabs();
        
        // Event handlers are now set up globally on DOMContentLoaded, no need to set up here
    },
    
    renderHtmlPreview(iframe, htmlContent, blockScripts) {
        if (blockScripts) {
            // Safe mode: Sanitize and render securely (scripts blocked)
            const sanitizedHtml = this.sanitizeEmailHtml(htmlContent);
            const safeDocument = this.createSafeDocument(sanitizedHtml);
            iframe.srcdoc = safeDocument;
            iframe.setAttribute('sandbox', 'allow-same-origin');
        } else {
            // Unsafe mode: Render original content with scripts allowed
            const enhancedDocument = this.createEnhancedDocument(htmlContent);
            iframe.srcdoc = enhancedDocument;
            // Add more sandbox permissions for full rendering including scripts
            iframe.setAttribute('sandbox', 'allow-same-origin allow-scripts allow-popups allow-forms');
        }
    },
    
    createSafeDocument(sanitizedHtml) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                        padding: 20px;
                        max-width: 100%;
                        overflow-wrap: break-word;
                        word-wrap: break-word;
                        line-height: 1.6;
                        color: #333;
                    }
                    img {
                        max-width: 100%;
                        height: auto;
                        border-radius: 4px;
                    }
                    a {
                        color: #0066cc;
                        text-decoration: none;
                        pointer-events: none;
                        cursor: not-allowed;
                        border-bottom: 1px dashed #0066cc;
                    }
                    table {
                        border-collapse: collapse;
                        max-width: 100%;
                        margin: 10px 0;
                    }
                    td, th {
                        padding: 8px;
                        border: 1px solid #ddd;
                    }
                    * {
                        max-width: 100%;
                    }
                    p {
                        margin: 10px 0;
                    }
                    h1, h2, h3, h4, h5, h6 {
                        margin: 15px 0 10px 0;
                        color: #222;
                    }
                </style>
            </head>
            <body>
                ${sanitizedHtml}
            </body>
            </html>
        `;
    },
    
    createEnhancedDocument(htmlContent) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    /* Reset and base styles */
                    * {
                        box-sizing: border-box;
                    }
                    
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;
                        padding: 20px;
                        margin: 0;
                        line-height: 1.6;
                        color: #333;
                        background: #fff;
                        max-width: 100%;
                        overflow-wrap: break-word;
                        word-wrap: break-word;
                    }
                    
                    /* Typography */
                    h1, h2, h3, h4, h5, h6 {
                        margin: 20px 0 10px 0;
                        line-height: 1.3;
                        color: #222;
                        font-weight: 600;
                    }
                    
                    p {
                        margin: 10px 0;
                    }
                    
                    a {
                        color: #0066cc;
                        text-decoration: none;
                        transition: color 0.2s;
                    }
                    
                    a:hover {
                        color: #004499;
                        text-decoration: underline;
                    }
                    
                    /* Images */
                    img {
                        max-width: 100%;
                        height: auto;
                        border-radius: 8px;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    }
                    
                    /* Tables */
                    table {
                        border-collapse: collapse;
                        max-width: 100%;
                        margin: 15px 0;
                        background: #fff;
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                        border-radius: 8px;
                        overflow: hidden;
                    }
                    
                    td, th {
                        padding: 12px;
                        border: 1px solid #e5e7eb;
                        text-align: left;
                    }
                    
                    th {
                        background-color: #f9fafb;
                        font-weight: 600;
                        color: #374151;
                    }
                    
                    tr:hover {
                        background-color: #f9fafb;
                    }
                    
                    /* Buttons */
                    button, .button, input[type="button"], input[type="submit"] {
                        padding: 10px 20px;
                        background: #0066cc;
                        color: white;
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 14px;
                        font-weight: 500;
                        transition: background 0.2s;
                    }
                    
                    button:hover, .button:hover {
                        background: #0052a3;
                    }
                    
                    /* Lists */
                    ul, ol {
                        margin: 10px 0;
                        padding-left: 25px;
                    }
                    
                    li {
                        margin: 5px 0;
                    }
                    
                    /* Blockquotes */
                    blockquote {
                        margin: 15px 0;
                        padding: 10px 20px;
                        border-left: 4px solid #0066cc;
                        background: #f9fafb;
                        font-style: italic;
                    }
                    
                    /* Code */
                    code {
                        background: #f3f4f6;
                        padding: 2px 6px;
                        border-radius: 4px;
                        font-family: 'Courier New', monospace;
                        font-size: 0.9em;
                    }
                    
                    pre {
                        background: #1f2937;
                        color: #e5e7eb;
                        padding: 15px;
                        border-radius: 8px;
                        overflow-x: auto;
                    }
                    
                    pre code {
                        background: none;
                        color: inherit;
                        padding: 0;
                    }
                    
                    /* Responsive */
                    @media (max-width: 600px) {
                        body {
                            padding: 10px;
                        }
                        
                        table {
                            font-size: 14px;
                        }
                        
                        td, th {
                            padding: 8px;
                        }
                    }
                </style>
            </head>
            <body>
                ${htmlContent}
            </body>
            </html>
        `;
    },
    
    beautifyHtml(html) {
        // Simple HTML beautifier - adds proper indentation and line breaks
        let formatted = html;
        let indent = 0;
        const indentSize = 2;
        
        // Remove existing whitespace between tags
        formatted = formatted.replace(/>\s+</g, '><');
        
        // Add line breaks and indentation
        const tokens = [];
        const regex = /(<\/?[^>]+>)/g;
        let lastIndex = 0;
        let match;
        
        while ((match = regex.exec(formatted)) !== null) {
            // Add text before tag
            if (match.index > lastIndex) {
                const text = formatted.substring(lastIndex, match.index).trim();
                if (text) {
                    tokens.push({ type: 'text', content: text });
                }
            }
            
            // Add tag
            const tag = match[1];
            tokens.push({ type: 'tag', content: tag });
            lastIndex = regex.lastIndex;
        }
        
        // Add remaining text
        if (lastIndex < formatted.length) {
            const text = formatted.substring(lastIndex).trim();
            if (text) {
                tokens.push({ type: 'text', content: text });
            }
        }
        
        // Format with indentation
        let result = '';
        const selfClosingTags = ['br', 'hr', 'img', 'input', 'meta', 'link', 'area', 'base', 'col', 'embed', 'source', 'track', 'wbr'];
        const inlineTags = ['a', 'span', 'strong', 'em', 'b', 'i', 'u', 'small', 'code', 'sub', 'sup'];
        
        for (let i = 0; i < tokens.length; i++) {
            const token = tokens[i];
            
            if (token.type === 'tag') {
                const tag = token.content;
                const tagName = tag.match(/<\/?([a-zA-Z0-9]+)/)?.[1]?.toLowerCase();
                const isClosing = tag.startsWith('</');
                const isSelfClosing = selfClosingTags.includes(tagName) || tag.endsWith('/>');
                const isInline = inlineTags.includes(tagName);
                
                if (isClosing) {
                    indent = Math.max(0, indent - indentSize);
                    if (!isInline) {
                        result += '\n' + ' '.repeat(indent);
                    }
                    result += tag;
                } else {
                    if (!isInline && result.length > 0) {
                        result += '\n' + ' '.repeat(indent);
                    }
                    result += tag;
                    if (!isSelfClosing && !isInline) {
                        indent += indentSize;
                    }
                }
            } else if (token.type === 'text') {
                // Add text content
                const trimmed = token.content.trim();
                if (trimmed) {
                    if (result.endsWith('>')) {
                        result += trimmed;
                    } else {
                        result += ' ' + trimmed;
                    }
                }
            }
        }
        
        return result.trim();
    },
    
    syntaxHighlightHtml(html) {
        // Add syntax highlighting to HTML code
        let highlighted = this.escapeHtml(html);
        
        // Highlight HTML tags
        highlighted = highlighted.replace(/(&lt;\/?[a-zA-Z0-9]+)/g, '<span class="html-tag">$1</span>');
        highlighted = highlighted.replace(/(&gt;)/g, '<span class="html-tag">$1</span>');
        
        // Highlight attributes
        highlighted = highlighted.replace(/([a-zA-Z-]+)=/g, '<span class="html-attr">$1</span>=');
        
        // Highlight attribute values
        highlighted = highlighted.replace(/=&quot;([^&]*)&quot;/g, '=<span class="html-value">&quot;$1&quot;</span>');
        highlighted = highlighted.replace(/=&#39;([^&]*)&#39;/g, '=<span class="html-value">&#39;$1&#39;</span>');
        
        // Highlight comments
        highlighted = highlighted.replace(/(&lt;!--.*?--&gt;)/g, '<span class="html-comment">$1</span>');
        
        // Highlight DOCTYPE
        highlighted = highlighted.replace(/(&lt;!DOCTYPE.*?&gt;)/gi, '<span class="html-doctype">$1</span>');
        
        return highlighted;
    },
    
    sanitizeEmailHtml(html) {
        // Create a temporary div to parse HTML
        const temp = document.createElement('div');
        temp.innerHTML = html;
        
        // Remove all script tags
        temp.querySelectorAll('script').forEach(el => el.remove());
        
        // Remove dangerous attributes
        const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout', 'onfocus', 'onblur'];
        temp.querySelectorAll('*').forEach(el => {
            dangerousAttrs.forEach(attr => el.removeAttribute(attr));
            
            // Remove javascript: protocols
            ['href', 'src', 'data', 'action'].forEach(attr => {
                const value = el.getAttribute(attr);
                if (value && value.toLowerCase().includes('javascript:')) {
                    el.setAttribute(attr, '#blocked');
                }
            });
            
            // Block external resources for security
            if (el.tagName === 'IMG' || el.tagName === 'LINK') {
                const src = el.getAttribute('src') || el.getAttribute('href');
                if (src && (src.startsWith('http://') || src.startsWith('https://'))) {
                    el.setAttribute('data-blocked-src', src);
                    el.removeAttribute('src');
                    el.removeAttribute('href');
                    if (el.tagName === 'IMG') {
                        el.alt = `[Image blocked: ${src}]`;
                        el.style.display = 'inline-block';
                        el.style.padding = '10px';
                        el.style.backgroundColor = '#f0f0f0';
                        el.style.border = '1px dashed #ccc';
                    }
                }
            }
        });
        
        return temp.innerHTML;
    },
    
    initializeBodyTabs() {
        const plainCard = document.getElementById('plainBodyCard');
        const htmlCard = document.getElementById('htmlBodyCard');
        const previewCard = document.getElementById('previewBodyCard');
        
        document.querySelectorAll('.body-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                // Remove active from all buttons
                document.querySelectorAll('.body-tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Hide all cards
                if (plainCard) plainCard.style.display = 'none';
                if (htmlCard) htmlCard.style.display = 'none';
                if (previewCard) previewCard.style.display = 'none';
                
                // Show selected card
                const target = btn.dataset.bodyTab;
                if (target === 'plain' && plainCard) plainCard.style.display = 'block';
                if (target === 'html' && htmlCard) htmlCard.style.display = 'block';
                if (target === 'preview' && previewCard) previewCard.style.display = 'block';
            });
        });
    },
    
    // These functions are no longer used - event handlers are set up globally on DOMContentLoaded
    setupExternalScriptsToggle() {
        // Deprecated - handlers now in global event delegation
    },
    
    setupBodyCopyButtons() {
        // Deprecated - handlers now in global event delegation
    },
    
    renderAttachments(data) {
        const container = document.getElementById('attachmentsContent');
        if (!container) return;
        
        const attachments = data.attachments || [];
        if (attachments.length === 0) {
            container.innerHTML = '<p>No attachments found</p>';
            return;
        }
        
        container.innerHTML = `
            <div class="attachments-grid">
                ${attachments.map(att => `
                    <div class="attachment-card">
                        <i class="fas fa-file-alt"></i>
                        <div class="attachment-info">
                            <strong>${this.escapeHtml(att.filename || 'Unknown')}</strong>
                            <span>${att.size || 'Unknown size'}</span>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },
    
    renderSecurity(data) {
        const urlsContent = document.getElementById('urlsContent');
        const ipsContent = document.getElementById('ipsContent');
        const encryptionContent = document.getElementById('encryptionContent');
        
        if (urlsContent) {
            const urls = data.urls || [];
            urlsContent.innerHTML = urls.length > 0 
                ? `<ul>${urls.map(url => `<li>${this.escapeHtml(url)}</li>`).join('')}</ul>`
                : '<p>No URLs found</p>';
        }
        
        if (ipsContent) {
            const ips = data.ip_addresses || [];
            ipsContent.innerHTML = ips.length > 0
                ? `<ul>${ips.map(ip => `<li>${this.escapeHtml(ip)}</li>`).join('')}</ul>`
                : '<p>No IP addresses found</p>';
        }
        
        if (encryptionContent) {
            encryptionContent.innerHTML = '<p>No encryption details available</p>';
        }
    },
    
    initializeTabSwitching() {
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                
                btn.classList.add('active');
                const target = btn.dataset.tab;
                const pane = document.getElementById(`${target}-tab`);
                if (pane) pane.classList.add('active');
            });
        });
    },
    
    initializeExportButtons() {
        
        // Remove any existing listeners by cloning nodes (prevents duplicates)
        const exportBtn = document.getElementById('exportDropdownBtn');
        const menu = document.getElementById('exportDropdownMenu');
        
        if (exportBtn) {
            const newExportBtn = exportBtn.cloneNode(true);
            exportBtn.parentNode.replaceChild(newExportBtn, exportBtn);
            
            newExportBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                const menu = document.getElementById('exportDropdownMenu');
                if (menu) {
                    menu.classList.toggle('active');
                }
            });
        }
        
        // Handle JSON download
        if (menu) {
            const jsonBtn = menu.querySelector('#downloadJSON');
            if (jsonBtn) {
                jsonBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.exportJSON();
                    menu.classList.remove('active');
                });
            }
        }
        
        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            const menu = document.getElementById('exportDropdownMenu');
            const container = e.target.closest('.export-dropdown-container');
            if (menu && !container && menu.classList.contains('active')) {
                menu.classList.remove('active');
            }
        });
        
        // New Analysis button
        const newAnalysisBtn = document.getElementById('newAnalysisFromResults');
        if (newAnalysisBtn) {
            const newBtn = newAnalysisBtn.cloneNode(true);
            newAnalysisBtn.parentNode.replaceChild(newBtn, newAnalysisBtn);
            newBtn.addEventListener('click', () => {
                Navigation.switchSection('analysis');
            });
        }
    },
    
    exportJSON() {
        const data = JSON.stringify(AppState.currentAnalysis, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const filename = AppState.currentAnalysis?.filename || 'analysis';
        a.download = `${filename.replace(/\.[^/.]+$/, '')}-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        UIComponents.showToast('JSON exported successfully', 'success');
    },
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// History Manager

const HistoryManager = {
    filtersInitialized: false,
    
    load() {
        this.renderHistory();
        if (!this.filtersInitialized) {
            this.initializeFilters();
            this.filtersInitialized = true;
        }
    },
    
    renderHistory() {
        const tbody = document.getElementById('historyTableBody');
        if (!tbody) return;
        
        const history = StorageManager.getHistory();
        
        if (history.length === 0) {
            tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="8">
                        <div class="empty-state">
                            <i class="fas fa-history"></i>
                            <p>No analysis history available</p>
                            <button class="btn btn-primary" onclick="Navigation.switchSection('analysis')">
                                Start Your First Analysis
                            </button>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = history.map(item => `
            <tr>
                <td><input type="checkbox"></td>
                <td>${new Date(item.timestamp).toLocaleString()}</td>
                <td>${Dashboard.escapeHtml(item.filename)}</td>
                <td>${Dashboard.escapeHtml(item.from || 'N/A')}</td>
                <td>${Dashboard.escapeHtml(item.subject || 'N/A')}</td>
                <td><span class="status-badge ${item.status}">${item.status}</span></td>
                <td><span class="badge badge-warning">${item.data?.anomalies?.length || 0}</span></td>
                <td>
                    <button class="btn-icon" onclick="HistoryManager.viewAnalysis(${item.id})">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn-icon" onclick="HistoryManager.deleteAnalysis(${item.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    },
    
    initializeFilters() {
        const searchInput = document.getElementById('historySearch');
        const statusFilter = document.getElementById('statusFilter');
        const dateFilter = document.getElementById('dateFilter');
        const clearBtn = document.getElementById('clearHistory');
        
        if (searchInput) {
            searchInput.addEventListener('input', () => this.applyFilters());
        }
        
        if (statusFilter) {
            statusFilter.addEventListener('change', () => this.applyFilters());
        }
        
        if (dateFilter) {
            dateFilter.addEventListener('change', () => this.applyFilters());
        }
        
        if (clearBtn) {
            clearBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                if (confirm('Are you sure you want to clear all history?')) {
                    StorageManager.clearHistory();
                    this.renderHistory();
                    Dashboard.updateStats();
                    UIComponents.showToast('History cleared', 'success');
                }
            });
        }
    },
    
    applyFilters() {
        const searchQuery = document.getElementById('historySearch')?.value.toLowerCase() || '';
        const statusFilter = document.getElementById('statusFilter')?.value || 'all';
        
        const rows = document.querySelectorAll('#historyTableBody tr');
        rows.forEach(row => {
            if (row.classList.contains('empty-row')) return;
            
            const text = row.textContent.toLowerCase();
            const status = row.querySelector('.status-badge')?.textContent || '';
            
            const matchesSearch = text.includes(searchQuery);
            const matchesStatus = statusFilter === 'all' || status === statusFilter;
            
            row.style.display = (matchesSearch && matchesStatus) ? '' : 'none';
        });
    },
    
    viewAnalysis(id) {
        const history = StorageManager.getHistory();
        const item = history.find(h => h.id === id);
        
        if (item) {
            AppState.currentAnalysis = item.data;
            Navigation.switchSection('results');
            document.getElementById('loadingSection').style.display = 'none';
            document.getElementById('resultsContent').style.display = 'block';
            
            // Use new renderer if available
            if (typeof NewResultsRenderer !== 'undefined') {
                NewResultsRenderer.render(item.data);
            } else {
                ResultsRenderer.render(item.data);
            }
        }
    },
    
    deleteAnalysis(id) {
        if (!confirm('Delete this analysis?')) return;
        
        let history = StorageManager.getHistory();
        history = history.filter(h => h.id !== id);
        localStorage.setItem(StorageManager.keys.HISTORY, JSON.stringify(history));
        
        this.load();
        Dashboard.updateStats();
        UIComponents.showToast('Analysis deleted', 'success');
    }
};

// Statistics Manager

const StatisticsManager = {
    load() {
        this.updateStats();
        this.initializeCharts();
    },
    
    updateStats() {
        const stats = StorageManager.getStats();
        
        document.getElementById('statTotalEmails').textContent = stats.total;
        document.getElementById('statSPFRate').textContent = '85%';
        document.getElementById('statDKIMRate').textContent = '78%';
        document.getElementById('statDMARCRate').textContent = '72%';
        document.getElementById('statAvgAttachments').textContent = '1.2';
        document.getElementById('statAnomalies').textContent = stats.suspicious + stats.malicious;
    },
    
    initializeCharts() {
        if (typeof Chart === 'undefined') return;
        
        // Auth Success Chart
        const authCtx = document.getElementById('authSuccessChart');
        if (authCtx) {
            new Chart(authCtx, {
                type: 'bar',
                data: {
                    labels: ['SPF', 'DKIM', 'DMARC'],
                    datasets: [{
                        label: 'Pass Rate (%)',
                        data: [85, 78, 72],
                        backgroundColor: ['#10b981', '#06b6d4', '#667eea']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }
        
        // Format Chart
        const formatCtx = document.getElementById('formatChart');
        if (formatCtx) {
            new Chart(formatCtx, {
                type: 'pie',
                data: {
                    labels: ['EML', 'MSG', 'MBOX'],
                    datasets: [{
                        data: [60, 30, 10],
                        backgroundColor: ['#667eea', '#764ba2', '#f093fb']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }
        
        // Volume Chart
        const volumeCtx = document.getElementById('volumeChart');
        if (volumeCtx) {
            new Chart(volumeCtx, {
                type: 'line',
                data: {
                    labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                    datasets: [{
                        label: 'Analyses',
                        data: [45, 62, 58, 71],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }
    }
};

// Documentation Tabs Manager

const DocumentationTabs = {
    init() {
        const tabButtons = document.querySelectorAll('.tab-btn');
        
        tabButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const targetTab = e.currentTarget.getAttribute('data-tab');
                this.switchTab(targetTab);
            });
        });
    },
    
    switchTab(tabId) {
        // Remove active class from all buttons and panes
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.remove('active');
        });
        
        // Add active class to clicked button and corresponding pane
        const activeButton = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
        const activePane = document.getElementById(tabId);
        
        if (activeButton && activePane) {
            activeButton.classList.add('active');
            activePane.classList.add('active');
        }
    }
};

// Initialize Application

document.addEventListener('DOMContentLoaded', () => {
    Navigation.init();
    FileUploader.init();
    DocumentationTabs.init();
    // Don't auto-load dashboard since it's no longer the default section
    
    // Initialize additional buttons
    const newAnalysisBtn = document.getElementById('newAnalysisBtn');
    const viewAllHistory = document.getElementById('viewAllHistory');
    const refreshStats = document.getElementById('refreshStats');
    const settingsBtn = document.getElementById('settingsBtn');
    const copyAuthHeader = document.getElementById('copyAuthHeader');
    
    if (newAnalysisBtn) {
        newAnalysisBtn.addEventListener('click', () => Navigation.switchSection('analysis'));
    }
    
    if (viewAllHistory) {
        viewAllHistory.addEventListener('click', () => Navigation.switchSection('history'));
    }
    
    if (refreshStats) {
        refreshStats.addEventListener('click', () => {
            Dashboard.load();
            UIComponents.showToast('Statistics refreshed', 'success');
        });
    }
    
    // Copy Authentication Results Header
    if (copyAuthHeader) {
        copyAuthHeader.addEventListener('click', () => {
            const authHeader = document.getElementById('authResultsHeader');
            if (authHeader && authHeader.textContent) {
                navigator.clipboard.writeText(authHeader.textContent)
                    .then(() => UIComponents.showToast('Authentication header copied!', 'success'))
                    .catch(() => UIComponents.showToast('Failed to copy', 'error'));
            }
        });
    }
    
    // Settings dropdown toggle
    if (settingsBtn) {
        const settingsDropdown = document.getElementById('settingsDropdown');
        
        settingsBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            settingsDropdown.classList.toggle('active');
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (settingsDropdown && !settingsDropdown.contains(e.target) && e.target !== settingsBtn) {
                settingsDropdown.classList.remove('active');
            }
        });
        
        // Prevent dropdown from closing when clicking inside it
        if (settingsDropdown) {
            settingsDropdown.addEventListener('click', (e) => {
                e.stopPropagation();
            });
        }
    }
    
    // System Health Monitor
    HealthMonitor.init();
    
    // Global Export Button Handlers (Event Delegation)
    document.addEventListener('click', function(e) {
        // Handle Export Dropdown Toggle
        if (e.target.closest('#exportDropdownBtn')) {
            e.preventDefault();
            e.stopPropagation();
            const menu = document.getElementById('exportDropdownMenu');
            if (menu) {
                menu.classList.toggle('active');
            }
            return;
        }
        
        // Handle JSON Download
        if (e.target.closest('#downloadJSON')) {
            e.preventDefault();
            e.stopPropagation();
            if (AppState.currentAnalysis) {
                const data = JSON.stringify(AppState.currentAnalysis, null, 2);
                const blob = new Blob([data], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                const filename = AppState.currentAnalysis?.filename || 'analysis';
                a.download = `${filename.replace(/\.[^/.]+$/, '')}-${Date.now()}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                UIComponents.showToast('JSON exported successfully', 'success');
                
                const menu = document.getElementById('exportDropdownMenu');
                if (menu) menu.classList.remove('active');
            }
            return;
        }
        
        // Handle New Analysis Button
        if (e.target.closest('#newAnalysisFromResults')) {
            e.preventDefault();
            Navigation.switchSection('analysis');
            return;
        }
        
        // ==================================
        // Copy Button Handlers
        // ==================================
        
        // Copy X-Headers
        if (e.target.closest('#copyXHeaders')) {
            e.preventDefault();
            e.stopPropagation();
            const btn = e.target.closest('#copyXHeaders');
            const xHeadersContent = document.getElementById('xHeadersContent');
            
            if (xHeadersContent && xHeadersContent.textContent) {
                navigator.clipboard.writeText(xHeadersContent.textContent)
                    .then(() => {
                        UIComponents.showToast('X-Headers copied to clipboard', 'success');
                        const icon = btn.querySelector('i');
                        if (icon) {
                            const originalClass = icon.className;
                            icon.className = 'fas fa-check';
                            setTimeout(() => icon.className = originalClass, 2000);
                        }
                    })
                    .catch(() => UIComponents.showToast('Failed to copy X-Headers', 'error'));
            } else {
                UIComponents.showToast('No X-Headers content to copy', 'warning');
            }
            return;
        }
        
        // Copy Plain Body Text
        if (e.target.closest('#copyPlainBody')) {
            e.preventDefault();
            e.stopPropagation();
            const btn = e.target.closest('#copyPlainBody');
            const plainBody = document.getElementById('plainBodyContent');
            
            if (plainBody && plainBody.textContent) {
                navigator.clipboard.writeText(plainBody.textContent)
                    .then(() => {
                        UIComponents.showToast('Plain text copied to clipboard', 'success');
                        const icon = btn.querySelector('i');
                        if (icon) {
                            const originalClass = icon.className;
                            icon.className = 'fas fa-check';
                            setTimeout(() => icon.className = originalClass, 2000);
                        }
                    })
                    .catch(() => UIComponents.showToast('Failed to copy text', 'error'));
            } else {
                UIComponents.showToast('No plain text content to copy', 'warning');
            }
            return;
        }
        
        // Copy HTML Source
        if (e.target.closest('#copyHtmlBody')) {
            e.preventDefault();
            e.stopPropagation();
            const btn = e.target.closest('#copyHtmlBody');
            
            if (ResultsRenderer.currentEmailData) {
                const htmlSource = ResultsRenderer.currentEmailData.body?.html || ResultsRenderer.currentEmailData.body_html || '';
                if (htmlSource && htmlSource !== 'No HTML content available') {
                    const beautifiedHtml = ResultsRenderer.beautifyHtml(htmlSource);
                    navigator.clipboard.writeText(beautifiedHtml)
                        .then(() => {
                            UIComponents.showToast('HTML source copied to clipboard', 'success');
                            const icon = btn.querySelector('i');
                            if (icon) {
                                const originalClass = icon.className;
                                icon.className = 'fas fa-check';
                                setTimeout(() => icon.className = originalClass, 2000);
                            }
                        })
                        .catch(() => UIComponents.showToast('Failed to copy HTML', 'error'));
                } else {
                    UIComponents.showToast('No HTML content to copy', 'warning');
                }
            } else {
                UIComponents.showToast('No email data available', 'error');
            }
            return;
        }
        
        // ==================================
        // HTML Preview Control Handlers
        // ==================================
        
        // Toggle External Scripts (Safe Mode)
        if (e.target.closest('#toggleExternalScripts')) {
            e.preventDefault();
            e.stopPropagation();
            const toggleBtn = e.target.closest('#toggleExternalScripts');
            const statusBadge = document.getElementById('externalScriptsStatus');
            
            if (!statusBadge) return;
            
            ResultsRenderer.externalScriptsEnabled = !ResultsRenderer.externalScriptsEnabled;
            
            // Update UI
            if (ResultsRenderer.externalScriptsEnabled) {
                statusBadge.innerHTML = '<i class="fas fa-check-circle"></i> Scripts Enabled';
                statusBadge.className = 'status-badge status-enabled';
                statusBadge.title = 'External scripts are allowed (use with caution)';
                toggleBtn.classList.add('active');
            } else {
                statusBadge.innerHTML = '<i class="fas fa-shield-alt"></i> Scripts Blocked';
                statusBadge.className = 'status-badge status-disabled';
                statusBadge.title = 'External scripts are blocked';
                toggleBtn.classList.remove('active');
            }
            
            // Re-render preview
            const previewFrame = document.getElementById('emailPreviewFrame');
            if (previewFrame && ResultsRenderer.currentEmailData) {
                const htmlContent = ResultsRenderer.currentEmailData.body?.html || ResultsRenderer.currentEmailData.body_html || '';
                if (htmlContent && htmlContent !== 'No HTML content available') {
                    ResultsRenderer.renderHtmlPreview(previewFrame, htmlContent, !ResultsRenderer.externalScriptsEnabled);
                    UIComponents.showToast(
                        ResultsRenderer.externalScriptsEnabled ? 'Scripts enabled - Use with caution!' : 'Scripts blocked - Safe mode',
                        ResultsRenderer.externalScriptsEnabled ? 'warning' : 'success'
                    );
                }
            }
            return;
        }
        
        // Refresh Preview
        if (e.target.closest('#refreshPreview')) {
            e.preventDefault();
            e.stopPropagation();
            const previewFrame = document.getElementById('emailPreviewFrame');
            
            if (previewFrame && ResultsRenderer.currentEmailData) {
                const htmlContent = ResultsRenderer.currentEmailData.body?.html || ResultsRenderer.currentEmailData.body_html || '';
                if (htmlContent && htmlContent !== 'No HTML content available') {
                    ResultsRenderer.renderHtmlPreview(previewFrame, htmlContent, !ResultsRenderer.externalScriptsEnabled);
                    UIComponents.showToast('Preview refreshed', 'success');
                } else {
                    UIComponents.showToast('No HTML content to refresh', 'warning');
                }
            } else {
                UIComponents.showToast('No email data available', 'error');
            }
            return;
        }
        
        // Close export dropdown when clicking outside
        const exportContainer = e.target.closest('.export-dropdown-container');
        if (!exportContainer) {
            const menu = document.getElementById('exportDropdownMenu');
            if (menu && menu.classList.contains('active')) {
                menu.classList.remove('active');
            }
        }
    });
});

// Health Monitoring System

const HealthMonitor = {
    checkInterval: null,
    statusIndicator: null,
    statusText: null,
    consecutiveFailures: 0,
    maxFailures: 2,
    
    init() {
        this.statusIndicator = document.querySelector('.status-online');
        this.statusText = document.querySelector('.footer-status');
        
        if (!this.statusIndicator || !this.statusText) {
            console.warn('Health monitor: Status elements not found');
            return;
        }
        
        // Initial check
        this.checkHealth();
        
        // Check every 10 seconds
        this.checkInterval = setInterval(() => {
            this.checkHealth();
        }, 10000);
    },
    
    async checkHealth() {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
            
            const response = await fetch('/api/health', {
                method: 'GET',
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'operational') {
                    this.setStatus('operational');
                    this.consecutiveFailures = 0;
                } else {
                    this.handleFailure();
                }
            } else {
                this.handleFailure();
            }
        } catch (error) {
            console.error('Health check failed:', error.message);
            this.handleFailure();
        }
    },
    
    handleFailure() {
        this.consecutiveFailures++;
        
        if (this.consecutiveFailures >= this.maxFailures) {
            this.setStatus('offline');
        }
    },
    
    setStatus(status) {
        if (!this.statusIndicator || !this.statusText) return;
        
        if (status === 'operational') {
            this.statusIndicator.className = 'fas fa-circle status-online';
            this.statusIndicator.style.color = '#10b981';
            this.statusText.innerHTML = `
                <i class="fas fa-circle status-online"></i> All Systems Operational
            `;
        } else {
            this.statusIndicator.className = 'fas fa-circle status-offline';
            this.statusIndicator.style.color = '#ef4444';
            this.statusIndicator.style.animation = 'none';
            this.statusText.innerHTML = `
                <i class="fas fa-circle status-offline"></i> System Offline
            `;
        }
    },
    
    stop() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
    }
};

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    HealthMonitor.stop();
});
