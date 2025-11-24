// EnvelopeX - New Results Renderer for PhishTool-style Interface
// Comprehensive tab-based email forensics display

const NewResultsRenderer = {
    currentData: null,

    render(data) {
        this.currentData = data;
        
        // Update breadcrumb with filename
        this.updateBreadcrumb(data);
        
        // Render all tabs
        this.renderDetails(data);
        this.renderAuthentication(data);
        this.renderURLs(data);
        this.renderAttachments(data);
        this.renderTransmission(data);
        this.renderXHeaders(data);
        this.renderMIMEStructure(data);
        this.renderBodyContents(data);
        
        // Initialize tab switching
        this.initializeTabSwitching();
        this.initializeBodyTabs();
    },

    /**
     * Update breadcrumb with filename
     */
    updateBreadcrumb(data) {
        const forensics = data.forensics || {};
        const fileMetadata = forensics.file_metadata || {};
        const filename = fileMetadata.file_name || data.metadata?.subject || 'Unknown File';
        
        // Update the analysis meta section
        const analysisMeta = document.getElementById('analysisMeta');
        if (analysisMeta) {
            analysisMeta.innerHTML = `
                <div style="display: flex; align-items: center; gap: 8px; color: var(--gray-600); font-size: 0.875rem;">
                    <a href="#" onclick="document.querySelector('[data-section=history]').click(); return false;" 
                       style="font-weight: 600; color: var(--primary); text-decoration: none; cursor: pointer;"
                       onmouseover="this.style.textDecoration='underline'"
                       onmouseout="this.style.textDecoration='none'">Analysis Result</a>
                    <i class="fas fa-chevron-right" style="font-size: 0.75rem;"></i>
                    <span style="color: var(--gray-900); font-weight: 500;">${this.escapeHtml(filename)}</span>
                </div>
            `;
        }
    },

    /**
     * TAB 1: DETAILS
     * Display ALL email fields in a clean list format
     */
    renderDetails(data) {
        const detailsList = document.getElementById('detailsList');
        if (!detailsList) return;

        const metadata = data.metadata || {};
        const headers = data.headers || {};
        const forensics = data.forensics || {};
        
        // Build comprehensive details array
        const details = [
            { label: 'From', value: metadata.from || headers.From || 'None' },
            { label: 'Display name', value: metadata.from_display_name || this.extractDisplayName(metadata.from) || 'None' },
            { label: 'Sender', value: metadata.sender || headers.Sender || 'None' },
            { label: 'To', value: this.formatArray(metadata.to) || headers.To || 'None' },
            { label: 'Cc', value: this.formatArray(metadata.cc) || headers.Cc || 'None' },
            { label: 'Bcc', value: this.formatArray(metadata.bcc) || 'None' },
            { label: 'In-Reply-To', value: metadata.in_reply_to || headers['In-Reply-To'] || 'None' },
            { label: 'Timestamp', value: metadata.date || headers.Date || 'None' },
            { label: 'Reply-To', value: metadata.reply_to || headers['Reply-To'] || 'None' },
            { label: 'Message-ID', value: metadata.message_id || headers['Message-ID'] || 'None' },
            { label: 'Return-Path', value: metadata.return_path || headers['Return-Path'] || 'None' },
            { label: 'Originating IP', value: metadata.originating_ip || 'None', isCode: true },
            { label: 'rDNS', value: metadata.reverse_dns || 'None' },
            { label: 'Subject', value: metadata.subject || headers.Subject || 'None' },
        ];

        // Render details list
        detailsList.innerHTML = details.map(detail => `
            <div class="detail-item">
                <div class="detail-item-label">${this.escapeHtml(detail.label)}</div>
                <div class="detail-item-value ${detail.value === 'None' ? 'empty' : ''}">
                    ${detail.isCode && detail.value !== 'None' 
                        ? `<code>${this.escapeHtml(detail.value)}</code>` 
                        : this.escapeHtml(detail.value)}
                </div>
            </div>
        `).join('');
    },

    /**
     * TAB 2: AUTHENTICATION
     * Display SPF, DKIM, DMARC with detailed information
     */
    renderAuthentication(data) {
        const authContent = document.getElementById('authenticationContent');
        if (!authContent) return;

        const auth = data.authentication || {};
        const headers = data.headers || {};
        
        // Extract authentication data
        const spf = auth.spf || {};
        const dkim = auth.dkim || {};
        const dmarc = auth.dmarc || {};
        const arc = auth.arc || {};

        let html = '';

        // SPF Section
        html += this.renderAuthSection({
            title: 'SPF',
            icon: 'envelope-open-text',
            status: spf.spf_pass_fail || 'unknown',
            fields: [
                { label: 'SPF', value: spf.spf_pass_fail || 'unknown' },
                { label: 'Originating IP', value: data.metadata?.originating_ip || 'None' },
                { label: 'Return-Path domain', value: spf.spf_domain || this.extractDomain(headers['Return-Path']) || 'None' },
                { label: 'SPF record', value: spf.spf_explanation || headers['Received-SPF'] || 'None' }
            ]
        });

        // DKIM Section
        const dkimVerifications = Array.isArray(dkim.dkim_signatures) ? dkim.dkim_signatures.length : 
                                 (dkim.dkim_signature_header_present ? 1 : 0);
        html += this.renderAuthSection({
            title: 'DKIM',
            icon: 'signature',
            status: dkim.dkim_pass_fail || 'unknown',
            fields: [
                { label: 'Verification(s)', value: `${dkimVerifications} Signature${dkimVerifications !== 1 ? 's' : ''}` },
                { label: 'Selector', value: dkim.dkim_selector || 'None' },
                { label: 'Signing domain', value: dkim.dkim_domain || 'None' },
                { label: 'Algorithm', value: dkim.dkim_algorithm || 'rsa-sha256' },
                { label: 'Verification', value: dkim.dkim_pass_fail || 'unknown' }
            ]
        });

        // DMARC Section
        html += this.renderAuthSection({
            title: 'DMARC',
            icon: 'shield-virus',
            status: dmarc.dmarc_pass_fail || 'unknown',
            fields: [
                { label: 'From domain', value: data.metadata?.sender_domain || 'None' },
                { label: 'DMARC record', value: dmarc.dmarc_policy || 'None' }
            ]
        });

        // ARC Section (if available)
        if (arc.arc_seal_present || arc.arc_message_signature_present) {
            html += this.renderAuthSection({
                title: 'ARC',
                icon: 'shield-alt',
                status: 'info',
                fields: [
                    { label: 'ARC-Seal', value: arc.arc_seal_present ? 'Present' : 'Not Present' },
                    { label: 'ARC-Message-Signature', value: arc.arc_message_signature_present ? 'Present' : 'Not Present' },
                    { label: 'ARC-Authentication-Results', value: arc.arc_authentication_results_present ? 'Present' : 'Not Present' }
                ]
            });
        }

        authContent.innerHTML = html;
    },

    renderAuthSection(config) {
        const statusClass = config.status === 'pass' ? 'pass' : 
                          config.status === 'fail' ? 'fail' : 
                          config.status === 'info' ? 'neutral' : 'warn';
        
        return `
            <div class="auth-section">
                <div class="auth-section-header">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <i class="fas fa-${config.icon}"></i>
                        <span class="auth-section-title">${config.title}</span>
                    </div>
                    <span class="status-badge ${statusClass}">
                        <i class="fas fa-${config.status === 'pass' ? 'check' : config.status === 'fail' ? 'times' : 'info-circle'}"></i>
                        ${config.status.toUpperCase()}
                    </span>
                </div>
                <div class="auth-section-body">
                    ${config.fields.map(field => `
                        <div class="auth-field">
                            <div class="auth-field-label">${field.label}</div>
                            <div class="auth-field-value">${this.escapeHtml(field.value)}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    },

    /**
     * TAB 3: URLs
     * Display all extracted URLs
     */
    renderURLs(data) {
        const urlsContent = document.getElementById('urlsContent');
        if (!urlsContent) return;

        const iocs = data.iocs || {};
        const urls = iocs.urls || [];
        const suspicious = iocs.urls_suspicious || [];

        if (urls.length === 0) {
            urlsContent.innerHTML = this.renderEmptyState('No URLs found in this email');
            return;
        }

        urlsContent.innerHTML = `
            <div class="url-list">
                ${urls.map(url => {
                    const isSuspicious = suspicious.includes(url);
                    return `
                        <div class="url-item">
                            <i class="fas fa-link url-icon"></i>
                            <span class="url-text">${this.escapeHtml(url)}</span>
                            ${isSuspicious ? '<span class="url-badge suspicious">Suspicious</span>' : ''}
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    },

    /**
     * TAB 4: ATTACHMENTS
     * Display all attachments with details
     */
    renderAttachments(data) {
        const attachmentsContent = document.getElementById('attachmentsContent');
        if (!attachmentsContent) return;

        const attachments = data.attachments || [];
        const forensics = data.forensics || {};
        const fileMetadata = forensics.file_metadata || {};

        let html = '';

        // Add email file metadata section
        if (fileMetadata.file_name) {
            html += `
                <div class="card" style="margin-bottom: 1.5rem;">
                    <div class="card-header">
                        <i class="fas fa-envelope"></i>
                        <h3>Email File Information</h3>
                    </div>
                    <div class="card-body">
                        <div class="details-list">
                            <div class="detail-item">
                                <div class="detail-item-label">File Name</div>
                                <div class="detail-item-value">${this.escapeHtml(fileMetadata.file_name)}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-item-label">File Type</div>
                                <div class="detail-item-value">${this.escapeHtml(fileMetadata.file_type || 'Unknown')}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-item-label">File Size</div>
                                <div class="detail-item-value">${this.formatBytes(fileMetadata.file_size || 0)}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-item-label">MD5</div>
                                <div class="detail-item-value"><code>${this.escapeHtml(fileMetadata.md5 || 'None')}</code></div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-item-label">SHA1</div>
                                <div class="detail-item-value"><code>${this.escapeHtml(fileMetadata.sha1 || 'None')}</code></div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-item-label">SHA256</div>
                                <div class="detail-item-value"><code>${this.escapeHtml(fileMetadata.sha256 || 'None')}</code></div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-item-label">Parsed At</div>
                                <div class="detail-item-value">${this.escapeHtml(fileMetadata.parsed_at || 'Unknown')}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-item-label">Parser Version</div>
                                <div class="detail-item-value">${this.escapeHtml(fileMetadata.parser_version || 'Unknown')}</div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        if (attachments.length === 0) {
            html += this.renderEmptyState('No email attachments found');
            attachmentsContent.innerHTML = html;
            return;
        }

        html += `
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-paperclip"></i>
                    <h3>Email Attachments (${attachments.length})</h3>
                </div>
                <div class="card-body" style="padding: 1rem;">
        `;

        html += attachments.map(att => `
            <div class="attachment-card">
                <div class="attachment-icon">
                    <i class="fas ${this.getFileIcon(att.filename)}"></i>
                </div>
                <div class="attachment-info">
                    <div class="attachment-name">${this.escapeHtml(att.filename || 'Unknown')}</div>
                    <div class="attachment-meta">
                        <span><i class="fas fa-file"></i> ${att.content_type || 'Unknown'}</span>
                        <span><i class="fas fa-weight"></i> ${this.formatBytes(att.size || 0)}</span>
                        ${att.md5 ? `<span><i class="fas fa-fingerprint"></i> MD5: ${att.md5.substring(0, 16)}...</span>` : ''}
                    </div>
                </div>
            </div>
        `).join('');
        
        html += `
                </div>
            </div>
        `;
        
        attachmentsContent.innerHTML = html;
    },

    /**
     * TAB 5: TRANSMISSION
     * Display email transmission hops
     */
    renderTransmission(data) {
        const transmissionContent = document.getElementById('transmissionContent');
        if (!transmissionContent) return;

        const forensics = data.forensics || {};
        const complete = forensics.complete_extraction || {};
        const received = complete.received_parsed || [];

        if (received.length === 0) {
            transmissionContent.innerHTML = this.renderEmptyState('No transmission data available');
            return;
        }

        transmissionContent.innerHTML = received.map((hop, index) => `
            <div class="transmission-hop">
                <div class="hop-header">
                    <div class="hop-number">${index + 1}</div>
                    <div class="hop-title">Hop ${index + 1}</div>
                    <div class="hop-timestamp">${hop.timestamp || 'Unknown time'}</div>
                </div>
                <div class="hop-details">
                    ${this.renderHopField('server', 'Received from', hop.from_server || 'Unknown')}
                    ${this.renderHopField('network-wired', 'IP Address', hop.from_ip || 'Unknown')}
                    ${this.renderHopField('arrow-right', 'Received by', hop.by_server || 'Unknown')}
                    ${this.renderHopField('envelope', 'Protocol', hop.protocol || 'Unknown')}
                </div>
            </div>
        `).join('');
    },

    renderHopField(icon, label, value) {
        return `
            <div class="hop-field">
                <i class="fas fa-${icon} hop-field-icon"></i>
                <div class="hop-field-label">${label}</div>
                <div class="hop-field-value">${this.escapeHtml(value)}</div>
            </div>
        `;
    },

    /**
     * TAB 6: X-HEADERS
     * Display all X- headers
     */
    renderXHeaders(data) {
        const xheadersContent = document.getElementById('xheadersContent');
        if (!xheadersContent) return;

        const headers = data.headers || {};
        const xHeaders = Object.entries(headers)
            .filter(([key]) => key.startsWith('X-') || key.startsWith('x-'))
            .sort(([a], [b]) => a.localeCompare(b));

        if (xHeaders.length === 0) {
            xheadersContent.innerHTML = this.renderEmptyState('No X-Headers found');
            return;
        }

        xheadersContent.innerHTML = `
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr>
                        <th style="text-align: left; padding: 12px; background: var(--gray-50); border-bottom: 2px solid var(--gray-300);">Header Name</th>
                        <th style="text-align: left; padding: 12px; background: var(--gray-50); border-bottom: 2px solid var(--gray-300);">Value</th>
                    </tr>
                </thead>
                <tbody>
                    ${xHeaders.map(([key, value]) => `
                        <tr style="border-bottom: 1px solid var(--gray-200);">
                            <td style="padding: 12px; font-weight: 600;">${this.escapeHtml(key)}</td>
                            <td style="padding: 12px; font-family: monospace; font-size: 0.875rem; word-break: break-all;">${this.escapeHtml(value)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    },

    /**
     * TAB 7: MIME STRUCTURE
     * Display MIME structure visualization
     */
    renderMIMEStructure(data) {
        const mimeContent = document.getElementById('mimeStructureContent');
        if (!mimeContent) return;

        const forensics = data.forensics || {};
        const analysisFlags = forensics.complete_extraction?.analysis_flags || {};
        const isMultipart = analysisFlags.is_multipart || false;

        if (!isMultipart) {
            mimeContent.innerHTML = this.renderEmptyState('Single-part message (no MIME structure)');
            return;
        }

        // Build MIME tree from body information
        const body = data.body || {};
        const attachments = data.attachments || [];

        let mimeHtml = '<div class="mime-tree">';
        mimeHtml += '<div class="mime-node"><div class="mime-node-header">';
        mimeHtml += '<span class="mime-node-type">multipart/mixed</span>';
        mimeHtml += '</div>';

        if (body.body_text) {
            mimeHtml += '<div class="mime-node"><div class="mime-node-header">';
            mimeHtml += '<span class="mime-node-type">text/plain</span>';
            mimeHtml += `<span class="mime-node-details">charset=${body.body_charset || 'utf-8'}</span>`;
            mimeHtml += '</div></div>';
        }

        if (body.body_html_raw) {
            mimeHtml += '<div class="mime-node"><div class="mime-node-header">';
            mimeHtml += '<span class="mime-node-type">text/html</span>';
            mimeHtml += `<span class="mime-node-details">charset=${body.body_charset || 'utf-8'}</span>`;
            mimeHtml += '</div></div>';
        }

        attachments.forEach(att => {
            mimeHtml += '<div class="mime-node"><div class="mime-node-header">';
            mimeHtml += `<span class="mime-node-type">${att.content_type || 'application/octet-stream'}</span>`;
            mimeHtml += `<span class="mime-node-details">${att.filename || 'unnamed'} (${this.formatBytes(att.size)})</span>`;
            mimeHtml += '</div></div>';
        });

        mimeHtml += '</div></div>';
        mimeContent.innerHTML = mimeHtml;
    },

    /**
     * TAB 8: BODY CONTENTS
     * Display plain text, HTML source, and HTML preview
     */
    renderBodyContents(data) {
        const body = data.body || {};
        const forensics = data.forensics || {};
        const rawEmail = forensics.complete_extraction?.raw_full_email || '';

        // Plain Text
        const plainContent = body.body_text || rawEmail || 'No plain text content available';
        const plainBodyContent = document.getElementById('plainBodyContent');
        if (plainBodyContent) {
            plainBodyContent.textContent = plainContent;
        }

        // HTML Source (beautified)
        const htmlSource = body.body_html_raw || 'No HTML content available';
        const htmlBodyContent = document.getElementById('htmlBodyContent');
        if (htmlBodyContent) {
            if (htmlSource !== 'No HTML content available') {
                htmlBodyContent.textContent = this.beautifyHTML(htmlSource);
            } else {
                htmlBodyContent.textContent = htmlSource;
            }
        }

        // HTML Preview
        const htmlPreview = body.body_html_sanitized || body.body_html_raw || '';
        const previewFrame = document.getElementById('emailPreviewFrame');
        if (previewFrame && htmlPreview && htmlPreview !== 'No HTML content available') {
            const previewDoc = previewFrame.contentDocument || previewFrame.contentWindow.document;
            previewDoc.open();
            previewDoc.write(htmlPreview);
            previewDoc.close();
        }
    },

    /**
     * UTILITY FUNCTIONS
     */
    initializeTabSwitching() {
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabPanes = document.querySelectorAll('.tab-pane');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const tabName = button.dataset.tab;

                // Remove active from all buttons and panes
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabPanes.forEach(pane => pane.classList.remove('active'));

                // Add active to clicked button and corresponding pane
                button.classList.add('active');
                const targetPane = document.getElementById(`${tabName}-tab`);
                if (targetPane) {
                    targetPane.classList.add('active');
                }
            });
        });
    },

    initializeBodyTabs() {
        const bodyTabBtns = document.querySelectorAll('.body-tab-btn');
        const plainCard = document.getElementById('plainBodyCard');
        const htmlCard = document.getElementById('htmlBodyCard');
        const previewCard = document.getElementById('previewBodyCard');

        bodyTabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tabName = btn.dataset.bodyTab;

                // Remove active from all buttons
                bodyTabBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                // Hide all cards
                if (plainCard) plainCard.style.display = 'none';
                if (htmlCard) htmlCard.style.display = 'none';
                if (previewCard) previewCard.style.display = 'none';

                // Show selected card
                if (tabName === 'plain' && plainCard) plainCard.style.display = 'block';
                if (tabName === 'html' && htmlCard) htmlCard.style.display = 'block';
                if (tabName === 'preview' && previewCard) previewCard.style.display = 'block';
            });
        });
    },

    formatArray(arr) {
        if (!arr) return null;
        if (Array.isArray(arr)) return arr.join(', ');
        return arr;
    },

    formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
    },

    extractDisplayName(from) {
        if (!from || from === 'None') return null;
        const match = from.match(/^(.+?)\s*<.*>$/);
        return match ? match[1].trim() : null;
    },

    extractDomain(email) {
        if (!email || email === 'None') return null;
        const match = email.match(/@([\w.-]+)/);
        return match ? match[1] : null;
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

    renderEmptyState(message) {
        return `
            <div class="tab-empty-state">
                <i class="fas fa-inbox"></i>
                <p>${message}</p>
            </div>
        `;
    },

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    beautifyHTML(html) {
        // Simple HTML beautifier
        let formatted = '';
        let indent = 0;
        const tab = '  ';
        
        // Split by tags
        const tokens = html.split(/(<[^>]+>)/g).filter(t => t.trim());
        
        tokens.forEach(token => {
            if (token.startsWith('</')) {
                // Closing tag
                indent = Math.max(0, indent - 1);
                formatted += tab.repeat(indent) + token + '\n';
            } else if (token.startsWith('<')) {
                // Opening tag
                formatted += tab.repeat(indent) + token + '\n';
                // Self-closing tags don't increase indent
                if (!token.endsWith('/>') && !token.startsWith('<!') && 
                    !token.match(/<(br|hr|img|input|meta|link)[\s>]/i)) {
                    indent++;
                }
            } else {
                // Text content
                const trimmed = token.trim();
                if (trimmed) {
                    formatted += tab.repeat(indent) + trimmed + '\n';
                }
            }
        });
        
        return formatted || html;
    }
};
