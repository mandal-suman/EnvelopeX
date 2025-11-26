# Changelog

All notable changes to EnvelopeX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-11-25

### 🎉 Major Release - Complete Platform Overhaul

This release represents a complete transformation of EnvelopeX from a basic email analyzer to a comprehensive email forensics platform with a modern React dashboard.

### Added

#### Frontend Dashboard
- **Modern React Dashboard**: Brand new React-based UI replacing the previous basic interface
- **Dashboard Page**: Drag-and-drop email file upload with real-time validation
- **Analysis Results Page**: Comprehensive results viewer with tabbed interface
  - Overview tab with risk scoring and key findings
  - Headers tab with complete routing information
  - IOCs tab with extracted indicators (URLs, IPs, domains, emails, hashes)
  - Authentication tab with SPF/DKIM/DMARC validation results
  - Attachments tab with file hashes and download links
  - Body Content tab with safe HTML rendering
- **History Page**: Browser-based analysis history with localStorage persistence
- **Settings Page**: API key configuration and preferences management
- **About Page**: Platform information and feature overview
- **Modern UI Components**: Clean navigation sidebar, simplified navbar, branded footer
- **API Integration**: Complete axios-based API client with interceptors
- **State Management**: React Context API for global state
- **Local Storage Service**: Browser-based persistence for history and settings

#### Backend API
- **RESTful API**: FastAPI-based REST API with comprehensive endpoints
- **Async Job Queue**: Background processing for large email files
- **Health Check Endpoint**: `/health` for monitoring backend status
- **Synchronous Analysis**: `/api/analyze` for immediate results
- **Asynchronous Analysis**: `/api/analyze_async` for job-based processing
- **Job Status Endpoint**: `/api/job/{job_id}` for tracking analysis progress
- **Attachment Download**: `/api/download/{job_id}/{filename}` for secure file retrieval
- **CORS Support**: Configured for cross-origin requests from React frontend
- **API Key Authentication**: Optional API key protection for production environments

#### Analysis Features
- **IOC Extraction**: Automatic extraction of URLs, IP addresses, domains, email addresses, and file hashes
- **Phishing Detection**: Display name spoofing, reply-to mismatches, brand impersonation detection
- **Authentication Analysis**: SPF, DKIM, and DMARC validation with detailed results
- **Tracking Detection**: Hidden tracking pixel and email beacon identification
- **Attachment Analysis**: File hashing (MD5, SHA1, SHA256) and metadata extraction
- **Header Analysis**: Complete email routing path with hop-by-hop tracking
- **HTML Body Analysis**: Safe rendering with XSS prevention and content sanitization
- **Risk Scoring**: Automated threat assessment with severity indicators

#### Documentation
- **Comprehensive README**: Complete setup and usage documentation
- **API Documentation**: Detailed endpoint descriptions and examples
- **Configuration Guide**: Environment variables and settings explanation
- **Security Documentation**: Best practices and security features overview

### Changed

- **Architecture**: Migrated from monolithic structure to REST API + SPA architecture
- **UI Framework**: Switched to Bootstrap 5 with React Bootstrap components
- **State Management**: Implemented React Context API replacing direct component state
- **File Handling**: Enhanced drag-and-drop with better validation and error handling
- **Results Display**: Reorganized into logical tabs for better user experience
- **Navigation**: Streamlined to 4 core pages (Dashboard, History, Settings, About)
- **Branding**: Removed third-party template artifacts, implemented custom EnvelopeX branding
- **Package.json**: Added OpenSSL legacy provider flag for Node.js v20 compatibility

### Removed

- **Volt Dashboard Components**: Removed 90% of unused Volt React Dashboard template components
- **Unnecessary Routes**: Reduced from 35+ routes to 5 focused application routes
- **Profile Management**: Removed user profile/authentication UI (not needed for local tool)
- **Notification System**: Removed unused notification components
- **Unused Dependencies**: Cleaned up package.json removing unnecessary packages
- **Legacy Code**: Removed old analysis scripts and deprecated functions

### Security

- **No External Transmission**: All analysis performed locally with no data leaving the system
- **HTML Sanitization**: Implemented bleach-based HTML sanitization for email body rendering
- **XSS Prevention**: Protected against cross-site scripting in email content display
- **API Key Support**: Optional API key authentication for production deployments
- **CORS Protection**: Configured CORS policies for secure API access
- **Input Validation**: Comprehensive file type and size validation
- **Secure File Handling**: Safe temporary file management with automatic cleanup

### Technical Details

- **Backend**: Python 3.11+, FastAPI 0.95.2, uvicorn 0.22.0
- **Frontend**: React 16.13.1, Bootstrap 5, axios 1.6.0, react-router-dom 5.2.0
- **Analysis Engine**: BeautifulSoup4, bleach, lxml, python-magic
- **State Management**: React Context API
- **Storage**: localStorage for browser-based persistence
- **Build System**: react-scripts 3.4.3 with custom webpack config

## [1.0.0] - Previous Release

### Initial Release
- Basic email parsing functionality
- Simple command-line interface
- Core IOC extraction capabilities
- Basic phishing detection

---

For more information, visit the [GitHub repository](https://github.com/mandal-suman/envelopex)
