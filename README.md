# EnvelopeX - Email Forensics Analysis Platform

[![Version](https://img.shields.io/badge/version-2.0.0--beta-blue.svg)](https://github.com/mandal-suman/envelopex)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/react-16.13.1-blue.svg)](https://reactjs.org/)
[![Bootstrap](https://img.shields.io/badge/bootstrap-5.0.0-purple.svg)](https://getbootstrap.com/)

A comprehensive email forensics and security analysis platform built with Python FastAPI backend and React dashboard.

> **v2.0.0 Release** - Complete platform overhaul with modern React dashboard, REST API architecture, and enhanced analysis capabilities. See [CHANGELOG.md](CHANGELOG.md) for full details.

## 🚀 Features

### Analysis Capabilities
- **IOC Extraction**: Automatically extract URLs, IP addresses, domains, emails, and file hashes
- **Phishing Detection**: Identify display name spoofing, reply-to mismatches, and brand impersonation
- **Authentication Analysis**: Validate SPF, DKIM, and DMARC results
- **Tracking Detection**: Detect hidden tracking pixels and email beacons
- **Attachment Analysis**: Hash and analyze email attachments with malware detection
- **Header Analysis**: Complete email routing path with hop tracking
- **Multiple Format Support**: .eml, .msg, .txt, .mbox, .mbx files

### Dashboard Features
- **Drag & Drop Upload**: Intuitive file upload with validation
- **Real-time Analysis**: Live progress tracking and status updates
- **Comprehensive Results**: Tabbed interface for detailed forensics data
- **Analysis History**: Browser-based history with localStorage
- **Risk Scoring**: Automated threat assessment with severity indicators
- **Export Capabilities**: Download results as JSON
- **Backend Monitoring**: Real-time health check and status display

## 📁 Project Structure

```
EnvelopeX/
├── backend/                 # Python FastAPI Backend
│   ├── app.py              # Main FastAPI application (335 lines)
│   ├── extractor.py        # Email forensics analyzer (543 lines)
│   ├── requirements.txt    # Python dependencies
│   └── .venv/             # Virtual environment
├── frontend/               # React Frontend Dashboard
│   ├── public/
│   │   ├── EnvelopeX.svg           # Static logo
│   │   ├── EnvelopeX-loading.svg   # Loading animation
│   │   └── EnvelopeX-inprogress.svg # Analysis indicator
│   ├── src/
│   │   ├── components/    # Reusable components
│   │   │   ├── Navbar.js      # Top navigation bar
│   │   │   ├── Sidebar.js     # Side navigation menu
│   │   │   └── Footer.js      # Footer component
│   │   ├── pages/         # Application pages
│   │   │   ├── Dashboard.js       # File upload & analysis
│   │   │   ├── AnalysisResults.js # Results viewer (tabs)
│   │   │   ├── History.js         # Analysis history
│   │   │   ├── SettingsPage.js    # Configuration
│   │   │   └── About.js           # Platform info
│   │   ├── services/      # API and storage
│   │   │   ├── api.js         # Backend API client (axios)
│   │   │   └── storage.js     # localStorage wrapper
│   │   ├── context/       # State management
│   │   │   └── AnalysisContext.js # Global state
│   │   ├── scss/          # Styles
│   │   ├── App.js         # Root component
│   │   ├── index.js       # Entry point
│   │   └── routes.js      # Route definitions
│   ├── package.json       # Node.js dependencies
│   └── .gitignore
├── .gitignore
├── CHANGELOG.md           # Version history
├── CONTRIBUTING.md        # Contribution guidelines
├── LICENSE                # MIT License
└── README.md             # This file
```

## 🛠️ Installation & Setup

### Prerequisites

- **Python 3.11+** - Backend server
- **Node.js 14+** - Frontend development
- **npm or yarn** - Package manager
- **Git** - Version control

### Quick Start

#### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the backend server
python app.py
```

The backend API will start on **http://localhost:8000**

**Backend Dependencies:**
- `fastapi==0.95.2` - Web framework
- `uvicorn[standard]==0.22.0` - ASGI server
- `python-multipart==0.0.6` - File upload handling
- `aiofiles==23.1.0` - Async file operations
- `pydantic==1.10.11` - Data validation
- `bleach==6.0.0` - HTML sanitization
- `beautifulsoup4==4.12.2` - HTML parsing
- `lxml==4.9.3` - XML processing
- `python-magic==0.4.27` - File type detection

#### 2. Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install
# or
yarn install

# Start development server
npm start
# or
yarn start
```

The dashboard will open at **http://localhost:3000**

**Key Frontend Dependencies:**
- `react` ^16.13.1 - UI library
- `react-router-dom` ^5.2.0 - Routing
- `axios` ^1.6.0 - HTTP client
- `bootstrap` 5.0.0-beta1 - CSS framework
- `@themesberg/react-bootstrap` ^1.4.1 - Bootstrap components
- `@fortawesome/react-fontawesome` ^0.1.17 - Icons
- `sass` ^1.50.0 - SCSS compiler

## 🎯 Usage

### Basic Workflow

1. **Start Backend**: Ensure Python backend is running on port 8000
2. **Open Dashboard**: Access React dashboard at http://localhost:3000
3. **Upload Email**: Drag & drop or select email file (.eml, .msg, etc.)
4. **Start Analysis**: Click "Start Analysis" button
5. **View Results**: Review comprehensive forensics results in tabbed interface
6. **Export Data**: Download results as JSON for further investigation

### Analysis Results Tabs

- **Overview**: Risk score, threat summary, key findings
- **Headers**: Complete email routing path with hop tracking
- **IOCs**: Extracted URLs, IPs, domains, emails, file hashes
- **Authentication**: SPF/DKIM/DMARC validation results
- **Attachments**: File list with MD5/SHA1/SHA256 hashes
- **Body Content**: Safe HTML rendering with XSS prevention

## 🔧 Configuration

### Backend Configuration

Environment variables (set in terminal or `.env` file):

```bash
# Optional configurations
export ENVELOPEX_MAX_UPLOAD_SIZE=104857600  # 100MB (default)
export ENVELOPEX_WORKER_TIMEOUT=120         # 120 seconds (default)
export ENVELOPEX_JOB_RETENTION=3600         # 1 hour (default)
export ENVELOPEX_API_KEY=your-secret-key    # API authentication (optional)
export PORT=8000                            # Backend port (default)
```

### Frontend Configuration

Create `.env` file in frontend directory:

```env
# Backend API URL
REACT_APP_API_URL=http://localhost:8000

# Optional: API Key for backend authentication
REACT_APP_API_KEY=your-secret-key
```

**Note:** Frontend uses `NODE_OPTIONS=--openssl-legacy-provider` for Node.js v20 compatibility (configured in package.json)

## 📊 API Documentation

### Backend Endpoints

#### Health Check
```
GET /health
Response: {"status": "healthy"}
```

#### Synchronous Analysis
```
POST /api/analyze
Content-Type: multipart/form-data
Body: file (email file)
Response: Complete analysis results JSON
```

#### Asynchronous Analysis
```
POST /api/analyze_async
Content-Type: multipart/form-data
Body: file (email file)
Response: {"job_id": "uuid", "status": "queued"}
```

#### Job Status
```
GET /api/job/{job_id}
Response: {"status": "done|running|failed", "result": {...}}
```

#### Download Attachment
```
GET /api/download/{job_id}/{filename}
Response: File download
```

### Response Structure

```json
{
  "basic_info": {
    "from": "sender@example.com",
    "to": ["recipient@example.com"],
    "subject": "Email Subject",
    "date": "2025-11-25T10:30:00"
  },
  "headers": [...],
  "iocs": {
    "urls": [...],
    "ips": [...],
    "domains": [...],
    "emails": [...]
  },
  "authentication": {
    "spf": "pass",
    "dkim": "pass",
    "dmarc": "pass"
  },
  "phishing_indicators": [...],
  "attachments": [...],
  "body": {
    "text": "...",
    "html": "..."
  }
}
```

## 🛡️ Security Features

### Data Protection
- **Local Processing**: All analysis performed locally, no external transmission
- **No Cloud Storage**: All data stays on your system
- **Browser Storage**: History stored in localStorage only
- **Temporary Files**: Automatic cleanup after analysis

### Security Measures
- **HTML Sanitization**: Bleach-based sanitization for email body rendering
- **XSS Prevention**: Protected against cross-site scripting in email content
- **CORS Protection**: Configured CORS policies for API access
- **Input Validation**: Comprehensive file type and size validation
- **API Key Support**: Optional API key authentication for production
- **Secure Headers**: Security headers configured in FastAPI

### Supported File Formats
- `.eml` - Standard email format
- `.msg` - Outlook message format
- `.txt` - Plain text emails
- `.mbox` - Unix mailbox format
- `.mbx` - Mailbox format

**Maximum File Size:** 100MB (configurable)

## 📦 Build for Production

### Backend Production

```bash
# Set production environment variables
export ENVELOPEX_API_KEY=your-production-key
export PORT=8000

# Run with production settings
python app.py
```

### Frontend Production

```bash
# Create optimized production build
npm run build
# or
yarn build

# Serve production build
npx serve -s build

# Or deploy to web server
# Build output is in frontend/build/
```

## 🧪 Development

### Backend Development

```bash
# Activate virtual environment
source backend/venv/bin/activate

# Run backend in development mode
cd backend
python app.py

# Backend runs with auto-reload on code changes
```

### Frontend Development

```bash
# Start development server with hot reload
cd frontend
npm start

# Frontend runs on port 3000 with auto-reload
```

### Code Style

**Backend (Python):**
- Follow PEP 8 style guide
- Type hints where appropriate
- Docstrings for functions and classes

**Frontend (JavaScript/React):**
- ES6+ features (arrow functions, destructuring, etc.)
- Functional components with hooks
- React best practices
- Bootstrap 5 for styling

## 🐛 Troubleshooting

### Backend Issues

**ModuleNotFoundError:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate
pip install -r requirements.txt
```

**Port Already in Use:**
```bash
# Change port in environment
export PORT=8001
python app.py
```

### Frontend Issues

**Node.js OpenSSL Error:**
- Already configured in package.json with `NODE_OPTIONS=--openssl-legacy-provider`

**CORS Issues:**
- Ensure backend is running on port 8000
- Check REACT_APP_API_URL in .env file

**Port 3000 in Use:**
```bash
# Set custom port
PORT=3001 npm start
```

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2025 EnvelopeX Team

## 📋 Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes and version history.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📧 Contact

For questions, issues, or feedback:
- GitHub Issues: [Report a bug or request a feature](https://github.com/mandal-suman/envelopex/issues)

## 🙏 Acknowledgments

- Built with FastAPI, React, and Bootstrap 5
- Email parsing powered by Python's email library
- IOC extraction using BeautifulSoup4 and custom regex patterns
- Inspired by the need for local, privacy-focused email forensics tools

---

**Built with ❤️ for security professionals and investigators**

**EnvelopeX v2.0.0** - Making email forensics awesome and powerful.
