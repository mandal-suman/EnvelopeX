# EnvelopeX - Email Forensics Analysis Platform

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/mandal-suman/envelopex)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/react-16.13.1-blue.svg)](https://reactjs.org/)

A comprehensive email forensics and security analysis platform built with Python FastAPI backend and React dashboard.

> **v2.0.0 Release** - Complete platform overhaul with modern React dashboard, REST API architecture, and enhanced analysis capabilities. See [CHANGELOG.md](CHANGELOG.md) for full details.

## 🚀 Features

- **IOC Extraction**: Automatically extract URLs, IP addresses, domains, emails, and file hashes
- **Phishing Detection**: Identify display name spoofing, reply-to mismatches, and brand impersonation
- **Authentication Analysis**: Validate SPF, DKIM, and DMARC results
- **Tracking Detection**: Detect hidden tracking pixels and email beacons
- **Attachment Analysis**: Hash and analyze email attachments with malware detection
- **Header Analysis**: Complete email routing path with hop tracking
- **Multiple Format Support**: .eml, .msg, .txt, .mbox, .mbx files

## 📁 Project Structure

```
EnvelopeX/
├── backend/                 # Python FastAPI Backend
│   ├── app.py              # Main FastAPI application
│   ├── extractor.py        # Email forensics analyzer
│   └── requirements.txt    # Python dependencies
├── frontend/               # React Frontend
│   ├── src/
│   │   ├── pages/         # Main application pages
│   │   ├── components/    # Reusable components
│   │   ├── services/      # API and storage services
│   │   └── context/       # React context for state
│   └── package.json       # Node.js dependencies
└── README.md
```

## 🛠️ Installation & Setup

### Prerequisites

- Python 3.11+ 
- Node.js 14+ and yarn/npm
- Git

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create and activate virtual environment (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Run the backend server:
```bash
python app.py
```

The backend will start on `http://localhost:8000`

### Dashboard Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install Node.js dependencies:
```bash
yarn install
# or
npm install
```

3. Start the development server:
```bash
yarn start
# or
npm start
```

The dashboard will open at `http://localhost:3000`

## 🎯 Usage

1. **Start Backend**: Ensure the Python backend is running on port 8000
2. **Open Frontend**: Access the React dashboard at http://localhost:3000
3. **Upload Email**: Drag & drop or select an email file (.eml, .msg, etc.)
4. **Analyze**: Click "Start Analysis" to begin forensics analysis
5. **View Results**: Review comprehensive analysis results with IOCs, headers, and risk assessment
6. **Export**: Download results as JSON for further investigation

## 🔧 Configuration

### Backend Configuration

Environment variables (optional):
- `ENVELOPEX_MAX_UPLOAD_SIZE`: Maximum file size (default: 100MB)
- `ENVELOPEX_WORKER_TIMEOUT`: Analysis timeout in seconds (default: 120)
- `ENVELOPEX_API_KEY`: API key for authentication (optional)
- `PORT`: Backend port (default: 8000)

### Frontend Configuration

Environment variables:
- `REACT_APP_API_URL`: Backend URL (default: http://localhost:8000)

## 📊 API Endpoints

- `GET /health` - Health check
- `POST /api/analyze` - Synchronous analysis
- `POST /api/analyze_async` - Asynchronous analysis with job queue
- `GET /api/job/{job_id}` - Get job status and results
- `GET /api/download/{job_id}/{filename}` - Download attachment

## 🛡️ Security Features

- No external data transmission
- Local browser storage for history
- Sanitized HTML rendering
- XSS prevention
- CORS protection

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 📋 Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes and version history.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📧 Contact

For questions, issues, or feedback:
- GitHub Issues: [Report a bug or request a feature](https://github.com/mandal-suman/envelopex/issues)
- Email: [Your contact email]

## 🙏 Acknowledgments

- Built with FastAPI, React, and Bootstrap 5
- Email parsing powered by Python's email library
- IOC extraction using BeautifulSoup4 and custom regex patterns
- Inspired by the need for local, privacy-focused email forensics tools

---

**Built with ❤️ for security professionals and investigators**

**EnvelopeX v2.0.0** - Making email forensics accessible and powerful.
