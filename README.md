# EnvelopeX v1.0.0 🔍

**Advanced Email Forensics Platform**

EnvelopeX is a comprehensive email forensics platform designed for cybersecurity professionals, SOC analysts, and incident responders. It provides deep forensic analysis of email messages with advanced threat detection and authentication validation.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-stable-green)


## 🎯 Key Features

- **Email Forensics**: Deep analysis of EML and TXT email files
- **Authentication Analysis**: SPF, DKIM, and DMARC validation
- **Threat Detection**: URL extraction, IP analysis, and anomaly detection
- **Professional Dashboard**: 8-tab analysis interface with dark/light themes
- **Analysis History**: Local storage of previous analyses

## 🚀 Quick Start

### Prerequisites
- Python 3.11 or higher
- pip package manager

### Installation

```bash
git clone https://github.com/mandal-suman/EnvelopeX.git
cd EnvelopeX
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python app.py
```

Access the platform at `http://localhost:5000`

## 💻 Usage

1. **Upload Email**: Drag & drop or select EML/TXT file
2. **Start Analysis**: Click "Start Forensic Analysis"
3. **View Results**: Navigate through analysis tabs
4. **Access History**: Review previous analyses

### Analysis Tabs

- **Details**: Email metadata and file information
- **Authentication**: SPF, DKIM, DMARC validation
- **URLs**: Extracted URLs and risk assessment
- **Attachments**: File details with hashes
- **Transmission**: Email routing visualization
- **X-Headers**: Extended header information
- **MIME Structure**: Message structure tree
- **Body Contents**: Plain text, HTML source, and preview

## 🏗️ Architecture

```
EnvelopeX/
├── app.py                  # Flask application
├── requirements.txt        # Dependencies
├── core/                   # Core modules
│   ├── analyzer.py         # Forensics analyzer
│   └── parser.py           # Email parser
├── templates/              # HTML templates
│   └── index.html          # Main dashboard
└── static/                 # CSS and JavaScript
    ├── css/style.css
    ├── js/main.js
    └── js/results-renderer-new.js
```

## 🔧 Technical Stack

**Backend**: Flask 3.0.0, dkimpy, dnspython, BeautifulSoup4
**Frontend**: Vanilla JavaScript, Chart.js, Font Awesome
**Key Libraries**: chardet, python-dateutil, Flask-CORS

## 🔒 Security

- No data persistence (in-memory only)
- 25MB file size limit
- Strict file validation
- HTML sanitization
- Sandboxed HTML preview

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 📞 Contact

- **GitHub**: [@mandal-suman](https://github.com/mandal-suman)
- **Issues**: [Report Bugs](https://github.com/mandal-suman/EnvelopeX/issues)

---

**EnvelopeX v1.0.0** - Made with 🔐 by security professionals
