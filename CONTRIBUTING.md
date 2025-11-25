# Contributing to EnvelopeX

Thank you for your interest in contributing to EnvelopeX! This document provides guidelines and instructions for contributing to the project.

## 🌟 Ways to Contribute

There are many ways to contribute to EnvelopeX:

- **Report Bugs**: Submit detailed bug reports with reproduction steps
- **Suggest Features**: Propose new features or enhancements
- **Improve Documentation**: Fix typos, clarify instructions, add examples
- **Write Code**: Fix bugs, implement features, improve performance
- **Share Feedback**: Tell us about your experience using EnvelopeX
- **Spread the Word**: Share EnvelopeX with others who might find it useful

## 🐛 Reporting Bugs

Before reporting a bug:

1. **Check existing issues** to see if the bug has already been reported
2. **Update to the latest version** to see if the bug has been fixed
3. **Verify the bug** by trying to reproduce it consistently

When reporting a bug, include:

- **Clear title** describing the issue
- **Steps to reproduce** the bug
- **Expected behavior** vs actual behavior
- **Screenshots** if applicable
- **Environment details**:
  - OS (Linux, macOS, Windows)
  - Python version
  - Node.js version
  - Browser (for frontend issues)
  - EnvelopeX version

## 💡 Suggesting Features

When suggesting a feature:

1. **Check existing issues** to avoid duplicates
2. **Provide context**: Explain the problem you're trying to solve
3. **Describe the solution**: How should the feature work?
4. **Consider alternatives**: What other approaches did you consider?
5. **Provide examples**: Show how the feature would be used

## 🔧 Development Setup

### Prerequisites

- Python 3.11 or higher
- Node.js 14 or higher
- Git
- A code editor (VS Code recommended)

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/envelopex.git
   cd envelopex
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/mandal-suman/envelopex.git
   ```

4. **Set up the backend**:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

5. **Set up the frontend**:
   ```bash
   cd frontend
   npm install
   ```

6. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 🏗️ Project Structure

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

## 📝 Coding Standards

### Python (Backend)

- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints where appropriate
- Write docstrings for functions and classes
- Keep functions focused and single-purpose
- Add comments for complex logic
- Maximum line length: 88 characters (Black formatter)

Example:
```python
def extract_urls(content: str) -> list[str]:
    """
    Extract all URLs from the given content.
    
    Args:
        content: The text content to parse
        
    Returns:
        List of extracted URLs
    """
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, content)
```

### JavaScript/React (Frontend)

- Use ES6+ features (arrow functions, destructuring, etc.)
- Follow React best practices and hooks patterns
- Use functional components over class components
- Keep components focused and reusable
- Add PropTypes or TypeScript for type checking
- Maximum line length: 100 characters

Example:
```javascript
const AnalysisCard = ({ title, data, icon }) => {
  return (
    <Card className="analysis-card">
      <Card.Header>
        <FontAwesomeIcon icon={icon} className="me-2" />
        {title}
      </Card.Header>
      <Card.Body>{data}</Card.Body>
    </Card>
  );
};
```

### General Guidelines

- Write clear, self-documenting code
- Add comments for complex logic, not obvious code
- Keep commits atomic and focused
- Write meaningful commit messages
- Test your changes thoroughly
- Update documentation for user-facing changes

## 🧪 Testing

Before submitting your changes:

1. **Test the backend**:
   ```bash
   cd backend
   python app.py
   # Verify http://localhost:8000/health works
   ```

2. **Test the frontend**:
   ```bash
   cd frontend
   npm start
   # Verify http://localhost:3000 loads
   ```

3. **Test the integration**:
   - Upload a sample email file
   - Verify analysis completes successfully
   - Check all tabs in the results view
   - Test export functionality
   - Verify history page works

4. **Test edge cases**:
   - Large files
   - Invalid file formats
   - Malformed email headers
   - Missing required fields

## 📤 Submitting Changes

### Commit Messages

Write clear commit messages following this format:

```
<type>: <subject>

<body (optional)>

<footer (optional)>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples**:
```
feat: add phishing detection for display name spoofing

fix: handle missing SPF records gracefully

docs: update installation instructions for Windows

refactor: simplify IOC extraction logic
```

### Pull Request Process

1. **Update your branch** with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push your changes**:
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create a pull request** on GitHub:
   - Use a clear, descriptive title
   - Reference related issues (e.g., "Fixes #123")
   - Describe what changes you made and why
   - Add screenshots for UI changes
   - List any breaking changes

4. **Respond to feedback**:
   - Address review comments promptly
   - Push additional commits to your branch
   - Mark conversations as resolved when addressed

5. **Squash commits** if requested:
   ```bash
   git rebase -i upstream/main
   git push --force-with-lease
   ```

## 🔍 Code Review

All contributions go through code review. Reviewers will check:

- Code quality and style
- Functionality and correctness
- Test coverage
- Documentation updates
- Security implications
- Performance considerations

Be patient and respectful during the review process. Reviews help maintain code quality and are a learning opportunity for everyone.

## 🛡️ Security

If you discover a security vulnerability:

1. **DO NOT** create a public issue
2. Email the maintainers privately
3. Provide details about the vulnerability
4. Allow time for a fix before public disclosure

## 📜 License

By contributing to EnvelopeX, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be recognized in:
- The project README
- Release notes
- GitHub contributors page

## ❓ Questions?

If you have questions about contributing:

- Check existing issues and discussions
- Review the documentation
- Open a new discussion on GitHub
- Contact the maintainers

---

Thank you for contributing to EnvelopeX! Your efforts help make email forensics more accessible to everyone. 🚀
