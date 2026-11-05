# WordPress Security Scanner - Desktop Application

## Overview

A Python desktop application for automated WordPress security testing with comprehensive report generation. This tool scans WordPress sites for common vulnerabilities and generates professional PDF/HTML reports with risk assessments and remediation recommendations.

## Features

### Security Checks

| Category | Checks | Severity |
|----------|--------|----------|
| **Version Detection** | WordPress core version fingerprinting | Info |
| **Plugin Enumeration** | Detect installed plugins and versions | Info |
| **Theme Enumeration** | Detect installed themes and versions | Info |
| **User Enumeration** | REST API, author archives, login errors | Medium |
| **XML-RPC Testing** | Status check, system.multicall abuse potential | High |
| **REST API Exposure** | User endpoints, route enumeration | Medium |
| **Security Headers** | X-Frame-Options, CSP, HSTS, X-XSS-Protection | Medium |
| **Config Exposure** | wp-config.php backups, .git, debug logs | Critical |
| **SSL/TLS Check** | Certificate validity, protocol versions | High |
| **Directory Listing** | wp-content, plugins, uploads directories | Low |
| **Backup Files** | .bak, .sql, .old file exposure | High |

### Scan Profiles

| Profile | Description | Duration |
|---------|-------------|----------|
| **Quick Scan** | Version, plugins, headers, XML-RPC | ~30 seconds |
| **Full Scan** | All security checks | ~2-5 minutes |
| **Custom Scan** | User-selected checks | Variable |

### Report Generation

- **PDF Reports**: Professional formatting with charts and tables
- **HTML Reports**: Interactive web-based reports
- **Executive Summary**: Risk score and high-level findings
- **Detailed Findings**: Complete vulnerability list with remediation
- **Charts**: Vulnerability distribution, severity breakdown
- **WPScan API Integration**: Cross-reference with known vulnerabilities

## Project Structure

```
wordpress-security-scanner/
├── src/
│   ├── __init__.py
│   ├── main.py                    # Application entry point
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── main_window.py         # Main application window
│   │   ├── scan_page.py           # Scan configuration interface
│   │   ├── results_page.py        # Results display
│   │   └── report_page.py         # Report generation interface
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── base_scanner.py        # Base scanner class
│   │   ├── wordpress_detection.py # Version detection
│   │   ├── plugin_scanner.py      # Plugin enumeration
│   │   ├── theme_scanner.py       # Theme enumeration
│   │   ├── user_enum.py           # User enumeration
│   │   ├── xmlrpc_scanner.py      # XML-RPC testing
│   │   ├── rest_api_scanner.py    # REST API checks
│   │   ├── security_headers.py    # Security headers audit
│   │   ├── config_exposure.py     # wp-config.php exposure
│   │   ├── ssl_scanner.py         # SSL/TLS validation
│   │   └── directory_scanner.py   # Directory listing checks
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── generator.py           # Report generation logic
│   │   ├── pdf_generator.py       # PDF report creation
│   │   ├── html_generator.py      # HTML report creation
│   │   └── templates/
│   │       ├── report.html        # HTML report template
│   │       └── report.css         # Report styling
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py              # Database schema
│   │   └── operations.py          # CRUD operations
│   └── utils/
│       ├── __init__.py
│       ├── helpers.py             # Utility functions
│       └── validators.py          # Input validation
├── requirements.txt
├── setup.py
├── README.md
└── .gitignore
```

## Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager
- Internet connection (for scanning)

### Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/wordpress-security-scanner.git
   cd wordpress-security-scanner
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv venv
   ```

3. **Activate virtual environment:**
   ```bash
   # Linux/Mac
   source venv/bin/activate
   
   # Windows
   venv\Scripts\activate
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the application:**
   ```bash
   python src/main.py
   ```

## Dependencies

```
# UI Framework
PySide6>=6.5.0

# HTTP & Networking
requests>=2.31.0
aiohttp>=3.9.0
urllib3>=2.0.0

# HTML Parsing
beautifulsoup4>=4.12.0
lxml>=4.9.0

# Report Generation
reportlab>=4.0.0
jinja2>=3.1.0
matplotlib>=3.8.0

# Database
aiosqlite>=0.19.0

# SSL/Security
pyopenssl>=23.0.0
cryptography>=41.0.0

# Utilities
python-dateutil>=2.8.0
colorama>=0.4.0
```

## Usage

### Basic Scan

1. Launch the application
2. Enter the target WordPress URL
3. Select a scan profile (Quick/Full/Custom)
4. Click "Start Scan"
5. View results in the Results tab
6. Generate report in the Reports tab

### Custom Scan

1. Select "Custom Scan" profile
2. Check/uncheck specific security checks
3. Configure WPScan API token (optional)
4. Start scan

### Report Generation

1. After scan completes, go to Reports tab
2. Select output format (PDF/HTML)
3. Choose save location
4. Click "Generate Report"
5. Open the generated report

## Configuration

### WPScan API Token

To check against known vulnerabilities:

1. Register at https://wpscan.com/register
2. Get your API token
3. Enter it in Settings tab
4. Enable "Check WPScan Database" option

### Scan Settings

- **Request Delay**: Time between requests (default: 1 second)
- **Timeout**: Request timeout (default: 10 seconds)
- **User-Agent**: Custom user agent string
- **Max Threads**: Parallel request limit (default: 5)

## Legal Disclaimer

**WARNING**: This tool is for **EDUCATIONAL and DEFENSIVE purposes only**.

- Only scan WordPress sites **you own** or have **written permission** to test
- Unauthorized scanning is illegal under computer fraud laws
- Use findings to **protect** your own WordPress installations
- Report vulnerabilities responsibly through proper disclosure channels

## Development

### Building from Source

1. Install development dependencies:
   ```bash
   pip install -r requirements.txt
   pip install pytest black flake8
   ```

2. Run tests:
   ```bash
   pytest tests/
   ```

3. Format code:
   ```bash
   black src/
   ```

4. Build executable:
   ```bash
   pip install pyinstaller
   pyinstaller --onefile --windowed src/main.py
   ```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Roadmap

### Phase 1: Core Scanner (Done)
- [x] Project structure
- [x] Base scanner engine
- [x] WordPress version detection
- [x] Plugin/theme enumeration
- [x] Basic UI

### Phase 2: Security Modules (Done)
- [x] User enumeration
- [x] XML-RPC testing
- [x] REST API checks
- [x] Security headers audit
- [x] wp-config.php exposure
- [x] SSL/TLS validation
- [x] Directory listing checks

### Phase 3: Database & Reports (Done)
- [x] SQLite integration
- [x] Scan history storage
- [x] PDF report generation
- [x] HTML report generation
- [x] Chart generation

### Phase 4: Advanced Features (Pending)
- [ ] WPScan API integration (token field is in the UI, endpoint wiring pending)
- [ ] Scheduled scans
- [ ] Multi-target batch scanning
- [ ] Custom report templates
- [ ] Plugin vulnerability database

## License

MIT License - See LICENSE file for details

## Support

- Documentation: docs/
- Issues: GitHub Issues
- Email: your.email@example.com

## Acknowledgments

- WPScan Team for vulnerability database
- WordPress community for security best practices
- OWASP for web security guidelines