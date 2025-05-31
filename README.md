# TSreconX

**TSreconX** is an advanced GitHub reconnaissance framework designed for offensive security professionals, red teams, and OSINT researchers. It automates the process of scanning public GitHub profiles and repositories for exposed secrets, commit-level leaks, and CI/CD misconfigurations.

---

## 🔍 Features

- Targeted GitHub recon using username and optional token
- Dork-based code searches to uncover exposed API keys and sensitive files
- Repository cloning with regex-based secret detection
- Git commit history analysis for historical leaks
- CI/CD configuration scanning (GitHub Actions, GitLab CI, Travis CI, CircleCI, etc.)
- User profile intelligence gathering
- Severity-based findings with categorized summary
- Exportable Markdown reports

---------------------------

## 🛠️ Installation

## git clone https://github.com/jamaldoTS/TSreconX.git
## cd TSreconX
## pip install -r requirements.txt
## python TSreconX.py

> ⚠️ Ensure you have Python 3.8+ and Git installed.

 🔑 To avoid GitHub API rate limits and increase visibility:

1. Go to https://github.com/settings/tokens

2. Click Generate new token

3. Select scopes: repo, read:user

4. Paste it in the token field in the app interface

---------------------------

📦 Modules

Module	Description

Dork Scanner	Searches GitHub using targeted dork queries
Repo Scanner	Clones repositories and scans for sensitive patterns
Git History	Inspects commit history for exposed secrets
CI/CD Scanner	Detects secrets in pipeline configurations
User Scanner	Extracts user profile metadata
Reporting	Generates a live and exportable Markdown report

---------------------------

📁 Output

TSreconX displays results live in the interface and allows exporting findings to a structured .md report.

Each report includes:

Tab-wise breakdown of results

Severity summary (High, Medium, Low)

Total dork queries, repos scanned, CI/CD alerts

---------------------------

📩 Support

For issues or feature requests, please contact:

📧 turbineshield@gmail.com

📄 License

MIT License. See LICENSE file for details.

---------------------------

⚠️ Disclaimer

TSreconX is intended for authorized use only. Any misuse against systems you do not own or have explicit permission to test is illegal and unethical.
Use responsibly.
