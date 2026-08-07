# Vigil

**AI-Powered Threat Hunting & Offensive Security Engine**  
*Human Commander + AI Tactical Compass Framework*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)](pyproject.toml)

---

Vigil is a CLI-based security analysis framework that parses scan outputs, log files, and source code to surface vulnerabilities, map MITRE ATT&CK techniques, discover live CVE exploits, and generate ranked tactical next-step commands for security teams.

Vigil adheres strictly to a **Human-in-the-Loop** model: it acts as a tactical intelligence compass while leaving executive decision-making and command execution in the hands of the operator.

---

## How It Works

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  YOUR SCAN DATA  │───▶│  VIGIL ENGINE     │───▶│  ACTIONABLE OUTPUT  │
│                  │    │                    │    │                     │
│  • Nmap output   │    │  1. Parse & Ingest │    │  • Ranked next steps│
│  • Auth logs     │    │  2. Heuristic Rules│    │  • CVE + PoC links  │
│  • PEASS output  │    │  3. CVE Correlation│    │  • MITRE ATT&CK map │
│  • Source code   │    │  4. AI Enrichment  │    │  • Kill chain phase │
│  • Web logs      │    │  5. Compass Engine │    │  • Privesc commands │
│  • Email headers │    │                    │    │  • HTML/SARIF report│
└─────────────────┘    └──────────────────┘    └─────────────────────┘
```

## Features

### Multi-Format Log Ingestion
Vigil auto-detects and parses **8 log formats** with a universal fallback:
- **Nmap** (XML + plaintext scan output)
- **Auth logs** (SSH brute force, login events)
- **Web server logs** (Apache, Nginx access/error logs)
- **PEASS output** (linPEAS / winPEAS privilege escalation logs)
- **Source code** (Python, JS, PHP, Go, C, Java — SAST auditing)
- **Email headers** (Phishing & social engineering detection)
- **Crontab files** (Persistence mechanism detection)
- **HTML source** (Web application vulnerability scanning)

### Red Team Compass Engine
The Compass Engine analyzes your scan results and generates:
- **Kill chain phase assessment** (Reconnaissance → Initial Access → Privilege Escalation)
- **Ranked tactical next steps** with concrete CLI command templates
- **MITRE ATT&CK technique mapping** for every finding
- **Pivot opportunities** and lateral movement suggestions

### Live CVE & Exploit Discovery
Three-tier vulnerability correlation — works online or fully offline:
1. **Local DB** — Instant offline lookup against curated known vulnerabilities
2. **OSV.dev + CVEDetails** — Multi-source live CVE search (no API key required for OSV)
3. **NVD API v2.0** — NIST National Vulnerability Database with CPE matching
4. **GitHub PoC Finder** — Discovers proof-of-concept exploit repos, verifies availability, and evaluates README quality to filter spam

### Multi-Provider AI with Auto-Fallback
- **Google Gemini** (primary)
- **OpenAI GPT-4o** (alternative)
- **Ollama** (fully local, no API key needed)
- If one provider fails, Vigil automatically falls back to the next

### Source Code Auditor (SAST)
Built-in static analysis for 7 vulnerability classes:
- SQL Injection (CWE-89)
- Command Injection / RCE (CWE-78)
- Hardcoded Secrets (CWE-798)
- Insecure Deserialization (CWE-502)
- SSRF (CWE-918)
- Weak Cryptography (CWE-327)
- AI-powered deep code analysis with secure refactoring suggestions

### Five Output Formats
- **CLI** — Terminal dashboard with color-coded severity indicators
- **HTML** — Self-contained executive forensic dashboard with interactive tabs
- **Markdown** — Structured report for documentation
- **JSON** — Structured data for SIEM ingestion
- **SARIF v2.1.0** — GitHub Code Scanning and IDE integration

### Diff Engine
Compare two scans to instantly see:
- Newly opened ports and services
- Closed/patched services
- Version changes
- New vulnerabilities vs. resolved ones

### Multi-Agent Orchestrator
Phase-locked state machine with Blackboard Memory:
- **Recon Agent** → **Initial Access Agent** → **PrivEsc Agent**
- Inter-agent handoff notes with context preservation
- Anti-loop guardrails prevent redundant re-analysis
- Human Commander override notes at every phase

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Bunny-sysd/vigil-hunter.git
cd vigil-hunter

# Install in development mode
pip install -e ".[all]"

# Or install with specific AI provider
pip install -e ".[gemini]"   # Google Gemini only
pip install -e ".[openai]"   # OpenAI only
```

### Configure AI Provider (Optional)

Vigil works **without any API keys** using heuristic rules and local databases. Add AI for deeper analysis:

```bash
# Set API key via CLI
vigil config set-key gemini YOUR_API_KEY

# Or use environment variables
export VIGIL_GEMINI_KEY=your_key_here
export VIGIL_PROVIDER=gemini

# Or use local Ollama (no key needed)
export VIGIL_PROVIDER=ollama
export VIGIL_OLLAMA_MODEL=llama3.1
```

---

## Usage

### Analyze a scan file
```bash
vigil analyze target_scan.txt
vigil analyze target_scan.txt --format html --output report.html
vigil analyze target_scan.txt --format sarif --output results.sarif
vigil analyze ./logs/ --mode htb   # Analyze entire directory
```

### Red Team Compass — Tactical next steps
```bash
vigil compass target_scan.txt --phase reconnaissance
vigil compass target_scan.txt --phase initial_access --note "Focus on web services"
vigil compass target_scan.txt --phase privilege_escalation
```

### Compare two scans (Diff Engine)
```bash
vigil diff scan_before.txt scan_after.txt
```

### MITRE ATT&CK Lookup
```bash
vigil mitre T1110           # Lookup by technique ID
vigil mitre "brute force"   # Search by keyword
vigil mitre T1595 --online  # Live query from attack.mitre.org
```

### Session Management
```bash
vigil session save my_engagement
vigil session list
```

### Offline Mode (no external API calls)
```bash
vigil analyze target_scan.txt --offline
vigil compass target_scan.txt --phase recon --offline
```

---

## Architecture

```
vigil/
├── cli.py                    # Click CLI interface
├── config.py                 # Multi-layer configuration system
├── models.py                 # Core data models (Finding, ScanResult, etc.)
├── ai/
│   ├── brain.py              # AI orchestrator with auto-fallback
│   ├── prompts.py            # System prompts with anti-hallucination guardrails
│   ├── agents/               # Specialized phase agents (Recon, InitialAccess, PrivEsc)
│   └── providers/            # Gemini, OpenAI, Ollama backends
├── engine/
│   ├── analyzer.py           # Main threat analysis orchestrator
│   ├── compass.py            # Red Team Compass tactical advisor
│   ├── orchestrator.py       # Multi-agent phase controller
│   ├── blackboard.py         # Shared session memory & handoff protocol
│   ├── version_matcher.py    # Semantic version-to-CVE matching
│   ├── nvd_client.py         # NVD API v2.0 client
│   ├── cve_search.py         # OSV.dev + CVEDetails multi-source CVE search
│   ├── github_poc_finder.py  # GitHub PoC repository discovery & verification
│   ├── known_vulns.py        # Offline vulnerability database
│   ├── mitre_attack.py       # MITRE ATT&CK knowledge base & mapping
│   ├── source_auditor.py     # Static code analysis (SAST)
│   ├── peass_analyzer.py     # linPEAS/winPEAS output parser
│   ├── credential_extractor.py # Credential harvesting from logs
│   ├── diff_engine.py        # Scan comparison engine
│   └── rules/                # Heuristic detection rules
│       ├── brute_force.py
│       ├── priv_escalation.py
│       ├── recon.py
│       └── persistence.py
├── ingestors/                # 8 format parsers + universal fallback
│   ├── nmap_xml.py
│   ├── nmap_text.py
│   ├── auth_log.py
│   ├── web_server.py
│   ├── email_parser.py
│   ├── crontab_parser.py
│   ├── html_source.py
│   └── universal_log.py
├── reporters/                # Output format generators
│   ├── cli_reporter.py
│   ├── html_reporter.py
│   ├── markdown_reporter.py
│   ├── sarif_reporter.py
│   └── graph_reporter.py
└── timeline/
    └── builder.py            # Attack timeline reconstruction
```

---

## Philosophy

> **"The human decides. Vigil informs."**

Vigil is built on the principle that **fully autonomous AI pentesting tools are unreliable and dangerous.** They loop, hallucinate findings, and execute unsafe commands without oversight.

Vigil takes a different approach:
- **Human Commander** — You choose what to run and when
- **AI Tactical Compass** — Vigil correlates data, maps techniques, discovers exploits, and ranks your options
- **Anti-Hallucination Guardrails** — Every AI prompt enforces evidence-grounding and prohibits fabrication
- **Offline-First** — Works without internet using local databases; AI enrichment is optional enhancement

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Run tests
pip install -e ".[dev]"
pytest

# Run with coverage
pytest --cov=vigil --cov-report=html
```

---

## License

[MIT License](LICENSE) — See LICENSE file for details.

---

<p align="center">
  <sub>Built by <a href="https://github.com/Bunny-sysd">Bunny-sysd</a></sub>
</p>
