# AI SOC Analyst Platform — AEGIS
# End-to-end autonomous security operations center powered by Claude AI

## Quick Start

### 1. Set up API keys
```bash
# Copy the example env file
copy .env.example .env

# Edit .env and add your Anthropic API key (required)
# Optionally add VirusTotal and AbuseIPDB keys
```

### 2. Install dependencies
```bash
# Python backend
pip install -r requirements.txt

# Frontend
cd frontend
npm install
cd ..
```

### 3. Run the platform
```bash
# Terminal 1: Start the backend
uvicorn server:app --reload --port 8000

# Terminal 2: Start the frontend
cd frontend
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## Features

### AI-Powered Alert Analysis
- Paste any SIEM alert (JSON or raw log) and get a full AI investigation
- Claude AI performs triage, severity classification, and root cause analysis
- Automatic MITRE ATT&CK technique mapping

### Threat Intelligence Enrichment
- **VirusTotal** — IP and file hash reputation lookups
- **AbuseIPDB** — IP abuse confidence scoring
- **NVD** — CVE vulnerability details (no API key needed)

### IOC Extraction
- Automatically extracts IPs, domains, URLs, file hashes, emails, and CVEs from raw text/logs
- Bulk extraction from paste-in logs

### MITRE ATT&CK Matrix
- Visual matrix view of all mapped techniques
- Organized by tactic with technique counts
- 50+ embedded techniques for offline mapping

### Risk Scoring Engine
- Composite 0-100 score based on:
  - Alert severity (0-30 pts)
  - AI confidence (0-25 pts)
  - Threat intel results (0-25 pts)
  - Asset criticality (0-10 pts)
  - IOC density (0-10 pts)

### Automated Response
- Tactic-specific response playbooks
- Auto-execute low-risk containment actions
- Queue high-risk actions for human approval
- Response plans for: Execution, Initial Access, Persistence, Credential Access, Lateral Movement, Defense Evasion, Impact, C2, Exfiltration

### Investigation History
- All investigations saved locally as JSON
- Browse past incidents with severity and risk scores
- Detailed modal view for each incident

---

## Architecture

```
Frontend (Vite + Vanilla JS) → API Proxy → Backend (FastAPI)
    ↓                                           ↓
 Dashboard                              Claude AI Agent
 Alert Analysis                          IOC Extractor
 Threat Intel                           Threat Intel APIs
 MITRE Matrix                           MITRE ATT&CK KB
 Incidents                              Risk Scorer
                                        Response Engine
```

## Author
**Thilakeswaran B**
Final Year B.E CSE (AI/ML)
Gnanamani College of Technology
