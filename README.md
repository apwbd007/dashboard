# SecIntel — Security Intelligence Aggregator

**Research | Application Security Dashboard**

A single-command security intelligence dashboard that aggregates CVE data, exploit probability scores, threat intel, and web application security research into one tactical interface.

## Data Sources

| Source | Type | Refresh |
|--------|------|---------|
| **NVD API 2.0** | CVEs published in last 7 days, with CVSS scores and CWE | 15 min |
| **FIRST EPSS** | Exploit Prediction Scoring for each CVE | 15 min |
| **CISA KEV** | Known Exploited Vulnerabilities catalog (last 30 days) | 1 hour |
| **GitHub Security Advisories** | Reviewed advisories across all ecosystems | 15 min |
| **PortSwigger Research** | Web app security research articles | 15 min |
| **Project Discovery** | Nuclei templates & tooling research | 15 min |
| **NCC Group Research** | Security research publications | 15 min |
| **Google Project Zero** | 0-day vulnerability research | 15 min |
| **HackerOne** | Bug bounty & disclosure blog | 15 min |
| **The Hacker News** | Threat intelligence & news | 15 min |
| **CISA Alerts** | US-CERT advisories and alerts | 15 min |

## Quick Start

```bash
# 1. Install dependencies
pip install flask requests feedparser apscheduler

# 2. Run
python app.py

# 3. Open browser
# http://127.0.0.1:5000
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Browser (HTML/JS)               │
│   Dashboard UI with tabs, filters, search        │
└──────────────────────┬──────────────────────────┘
                       │ /api/*
┌──────────────────────▼──────────────────────────┐
│              Flask Application                   │
│                                                  │
│  ┌──────────┐ ┌──────────┐ ┌─────────────────┐ │
│  │ NVD API  │ │ CISA KEV │ │ GitHub Advisory │ │
│  │ + EPSS   │ │          │ │                 │ │
│  └──────────┘ └──────────┘ └─────────────────┘ │
│  ┌──────────────────────────────────────────┐   │
│  │  RSS Aggregator (PortSwigger, PD, NCC,  │   │
│  │  Project Zero, HackerOne, THN, CISA)    │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  ┌─────────┐  ┌──────────────┐                  │
│  │ SQLite  │  │ APScheduler  │                  │
│  │ Cache   │  │ (15 min job) │                  │
│  └─────────┘  └──────────────┘                  │
└─────────────────────────────────────────────────┘
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard UI |
| `GET /api/dashboard` | Full aggregated data |
| `GET /api/cves?days=7` | CVEs with EPSS scores |
| `GET /api/kev` | CISA KEV catalog |
| `GET /api/ghsa?ecosystem=npm&severity=critical` | GitHub Advisories |
| `GET /api/intel?category=webapp_research` | RSS intel feeds |
| `GET /api/health` | Health check |

## Features

- **CVE Intel**: NVD CVEs sorted by CVSS, enriched with EPSS exploit probability
- **CISA KEV**: Known exploited vulns with ransomware campaign tracking
- **GitHub Advisories**: Reviewed advisories with ecosystem filtering
- **Threat Intel & Research**: Aggregated RSS from top security sources
- **Search & Filter**: Real-time filtering across all panels
- **Auto-refresh**: Background scheduler refreshes every 15 minutes
- **SQLite caching**: Reduces API load with configurable TTL
- **Zero config**: No Docker, no external databases, just Python

## Future Extensions (SecIntel Roadmap)

- [ ] LLM enrichment: auto-summarize CVEs relevant to our stack
- [ ] MCP integration: feed data into HexStrike and Copilot agents
- [ ] Alerting: Slack/email notifications for critical CVEs matching our tech stack
- [ ] Custom watchlists: track specific vendors, products, or CWEs
- [ ] Historical trending: CVE volume and severity trends over time
- [ ] nuclei-templates tracking: new template releases mapped to CVEs
- [ ] Integration with internal asset inventory for exposure scoring
