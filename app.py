#!/usr/bin/env python3
"""
SecIntel - Security Intelligence Aggregator
Team 6 Research | Application Security Dashboard
"""

import json
import os
import time
import sqlite3
import hashlib
import logging
import threading
import urllib3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import feedparser
from flask import Flask, jsonify, render_template, request
from apscheduler.schedulers.background import BackgroundScheduler

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_PATH = Path(__file__).parent / "secintel.db"
CACHE_TTL = 900  # 15 min default cache
FEED_FETCH_TIMEOUT = 20
LOG = logging.getLogger("secintel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ── Corporate Proxy ──
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
PROXY_URL = ""  # e.g. "http://proxy.corp.net:8080"
PROXIES = {
    "http": PROXY_URL,
    "https": PROXY_URL,
}
os.environ["HTTP_PROXY"] = PROXY_URL
os.environ["HTTPS_PROXY"] = PROXY_URL

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS feed_cache (
            key TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            fetched_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cve_items (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            published TEXT,
            modified TEXT,
            references_json TEXT,
            source TEXT,
            epss_score REAL,
            epss_percentile REAL,
            cwe TEXT,
            raw_json TEXT
        );
        CREATE TABLE IF NOT EXISTS intel_items (
            id TEXT PRIMARY KEY,
            title TEXT,
            summary TEXT,
            url TEXT,
            source TEXT,
            category TEXT,
            published TEXT,
            raw_json TEXT
        );
    """)
    conn.commit()
    conn.close()


def cache_get(key: str, ttl: int = CACHE_TTL):
    conn = get_db()
    row = conn.execute("SELECT data, fetched_at FROM feed_cache WHERE key = ?", (key,)).fetchone()
    conn.close()
    if row and (time.time() - row["fetched_at"]) < ttl:
        return json.loads(row["data"])
    return None


def cache_set(key: str, data):
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO feed_cache (key, data, fetched_at) VALUES (?, ?, ?)",
        (key, json.dumps(data), time.time()),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Feed Fetchers
# ---------------------------------------------------------------------------

def fetch_nvd_cves(days_back: int = 7, results_per_page: int = 200, max_results: int = 2000):
    """Fetch recent CVEs from NVD API 2.0 with pagination"""
    cache_key = f"nvd_cves_{days_back}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    all_vulns = []
    start_index = 0

    while start_index < max_results:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index,
        }

        try:
            resp = requests.get(url, params=params, timeout=FEED_FETCH_TIMEOUT, proxies=PROXIES, verify=False)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            LOG.error(f"NVD fetch failed (startIndex={start_index}): {e}")
            break

        vulns = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        all_vulns.extend(vulns)

        LOG.info(f"NVD page fetched: {len(vulns)} items (startIndex={start_index}, total={total_results})")

        # Stop if we got everything or this page was empty
        if not vulns or start_index + len(vulns) >= total_results:
            break

        start_index += len(vulns)

        # NVD rate limit: max 5 requests per 30 sec without API key
        time.sleep(6)

    results = []
    for vuln in all_vulns:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Extract description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # Extract CVSS
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if ver in metrics and metrics[ver]:
                m = metrics[ver][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", m.get("baseSeverity", "UNKNOWN"))
                break

        # Extract CWE
        cwe = ""
        for weakness in cve.get("weaknesses", []):
            for wd in weakness.get("description", []):
                if wd.get("lang") == "en":
                    cwe = wd.get("value", "")
                    break

        # References
        refs = [r.get("url", "") for r in cve.get("references", [])]

        item = {
            "cve_id": cve_id,
            "description": desc[:500],
            "severity": severity.upper() if severity else "UNKNOWN",
            "cvss_score": cvss_score,
            "published": cve.get("published", ""),
            "modified": cve.get("lastModified", ""),
            "cwe": cwe,
            "references": refs[:5],
            "source": "NVD",
        }
        results.append(item)

    LOG.info(f"NVD total: {len(results)} CVEs fetched for last {days_back} days")

    # Sort by CVSS descending
    results.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)
    cache_set(cache_key, results)
    return results


def fetch_epss_scores(cve_ids: list):
    """Fetch EPSS scores for a list of CVE IDs"""
    if not cve_ids:
        return {}

    cache_key = f"epss_{hashlib.md5(','.join(sorted(cve_ids)).encode()).hexdigest()}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    # EPSS API accepts comma-separated CVE IDs (max ~100 per request)
    scores = {}
    batch_size = 50
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i : i + batch_size]
        url = f"https://api.first.org/data/v1/epss?cve={','.join(batch)}"
        try:
            resp = requests.get(url, timeout=FEED_FETCH_TIMEOUT, proxies=PROXIES, verify=False)
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("data", []):
                scores[item["cve"]] = {
                    "epss": float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                }
        except Exception as e:
            LOG.error(f"EPSS fetch failed: {e}")

    cache_set(cache_key, scores)
    return scores


def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog"""
    cache_key = "cisa_kev"
    cached = cache_get(cache_key, ttl=3600)
    if cached:
        return cached

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url, timeout=FEED_FETCH_TIMEOUT, proxies=PROXIES, verify=False)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        LOG.error(f"CISA KEV fetch failed: {e}")
        return []

    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    results = []
    for v in data.get("vulnerabilities", []):
        if v.get("dateAdded", "") >= cutoff:
            results.append({
                "cve_id": v.get("cveID", ""),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "description": v.get("shortDescription", ""),
                "date_added": v.get("dateAdded", ""),
                "due_date": v.get("dueDate", ""),
                "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                "source": "CISA_KEV",
            })

    results.sort(key=lambda x: x.get("date_added", ""), reverse=True)
    cache_set(cache_key, results)
    return results


def fetch_rss_feed(url: str, source: str, category: str, limit: int = 50):
    """Generic RSS/Atom feed fetcher, newest first"""
    cache_key = f"rss_{hashlib.md5(url.encode()).hexdigest()}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    try:
        feed = feedparser.parse(url)
    except Exception as e:
        LOG.error(f"RSS fetch failed ({source}): {e}")
        return []

    results = []
    for entry in feed.entries[:limit]:
        published = ""

        # Try feedparser's pre-parsed time structs first (most reliable)
        parsed_time = None
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            parsed_time = entry.published_parsed
        elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
            parsed_time = entry.updated_parsed

        if parsed_time:
            try:
                pub_dt = datetime(*parsed_time[:6], tzinfo=timezone.utc)
                published = pub_dt.isoformat()
            except Exception:
                pass

        # Fallback: try to parse raw date string into ISO
        if not published:
            raw_date = getattr(entry, "published", "") or getattr(entry, "updated", "")
            if raw_date:
                try:
                    from email.utils import parsedate_to_datetime
                    pub_dt = parsedate_to_datetime(raw_date).astimezone(timezone.utc)
                    published = pub_dt.isoformat()
                except Exception:
                    # Last resort: keep raw string, will sort to bottom
                    published = raw_date

        results.append({
            "id": hashlib.md5((entry.get("link", "") + entry.get("title", "")).encode()).hexdigest(),
            "title": entry.get("title", ""),
            "summary": (entry.get("summary", "") or "")[:300],
            "url": entry.get("link", ""),
            "source": source,
            "category": category,
            "published": published,
        })

    cache_set(cache_key, results)
    return results


def fetch_github_advisories(ecosystem: str = "", severity: str = "", limit: int = 20):
    """Fetch GitHub Security Advisories via the public API"""
    cache_key = f"ghsa_{ecosystem}_{severity}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    url = "https://api.github.com/advisories"
    params = {"per_page": limit, "type": "reviewed"}
    if ecosystem:
        params["ecosystem"] = ecosystem
    if severity:
        params["severity"] = severity

    try:
        resp = requests.get(url, params=params, timeout=FEED_FETCH_TIMEOUT,
                           headers={"Accept": "application/vnd.github+json"},
                           proxies=PROXIES, verify=False)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        LOG.error(f"GitHub Advisories fetch failed: {e}")
        return []

    results = []
    for adv in data:
        cve_id = ""
        if adv.get("cve_id"):
            cve_id = adv["cve_id"]
        elif adv.get("identifiers"):
            for ident in adv["identifiers"]:
                if ident.get("type") == "CVE":
                    cve_id = ident.get("value", "")
                    break

        results.append({
            "ghsa_id": adv.get("ghsa_id", ""),
            "cve_id": cve_id,
            "summary": adv.get("summary", ""),
            "description": (adv.get("description", "") or "")[:400],
            "severity": (adv.get("severity") or "unknown").upper(),
            "published": adv.get("published_at", ""),
            "updated": adv.get("updated_at", ""),
            "url": adv.get("html_url", ""),
            "source": "GitHub_Advisory",
            "ecosystems": [v.get("package", {}).get("ecosystem", "") for v in adv.get("vulnerabilities", [])],
        })

    cache_set(cache_key, results)
    return results


# ---------------------------------------------------------------------------
# RSS Feed configs
# ---------------------------------------------------------------------------
RSS_FEEDS = [
    {
        "url": "https://portswigger.net/research/rss",
        "source": "PortSwigger",
        "category": "webapp_research",
    },
    {
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "source": "CISA_Alerts",
        "category": "threat_intel",
    },
    {
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "source": "TheHackerNews",
        "category": "threat_intel",
    },
    {
        "url": "https://blog.projectdiscovery.io/rss/",
        "source": "ProjectDiscovery",
        "category": "webapp_research",
    },
    {
        "url": "https://research.nccgroup.com/feed/",
        "source": "NCC_Group",
        "category": "webapp_research",
    },
    {
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "source": "Project_Zero",
        "category": "vuln_research",
    },
    {
        "url": "https://blog.hackerone.com/rss.xml",
        "source": "HackerOne",
        "category": "webapp_research",
    },
    # ── Threat Intel ──
    {
        "url": "https://krebsonsecurity.com/feed/",
        "source": "KrebsOnSecurity",
        "category": "threat_intel",
    },
    {
        "url": "https://securelist.com/feed/",
        "source": "Securelist",
        "category": "threat_intel",
    },
    {
        "url": "https://www.sentinelone.com/labs/feed/",
        "source": "SentinelLabs",
        "category": "threat_intel",
    },
    {
        "url": "https://www.bleepingcomputer.com/feed/",
        "source": "BleepingComputer",
        "category": "threat_intel",
    },
    {
        "url": "https://blog.talosintelligence.com/rss/",
        "source": "Cisco_Talos",
        "category": "threat_intel",
    },
    {
        "url": "https://feeds.feedburner.com/eset/blog",
        "source": "ESET_Research",
        "category": "threat_intel",
    },
    # ── Vuln Research ──
    {
        "url": "https://blog.rapid7.com/rss/",
        "source": "Rapid7",
        "category": "vuln_research",
    },
    {
        "url": "https://snyk.io/blog/feed/",
        "source": "Snyk",
        "category": "vuln_research",
    },
    {
        "url": "https://www.tenable.com/blog/feed",
        "source": "Tenable",
        "category": "vuln_research",
    },
    {
        "url": "https://blog.assetnote.io/feed.xml",
        "source": "Assetnote",
        "category": "webapp_research",
    },
    # ── Web App Security ──
    {
        "url": "https://www.trailofbits.com/feed",
        "source": "TrailOfBits",
        "category": "webapp_research",
    },
    {
        "url": "https://security.googleblog.com/feeds/posts/default",
        "source": "Google_Security",
        "category": "vuln_research",
    },
    {
        "url": "https://msrc.microsoft.com/blog/feed",
        "source": "Microsoft_MSRC",
        "category": "vuln_research",
    },
    {
        "url": "https://blog.cloudflare.com/rss/",
        "source": "Cloudflare",
        "category": "webapp_research",
    },
    # ── AI Security ──
    {
        "url": "https://embracethered.com/blog/index.xml",
        "source": "Embrace_The_Red",
        "category": "ai_security",
    },
    {
        "url": "https://atlas.mitre.org/rss.xml",
        "source": "MITRE_ATLAS",
        "category": "ai_security",
    },
    {
        "url": "https://hiddenlayer.com/research/feed/",
        "source": "HiddenLayer",
        "category": "ai_security",
    },
    {
        "url": "https://blog.protectai.com/rss/",
        "source": "ProtectAI",
        "category": "ai_security",
    },
    {
        "url": "https://invariantlabs.ai/blog/rss.xml",
        "source": "InvariantLabs",
        "category": "ai_security",
    },
    {
        "url": "https://lilianweng.github.io/index.xml",
        "source": "Lilian_Weng",
        "category": "ai_security",
    },
    {
        "url": "https://www.theregister.com/software/ai_ml/headlines.atom",
        "source": "The_Register_AI",
        "category": "ai_news",
    },
    # ── AI News & Updates ──
    {
        "url": "https://openai.com/news/rss.xml",
        "source": "OpenAI",
        "category": "ai_news",
    },
    {
        "url": "https://www.anthropic.com/rss.xml",
        "source": "Anthropic",
        "category": "ai_news",
    },
    {
        "url": "https://blog.google/technology/ai/rss/",
        "source": "Google_AI",
        "category": "ai_news",
    },
    {
        "url": "https://ai.meta.com/blog/rss/",
        "source": "Meta_AI",
        "category": "ai_news",
    },
    {
        "url": "https://huggingface.co/blog/feed.xml",
        "source": "HuggingFace",
        "category": "ai_news",
    },
    {
        "url": "https://blogs.nvidia.com/feed/",
        "source": "NVIDIA_Blog",
        "category": "ai_news",
    },
    {
        "url": "https://simonwillison.net/atom/everything/",
        "source": "Simon_Willison",
        "category": "ai_news",
    },
    {
        "url": "https://www.latent.space/feed",
        "source": "Latent_Space",
        "category": "ai_news",
    },
    {
        "url": "https://machinelearningmastery.com/blog/feed/",
        "source": "ML_Mastery",
        "category": "ai_news",
    },
    {
        "url": "https://thesequence.substack.com/feed",
        "source": "TheSequence",
        "category": "ai_news",
    },
]

# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def aggregate_all():
    """Run all fetchers in parallel and return structured data"""
    LOG.info("Starting full aggregation (parallel)...")
    start_time = time.time()

    # 1. NVD first — EPSS depends on the CVE IDs
    cves = fetch_nvd_cves(days_back=7, results_per_page=2000)
    cve_ids = [c["cve_id"] for c in cves if c.get("cve_id")]

    # 2. Everything else in parallel
    with ThreadPoolExecutor(max_workers=12) as pool:
        epss_future = pool.submit(fetch_epss_scores, cve_ids)
        kev_future = pool.submit(fetch_cisa_kev)
        ghsa_future = pool.submit(fetch_github_advisories, "", "", 25)

        rss_futures = {
            pool.submit(fetch_rss_feed, f["url"], f["source"], f["category"]): f["source"]
            for f in RSS_FEEDS
        }

        # Collect structured API results
        try:
            epss = epss_future.result(timeout=30)
        except Exception as e:
            LOG.error(f"EPSS parallel fetch failed: {e}")
            epss = {}

        try:
            kev = kev_future.result(timeout=30)
        except Exception as e:
            LOG.error(f"KEV parallel fetch failed: {e}")
            kev = []

        try:
            ghsa = ghsa_future.result(timeout=30)
        except Exception as e:
            LOG.error(f"GHSA parallel fetch failed: {e}")
            ghsa = []

        # Collect RSS results
        rss_items = []
        for future in as_completed(rss_futures, timeout=60):
            source = rss_futures[future]
            try:
                rss_items.extend(future.result())
            except Exception as e:
                LOG.error(f"RSS feed failed ({source}): {e}")

    # 3. Enrich CVEs with EPSS
    for c in cves:
        if c["cve_id"] in epss:
            c["epss_score"] = epss[c["cve_id"]]["epss"]
            c["epss_percentile"] = epss[c["cve_id"]]["percentile"]

    # 4. Sort RSS newest first
    rss_items.sort(key=lambda x: x.get("published", ""), reverse=True)

    elapsed = round(time.time() - start_time, 1)
    LOG.info(f"Aggregation complete in {elapsed}s: {len(cves)} CVEs, {len(kev)} KEV, {len(ghsa)} GHSA, {len(rss_items)} RSS")

    return {
        "cves": cves,
        "kev": kev,
        "ghsa": ghsa,
        "intel": rss_items,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total_cves": len(cves),
            "critical_cves": len([c for c in cves if c.get("severity") == "CRITICAL"]),
            "high_cves": len([c for c in cves if c.get("severity") == "HIGH"]),
            "kev_count": len(kev),
            "ghsa_count": len(ghsa),
            "intel_count": len(rss_items),
        },
    }


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/dashboard")
def api_dashboard():
    """Full aggregated dashboard data"""
    data = aggregate_all()
    return jsonify(data)


@app.route("/api/cves")
def api_cves():
    days = int(request.args.get("days", 7))
    cves = fetch_nvd_cves(days_back=days)
    cve_ids = [c["cve_id"] for c in cves if c.get("cve_id")]
    epss = fetch_epss_scores(cve_ids)
    for c in cves:
        if c["cve_id"] in epss:
            c["epss_score"] = epss[c["cve_id"]]["epss"]
            c["epss_percentile"] = epss[c["cve_id"]]["percentile"]
    return jsonify({"cves": cves, "count": len(cves)})


@app.route("/api/kev")
def api_kev():
    return jsonify({"kev": fetch_cisa_kev()})


@app.route("/api/ghsa")
def api_ghsa():
    ecosystem = request.args.get("ecosystem", "")
    severity = request.args.get("severity", "")
    return jsonify({"advisories": fetch_github_advisories(ecosystem=ecosystem, severity=severity)})


@app.route("/api/intel")
def api_intel():
    category = request.args.get("category", "")
    items = []
    for feed_cfg in RSS_FEEDS:
        if category and feed_cfg["category"] != category:
            continue
        items.extend(fetch_rss_feed(feed_cfg["url"], feed_cfg["source"], feed_cfg["category"]))
    return jsonify({"intel": items, "count": len(items)})


@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()

    # Pre-warm cache so first user gets instant response
    LOG.info("Pre-warming cache (parallel fetch)...")
    try:
        aggregate_all()
        LOG.info("Cache warm — ready to serve")
    except Exception as e:
        LOG.error(f"Pre-warm failed (will retry on first request): {e}")

    # Background scheduler for periodic refresh
    scheduler = BackgroundScheduler()
    scheduler.add_job(aggregate_all, "interval", minutes=15, id="refresh_feeds")
    scheduler.start()

    LOG.info("SecIntel starting on http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
