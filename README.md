# VIGILIS

**Professional Website Security Assessment Platform**

VIGILIS independently evaluates a website's HTTPS enforcement, TLS certificate
health, and security header configuration, then produces an explainable
score, prioritized recommendations, and downloadable reports (TXT / HTML /
PDF).

VIGILIS is a configuration and posture assessment tool. It is **not** a
penetration testing framework, exploitation toolkit, or vulnerability
scanner — it evaluates *publicly observable* security configuration only.

---

## Prerequisites

- Python 3.10+ (for running locally), **or**
- Docker + Docker Compose (for running in a container — no local Python setup needed)

## Features

- **HTTPS Verification** — independently probes both HTTP and HTTPS and
  checks whether HTTP genuinely redirects to HTTPS.
- **SSL/TLS Certificate Validation** — connects directly on port 443 and
  inspects issuer, validity window, and expiry.
- **Security Header Analysis** — checks for `Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, and `Permissions-Policy`.
- **Explainable Scoring (0–100)** — every point traces back to specific
  evidence collected by an assessment module. No black-box scoring.
- **Recommendation Engine** — prioritized, actionable, educational findings
  derived strictly from evidence.
- **Report Generation** — TXT, HTML, and PDF reports, all built from the
  same structured assessment data.
- **Scan History** — every assessment is persisted to SQLite and browsable
  by website or chronologically.

## Architecture

The codebase follows a layered, modular architecture: Flask routes stay
thin and only coordinate; assessment logic lives in independent modules
that never depend on one another; scoring and recommendations interpret
evidence without performing assessments themselves; reporting and
persistence are separate concerns.

```
vigilis/
├── app.py                     # Flask presentation layer (thin routes)
├── core/
│   └── engine.py               # Coordinates module execution
├── modules/                    # Independent assessment modules
│   ├── https_module.py
│   ├── ssl_module.py
│   └── headers_module.py
├── services/
│   ├── validation.py           # Input validation & normalization
│   ├── scoring.py              # Evidence → explainable score
│   └── recommendations.py      # Evidence → actionable guidance
├── reports/
│   └── report_generator.py     # TXT / HTML / PDF report generation
├── persistence/
│   └── db.py                   # SQLite scan history
├── templates/                  # Jinja2 templates (dark, restrained UI)
├── static/
│   ├── css/style.css           # VIGILIS Design System implementation
│   └── js/main.js
└── requirements.txt
```

Dependency direction: `routes → services/engine → modules`. Modules never
call upward, and never talk to one another directly.

## Running Locally

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000** in your browser.

The SQLite database is created automatically at `instance/vigilis.sqlite3`
on first run.

## Running with Docker

**Using Docker Compose (recommended):**

```bash
docker compose up --build
```

Then open **http://localhost:5000**. Scan history persists across
restarts in a Docker volume (`vigilis-data`).

To run in the background:
```bash
docker compose up -d --build
```

To stop:
```bash
docker compose down          # keeps your scan history
docker compose down -v       # also deletes scan history
```

## Usage

1. Enter a domain or full URL (e.g. `example.com` or `https://example.com`)
   on the homepage and click **Run Assessment**.
2. Review the results dashboard: overall score, HTTPS status, certificate
   details, header findings, and prioritized recommendations.
3. Download a report in TXT, HTML, or PDF format.
4. Revisit past assessments any time from **History**.

## Scoring Model

| Check                          | Points |
|---------------------------------|--------|
| HTTPS Enabled                   | 20     |
| Valid SSL Certificate           | 20     |
| Strict-Transport-Security (HSTS)| 10     |
| Content-Security-Policy (CSP)   | 15     |
| X-Frame-Options                 | 10     |
| X-Content-Type-Options          | 10     |
| Referrer-Policy                 | 10     |
| Permissions-Policy              | 5      |
| **Total**                       | **100**|

| Score   | Rating              |
|---------|---------------------|
| 80–100  | Secure              |
| 60–79   | Moderate            |
| < 60    | Needs Improvement   |

## Tech Stack

- **Backend:** Python 3, Flask
- **Assessment:** `requests`, `ssl`, `socket`
- **Reporting:** `reportlab` (PDF), native HTML/TXT generation
- **Persistence:** SQLite (stdlib `sqlite3`)
- **Frontend:** Server-rendered Jinja2 templates, plain CSS/JS
  (dark theme, Space Grotesk / Inter / JetBrains Mono)

## Notes

- Assessments only inspect publicly observable configuration — no
  exploitation, brute-forcing, or intrusive scanning is performed.
- Certificate inspection connects directly to port 443 using Python's
  standard `ssl` module; header analysis uses a standard HTTP(S) GET
  request with a descriptive User-Agent.
