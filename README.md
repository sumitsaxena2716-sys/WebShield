# WebShield — Automated Web Security Scanner

A responsive Flask application for defensive, non-invasive first-pass website auditing. Built for a cybersecurity bootcamp project and suitable for further development as a portfolio project.

## Features

- Responsive dashboard, mobile navigation, custom 404 and rate-limit pages.
- URL validation and a required authorization confirmation.
- HTTPS/TLS certificate verification, redirect-by-redirect target validation, timeouts, response-size limits, and basic public-IP checks.
- Checks for common HTTP security headers, HTTP response status, page title, meta description, favicon link, and mobile viewport metadata.
- Optional bounded broken-link checking (default maximum: 30 links).
- Scan history in SQLite and downloadable JSON reports.
- Security response headers, request rate limits, safe database parameterization, user-facing success/error messages, and basic automated tests.
- No exploit payloads, brute force, port scanning, or destructive tests.

## Requirements

- Python 3.10+ recommended
- Internet access for scanning public websites
- Windows PowerShell, macOS Terminal, or Linux shell

## Local setup (Windows PowerShell)

```powershell
cd WebShield
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Open `http://127.0.0.1:5000`.

If PowerShell blocks activation, you can run the virtual environment's interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

macOS/Linux:

```bash
cd WebShield
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
python app.py
```

## Configuration

Environment variables are documented in `.env.example`. Set a long, random `SECRET_KEY` before deployment. The development fallback secret is not suitable for production. Never commit `.env` or database files.

`WEBSHIELD_MAX_LINKS` limits how many links are checked per page. `WEBSHIELD_TIMEOUT` sets the request timeout. `WEBSHIELD_MAX_RESPONSE_BYTES` caps the downloaded HTML body size. `RATELIMIT_STORAGE_URI` can point to a shared Redis instance in a multi-worker deployment.

## Tests

```bash
pytest -q
```

Tests include basic route behavior, authorization gating, URL validation, and report-not-found handling. They do not replace end-to-end browser testing or a professional security assessment.

## How to use

1. Start the app and open the dashboard.
2. Enter a public website URL.
3. Confirm you own the website or have explicit permission to scan it.
4. Optionally enable bounded link checking.
5. Review findings and remediation guidance.
6. Download the JSON report for documentation.

## Architecture

```text
Browser (responsive HTML/CSS/JS)
        |
        | POST /api/scan (JSON)
        v
Flask routes + rate limiting
        |
        +--> URL validation / DNS public-address checks
        +--> Safe HTTP client (TLS verification, timeouts, bounded body)
        +--> Header + HTML metadata checks
        +--> Optional bounded link checks
        |
        +--> SQLite (scan history, parameterized queries)
        |
        v
JSON report --> Browser results UI / download
```

## Threat model summary

| Asset / risk | Mitigation in this project | Remaining risk |
|---|---|---|
| Scanner abused as an SSRF proxy | Authorization confirmation, block non-public IPs, validate redirect hops | DNS rebinding and network changes require isolated worker + egress firewall |
| Resource exhaustion | Rate limits, timeouts, bounded links, response-size cap | Shared storage needed for multi-worker rate limiting |
| SQL injection in history | Parameterized SQL queries | Review all future queries and migrations |
| Transport downgrade | TLS verification and HTTPS finding | HSTS is checked for presence; correctness requires contextual review |
| Sensitive data leakage | Generic API errors; no passwords/tokens are collected | Logs and hosting environment still need operational controls |
| XSS in report UI | Uses DOM `textContent`, no target HTML rendered into the dashboard | Re-test after UI changes and keep CSP restrictive |
| Unauthorized scans | Explicit authorization confirmation and responsible-use notice | A checkbox is not proof of authorization; enforce policy and access controls for hosted deployments |

## Security controls and known limitations

- The scanner checks a bounded set of common response headers and page properties. It does not test SQL injection, XSS exploitability, CSRF, login flows, authorization/IDOR, API logic, dependency vulnerabilities in the target, or source code.
- A link failure may be caused by bot blocking, authentication, rate limits, or HEAD support—not necessarily a broken link.
- A simple HTTP scanner cannot reliably identify horizontal overflow, broken visual buttons, footer behavior, or all accessibility issues. Use browser testing on desktop and mobile for those.
- The score is an indicative checklist score only, not a certification or a likelihood of compromise.
- A public website should not be able to use this service as a general-purpose URL fetcher. Before exposing it publicly, put scanning in a dedicated isolated worker/container with strict outbound firewall rules, DNS controls, concurrency limits, abuse monitoring, and authenticated access. Consider a policy/allowlist for target domains.
- This app intentionally does not enable HSTS on itself because HTTPS termination depends on deployment. Configure HSTS at the HTTPS reverse proxy only after confirming all relevant subdomains are HTTPS-ready.
- The example contact address uses the reserved `.invalid` domain and is intentionally non-routable; replace it with a real monitored address before public deployment.

## Production deployment checklist

1. Use a supported Python runtime and pinned, reviewed dependency versions.
2. Set a strong secret through a secret manager/environment variable.
3. Use a production WSGI server such as Gunicorn behind a maintained reverse proxy.
4. Terminate TLS at a trusted proxy; configure HTTPS redirects and HSTS only after HTTPS readiness.
5. Do not expose the development server to the public internet.
6. Add authentication for scan history and report access if multiple users will use the service.
7. Use shared rate-limit storage for multiple workers.
8. Put scan jobs in a separate isolated worker with strict egress restrictions.
9. Add CI checks for tests, Bandit, dependency audit, and secret scanning.
10. Configure centralized access-controlled logs, alerts, backups, and restore tests.
11. Perform authorized browser-based responsive and accessibility tests.
12. Review privacy notices and applicable legal obligations before collecting user data.

## Suggested CI security checks

```bash
pip install bandit pip-audit
bandit -q -r app.py
pip-audit
pytest -q
```

These checks may report issues depending on package versions and environment; investigate results rather than suppressing them blindly.

## Project structure

```text
WebShield/
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── about.html
│   ├── 404.html
│   └── 429.html
├── static/
│   ├── favicon.svg
│   ├── css/style.css
│   └── js/app.js
└── tests/
    ├── conftest.py
    └── test_app.py
```

## Submission note

Before submitting to a bootcamp, run the app and tests yourself, take screenshots of the working interface and report, and describe the project honestly as a non-invasive security configuration scanner. Do not claim complete security or a successful scan until you have verified it in your environment.
